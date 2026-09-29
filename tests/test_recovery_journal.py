"""Synthetic private journals; no approval, keys, accounts or live user memory."""

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum_memory import recovery_journal as journal
from continuum_memory.errors import MemoryError
from continuum_memory.security import create_private_directory, write_private
from fixtures.harness import private_test_home
from fixtures.windows_acl import set_fixture_acl


def locator(number=1):
    return {"version": 1, "vault_id": "vault_123456", "nonce": "nonce_%08d" % number,
            "binding": "%064x" % number}


class RecoveryJournalTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cm-recovery-")
        self.addCleanup(self.temporary.cleanup)
        self.home = private_test_home(self.temporary.name)
        self.directory = self.home / journal.JOURNAL_DIRECTORY

    def assert_code(self, code, operation, *args, **kwargs):
        with self.assertRaises(MemoryError) as caught:
            operation(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn(str(self.home), caught.exception.message)

    def raw_file(self, name, data):
        if not self.directory.exists():
            create_private_directory(self.directory)
        path = self.directory / name
        write_private(path, data)
        return path

    def test_exact_opaque_roundtrip_survives_a_fresh_process(self):
        expected = locator()
        path = journal.persist_locator(self.home, expected)
        self.assertEqual(path, self.directory / (expected["nonce"] + ".json"))
        self.assertEqual(json.loads(path.read_bytes()), expected)
        self.assertEqual(set(json.loads(path.read_bytes())), {"version", "vault_id", "nonce", "binding"})
        result = subprocess.run(
            [sys.executable, "-c", "import json,sys; from continuum_memory.recovery_journal "
             "import load_locators; print(json.dumps(load_locators(sys.argv[1])))", str(self.home)],
            env=self.child_environment(), capture_output=True, timeout=15, check=True,
        )
        self.assertEqual(json.loads(result.stdout), {"locators": [expected], "next_cursor": None})
        self.assertEqual(result.stderr, b"")

    def test_repeated_nonce_never_replaces_original(self):
        expected = locator()
        path = journal.persist_locator(self.home, expected)
        original = path.read_bytes()
        for candidate in (expected, dict(expected, binding="f" * 64)):
            self.assert_code("recovery_journal_conflict", journal.persist_locator, self.home, candidate)
            self.assertEqual(path.read_bytes(), original)

    def test_invalid_descriptor_never_creates_a_directory(self):
        for candidate in (dict(locator(), version=True), dict(locator(), body="synthetic unwanted text"),
                          dict(locator(), nonce="../unsafe"), dict(locator(), binding="x" * 64)):
            with self.subTest(candidate=candidate), self.assertRaises(MemoryError):
                journal.persist_locator(self.home, candidate)
            self.assertFalse(self.directory.exists())

    def test_missing_and_empty_are_not_execution_results(self):
        self.assert_code("recovery_journal_missing", journal.load_locators, self.home)
        self.assertFalse(self.directory.exists())
        create_private_directory(self.directory)
        self.assertEqual(journal.load_locators(self.home), {"locators": [], "next_cursor": None})
        self.assert_code("recovery_journal_missing", journal.load_locators,
                         self.home, nonce=locator()["nonce"])

    def test_lexical_pages_are_deterministic_and_targeted_lookup_is_exact(self):
        for number in (4, 1, 3, 2):
            journal.persist_locator(self.home, locator(number))
        first = journal.load_locators(self.home, limit=2)
        self.assertEqual(first, {"locators": [locator(1), locator(2)], "next_cursor": locator(2)["nonce"]})
        second = journal.load_locators(self.home, after=first["next_cursor"], limit=2)
        self.assertEqual(second, {"locators": [locator(3), locator(4)], "next_cursor": None})
        self.assertEqual(journal.load_locators(self.home, after=locator(4)["nonce"]),
                         {"locators": [], "next_cursor": None})
        self.assertEqual(journal.load_locators(self.home, nonce=locator(3)["nonce"]),
                         {"locators": [locator(3)], "next_cursor": None})
        # A later lower-sorting publication requires restarting this non-snapshot
        # listing; the documented lexical cursor is never an execution receipt.
        journal.persist_locator(self.home, locator(0))
        self.assertEqual(journal.load_locators(self.home, after=locator(2)["nonce"], limit=2), second)
        self.assertEqual(journal.load_locators(self.home, limit=1)["locators"], [locator(0)])

    def test_invalid_listing_arguments_are_rejected(self):
        for kwargs in ({"limit": True}, {"limit": 0}, {"limit": 26}, {"after": "../unsafe"},
                       {"nonce": "bad"}, {"nonce": locator()["nonce"], "after": locator()["nonce"]}):
            with self.subTest(kwargs=kwargs), self.assertRaises(MemoryError):
                journal.load_locators(self.home, **kwargs)

    def test_scan_limit_is_explicit_and_does_not_block_direct_recovery(self):
        for number in range(4):
            journal.persist_locator(self.home, locator(number))
        # Small bound, real entries: exercise the same production limit branch
        # without thousands of unnecessary durable fixture publications.
        with patch.object(journal, "MAX_JOURNAL_ENTRIES", 3):
            self.assert_code("recovery_journal_scan_limit", journal.load_locators, self.home, limit=1)
            self.assertEqual(journal.load_locators(self.home, nonce=locator(3)["nonce"])["locators"], [locator(3)])
        self.assertEqual(len(list(self.directory.iterdir())), 4)

    def test_malformed_ambiguous_and_oversized_records_fail_without_deletion(self):
        valid = json.dumps(locator()).encode()
        invalid_records = [
            b"", b"{", b"\xff", b"null", valid[:-1] + b',"version":1}',
            valid.replace(b'"version": 1', b'"version": true'),
            valid[:-1] + b',"body":"synthetic unwanted text"}',
            valid.replace(b'"version": 1', b'"version": NaN'),
            b"[" * 65 + b"0" + b"]" * 65,
            valid + b" " * journal.MAX_LOCATOR_BYTES,
            json.dumps(locator(2)).encode(),
        ]
        for number, raw in enumerate(invalid_records):
            with self.subTest(number=number), tempfile.TemporaryDirectory(prefix="cm-invalid-") as temporary:
                home = private_test_home(temporary)
                directory = home / journal.JOURNAL_DIRECTORY
                create_private_directory(directory)
                path = directory / (locator()["nonce"] + ".json")
                write_private(path, raw)
                expected_code = ("unsafe_file" if os.name == "nt" and len(raw) > journal.MAX_LOCATOR_BYTES
                                 else "recovery_journal_invalid")
                self.assert_code(expected_code, journal.load_locators, home)
                self.assertEqual(path.read_bytes(), raw)

    def test_unknown_and_corrupt_entries_are_not_silently_hidden_by_pages(self):
        journal.persist_locator(self.home, locator(1))
        corrupt = self.raw_file(locator(9)["nonce"] + ".json", b"{")
        self.assert_code("recovery_journal_invalid", journal.load_locators, self.home, limit=1)
        self.assert_code("recovery_journal_invalid", journal.load_locators,
                         self.home, after=locator(9)["nonce"])
        self.assertEqual(journal.load_locators(self.home, nonce=locator(1)["nonce"])["locators"], [locator(1)])
        self.assertEqual(corrupt.read_bytes(), b"{")
        unexpected = self.raw_file("unknown.txt", b"synthetic residue")
        self.assert_code("recovery_journal_invalid", journal.load_locators, self.home)
        self.assertEqual(unexpected.read_bytes(), b"synthetic residue")

    def test_hardlinked_record_is_rejected_and_retained(self):
        path = journal.persist_locator(self.home, locator())
        link = self.home / "linked-record"
        os.link(path, link)
        self.assert_code("unsafe_file", journal.load_locators, self.home)
        self.assertTrue(path.exists())
        self.assertEqual(link.read_bytes(), path.read_bytes())

    def test_broad_record_permissions_are_rejected_without_repair(self):
        path = journal.persist_locator(self.home, locator())
        if os.name == "nt":
            set_fixture_acl(path, broad=True)
            self.addCleanup(set_fixture_acl, path)
        else:
            path.chmod(0o644)
        self.assert_code("unsafe_permissions", journal.load_locators, self.home)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)

    def test_broad_directory_permissions_are_rejected_without_repair(self):
        journal.persist_locator(self.home, locator())
        if os.name == "nt":
            set_fixture_acl(self.directory, broad=True)
            self.addCleanup(set_fixture_acl, self.directory)
        else:
            self.directory.chmod(0o755)
        self.assert_code("unsafe_permissions", journal.load_locators, self.home)
        self.assert_code("unsafe_permissions", journal.persist_locator, self.home, locator(2))
        self.assertFalse((self.directory / (locator(2)["nonce"] + ".json")).exists())

    @unittest.skipIf(os.name == "nt", "POSIX links/FIFO; native Windows reparse tests are separate")
    def test_symlinks_fifo_and_wrong_directory_type_fail_without_blocking(self):
        create_private_directory(self.directory)
        for kind in ("symlink", "fifo", "directory"):
            with self.subTest(kind=kind):
                path = self.directory / (locator()["nonce"] + ".json")
                if kind == "symlink":
                    path.symlink_to(self.home / "missing-target")
                elif kind == "fifo":
                    os.mkfifo(path, 0o600)
                else:
                    create_private_directory(path)
                with self.assertRaises(MemoryError):
                    journal.load_locators(self.home)
                self.assertTrue(os.path.lexists(path))
                path.rmdir() if kind == "directory" else path.unlink()
        self.directory.rmdir()
        self.directory.symlink_to(self.home, target_is_directory=True)
        with self.assertRaises(MemoryError):
            journal.persist_locator(self.home, locator())
        self.assertFalse((self.home / (locator()["nonce"] + ".json")).exists())

    @unittest.skipUnless(sys.platform == "darwin", "Native macOS ACL rejection")
    def test_extended_acl_is_rejected_without_repair(self):
        path = journal.persist_locator(self.home, locator())
        subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(path)], check=True, capture_output=True)
        self.addCleanup(subprocess.run, ["/bin/chmod", "-N", str(path)], check=True, capture_output=True)
        self.assert_code("unsafe_permissions", journal.load_locators, self.home)

    @unittest.skipIf(os.name == "nt", "POSIX file and directory fsync ordering")
    def test_publication_flushes_file_then_journal_then_parent(self):
        original = os.fsync
        seen = []
        def observe(fd):
            info = os.fstat(fd)
            seen.append((stat.S_ISDIR(info.st_mode), info.st_ino))
            return original(fd)
        with patch.object(journal.os, "fsync", side_effect=observe):
            path = journal.persist_locator(self.home, locator())
        self.assertEqual(seen, [(False, path.stat().st_ino), (True, self.directory.stat().st_ino),
                                (True, self.home.stat().st_ino)])
        seen.clear()
        with patch.object(journal.os, "fsync", side_effect=observe):
            path = journal.persist_locator(self.home, locator(2))
        self.assertEqual(seen, [(False, path.stat().st_ino), (True, self.directory.stat().st_ino),
                                (True, self.home.stat().st_ino)])

    @unittest.skipIf(os.name == "nt", "POSIX write failure injection")
    def test_partial_or_zero_write_never_reports_success_or_removes_residue(self):
        original = os.write
        for number, zero in enumerate((False, True), start=1):
            expected = locator(number)
            written = []
            def fail(fd, data):
                if zero:
                    return 0
                if written:
                    raise OSError("synthetic write failure")
                written.append(original(fd, data[:7]))
                return written[0]
            with patch.object(journal.os, "write", side_effect=fail):
                self.assert_code("recovery_journal_unavailable", journal.persist_locator, self.home, expected)
            path = self.directory / (expected["nonce"] + ".json")
            self.assertEqual(path.stat().st_size, 0 if zero else 7)
            self.assert_code("recovery_journal_conflict", journal.persist_locator, self.home, expected)
            self.assert_code("recovery_journal_invalid", journal.load_locators, self.home, nonce=expected["nonce"])

    @unittest.skipIf(os.name == "nt", "POSIX fsync failure injection")
    def test_each_flush_failure_preserves_record_and_fails_closed(self):
        original = os.fsync
        for number in (1, 2, 3):
            calls = []
            def fail(fd):
                calls.append(fd)
                if len(calls) == number:
                    raise OSError("synthetic flush failure")
                return original(fd)
            with patch.object(journal.os, "fsync", side_effect=fail):
                self.assert_code("recovery_journal_unavailable", journal.persist_locator, self.home, locator(number))
            path = self.directory / (locator(number)["nonce"] + ".json")
            self.assertEqual(json.loads(path.read_bytes()), locator(number))
            self.assert_code("recovery_journal_conflict", journal.persist_locator, self.home, locator(number))

    @unittest.skipUnless(os.name == "nt", "Native Windows FlushFileBuffers failure fixture")
    def test_native_flush_failure_retains_locator_and_never_reports_publication(self):
        from continuum_memory.windows_boundary import WindowsBoundary

        original_write = WindowsBoundary.write_new
        observed = []
        def fail_flush(boundary, path, raw):
            # CREATE_NEW, owner/DACL checks and WriteFile are real. Only the
            # final flush fails; production must close and retain this file.
            with patch.object(boundary.kernel, "FlushFileBuffers", return_value=0) as fault:
                try:
                    return original_write(boundary, path, raw)
                finally:
                    observed.append(fault.call_count)

        expected = locator()
        with patch.object(WindowsBoundary, "write_new", new=fail_flush):
            self.assert_code("windows_boundary_error", journal.persist_locator, self.home, expected)
        self.assertEqual(observed, [1])
        path = self.directory / (expected["nonce"] + ".json")
        original = path.read_bytes()
        self.assertEqual(json.loads(original), expected)
        # Readable residue is only a locator, not proof of durable publication
        # or action execution. A retry must never adopt or replace it.
        self.assertEqual(journal.load_locators(self.home, nonce=expected["nonce"]),
                         {"locators": [expected], "next_cursor": None})
        for candidate in (expected, dict(expected, binding="f" * 64)):
            self.assert_code("recovery_journal_conflict", journal.persist_locator, self.home, candidate)
            self.assertEqual(path.read_bytes(), original)

    @unittest.skipUnless(os.name == "nt", "Native Windows post-flush readback failure fixture")
    def test_native_readback_failure_retains_flushed_locator_without_adopting_it(self):
        from continuum_memory.windows_boundary import WindowsBoundary

        cases = (({"side_effect": MemoryError("windows_boundary_error", "Synthetic native read failure.")},
                  "windows_boundary_error"),
                 ({"return_value": b"{}"}, "recovery_journal_unavailable"))
        for number, (fault_arguments, code) in enumerate(cases, start=1):
            with self.subTest(code=code):
                expected = locator(number)
                # The full native write and FlushFileBuffers finish first.
                # Inject only the final bounded read, or its mismatching bytes.
                with patch.object(WindowsBoundary, "_read_handle", **fault_arguments) as fault:
                    self.assert_code(code, journal.persist_locator, self.home, expected)
                self.assertEqual(fault.call_count, 1)
                path = self.directory / (expected["nonce"] + ".json")
                original = path.read_bytes()
                self.assertEqual(json.loads(original), expected)
                self.assertEqual(journal.load_locators(self.home, nonce=expected["nonce"]),
                                 {"locators": [expected], "next_cursor": None})
                for candidate in (expected, dict(expected, binding="f" * 64)):
                    self.assert_code("recovery_journal_conflict", journal.persist_locator, self.home, candidate)
                    self.assertEqual(path.read_bytes(), original)

    @unittest.skipIf(os.name == "nt", "POSIX namespace replacement race")
    def test_directory_replacement_after_open_is_detected_and_not_followed(self):
        original = os.write
        saved = self.home / "old-recovery"
        def replace(fd, data):
            self.directory.rename(saved)
            create_private_directory(self.directory)
            return original(fd, data)
        with patch.object(journal.os, "write", side_effect=replace):
            self.assert_code("recovery_journal_unavailable", journal.persist_locator, self.home, locator())
        self.assertEqual(list(self.directory.iterdir()), [])
        self.assertEqual(json.loads((saved / (locator()["nonce"] + ".json")).read_bytes()), locator())

    def child_environment(self):
        root = Path(__file__).resolve().parents[1]
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join((str(root / "src"), str(root)))
        return environment

    def concurrent_writers(self, numbers):
        script = (
            "import json,sys; from continuum_memory.recovery_journal import persist_locator; "
            "from continuum_memory.errors import MemoryError\n"
            "print('ready',flush=True); sys.stdin.readline()\n"
            "try:\n persist_locator(sys.argv[1],json.loads(sys.argv[2])); print('ok')\n"
            "except MemoryError as error:\n print(error.code)\n"
        )
        processes = [subprocess.Popen(
            [sys.executable, "-c", script, str(self.home), json.dumps(locator(number))],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=self.child_environment(),
        ) for number in numbers]
        try:
            for process in processes:
                self.assertEqual(process.stdout.readline(), "ready\n")
            for process in processes:
                process.stdin.write("go\n")
                process.stdin.flush()
            results = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 0)
                self.assertEqual(stderr, "")
                results.append(stdout.strip())
            return results
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=15)

    def test_real_concurrent_distinct_writers_can_create_one_private_directory(self):
        self.assertEqual(self.concurrent_writers((1, 2, 3, 4)), ["ok"] * 4)
        self.assertEqual(journal.load_locators(self.home)["locators"], [locator(i) for i in (1, 2, 3, 4)])

    def test_real_concurrent_same_nonce_has_exactly_one_winner(self):
        results = self.concurrent_writers((1, 1, 1))
        self.assertEqual(results.count("ok"), 1)
        self.assertTrue(all(result in ("ok", "recovery_journal_conflict", "windows_boundary_error")
                            for result in results))
        self.assertEqual(journal.load_locators(self.home)["locators"], [locator()])


if __name__ == "__main__":
    unittest.main()
