"""SQLite locks survive native ACL observations; synthetic local fixtures only."""

import json
import os
import select
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from continuum_memory import macos_acl, security, storage
from continuum_memory.errors import MemoryError
from continuum_memory.security import ensure_private_sqlite_file, write_private
from tests.test_macos_acl import FakeACL


def _sidecar_identities(home):
    result = {}
    for suffix in ("-wal", "-shm"):
        path = home / ("continuum.db" + suffix)
        try:
            info = path.stat()
            result[suffix] = [info.st_dev, info.st_ino]
        except FileNotFoundError:
            result[suffix] = None
    return result


def _writer(home_value, additional_store):
    home = Path(home_value).resolve()
    if Path(tempfile.gettempdir()).resolve() not in home.parents:
        raise RuntimeError("The lock regression requires a disposable temporary vault")
    security.ensure_private_regular(home / ".sqlite-lock-fixture")
    store = storage.Store(home)
    original = _sidecar_identities(home)
    if additional_store:
        # A second Store's pre-open checks also run while the first connection
        # owns locks, so merely fixing the post-open check would be insufficient.
        other = storage.Store(home)
        if other.vault_id != store.vault_id:
            raise RuntimeError("The synthetic vault identity changed")
        other.close()
    print(json.dumps({"phase": "ready", "original": original,
                      "current": _sidecar_identities(home)}), flush=True)
    if sys.stdin.readline() != "commit\n":
        raise RuntimeError("The synthetic commit was not requested")
    store.begin()
    store.connection.execute("INSERT INTO metadata(key,value) VALUES('synthetic_lock_probe','committed')")
    store.commit()
    own_count = store.connection.execute("SELECT count(*) FROM metadata WHERE key='synthetic_lock_probe'").fetchone()[0]
    print(json.dumps({"phase": "committed", "count": own_count,
                      "current": _sidecar_identities(home)}), flush=True)
    if sys.stdin.readline() != "crash\n":
        raise RuntimeError("The synthetic abrupt exit was not requested")
    # No connection.close(), context-manager exit or graceful checkpoint.
    os._exit(73)


class SQLiteACLObservationContractTest(unittest.TestCase):
    def setUp(self):
        self.path = Path("synthetic-sqlite.db")
        self.metadata = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o600,
                                        st_nlink=1, st_uid=501, st_gid=20, st_ctime_ns=1)

    def test_native_query_uses_no_extra_open_or_close(self):
        library = FakeACL()
        with patch.object(macos_acl.sys, "platform", "darwin"), \
                patch.object(Path, "lstat", return_value=self.metadata), \
                patch.object(macos_acl, "_library", return_value=library), \
                patch.object(macos_acl.os, "open") as opening, \
                patch.object(macos_acl.os, "close") as closing:
            macos_acl.require_no_acl_sqlite_path(self.path, self.metadata)
        library.acl_get_link_np.assert_called_once_with(os.fsencode(self.path), macos_acl.ACL_TYPE_EXTENDED)
        library.acl_get_fd_np.assert_not_called()
        opening.assert_not_called()
        closing.assert_not_called()

    def test_every_metadata_change_before_or_after_query_is_refused_without_retry(self):
        for field in vars(self.metadata):
            changed = SimpleNamespace(**vars(self.metadata))
            setattr(changed, field, getattr(changed, field) + 1)
            for position in (0, 1):
                observations = [self.metadata, self.metadata]
                observations[position] = changed
                library = FakeACL()
                with self.subTest(field=field, position=position), \
                        patch.object(macos_acl.sys, "platform", "darwin"), \
                        patch.object(Path, "lstat", side_effect=observations) as observed, \
                        patch.object(macos_acl, "_library", return_value=library):
                    with self.assertRaises(MemoryError) as caught:
                        macos_acl.require_no_acl_sqlite_path(self.path, self.metadata)
                    self.assertEqual(caught.exception.code, "unsafe_file")
                    self.assertEqual(observed.call_count, position + 1)
                    self.assertEqual(library.acl_get_link_np.call_count, position)

    def test_query_failure_or_nonempty_acl_never_falls_back(self):
        for failure in (OSError("sensitive-path"), AttributeError("sensitive-symbol"),
                        TypeError("sensitive-value"), ValueError("sensitive-value")):
            with self.subTest(failure=type(failure).__name__), \
                    patch.object(macos_acl.sys, "platform", "darwin"), \
                    patch.object(Path, "lstat", return_value=self.metadata), \
                    patch.object(macos_acl, "_library", side_effect=failure) as library:
                with self.assertRaises(MemoryError) as caught:
                    macos_acl.require_no_acl_sqlite_path(self.path, self.metadata)
                self.assertEqual(caught.exception.code, "acl_unavailable")
                self.assertNotIn("sensitive", str(caught.exception.as_dict()))
                library.assert_called_once_with()
        library = FakeACL(size=68)
        with patch.object(macos_acl.sys, "platform", "darwin"), \
                patch.object(Path, "lstat", return_value=self.metadata), \
                patch.object(macos_acl, "_library", return_value=library):
            with self.assertRaises(MemoryError) as caught:
                macos_acl.require_no_acl_sqlite_path(self.path, self.metadata)
        self.assertEqual(caught.exception.code, "unsafe_permissions")
        self.assertEqual(library.acl_get_link_np.call_count, 1)

    def test_other_platforms_do_not_load_native_acl_or_touch_paths(self):
        for platform in ("linux", "win32"):
            with self.subTest(platform=platform), patch.object(macos_acl.sys, "platform", platform), \
                    patch.object(Path, "lstat") as lstat, patch.object(macos_acl, "_library") as library:
                macos_acl.require_no_acl_sqlite_path(self.path, self.metadata)
                lstat.assert_not_called()
                library.assert_not_called()


@unittest.skipUnless(sys.platform == "darwin", "Native macOS SQLite/ACL lock-preservation evidence")
class NativeSQLiteLockPreservationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cm-sql-lock-")
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)

    def observer_count(self):
        # Deliberately ordinary writable-mode sqlite3.connect, even though its
        # only statement is SELECT. mode=ro would conceal the historical bug.
        connection = sqlite3.connect(self.home / "continuum.db")
        try:
            return connection.execute("SELECT count(*) FROM metadata WHERE key='synthetic_lock_probe'").fetchone()[0]
        finally:
            connection.close()

    def receive(self, process):
        ready, _, _ = select.select([process.stdout], [], [], 15)
        self.assertTrue(ready, "The synthetic writer did not reach the expected phase")
        line = process.stdout.readline()
        self.assertTrue(line, "The synthetic writer exited before its expected phase")
        return json.loads(line)

    def run_two_process_regression(self, additional_store):
        storage.Store.bootstrap(self.home, [{"name": "fixture", "path_hint": "/fixture", "providers": ["codex"]}])
        write_private(self.home / ".sqlite-lock-fixture", b"disposable fixture\n")
        root = Path(__file__).resolve().parents[1]
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join((str(root / "src"), str(root)))
        process = subprocess.Popen(
            [sys.executable, "-c", "import sys; from tests.test_sqlite_lock_preservation import _writer; "
             "_writer(sys.argv[1], sys.argv[2] == 'multiple')", str(self.home),
             "multiple" if additional_store else "single"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment,
        )
        try:
            ready = self.receive(process)
            self.assertEqual(ready["phase"], "ready")
            original = ready["original"]
            self.assertTrue(all(identity is not None for identity in original.values()))
            self.assertEqual(ready["current"], original)
            self.assertEqual(self.observer_count(), 0)
            # Historical failure: closing that reader removed both files while
            # the live writer still held handles to their now-unlinked inodes.
            self.assertEqual(_sidecar_identities(self.home), original)
            process.stdin.write("commit\n")
            process.stdin.flush()
            committed = self.receive(process)
            self.assertEqual(committed["phase"], "committed")
            self.assertEqual(committed["count"], 1)
            self.assertEqual(committed["current"], original)
            self.assertEqual(self.observer_count(), 1)
            self.assertEqual(_sidecar_identities(self.home), original)
            process.stdin.write("crash\n")
            process.stdin.flush()
            stdout, stderr = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 73)
            self.assertEqual((stdout, stderr), ("", ""))
            self.assertEqual(_sidecar_identities(self.home), original)
            self.assertEqual(self.observer_count(), 1)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=15)

    def test_committed_row_survives_other_reader_close_and_abrupt_writer_exit(self):
        self.run_two_process_regression(False)

    def test_second_store_in_writer_process_preserves_first_store_locks(self):
        self.run_two_process_regression(True)

    def test_all_database_sidecar_observations_avoid_extra_descriptors(self):
        database = self.home / "continuum.db"
        materials = {Path(str(database) + suffix) for suffix in ("", "-wal", "-shm", "-journal")}
        for path in materials:
            write_private(path, b"synthetic")
        regular = self.home / "synthetic.cap"
        write_private(regular, b"synthetic")
        original_open = os.open
        regular_observations = []
        def reject_sqlite_open(path, *args, **kwargs):
            observed = Path(path)
            self.assertNotIn(observed, materials, "SQLite material must not get an independent metadata descriptor")
            if observed == regular:
                regular_observations.append(path)
            return original_open(path, *args, **kwargs)
        with patch.object(macos_acl.os, "open", side_effect=reject_sqlite_open):
            storage._validate_database_files(database)
            security.ensure_private_regular(regular)
        self.assertEqual(len(regular_observations), 1, "Ordinary private files retain descriptor-bound ACL checks")

    def test_bootstrap_and_both_store_opens_never_metadata_open_sqlite_material(self):
        database = self.home / "continuum.db"
        materials = {Path(str(database) + suffix) for suffix in ("", "-wal", "-shm", "-journal")}
        original_open = os.open
        observed = []
        def reject_metadata_open(path, flags, *args, **kwargs):
            if Path(path) in materials:
                observed.append((Path(path), flags))
                self.assertFalse(flags & macos_acl.DARWIN_O_EVTONLY,
                                 "Production SQLite validation must not independently metadata-open its files")
            return original_open(path, flags, *args, **kwargs)
        with patch.object(macos_acl.os, "open", side_effect=reject_metadata_open):
            created = storage.Store.bootstrap(
                self.home, [{"name": "fixture", "path_hint": "/fixture", "providers": ["codex"]}])
            first = storage.Store(self.home)
            try:
                second = storage.Store(self.home)
                try:
                    self.assertEqual(first.vault_id, created["vault_id"])
                    self.assertEqual(second.vault_id, first.vault_id)
                finally:
                    second.close()
            finally:
                first.close()
        # The one legitimate Python-level open initializes an empty private
        # database before SQLite owns it; SQLite's own native opens are separate.
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0][0], database)
        self.assertEqual(observed[0][1] & (os.O_CREAT | os.O_EXCL), os.O_CREAT | os.O_EXCL)

    def test_sqlite_file_type_link_mode_and_owner_checks_precede_acl_query(self):
        source = self.home / "original"
        write_private(source, b"synthetic")
        for kind in ("symlink", "hardlink", "fifo", "directory", "mode", "owner"):
            with self.subTest(kind=kind):
                target = self.home / kind
                if kind == "symlink":
                    target.symlink_to(source)
                elif kind == "hardlink":
                    os.link(source, target)
                elif kind == "fifo":
                    os.mkfifo(target, 0o600)
                elif kind == "directory":
                    target.mkdir(mode=0o700)
                else:
                    write_private(target, b"synthetic")
                    if kind == "mode":
                        target.chmod(0o644)
                uid = os.getuid() + (1 if kind == "owner" else 0)
                with patch.object(security.os, "getuid", return_value=uid), \
                        patch.object(macos_acl, "_library") as library:
                    with self.assertRaises(MemoryError) as caught:
                        ensure_private_sqlite_file(target)
                    self.assertEqual(caught.exception.code,
                                     {"mode": "unsafe_permissions", "owner": "unsafe_owner"}.get(kind, "unsafe_file"))
                    library.assert_not_called()
                if kind == "hardlink":
                    target.unlink()

    def test_actual_sqlite_acl_denial_is_preserved(self):
        target = self.home / "continuum.db"
        write_private(target, b"synthetic")
        subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(target)],
                       check=True, capture_output=True, timeout=5)
        with self.assertRaises(MemoryError) as caught:
            ensure_private_sqlite_file(target)
        self.assertEqual(caught.exception.code, "unsafe_permissions")

    def test_pathname_changes_after_native_acl_query_are_refused(self):
        original_check = macos_acl._check_acl
        for kind in ("replace", "symlink", "unlink", "chmod", "hardlink"):
            with self.subTest(kind=kind):
                source = self.home / (kind + ".db")
                other = self.home / (kind + ".other")
                displaced = self.home / (kind + ".displaced")
                write_private(source, b"original")
                write_private(other, b"untouched")
                changed = []
                def change_after_query(library, query, target):
                    original_check(library, query, target)
                    if target != os.fsencode(source):
                        return
                    changed.append(kind)
                    if kind in ("replace", "symlink"):
                        source.rename(displaced)
                        if kind == "replace":
                            write_private(source, b"replacement")
                        else:
                            source.symlink_to(other)
                    elif kind == "unlink":
                        source.unlink()
                    elif kind == "chmod":
                        source.chmod(0o644)
                    else:
                        os.link(source, displaced)
                with patch.object(macos_acl, "_check_acl", side_effect=change_after_query):
                    with self.assertRaises(MemoryError) as caught:
                        ensure_private_sqlite_file(source)
                self.assertEqual(changed, [kind])
                self.assertEqual(caught.exception.code, "acl_unavailable" if kind == "unlink" else "unsafe_file")
                self.assertEqual(other.read_bytes(), b"untouched")


if __name__ == "__main__":
    unittest.main()
