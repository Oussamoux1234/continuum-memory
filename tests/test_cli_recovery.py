"""Real CLI loss and fresh-process recovery with content-free durable locators.

Plaintext synthetic approval only. POSIX fault cases use actual daemon/CLI
processes and local sockets; the non-crash roundtrip also exercises native
Windows named pipes when run by that platform's existing fixture harness.
This is process-crash coverage, not power-loss or OS-backed approval evidence.
"""

import contextlib
import json
import os
import select
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path

from continuum_memory.security import read_private, sign_grant
from continuum_memory.storage import load_capability, paths
from fixtures.harness import EphemeralHarness


ROOT = Path(__file__).resolve().parents[1]
BODY = "cli-recovery-private-body-canary"
EVIDENCE = "cli-recovery-private-evidence-canary"
SUBJECT = "cli-recovery-private-subject-canary"


class PipeBarrier:
    """One bounded parent/child rendezvous; no scheduling sleeps or PID guesses."""

    def __init__(self, case):
        self.case = case
        self.ready_read, self.ready_write = os.pipe()
        self.release_read, self.release_write = os.pipe()
        self.child_ends = (self.ready_write, self.release_read)
        self.open_fds = set((self.ready_read, self.ready_write, self.release_read, self.release_write))
        case.addCleanup(self.close)

    def args(self):
        return ["--ready-fd", str(self.ready_write), "--release-fd", str(self.release_read)]

    def spawned(self):
        for fd in self.child_ends:
            os.close(fd)
            self.open_fds.remove(fd)

    def ready(self):
        readable, _, _ = select.select([self.ready_read], [], [], 10)
        self.case.assertEqual(readable, [self.ready_read], "CLI recovery fixture did not reach its barrier")
        self.case.assertEqual(os.read(self.ready_read, 1), b"R")

    def release(self):
        os.write(self.release_write, b"G")

    def close(self):
        for fd in self.open_fds:
            os.close(fd)
        self.open_fds.clear()


class CliRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.fx = EphemeralHarness(daemon_module="tests.cli_recovery_support")
        self.addCleanup(self.fx.close)
        self.env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT / "src"), str(ROOT)]),
                        PYTHONPYCACHEPREFIX=str(ROOT / "work" / "pycache"))
        self.params = ["remember", "--project", self.fx.projects["alpha"]["id"],
                       "--subject", SUBJECT, "--claim", BODY, "--evidence", EVIDENCE]

    def database(self):
        # An observer must not checkpoint or unlink the running daemon's WAL.
        # A writable second connection can clean up sidecars when it closes.
        uri = paths(self.fx.data_dir)["db"].as_uri() + "?mode=ro"
        return contextlib.closing(sqlite3.connect(uri, uri=True))

    def counts(self):
        with self.database() as db:
            return tuple(db.execute(sql).fetchone()[0] for sql in (
                "SELECT count(*) FROM assertion_versions",
                "SELECT count(*) FROM admin_results",
                "SELECT count(*) FROM admin_challenges WHERE used_at IS NOT NULL"))

    def methods(self):
        return read_private(self.fx.data_dir / ".cli-recovery-fixture" / "methods").decode("ascii").splitlines()

    def challenge(self):
        with self.database() as db:
            rows = db.execute("SELECT nonce,preview_digest,operation FROM admin_challenges").fetchall()
        self.assertEqual(len(rows), 1)
        return rows[0]

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)

    def child(self, point, barrier=None):
        command = [sys.executable, "-m", "tests.cli_recovery_support", "cli", "--data-dir",
                   str(self.fx.data_dir), "--point", point]
        kwargs = {}
        if barrier:
            command.extend(barrier.args())
            kwargs["pass_fds"] = barrier.child_ends
        process = subprocess.Popen(command + self.params, cwd=ROOT, env=self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
        self.addCleanup(self.stop, process)
        if barrier:
            barrier.spawned()
        return process

    def crashed(self, process):
        stdout, stderr = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 73, (stdout, stderr))
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"")

    def recover(self, *args, expected=0):
        # This is a brand-new, unpatched CLI interpreter: no fixture broker,
        # original preview, grant, request body, or old process memory.
        command = [sys.executable, "-m", "continuum_memory.cli", "--data-dir", str(self.fx.data_dir),
                   "--json", "recover"] + list(args)
        completed = subprocess.run(command, cwd=ROOT, env=self.env, capture_output=True, timeout=15)
        self.assertEqual(completed.returncode, expected, (completed.stdout, completed.stderr))
        self.assertEqual(completed.stderr, b"")
        return json.loads(completed.stdout)

    def journal_bytes(self):
        directory = self.fx.data_dir / "recovery"
        return {path.name: read_private(path) for path in directory.iterdir()} if directory.exists() else {}

    def assert_private_locator(self, nonce, digest, operation):
        records = self.journal_bytes()
        self.assertEqual(set(records), {nonce + ".json"})
        descriptor = json.loads(records[nonce + ".json"])
        self.assertEqual(set(descriptor), {"version", "vault_id", "nonce", "binding"})
        self.assertEqual(descriptor["nonce"], nonce)
        self.assertEqual(descriptor["version"], 1)
        token = load_capability(paths(self.fx.data_dir)["control"])["token"]
        grant = sign_grant(token.encode("ascii"), nonce, operation, digest)
        for forbidden in (BODY, EVIDENCE, SUBJECT, digest, token, grant, "preview_digest", '"grant"', '"preview"'):
            self.assertNotIn(forbidden.encode(), b"\n".join(records.values()))
        return records

    def assert_recovered(self, nonce, expected_status, expected_exit):
        before = self.counts()
        journal = self.journal_bytes()
        methods = self.methods()
        result = self.recover("--nonce", nonce, expected=expected_exit)
        self.assertEqual(set(result), {"status", "scope", "operations", "next_cursor", "has_more"})
        self.assertEqual(result["status"], "complete" if expected_status == "committed" else "unresolved")
        self.assertEqual(result["scope"], "page")
        self.assertFalse(result["has_more"])
        self.assertIsNone(result["next_cursor"])
        self.assertEqual(len(result["operations"]), 1)
        operation = result["operations"][0]
        self.assertEqual(operation["nonce"], nonce)
        self.assertEqual(operation["status"], expected_status)
        if expected_status == "committed":
            self.assertTrue(operation["receipt"]["committed"])
            self.assertEqual(operation["receipt"]["receipt_id"], nonce)
        else:
            self.assertNotIn("receipt", operation)
        self.assertEqual(self.counts(), before, "Recovery must never replay the original operation")
        self.assertEqual(self.methods(), methods + ["admin_recover"],
                         "Recovery must not attempt approval, apply, or mutation over actual IPC")
        self.assertEqual(self.journal_bytes(), journal, "Recovery must retain immutable local descriptors")
        return result

    def test_normal_cli_then_fresh_recover_preserves_receipt_without_reapproval(self):
        process = self.child("none")
        stdout, stderr = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 0, (stdout, stderr))
        self.assertEqual(stderr, b"")
        original = json.loads(stdout)
        nonce, digest, operation = self.challenge()
        self.assertEqual(self.counts(), (1, 1, 1))
        self.assert_private_locator(nonce, digest, operation)
        recovered = self.assert_recovered(nonce, "committed", 0)
        self.assertEqual(recovered["operations"][0]["receipt"]["result"],
                         {key: value for key, value in original.items() if key != "commit"})
        self.assertEqual(self.recover()["operations"], recovered["operations"])

    @unittest.skipIf(os.name == "nt", "POSIX subprocess/socket crash matrix; native happy path is tested separately")
    def test_process_exit_before_journal_persistence_never_sends_apply(self):
        self.crashed(self.child("before_journal"))
        self.assertEqual(self.counts(), (0, 0, 0))
        self.assertEqual(self.journal_bytes(), {})
        recovered = self.recover(expected=2)
        self.assertEqual(recovered["error"]["code"], "recovery_journal_missing")
        self.assertEqual(self.counts(), (0, 0, 0))

    @unittest.skipIf(os.name == "nt", "POSIX subprocess/socket crash matrix; native happy path is tested separately")
    def test_process_exits_after_journal_before_send_and_during_partial_send(self):
        for point in ("after_journal", "before_send", "partial_send"):
            with self.subTest(point=point):
                # Independent vaults make exact one-action/grant counts meaningful.
                previous = self.fx
                self.fx = EphemeralHarness(daemon_module="tests.cli_recovery_support")
                self.params[2] = self.fx.projects["alpha"]["id"]
                try:
                    self.crashed(self.child(point))
                    nonce, digest, operation = self.challenge()
                    self.assertEqual(self.counts(), (0, 0, 0))
                    self.assert_private_locator(nonce, digest, operation)
                    self.assert_recovered(nonce, "unknown", 2)
                    self.assert_recovered(nonce, "unknown", 2)
                finally:
                    self.fx.close()
                    self.fx = previous
                    self.params[2] = previous.projects["alpha"]["id"]

    @unittest.skipIf(os.name == "nt", "POSIX subprocess/socket crash matrix; native happy path is tested separately")
    def test_process_exit_after_real_reply_before_print_is_recoverable(self):
        self.crashed(self.child("before_print"))
        nonce, digest, operation = self.challenge()
        self.assertEqual(self.counts(), (1, 1, 1))
        self.assert_private_locator(nonce, digest, operation)
        self.assert_recovered(nonce, "committed", 0)

    @unittest.skipIf(os.name == "nt", "POSIX subprocess/socket crash matrix; native happy path is tested separately")
    def test_inflight_absent_receipt_is_unknown_then_resolves_without_retry(self):
        self.restart_daemon(point="in_flight")
        barrier = PipeBarrier(self)
        process = self.child("in_flight", barrier)
        barrier.ready()
        companions = [Path(str(paths(self.fx.data_dir)["db"]) + suffix) for suffix in ("-wal", "-shm")]
        identities = [(path.stat().st_dev, path.stat().st_ino) for path in companions]
        nonce, digest, operation = self.challenge()
        self.assertEqual(self.counts(), (0, 0, 0))
        journal = self.assert_private_locator(nonce, digest, operation)
        self.assert_recovered(nonce, "unknown", 2)
        self.assertEqual([(path.stat().st_dev, path.stat().st_ino) for path in companions], identities,
                         "Read-only test observations must not unlink the live daemon's WAL or SHM")
        barrier.release()
        self.crashed(process)
        self.assertEqual(self.counts(), (1, 1, 1))
        self.assert_recovered(nonce, "committed", 0)
        self.assertEqual(self.journal_bytes(), journal)

    def restart_daemon(self, barrier=None, point="none"):
        self.fx.daemon.terminate()
        self.fx.daemon.communicate(timeout=5)
        command = [sys.executable, "-m", "tests.cli_recovery_support", "daemon", "--data-dir",
                   str(self.fx.data_dir), "--point", point]
        kwargs = {}
        if barrier:
            command = [sys.executable, "-m", "tests.cli_recovery_support", "daemon", "--data-dir",
                       str(self.fx.data_dir), "--point", "before_reply"] + barrier.args()
            kwargs["pass_fds"] = barrier.child_ends
        self.fx.daemon = subprocess.Popen(command, cwd=ROOT, env=self.env, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.PIPE, **kwargs)
        if barrier:
            barrier.spawned()
        self.fx._wait_ready()

    @unittest.skipIf(os.name == "nt", "POSIX subprocess/socket crash matrix; native happy path is tested separately")
    def test_real_commit_before_any_reply_recovers_after_cli_exit_and_forget_reopen(self):
        daemon_barrier = PipeBarrier(self)
        self.restart_daemon(daemon_barrier)
        cli_barrier = PipeBarrier(self)
        process = self.child("before_reply", cli_barrier)
        cli_barrier.ready()
        daemon_barrier.ready()
        nonce, digest, operation = self.challenge()
        self.assertEqual(self.counts(), (1, 1, 1))
        journal = self.assert_private_locator(nonce, digest, operation)
        cli_barrier.release()
        self.crashed(process)
        daemon_barrier.release()
        recovered = self.assert_recovered(nonce, "committed", 0)
        assertion = recovered["operations"][0]["receipt"]["result"]["assertion_id"]
        self.fx.approve({"operation": "forget", "project": self.fx.projects["alpha"]["id"],
                         "target_id": assertion})
        self.restart_daemon()
        self.assertEqual(self.counts()[:2], (0, 2))
        self.assertEqual(self.assert_recovered(nonce, "committed", 0), recovered)
        self.assertEqual(self.journal_bytes(), journal)
        with self.database() as db:
            dumped = "\n".join(db.iterdump())
        for forbidden in (BODY, EVIDENCE, SUBJECT, digest):
            self.assertNotIn(forbidden, dumped)
        self.assertEqual(self.fx.control.call("audit_verify", {})["status"], "valid")
