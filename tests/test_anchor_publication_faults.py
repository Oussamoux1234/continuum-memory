"""POSIX audit-anchor publication faults after a real synthetic SQL commit.

Only exact publication paths/live FDs are intercepted. This is process-crash and
injected-I/O-error evidence, not power-loss, SQLCipher or Windows evidence.
"""

import errno
import json
import os
import re
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum_memory import security
from continuum_memory.errors import MemoryError
from continuum_memory.security import canonical_json, read_private
from continuum_memory.storage import Store, load_capability, paths
from tests.admin_crash_support import (
    AdminCrashFixture, CRASH_EXIT, fixture_kernel, fixture_params, snapshot,
)


CHECKPOINTS = ("temp_created", "partial_write", "file_synced", "before_rename", "after_rename", "directory_synced")
FAULTS = {"write_enospc": errno.ENOSPC, "file_fsync_eio": errno.EIO,
          "rename_eio": errno.EIO, "directory_fsync_eio": errno.EIO}
CANARY = "anchorpublicationcanary"


class PublicationFault:
    """Bound a single fault to one existing anchor's replacement, never the DB."""

    def __init__(self, anchor, point):
        self.anchor = anchor
        self.point = point
        self.checkpoints = []
        self.injected = []
        self.temporary = None
        self.live = {}
        self.file_fd = self.directory_fd = None
        self.renamed = False
        self.writes = 0
        self.publications = 0
        self.real_open, self.real_close = os.open, os.close
        self.real_write, self.real_fsync, self.real_replace = os.write, os.fsync, os.replace
        self.real_private = security.write_private

    def checkpoint(self, label):
        self.checkpoints.append(label)
        if self.point == label:
            print(canonical_json({"checkpoint": label, "reached": self.checkpoints}), flush=True)
            os._exit(CRASH_EXIT)

    def inject(self, name):
        if self.point == name:
            if self.injected:
                raise AssertionError("Fault injected more than once")
            self.injected.append({"fault": name, "errno": FAULTS[name]})
            raise OSError(FAULTS[name], "synthetic anchor publication fault")

    @staticmethod
    def identity(fd):
        info = os.fstat(fd)
        return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)

    def matches(self, fd, tracked):
        return tracked is not None and fd == tracked and self.live.get(fd) == self.identity(fd)

    def open(self, path, flags, *args, **kwargs):
        fd = self.real_open(path, flags, *args, **kwargs)
        if self.temporary is not None and Path(path) == self.temporary and flags & os.O_CREAT:
            if self.file_fd is not None or not flags & os.O_EXCL or not flags & os.O_WRONLY:
                raise AssertionError("Unexpected publication temporary open")
            self.live[fd] = self.identity(fd)
            if self.live[fd][2] != stat.S_IFREG:
                raise AssertionError("Publication temporary is not regular")
            self.file_fd = fd
            self.checkpoint("temp_created")
        elif self.renamed and Path(path) == self.anchor.parent and flags == os.O_RDONLY:
            self.live[fd] = self.identity(fd)
            directory = self.anchor.parent.stat()
            if self.live[fd] != (directory.st_dev, directory.st_ino, stat.S_IFDIR):
                raise AssertionError("Unexpected publication directory handle")
            self.directory_fd = fd
        return fd

    def close(self, fd):
        try:
            return self.real_close(fd)
        finally:
            self.live.pop(fd, None)
            if fd == self.file_fd:
                self.file_fd = None
            if fd == self.directory_fd:
                self.directory_fd = None

    def write(self, fd, data):
        if not self.matches(fd, self.file_fd):
            return self.real_write(fd, data)
        self.writes += 1
        if self.writes == 1:
            # Return an actual positive short write. ENOSPC, if selected, occurs
            # on the next real write-loop iteration, never before any bytes exist.
            count = self.real_write(fd, data[:7])
            if not 0 < count < len(data):
                raise AssertionError("Positive partial-write control was not reached")
            self.checkpoint("partial_write")
            return count
        self.inject("write_enospc")
        return self.real_write(fd, data)

    def fsync(self, fd):
        if self.matches(fd, self.file_fd):
            self.inject("file_fsync_eio")
            self.real_fsync(fd)
            self.checkpoint("file_synced")
        elif self.matches(fd, self.directory_fd):
            self.inject("directory_fsync_eio")
            self.real_fsync(fd)
            self.checkpoint("directory_synced")
        else:
            self.real_fsync(fd)

    def replace(self, source, destination, *args, **kwargs):
        if self.temporary is not None and Path(source) == self.temporary and Path(destination) == self.anchor:
            self.checkpoint("before_rename")
            self.inject("rename_eio")
            self.real_replace(source, destination, *args, **kwargs)
            self.renamed = True
            self.checkpoint("after_rename")
        else:
            return self.real_replace(source, destination, *args, **kwargs)

    def private(self, path, data):
        pattern = r"\." + re.escape(self.anchor.name) + r"\.[0-9a-f]{12}\.tmp"
        if self.temporary is not None or path.parent != self.anchor.parent or not re.fullmatch(pattern, path.name):
            raise AssertionError("Unexpected path inside exact anchor publication")
        self.temporary = path
        return self.real_private(path, data)

    def publish(self, original, connection, path):
        self.publications += 1
        if path != self.anchor or self.publications != 1:
            raise AssertionError("Fault must target exactly one operation anchor publication")
        # Installed only after bootstrap, preview, grant consumption and SQL
        # commit. All other paths and FDs delegate to the captured real functions.
        with patch.object(security, "write_private", side_effect=self.private), \
                patch.object(security.os, "open", side_effect=self.open), \
                patch.object(security.os, "close", side_effect=self.close), \
                patch.object(security.os, "write", side_effect=self.write), \
                patch.object(security.os, "fsync", side_effect=self.fsync), \
                patch.object(security.os, "replace", side_effect=self.replace):
            original(connection, path)


def publication_child(home, point, challenge):
    store = Store(home)
    try:
        control = store.authenticate(load_capability(paths(home)["control"])["token"])
        observed = PublicationFault(paths(home)["audit_head"], point)
        original = store._sync_audit_head_raw
        with patch.object(store, "_sync_audit_head_raw",
                          side_effect=lambda connection, path: observed.publish(original, connection, path)):
            result = fixture_kernel(store).admin_apply(control, fixture_params(control, challenge))
        if observed.publications != 1 or observed.live:
            raise AssertionError("Publication hook was not reached or leaked a tracked FD")
        print(canonical_json({"reached": observed.checkpoints, "injected": observed.injected, "result": result}), flush=True)
    finally:
        store.close()


@unittest.skipIf(os.name == "nt", "POSIX publication only; Windows has a separate private-file implementation")
class AnchorPublicationFaultTest(AdminCrashFixture, unittest.TestCase):
    def setUp(self):
        self.setup_crash_fixture("continuum-anchor-publication-")
        self.fx.approve("remember", subject="unrelated retained memory", claim="retained fixture", evidence="retained evidence")
        self.challenge = self.fx.preview("remember", subject=CANARY, claim=CANARY + " body",
                                        evidence=CANARY + " evidence", disclosure=["codex", "claude"])
        self.original = snapshot(self.fx.store.connection)
        self.old_anchor = read_private(paths(self.fx.home)["audit_head"])
        self.before_sequence = self.fx.store.connection.execute("SELECT value FROM sequence").fetchone()[0]
        self.growth = {"claim_threads": 1, "assertion_versions": 1, "evidence": 1, "assertion_disclosures": 2,
                       "evidence_refs": 1, "assertion_fts": 1, "attestations": 3, "consent_receipts": 1,
                       "provenance_activities": 1, "audience_sequences": 2, "audit_events": 1, "admin_results": 1}
        self.retained = {table: self.rows(self.fx.store.connection, table) for table in self.growth}
        self.fx.store.close()
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse(os.path.lexists(str(paths(self.fx.home)["db"]) + suffix))

    @staticmethod
    def rows(db, table):
        # Table identifiers come only from the fixed reviewed inventory above.
        return [canonical_json(dict(row)) for row in db.execute("SELECT * FROM " + table)]

    def run_case(self, home, point):
        completed = subprocess.run([sys.executable, "-m", "tests.test_anchor_publication_faults",
                                    "--publication-child", str(home), point],
                                   input=canonical_json(self.challenge).encode(), env=self.environment,
                                   capture_output=True, timeout=15)
        self.assertEqual(completed.stderr, b"")
        self.assertLess(len(completed.stdout), 32768)
        self.assertEqual(completed.returncode, CRASH_EXIT if point in CHECKPOINTS else 0)
        return json.loads(completed.stdout)

    def assert_committed(self, home, point, report):
        published = point in {"success", "after_rename", "directory_synced", "directory_fsync_eio"}
        with self.opened(home) as (store, kernel, control):
            db = store.connection
            committed = snapshot(db)
            self.assertNotEqual(committed, self.original)
            self.assert_integrity(store)
            for table, growth in self.growth.items():
                rows = self.rows(db, table)
                self.assertEqual(len(rows), len(self.retained[table]) + growth, table)
                self.assertTrue(set(self.retained[table]) <= set(rows), table)
            self.assertEqual(db.execute("SELECT value FROM sequence").fetchone()[0], self.before_sequence + 1)
            used = db.execute("SELECT used_at FROM admin_challenges WHERE nonce=?", (self.challenge["nonce"],)).fetchone()[0]
            self.assertIsNotNone(used)
            head = db.execute("SELECT audit_seq,mac,operation,target_id FROM audit_events ORDER BY audit_seq DESC LIMIT 1").fetchone()
            expected_anchor = (canonical_json({"audit_seq": head["audit_seq"], "mac": head["mac"]}) + "\n").encode()
            self.assertNotEqual(expected_anchor, self.old_anchor)
            self.assertEqual(read_private(paths(home)["audit_head"]), expected_anchor if published else self.old_anchor)
            status = "valid" if published else "external_anchor_stale"
            self.assertEqual(store.verify_audit()["status"], status)
            locator = {"nonce": self.challenge["nonce"], "preview_digest": self.challenge["preview_digest"]}
            receipt = kernel.admin_result(control, locator)
            self.assertTrue(receipt["committed"])
            self.assertEqual(receipt["operation"], "remember")
            self.assertEqual(receipt["audit_anchor"], status)
            self.assertNotIn(CANARY, canonical_json(receipt))
            result = receipt["result"]
            self.assertEqual((head["operation"], head["target_id"]), ("assertion_accepted", result["assertion_id"]))
            self.assertEqual((result["recorded_seq"], result["authority"], result["supersedes"]),
                             (self.before_sequence + 1, "data", None))
            assertion = db.execute("SELECT * FROM assertion_versions WHERE id=?", (result["assertion_id"],)).fetchone()
            self.assertEqual((assertion["body"], assertion["lifecycle"], assertion["thread_id"]),
                             (CANARY + " body", "active", result["memory_id"]))
            self.assertEqual(db.execute("SELECT body FROM evidence WHERE id=?", (assertion["evidence_id"],)).fetchone()[0],
                             CANARY + " evidence")
            self.assertEqual({row[0] for row in db.execute("SELECT provider FROM assertion_disclosures WHERE assertion_id=?",
                                                          (result["assertion_id"],))}, {"codex", "claude"})
            self.assertEqual([row[0] for row in db.execute("SELECT assertion_id FROM assertion_fts WHERE assertion_fts MATCH ?",
                                                          (CANARY,))], [result["assertion_id"]])
            if point not in CHECKPOINTS:
                self.assertEqual({key: value for key, value in report["result"].items() if key != "commit"}, result)
                self.assertEqual(report["result"]["commit"], {
                    "status": "committed", "receipt_id": self.challenge["nonce"],
                    "audit_anchor": "synced" if point == "success" else "degraded"})
            # Abrupt exits bypass finally cleanup. These leftovers are private
            # files, not alternate anchors and not candidates for automatic use.
            leftovers = sorted(home.glob(".audit.head.*.tmp"))
            orphan = point in CHECKPOINTS[:4]
            self.assertEqual(len(leftovers), 1 if orphan else 0)
            original_leftovers = {}
            for temporary in leftovers:
                info = temporary.lstat()
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual((info.st_uid, stat.S_IMODE(info.st_mode), info.st_nlink), (os.getuid(), 0o600, 1))
                content = read_private(temporary)
                if point == "temp_created":
                    self.assertEqual(content, b"")
                elif point == "partial_write":
                    self.assertTrue(0 < len(content) < len(expected_anchor))
                    self.assertEqual(content, expected_anchor[:len(content)])
                else:
                    self.assertEqual(content, expected_anchor)
                self.assertNotIn(CANARY.encode(), content)
                original_leftovers[temporary] = content
            self.assertEqual(kernel.audit_reconcile(control, {})["status"], "valid")
            self.assertEqual(read_private(paths(home)["audit_head"]), expected_anchor)
            self.assertEqual(snapshot(db), committed)
            self.assertEqual(kernel.admin_result(control, locator)["result"], result)
            with self.assertRaises(MemoryError) as replay:
                kernel.admin_apply(control, fixture_params(control, self.challenge))
            self.assertEqual(replay.exception.code, "approval_replay")
            self.assertEqual(snapshot(db), committed)
            self.assertEqual({path: read_private(path) for path in home.glob(".audit.head.*.tmp")}, original_leftovers)
        with self.opened(home) as (store, kernel, control):
            self.assertEqual(snapshot(store.connection), committed)
            self.assertEqual(store.verify_audit()["status"], "valid")
            self.assertEqual(kernel.admin_result(control, locator)["result"], result)
            self.assert_integrity(store)

    def test_real_exits_inside_publication_preserve_committed_receipt_and_complete_anchor(self):
        for index, point in enumerate(CHECKPOINTS):
            with self.subTest(point=point):
                home = self.copied_vault(point)
                report = self.run_case(home, point)
                self.assertEqual(report, {"checkpoint": point, "reached": list(CHECKPOINTS[:index + 1])})
                self.assert_committed(home, point, report)

    def test_io_errors_are_committed_degraded_even_after_rename(self):
        prefixes = {"write_enospc": 2, "file_fsync_eio": 2, "rename_eio": 4, "directory_fsync_eio": 5}
        for point, error in FAULTS.items():
            with self.subTest(point=point):
                home = self.copied_vault(point)
                report = self.run_case(home, point)
                self.assertEqual(report["injected"], [{"fault": point, "errno": error}])
                self.assertEqual(report["reached"], list(CHECKPOINTS[:prefixes[point]]))
                self.assert_committed(home, point, report)

    def test_success_control_reaches_every_publication_checkpoint(self):
        home = self.copied_vault("success")
        report = self.run_case(home, "success")
        self.assertEqual(report["injected"], [])
        self.assertEqual(report["reached"], list(CHECKPOINTS))
        self.assert_committed(home, "success", report)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--publication-child":
        publication_child(Path(sys.argv[2]), sys.argv[3], json.loads(sys.stdin.buffer.read()))
    else:
        unittest.main()
