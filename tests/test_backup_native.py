"""Prepared native staging contracts, not backup/restore acceptance evidence.

The pinned SQLCipher backend is mandatory. Synthetic owner operations populate
the fixture; no test claims real human approval or revocation freshness.
"""

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from continuum_memory import backup, storage
from continuum_memory.admission import POLICY_FILE
from continuum_memory.audit_validation import verify_audit_snapshot
from continuum_memory.daemon_lock import DaemonLock
from continuum_memory.errors import MemoryError
from continuum_memory.kernel import Kernel
from continuum_memory.security import canonical_json, read_private, replace_private, write_private
from continuum_memory.storage import Store, load_capability, paths
from tests import test_encrypted_export_contract as export_probe
from tests import test_snapshot_forget as fixture


CANARY = "BACKUPNATIVECANARY0fd5278bd90e"
CHECKPOINT = {"authority_id": "auth_synthetic", "generation": 0, "digest": "b" * 64}
ROOT = Path(__file__).resolve().parents[1]


def _validate_in_fresh_process(candidate_path, key_path):
    """Validate only a closed candidate; never activate or restore a vault."""
    try:
        storage._require_sqlcipher_runtime()
        key = read_private(Path(key_path), storage.STORAGE_KEY_BYTES)
        result = backup.validate_candidate(Path(candidate_path), key)
        safe_result = {name: result[name] for name in (
            "status", "format_version", "restore_ready", "freshness", "revocation_reconciliation")}
    except Exception:
        # No exception representation, SQL, key, manifest or source rows in logs.
        print("backup-child-validation-failed", file=sys.stderr)
        return 2
    print(json.dumps(safe_result, sort_keys=True))
    return 0


class _ConnectionBoundary:
    """Delegate every native operation; inject faults only at named boundaries."""

    def __init__(self, connection, *, after=None, detach_error=False, rollback_error=False):
        self.connection = connection
        self.after = after or (lambda _name: None)
        self.detach_error = detach_error
        self.rollback_error = rollback_error
        self.failures = []

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def execute(self, statement, parameters=()):
        if statement == "DETACH DATABASE continuum_backup" and self.detach_error:
            self.failures.append("detach")
            raise OSError("synthetic-detach-sensitive-canary")
        result = self.connection.execute(statement, parameters)
        if statement.startswith("ATTACH DATABASE"):
            self.after("attach")
        elif statement.startswith("SELECT sqlcipher_export"):
            # Complete the real native function before injecting interruption;
            # leave no unconsumed SELECT cursor to manufacture a detach failure.
            result.fetchall()
            self.after("export")
        return result

    def commit(self):
        result = self.connection.commit()
        self.after("commit")
        return result

    def rollback(self):
        if self.rollback_error:
            self.failures.append("rollback")
            raise OSError("synthetic-rollback-sensitive-canary")
        return self.connection.rollback()


class BackupNativeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        storage._require_sqlcipher_runtime()

    apply = fixture.SnapshotForgetTest.apply
    approve = fixture.SnapshotForgetTest.approve
    remember = fixture.SnapshotForgetTest.remember
    context = fixture.SnapshotForgetTest.context

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="continuum-backup-native-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "vault"
        self.staging = self.root / "staging ' bound path"
        self.keys = self.root / "approved-keys"
        self.sqlite_temp = self.root / "sqlite-temp"
        for directory in (self.home, self.staging, self.keys, self.sqlite_temp):
            directory.mkdir(mode=0o700)
        environment = patch.dict(os.environ, {"SQLITE_TMPDIR": str(self.sqlite_temp)})
        environment.start()
        self.addCleanup(environment.stop)
        boot = Store.bootstrap(self.home, [
            {"name": name, "path_hint": "/synthetic/" + name, "providers": ["codex", "claude"]}
            for name in ("alpha", "beta")
        ])
        self.projects = {project["name"]: project for project in boot["projects"]}
        self.project = self.projects["alpha"]["id"]
        # Initialize before acquiring the lease: bootstrap reserves memoryd.lock.
        # The real cooperating lease still precedes Store and outlives its close.
        self.lease = DaemonLock(self.home)
        self.lease.__enter__()
        self.addCleanup(self.lease.__exit__, None, None, None)
        self.lease.prepare_socket(paths(self.home)["socket"])
        self.store = Store(self.home)
        self.addCleanup(self._close_store)
        self.now = datetime(2027, 1, 1, tzinfo=timezone.utc)
        self.kernel = Kernel(self.store, now_provider=lambda: self.now,
                             approval_public_key_provider=lambda _uid: None,
                             allow_prototype_approval=True)
        self.control = self.store.authenticate(load_capability(paths(self.home)["control"])["token"])
        self.codex = self.store.authenticate(load_capability(
            Path(self.projects["alpha"]["capabilities"]["codex"]))["token"])
        first = self.remember("backup retained", CANARY + " original")
        self.live = self.approve(operation="correct", target_id=first["assertion_id"], claim=CANARY + " revised")
        discarded = self.remember("backup forgotten", "Synthetic forgotten body")
        self.approve(operation="forget", target_id=discarded["assertion_id"])
        for label in ("accepted", "forgotten", "pending"):
            proposal = self.kernel.propose(self.codex, {
                "subject": "backup proposal " + label, "claim": "Synthetic proposed " + label,
                "evidence": "Synthetic proposal evidence", "source_handle": "fixture:backup",
                "disclosure": ["codex"], "idempotency_key": "backup-delivery-" + label,
            })
            if label == "accepted":
                self.approve(operation="accept_proposal", proposal_id=proposal["proposal_id"])
            elif label == "forgotten":
                self.approve(operation="forget", target_id=proposal["proposal_id"])
        self.context(CANARY)
        for table in ("assertion_fts", "admin_results", "deletion_receipts", "proposal_tombstones", "proposals", "audit_events"):
            self.assertGreater(self.store.connection.execute("SELECT count(*) FROM " + table).fetchone()[0], 0)
        self.policy_path = self.home / POLICY_FILE
        self.policy = b'{"version":1,"deny_literals":["synthetic-denied-fixture"],"allow_sha256":[]}\n'
        write_private(self.policy_path, self.policy)
        self.source_key = paths(self.home)["storage_key"].read_bytes()
        self.backup_key = secrets.token_bytes(32)
        while self.backup_key == self.source_key:
            self.backup_key = secrets.token_bytes(32)
        self.key_file = self.keys / "backup.key"
        write_private(self.key_file, self.backup_key)
        self.store.connection.execute("CREATE TEMP TABLE backup_temp_canary(body TEXT)")
        self.store.connection.execute("INSERT INTO backup_temp_canary VALUES (?)", (CANARY,))
        self.before = self.snapshot(self.store.connection)
        self.controls = self.control_files()

    def _close_store(self):
        if self.store.connection is not None:
            self.store.close()

    @staticmethod
    def snapshot(connection):
        return export_probe.EncryptedExportContractTest._snapshot(connection)

    def control_files(self):
        names = {"continuum.db" + suffix for suffix in ("", "-wal", "-shm", "-journal")}
        return {str(path.relative_to(self.home)): path.read_bytes()
                for path in self.home.rglob("*") if path.is_file() and path.name not in names}

    def target(self, staging=None):
        return (staging or self.staging) / "backup.cdb"

    def new_staging(self, name):
        directory = self.root / name
        directory.mkdir(mode=0o700)
        return directory

    @staticmethod
    def private_inventory(directory):
        """Keep comparison bytes in memory; callers must not format this value."""
        result = {}
        for path in [directory, *sorted(directory.rglob("*"))]:
            info = path.lstat()
            result[str(path.relative_to(directory))] = (
                info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                path.read_bytes() if path.is_file() else None,
            )
        return result

    def export(self, staging=None):
        self.lease.check()
        return backup.export_candidate(self.store, staging or self.staging, self.key_file)

    def open_keyed(self, path, key, *, writable=False):
        connection = storage.sqlite3.connect(path.as_uri() + ("?mode=rw" if writable else "?mode=ro&immutable=1"),
                                             uri=True, isolation_level=None)
        connection.row_factory = storage.sqlite3.Row
        try:
            connection.execute('PRAGMA key = "x\'%s\'"' % key.hex())
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("SELECT count(*) FROM sqlite_schema").fetchone()
            return connection
        except BaseException:
            connection.close()
            raise

    @contextmanager
    def connection_boundary(self, **options):
        native = self.store.connection
        boundary = _ConnectionBoundary(native, **options)
        self.store.connection = boundary
        try:
            yield boundary
        finally:
            if self.store.connection is boundary:
                self.store.connection = native

    def assert_source_unchanged(self, *, reopened=False):
        self.lease.check()
        self.assertFalse(self.store.connection.in_transaction)
        self.assertNotIn(backup.ALIAS, [row[1] for row in self.store.connection.execute("PRAGMA database_list")])
        self.assertEqual(self.snapshot(self.store.connection), self.before)
        self.assertTrue(self.control_files() == self.controls, "Source private control files changed")
        self.assertEqual(self.store.verify_audit()["status"], "valid")
        if not reopened:
            self.assertEqual([tuple(row) for row in self.store.connection.execute("SELECT * FROM backup_temp_canary")],
                             [(CANARY,)])

    def assert_invalid(self, path, key=None):
        before = path.read_bytes()
        with self.assertRaises(MemoryError) as caught:
            backup.validate_candidate(path, self.backup_key if key is None else key)
        self.assertEqual(caught.exception.code, "backup_invalid")
        self.assertEqual(path.read_bytes(), before)

    def assert_private_ciphertext(self, staging):
        self.assertEqual({path.name for path in staging.iterdir()}, {"backup.cdb"})
        for directory in (staging, self.sqlite_temp):
            for path in directory.rglob("*"):
                if path.is_file():
                    payload = path.read_bytes()
                    self.assertTrue(CANARY.encode() not in payload, "Plaintext canary found in candidate or residue")
                    for key in (self.backup_key, self.source_key, self.store.audit_key):
                        self.assertTrue(key not in payload, "Raw key found in candidate or residue")
                    self.assertFalse(payload.startswith(b"SQLite format 3\x00"))
        self.assertEqual(self.target(staging).stat().st_mode & 0o777, 0o600)
        self.assertTrue(self.key_file.read_bytes() == self.backup_key, "Private backup key changed")
        self.assertEqual(list(self.keys.iterdir()), [self.key_file])

    def test_production_round_trip_preserves_rows_headers_receipts_audit_and_policy(self):
        result = self.export()
        self.assertEqual(result["status"], "staged_not_published")
        self.assertEqual(result["format_version"], 2)
        self.assertFalse(result["restore_ready"])
        self.assertEqual(result["freshness"], "unverified")
        self.assertEqual(result["revocation_reconciliation"], "not_performed")
        self.assertIsNone(result["manifest"]["revocation_checkpoint"])
        self.assertEqual(result["manifest"]["format_version"], 2)
        candidate = self.open_keyed(self.target(), self.backup_key)
        try:
            self.assertEqual(candidate.execute("SELECT value FROM metadata WHERE key='storage_mode'").fetchone()[0],
                             "continuum-backup-v2-sqlcipher-4.19.0")
            copied = self.snapshot(candidate)
            copied["schema"] = [row for row in copied["schema"] if row[2] not in backup.RESERVED_TABLES]
            for name in backup.RESERVED_TABLES:
                del copied["rows"][name]
            copied["rows"]["metadata"] = sorted(
                ((name, storage.STORAGE_MODE if name == "storage_mode" else value)
                 for name, value in copied["rows"]["metadata"]), key=repr)
            self.assertEqual(copied, self.before)
            self.assertEqual([tuple(row) for row in candidate.execute("PRAGMA integrity_check")], [("ok",)])
            self.assertEqual(candidate.execute("PRAGMA cipher_integrity_check").fetchall(), [])
            self.assertEqual(candidate.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual([tuple(row) for row in candidate.execute(
                "SELECT assertion_id FROM assertion_fts WHERE assertion_fts MATCH ?", (CANARY,))],
                [(self.live["assertion_id"],)])
            material = candidate.execute("SELECT audit_key,admission_policy FROM continuum_backup_material").fetchone()
            self.assertEqual(tuple(material), (self.store.audit_key, self.policy))
            self.assertEqual(verify_audit_snapshot(candidate, material[0], lambda: result["manifest"]["audit_head"])["status"],
                             "valid")
        finally:
            candidate.close()
        self.assert_source_unchanged()
        self.assert_private_ciphertext(self.staging)

    def test_explicit_checkpoint_remains_unverified_in_new_exports(self):
        result = backup.export_candidate(self.store, self.staging, self.key_file, CHECKPOINT)
        self.assertEqual(result["status"], "staged_not_published")
        self.assertEqual(result["format_version"], 2)
        self.assertEqual(result["manifest"]["revocation_checkpoint"], CHECKPOINT)
        self.assertEqual(result["freshness"], "unverified")
        self.assertEqual(result["revocation_reconciliation"], "not_performed")
        self.assertFalse(result["restore_ready"])
        self.assert_source_unchanged()
        self.assert_private_ciphertext(self.staging)

    def test_manifest_versions_require_matching_storage_markers(self):
        exported = self.export()
        ciphertext = self.target().read_bytes()
        original = self.private_inventory(self.staging)
        legacy_marker = "continuum-backup-v1-sqlcipher-4.19.0"
        current_marker = "continuum-backup-v2-sqlcipher-4.19.0"
        cases = (
            ("legacy", 1, legacy_marker, CHECKPOINT, True),
            ("legacy-null", 1, legacy_marker, None, False),
            ("current-null", 2, current_marker, None, True),
            ("current-checkpoint", 2, current_marker, CHECKPOINT, True),
            ("legacy-with-current-marker", 1, current_marker, CHECKPOINT, False),
            ("current-with-legacy-marker", 2, legacy_marker, CHECKPOINT, False),
            ("unknown-version", 3, current_marker, CHECKPOINT, False),
            ("unknown-marker", 2, "continuum-backup-v3-sqlcipher-4.19.0", None, False),
        )
        for label, version, marker, checkpoint, valid in cases:
            with self.subTest(label=label):
                directory = self.new_staging("version-" + label)
                candidate = self.target(directory)
                write_private(candidate, ciphertext)
                manifest = dict(exported["manifest"], format_version=version, revocation_checkpoint=checkpoint)
                connection = self.open_keyed(candidate, self.backup_key, writable=True)
                try:
                    connection.execute("UPDATE continuum_backup_manifest SET payload=?", (canonical_json(manifest),))
                    connection.execute("UPDATE metadata SET value=? WHERE key='storage_mode'", (marker,))
                finally:
                    connection.close()
                before = self.private_inventory(directory)
                if valid:
                    result = backup.validate_candidate(candidate, self.backup_key)
                    self.assertEqual(result["status"], "validated_not_activated")
                    self.assertEqual(result["format_version"], version)
                    self.assertEqual(result["manifest"], manifest)
                    self.assertEqual(result["freshness"], "unverified")
                    self.assertEqual(result["revocation_reconciliation"], "not_performed")
                    self.assertFalse(result["restore_ready"])
                else:
                    with self.assertRaises(MemoryError) as caught:
                        backup.validate_candidate(candidate, self.backup_key)
                    self.assertEqual(caught.exception.code, "backup_invalid")
                self.assertTrue(self.private_inventory(directory) == before, "Candidate validation changed private files")
                self.assert_source_unchanged()
                self.assert_private_ciphertext(directory)
        self.assertTrue(self.private_inventory(self.staging) == original, "Original candidate changed")

    def test_keys_are_distinct_and_wrong_key_checks_use_a_source_copy(self):
        self.export()
        self.assertNotEqual(self.source_key, self.backup_key)
        self.assert_invalid(self.target(), self.source_key)
        # Close/checkpoint only the fixture before copying every remaining fixed
        # native artifact; never try the wrong key on the live source itself.
        self.store.close()
        copied_dir = self.new_staging("source-copy")
        for suffix in ("", "-wal", "-shm", "-journal"):
            source = Path(str(paths(self.home)["db"]) + suffix)
            if source.exists():
                destination = copied_dir / source.name
                shutil.copyfile(source, destination)
                destination.chmod(0o600)
        with self.assertRaises(storage.sqlite3.DatabaseError):
            self.open_keyed(copied_dir / "continuum.db", self.backup_key)
        self.store = Store(self.home)
        self.assert_source_unchanged(reopened=True)
        self.assert_private_ciphertext(self.staging)

    def test_real_authorizer_failure_rolls_back_and_refuses_partial_retry(self):
        denied = []

        def authorizer(action, first, _second, database, _origin):
            if action == storage.sqlite3.SQLITE_INSERT and first == "continuum_backup_material" and database == backup.ALIAS:
                denied.append(first)
                return storage.sqlite3.SQLITE_DENY
            return storage.sqlite3.SQLITE_OK

        self.store.connection.set_authorizer(authorizer)
        try:
            with self.assertRaises(MemoryError) as caught:
                self.export()
        finally:
            self.store.connection.set_authorizer(None)
        self.assertEqual(caught.exception.code, "backup_invalid")
        self.assertEqual(denied, ["continuum_backup_material"])
        self.assert_invalid(self.target())
        self.assert_source_unchanged()
        self.assert_private_ciphertext(self.staging)
        with self.assertRaises(MemoryError) as caught:
            self.export()
        self.assertEqual(caught.exception.code, "backup_destination_exists")

    def test_cancellation_after_real_attach_export_or_commit_restores_connection(self):
        for point in ("attach", "export", "commit"):
            with self.subTest(point=point):
                staging = self.new_staging("cancel-" + point)
                fired = []

                def interrupted(name):
                    if name == point:
                        fired.append(name)
                        raise KeyboardInterrupt("synthetic cancellation")

                with self.connection_boundary(after=interrupted), self.assertRaises(KeyboardInterrupt):
                    self.export(staging)
                self.assertEqual(fired, [point])
                self.assert_source_unchanged()
                if point == "commit":
                    self.assertFalse(backup.validate_candidate(self.target(staging), self.backup_key)["restore_ready"])
                else:
                    self.assert_invalid(self.target(staging))

    def test_commit_return_error_retains_complete_unpublished_candidate(self):
        fired = []

        def failed_return(point):
            if point == "commit":
                fired.append(point)
                raise OSError("synthetic-commit-sensitive-canary")

        with self.connection_boundary(after=failed_return), self.assertRaises(MemoryError) as caught:
            self.export()
        self.assertEqual(caught.exception.code, "backup_invalid")
        self.assertEqual(fired, ["commit"])
        self.assertNotIn("canary", str(caught.exception))
        self.assertEqual(backup.validate_candidate(self.target(), self.backup_key)["status"], "validated_not_activated")
        self.assert_source_unchanged()

    def test_detach_or_rollback_failure_closes_unsafe_store(self):
        for failure in ("detach", "rollback"):
            with self.subTest(failure=failure):
                staging = self.new_staging("unsafe-" + failure)
                fired = []

                def interrupted(point):
                    if failure == "rollback" and point == "export":
                        fired.append(point)
                        raise KeyboardInterrupt("synthetic cancellation")

                with self.connection_boundary(after=interrupted, detach_error=failure == "detach",
                                              rollback_error=failure == "rollback") as boundary:
                    with self.assertRaises(MemoryError) as caught:
                        self.export(staging)
                self.assertEqual(caught.exception.code, "backup_invalid")
                self.assertEqual(boundary.failures, [failure])
                if failure == "rollback":
                    self.assertEqual(fired, ["export"])
                with self.assertRaises(storage.sqlite3.ProgrammingError):
                    self.store.connection.execute("SELECT 1")
                self.store = Store(self.home)
                self.assert_source_unchanged(reopened=True)
                if failure == "detach":
                    self.assertFalse(backup.validate_candidate(self.target(staging), self.backup_key)["restore_ready"])
                else:
                    self.assert_invalid(self.target(staging))

    def test_postcommit_validation_failure_retains_unpublished_artifact(self):
        original = backup.validate_candidate
        fired = []

        def refuse_after_validation(*args):
            original(*args)
            fired.append("validated")
            raise OSError("synthetic-validation-sensitive-canary")

        with patch.object(backup, "validate_candidate", side_effect=refuse_after_validation):
            with self.assertRaises(MemoryError) as caught:
                self.export()
        self.assertEqual(caught.exception.code, "backup_invalid")
        self.assertEqual(fired, ["validated"])
        self.assertFalse(original(self.target(), self.backup_key)["restore_ready"])
        self.assert_source_unchanged()

    def test_invalid_policy_bytes_and_policy_change_cannot_be_archived(self):
        invalid = b'{"version":1,"allow_sha256":["invalid-digest"]}'
        replace_private(self.policy_path, invalid)
        with patch.object(backup.AdmissionPolicy, "load", side_effect=AssertionError("capture must use from_bytes")) as loader:
            with self.assertRaises(MemoryError) as caught:
                self.export()
            loader.assert_not_called()
        self.assertEqual(caught.exception.code, "backup_invalid")
        self.assert_invalid(self.target())
        replace_private(self.policy_path, self.policy)
        staging = self.new_staging("policy-changed")
        fired = []

        def changed(point):
            if point == "export":
                fired.append(point)
                replace_private(self.policy_path, b'{"version":1,"deny_literals":["changed-policy"]}')

        try:
            with self.connection_boundary(after=changed), self.assertRaises(MemoryError):
                self.export(staging)
        finally:
            replace_private(self.policy_path, self.policy)
        self.assertEqual(fired, ["export"])
        self.assert_invalid(self.target(staging))
        self.assert_source_unchanged()

    def test_backup_key_replacement_before_commit_or_return_refuses_success(self):
        changed_key = bytes(value ^ 1 for value in self.backup_key)
        for point in ("export", "validated"):
            with self.subTest(point=point):
                staging = self.new_staging("backup-key-changed-" + point)
                fired = []
                original = backup.validate_candidate

                def changed(name):
                    if name == point:
                        replace_private(self.key_file, changed_key)
                        fired.append(name)

                def validated(*args):
                    result = original(*args)
                    changed("validated")
                    return result

                try:
                    with self.connection_boundary(after=changed):
                        with patch.object(backup, "validate_candidate", side_effect=validated):
                            with self.assertRaises(MemoryError) as caught:
                                self.export(staging)
                    self.assertEqual(caught.exception.code, "backup_invalid")
                    self.assertEqual(fired, [point])
                    self.assertEqual(self.key_file.read_bytes(), changed_key)
                finally:
                    replace_private(self.key_file, self.backup_key)
                if point == "export":
                    self.assert_invalid(self.target(staging))
                else:
                    self.assertEqual(original(self.target(staging), self.backup_key)["status"],
                                     "validated_not_activated")
                self.assert_source_unchanged()

    def test_pending_rotation_and_custody_residue_refuse_before_destination_creation(self):
        for directory in (self.home, self.staging):
            for name in ("storage.rotation.json", "storage.key.next", ".storage.key.legacy.tmp"):
                with self.subTest(directory=directory.name, name=name):
                    residue = directory / name
                    write_private(residue, b"synthetic-residue")
                    try:
                        with self.assertRaises(MemoryError):
                            self.export()
                        self.assertFalse(self.target().exists())
                        self.assertEqual(residue.read_bytes(), b"synthetic-residue")
                    finally:
                        residue.unlink()
        self.assert_source_unchanged()

    def test_late_rotation_marker_or_source_key_change_rolls_back(self):
        for change in ("rotation", "key-bytes", "key-inode", "anchor-inode"):
            with self.subTest(change=change):
                staging = self.new_staging("source-change-" + change)
                marker = self.home / "storage.rotation.json"
                key_path = paths(self.home)["storage_key"]
                anchor_path = paths(self.home)["audit_head"]
                fired = []

                def changed(point):
                    if point != "export":
                        return
                    fired.append(point)
                    if change == "rotation":
                        write_private(marker, b"synthetic-late-rotation")
                    elif change == "anchor-inode":
                        replace_private(anchor_path, anchor_path.read_bytes())
                    else:
                        replace_private(key_path, b"x" * 32 if change == "key-bytes" else self.source_key)

                try:
                    with self.connection_boundary(after=changed), self.assertRaises(MemoryError):
                        self.export(staging)
                finally:
                    if marker.exists():
                        marker.unlink()
                    if key_path.read_bytes() != self.source_key:
                        replace_private(key_path, self.source_key)
                self.assertEqual(fired, ["export"])
                self.assert_invalid(self.target(staging))
                self.assert_source_unchanged()

    def test_active_transaction_or_alias_is_refused_without_changing_it(self):
        self.store.begin()
        try:
            with self.assertRaises(MemoryError) as caught:
                self.export()
            self.assertEqual(caught.exception.code, "backup_busy")
            self.assertTrue(self.store.connection.in_transaction)
            self.assertFalse(self.target().exists())
        finally:
            self.store.rollback()
        occupied = self.root / "occupied.cdb"
        write_private(occupied, b"")
        self.store.connection.execute("ATTACH DATABASE ? AS continuum_backup KEY ?",
                                      (str(occupied), "x'%s'" % self.backup_key.hex()))
        try:
            with self.assertRaises(MemoryError) as caught:
                self.export()
            self.assertEqual(caught.exception.code, "backup_busy")
            self.assertIn(backup.ALIAS, [row[1] for row in self.store.connection.execute("PRAGMA database_list")])
            self.assertFalse(self.target().exists())
        finally:
            self.store.connection.execute("DETACH DATABASE continuum_backup")
        self.assert_source_unchanged()

    def test_changed_source_mode_identity_header_or_schema_is_rejected_without_repair(self):
        mutations = {
            "mode": ("UPDATE metadata SET value='unsupported' WHERE key='storage_mode'",
                     "UPDATE metadata SET value=? WHERE key='storage_mode'", (storage.STORAGE_MODE,)),
            "vault": ("UPDATE metadata SET value='vlt_changed' WHERE key='vault_id'",
                      "UPDATE metadata SET value=? WHERE key='vault_id'", (self.store.vault_id,)),
            "header": ("PRAGMA user_version=4", "PRAGMA user_version=5", ()),
            "schema": ("CREATE TABLE unreviewed(value TEXT)", "DROP TABLE unreviewed", ()),
        }
        for label, (mutation, restore, parameters) in mutations.items():
            with self.subTest(label=label):
                staging = self.new_staging("source-invalid-" + label)
                self.store.connection.execute(mutation)
                changed = self.snapshot(self.store.connection)
                try:
                    with self.assertRaises(MemoryError) as caught:
                        self.export(staging)
                    self.assertEqual(caught.exception.code, "backup_invalid")
                    self.assertEqual(self.snapshot(self.store.connection), changed)
                    self.assert_invalid(self.target(staging))
                finally:
                    self.store.connection.execute(restore, parameters)
                self.assert_source_unchanged()

    def test_readonly_validation_rejects_native_corruption_without_repair(self):
        self.export()
        mutations = {
            "schema": "CREATE TABLE unreviewed(value TEXT)",
            "header": "PRAGMA application_id=1",
            "manifest": "UPDATE continuum_backup_manifest SET payload='{}'",
            "policy": "UPDATE continuum_backup_material SET admission_policy=CAST('{\"version\":true}' AS BLOB)",
            "audit": "UPDATE audit_events SET operation='tampered' WHERE audit_seq=1",
            "metadata": "UPDATE metadata SET value='vlt_other' WHERE key='vault_id'",
        }
        for label, statement in mutations.items():
            with self.subTest(label=label):
                directory = self.new_staging("corrupt-" + label)
                candidate = self.target(directory)
                shutil.copyfile(self.target(), candidate)
                candidate.chmod(0o600)
                connection = self.open_keyed(candidate, self.backup_key, writable=True)
                try:
                    connection.execute(statement)
                finally:
                    connection.close()
                self.assert_invalid(candidate)
                self.assertEqual({path.name for path in directory.iterdir()}, {"backup.cdb"})
        directory = self.new_staging("corrupt-cipher")
        candidate = self.target(directory)
        shutil.copyfile(self.target(), candidate)
        candidate.chmod(0o600)
        with candidate.open("r+b") as handle:
            handle.seek(4200)
            original = handle.read(1)
            self.assertEqual(len(original), 1)
            handle.seek(4200)
            handle.write(bytes([original[0] ^ 1]))
        self.assert_invalid(candidate)
        self.assert_source_unchanged()

    def test_truncated_native_candidates_fail_closed_without_repair(self):
        self.export()
        ciphertext = self.target().read_bytes()
        connection = self.open_keyed(self.target(), self.backup_key)
        try:
            page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        finally:
            connection.close()
        self.assertGreater(len(ciphertext), 2 * page_size)
        self.assertEqual(len(ciphertext) % page_size, 0)
        lengths = {
            "empty": 0,
            "salt-only": 16,
            "short-first-page": page_size - 1,
            "half-whole-pages": (len(ciphertext) // (2 * page_size)) * page_size,
            "missing-last-byte": len(ciphertext) - 1,
        }
        original = self.private_inventory(self.staging)
        keys = self.private_inventory(self.keys)
        temporary = self.private_inventory(self.sqlite_temp)
        for label, length in lengths.items():
            with self.subTest(label=label):
                directory = self.new_staging("truncated-" + label)
                candidate = self.target(directory)
                write_private(candidate, ciphertext[:length])
                before = self.private_inventory(directory)
                with self.assertRaises(MemoryError) as caught:
                    backup.validate_candidate(candidate, self.backup_key)
                self.assertEqual(caught.exception.code, "backup_invalid")
                self.assertTrue(self.private_inventory(directory) == before,
                                "Rejected candidate or companions changed")
                self.assert_source_unchanged()
        self.assertTrue(self.private_inventory(self.staging) == original, "Original candidate changed")
        self.assertTrue(self.private_inventory(self.keys) == keys, "Private key directory changed")
        self.assertTrue(self.private_inventory(self.sqlite_temp) == temporary, "SQLite temporary residue changed")

    def test_fresh_process_validates_closed_candidate_without_activating_it(self):
        self.export()
        watched = (self.staging, self.keys, self.sqlite_temp)
        before = [self.private_inventory(directory) for directory in watched]
        environment = dict(os.environ, PYTHONPATH=os.pathsep.join((str(ROOT / "src"), str(ROOT))),
                           PYTHONDONTWRITEBYTECODE="1")
        command = [sys.executable, "-W", "error::ResourceWarning", "-m", "tests.test_backup_native",
                   "--validate-backup-child", str(self.target()), str(self.key_file)]
        try:
            child = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True,
                                   timeout=30, check=False)
        except subprocess.TimeoutExpired:
            self.fail("Fresh-process backup validation exceeded its bounded timeout")
        self.assertTrue(child.returncode == 0, "Fresh-process validation failed; output withheld")
        self.assertTrue(child.stderr == b"", "Fresh-process validation wrote diagnostics; output withheld")
        for secret in (self.source_key, self.backup_key, self.store.audit_key):
            for representation in (secret, secret.hex().encode()):
                self.assertTrue(representation not in child.stdout + child.stderr,
                                "Fresh-process output exposed private material")
        try:
            result = json.loads(child.stdout)
        except (UnicodeError, ValueError):
            self.fail("Fresh-process validation returned invalid JSON; output withheld")
        self.assertTrue(result == {"status": "validated_not_activated", "format_version": 2,
                                   "restore_ready": False, "freshness": "unverified",
                                   "revocation_reconciliation": "not_performed"},
                        "Unexpected fresh-process validation state")
        self.assertTrue([self.private_inventory(directory) for directory in watched] == before,
                        "Fresh-process validation changed private files or created companions")
        self.assert_source_unchanged()

    def test_occupied_artifact_and_orphan_sidecars_are_preserved(self):
        self.export()
        cases = [("artifact", self.staging, "backup_destination_exists")]
        for suffix in ("-wal", "-shm", "-journal"):
            directory = self.new_staging("orphan" + suffix)
            write_private(Path(str(self.target(directory)) + suffix), b"synthetic-occupied-companion")
            cases.append(("orphan" + suffix, directory, "backup_invalid"))
            directory = self.new_staging("occupied" + suffix)
            write_private(self.target(directory), self.target().read_bytes())
            write_private(Path(str(self.target(directory)) + suffix), b"synthetic-occupied-companion")
            cases.append(("occupied" + suffix, directory, "backup_destination_exists"))
        keys = self.private_inventory(self.keys)
        temporary = self.private_inventory(self.sqlite_temp)
        for label, directory, error_code in cases:
            with self.subTest(label=label):
                before = self.private_inventory(directory)
                with self.assertRaises(MemoryError) as caught:
                    self.export(directory)
                self.assertEqual(caught.exception.code, error_code)
                self.assertTrue(self.private_inventory(directory) == before,
                                "Occupied artifact or companion changed")
                self.assert_source_unchanged()
        self.assertTrue(self.private_inventory(self.keys) == keys, "Private key directory changed")
        self.assertTrue(self.private_inventory(self.sqlite_temp) == temporary, "SQLite temporary residue changed")

    def test_candidate_sidecars_and_observed_replacement_are_not_repaired(self):
        self.export()
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(str(self.target()) + suffix)
            write_private(sidecar, b"untrusted-companion")
            try:
                self.assert_invalid(self.target())
                self.assertEqual(sidecar.read_bytes(), b"untrusted-companion")
            finally:
                sidecar.unlink()
        original = backup._require_headers
        old_inode = self.target().stat().st_ino

        def replace_during_validation(connection):
            original(connection)
            replacement = self.staging / "replacement.cdb"
            shutil.copyfile(self.target(), replacement)
            replacement.chmod(0o600)
            os.replace(replacement, self.target())

        with patch.object(backup, "_require_headers", side_effect=replace_during_validation):
            self.assert_invalid(self.target())
        self.assertNotEqual(self.target().stat().st_ino, old_inode)
        self.assert_source_unchanged()

    def test_closed_wal_header_candidate_validation_creates_no_companions(self):
        self.export()
        connection = self.open_keyed(self.target(), self.backup_key, writable=True)
        try:
            self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            self.assertEqual(tuple(connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()), (0, 0, 0))
        finally:
            connection.close()
        self.assertEqual({path.name for path in self.staging.iterdir()}, {"backup.cdb"})

        def observed():
            info = self.target().stat()
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                    info.st_mode, info.st_nlink, self.target().read_bytes())

        before = observed()
        result = backup.validate_candidate(self.target(), self.backup_key)
        self.assertEqual(result["status"], "validated_not_activated")
        self.assertFalse(result["restore_ready"])
        self.assertEqual(observed(), before)
        self.assertEqual({path.name for path in self.staging.iterdir()}, {"backup.cdb"})
        self.assert_source_unchanged()


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--validate-backup-child":
        raise SystemExit(_validate_in_fresh_process(sys.argv[2], sys.argv[3]))
    unittest.main()
