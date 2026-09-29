"""Pure backup metadata/key-path tests; not native encrypted-backup proof."""

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from continuum_memory import backup
from continuum_memory.admission import AdmissionPolicy, MAX_POLICY_BYTES, POLICY_FILE
from continuum_memory.backup import APPLICATION_ID, validate_candidate, validate_manifest, read_backup_key_file
from continuum_memory.errors import MemoryError
from continuum_memory import storage
from continuum_memory.migrations import SCHEMA_SQL, migrate
from continuum_memory.security import write_private


def manifest(version=2):
    return {"format_version": version, "vault_id": "vlt_fixture", "recorded_seq": 4, "user_version": 5,
            "application_id": APPLICATION_ID, "cipher_version": storage.SQLCIPHER_VERSION,
            "source_storage_mode": storage.STORAGE_MODE, "audit_head": {"audit_seq": 3, "mac": "a" * 64},
            "revocation_checkpoint": {"authority_id": "auth_fixture", "generation": 1, "digest": "b" * 64}}


class BackupContractTest(unittest.TestCase):
    def test_exact_manifest_is_data_not_freshness_authority(self):
        for version in (1, 2):
            with self.subTest(version=version):
                original = manifest(version)
                self.assertIs(validate_manifest(original), original)
                self.assertNotIn("authorized", original)

    def test_absent_checkpoint_is_explicit_null_only_in_version_two(self):
        current = manifest(2)
        current["revocation_checkpoint"] = None
        self.assertIs(validate_manifest(current), current)
        self.assertIsNone(current["revocation_checkpoint"])
        legacy = dict(current, format_version=1)
        with self.assertRaises(MemoryError) as caught:
            validate_manifest(legacy)
        self.assertEqual(caught.exception.code, "backup_invalid")

    def test_nonnull_checkpoint_remains_strict_in_both_versions(self):
        valid = manifest()["revocation_checkpoint"]
        malformed = [True, False, [], "not-provided", 0, {}, dict(valid, extra="canary")]
        malformed.extend({key: value for key, value in valid.items() if key != omitted} for omitted in valid)
        malformed.extend(dict(valid, generation=value) for value in (-1, 2**63, True, False, 1.0, "1", None))
        malformed.extend(dict(valid, authority_id=value) for value in (None, True, "bad", "a" * 9000))
        malformed.extend(dict(valid, digest=value) for value in (None, True, "b" * 63, "B" * 64, "g" * 64))
        for version in (1, 2):
            for checkpoint in malformed:
                with self.subTest(version=version, checkpoint=checkpoint):
                    value = dict(manifest(version), revocation_checkpoint=checkpoint)
                    with self.assertRaises(MemoryError) as caught:
                        validate_manifest(value)
                    self.assertEqual(caught.exception.code, "backup_invalid")

    def test_unknown_fields_versions_types_modes_and_unbounded_values_fail_uniformly(self):
        changes = [{"format_version": value} for value in (True, False, None, 0, -1, 3, 2**63, 1.0, 2.0, "1", "2")]
        changes += [{"user_version": 6}, {"user_version": True}, {"application_id": 0}, {"application_id": True},
                   {"recorded_seq": -1}, {"recorded_seq": True}, {"recorded_seq": 2**63},
                   {"source_storage_mode": "plaintext"}, {"cipher_version": "4.18"},
                   {"vault_id": "x" * 9000}, {"storage_key": "sensitive-canary"},
                   {"audit_head": None}, {"audit_head": True},
                   {"audit_head": {"audit_seq": True, "mac": "a" * 64}},
                   {"audit_head": {"audit_seq": -1, "mac": "a" * 64}},
                   {"audit_head": {"audit_seq": 3, "mac": "a" * 64, "extra": True}},
                   {"audit_head": {"audit_seq": 9, "mac": "a" * 64}},
                   {"audit_head": {"audit_seq": 0, "mac": "a" * 64}},
                   {"revocation_checkpoint": {"authority_id": "bad", "generation": 0, "digest": "b" * 64}},
                   {"revocation_checkpoint": {"authority_id": "auth_fixture", "generation": True, "digest": "b" * 64}},
                   {"revocation_checkpoint": {"authority_id": "auth_fixture", "generation": 0, "digest": "B" * 64}}]
        errors = []
        for version in (1, 2):
            for changed in changes:
                with self.subTest(version=version, changed=changed):
                    with self.assertRaises(MemoryError) as caught:
                        validate_manifest(dict(manifest(version), **changed))
                    errors.append(caught.exception.as_dict())
        self.assertTrue(all(error == errors[0] for error in errors))
        self.assertEqual(errors[0]["code"], "backup_invalid")

    def test_missing_manifest_fields_and_nonobjects_fail(self):
        for version in (1, 2):
            for name in manifest(version):
                value = manifest(version)
                del value[name]
                with self.assertRaises(MemoryError):
                    validate_manifest(value)
        for value in (None, [], True, "sensitive-canary"):
            with self.assertRaises(MemoryError):
                validate_manifest(value)

    def test_a_well_formed_old_generation_is_not_mislabeled_current(self):
        # The shape validator cannot establish freshness; activation is absent.
        for version in (1, 2):
            for generation in (0, 2**63 - 1):
                value = manifest(version)
                value["revocation_checkpoint"]["generation"] = generation
                self.assertEqual(validate_manifest(value)["revocation_checkpoint"]["generation"], generation)


class BackupSourceSizeContractTest(unittest.TestCase):
    """Pure scalar validation; no simulated encryption or native acceptance."""

    def test_integer_and_sqlcipher_text_page_sizes_preserve_exact_budget(self):
        for size in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
            limit = (backup.MAX_BACKUP_BYTES - 65536) // size
            for value in (size, str(size)):
                with self.subTest(page_size=value):
                    backup._require_source_size(1, value)
                    backup._require_source_size(limit, value)
                    with self.assertRaises(MemoryError) as caught:
                        backup._require_source_size(limit + 1, value)
                    self.assertEqual(caught.exception.code, "backup_invalid")

    def test_malformed_sizes_and_counts_fail_with_redacted_error(self):
        invalid_sizes = (
            None, True, False, 4096.0, b"4096", [], {}, -4096, 0, 1, 256,
            513, 4095, 65537, 131072, "", "0", "-4096", "+4096", " 4096",
            "4096 ", "4096\n", "04096", "４０９６", "4096.0", "4096e0",
            "131072", "9" * 10000,
        )
        invalid_counts = (None, True, False, 1.0, "1", b"1", [], {}, -1, 0, 2**63)
        cases = [(1, value) for value in invalid_sizes]
        cases += [(value, size) for value in invalid_counts for size in (4096, "4096")]
        for index, (count, size) in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(MemoryError) as caught:
                    backup._require_source_size(count, size)
                self.assertEqual(caught.exception.as_dict(), {
                    "code": "backup_invalid",
                    "message": "The encrypted backup candidate failed validation.",
                })


class CapturedPolicyContractTest(unittest.TestCase):
    """Pure captured-byte admission contracts; no cipher or restore evidence."""

    def test_absent_and_explicit_default_policy_match(self):
        self.assertEqual(AdmissionPolicy.from_bytes(None), AdmissionPolicy())
        self.assertEqual(AdmissionPolicy.from_bytes(b'{"version":1}'), AdmissionPolicy())

    def test_captured_policy_matches_real_private_file_load(self):
        payload = (b'{"version":1,"deny_literals":["synthetic-block"],"allow_sha256":["'
                   + b"a" * 64 + b'"]}')
        captured = AdmissionPolicy.from_bytes(payload)
        with tempfile.TemporaryDirectory(prefix="backup-policy-contract-") as directory:
            home = Path(directory).resolve()
            home.chmod(0o700)
            write_private(home / POLICY_FILE, payload)
            self.assertEqual(AdmissionPolicy.load(home), captured)
        self.assertEqual(captured.deny_literals, ("synthetic-block",))
        self.assertEqual(captured.allow_sha256, frozenset({"a" * 64}))

    def test_invalid_captured_bytes_fail_with_one_content_free_error(self):
        cases = (
            b"", b"not-json-private-sentinel", b'{"version":1,"version":1}',
            b'{"version":true}', b'{"version":2}', b'{"version":1,"extra":"private-sentinel"}',
            b'{"version":1,"allow_sha256":["private-sentinel"]}',
            b'{"version":1,"deny_literals":["bad"]}',
            b'{"version":1,"deny_literals":["same-entry","same-entry"]}',
            b" " * (MAX_POLICY_BYTES + 1), b"\xff", "private-sentinel",
            bytearray(b'{"version":1}'), memoryview(b'{"version":1}'), True, 1, [], {},
        )
        for index, payload in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(MemoryError) as caught:
                    AdmissionPolicy.from_bytes(payload)
                self.assertEqual(caught.exception.as_dict(), {
                    "code": "admission_policy_invalid",
                    "message": "The local admission policy is invalid or unsafe.",
                })
                self.assertTrue(caught.exception.__suppress_context__)


class BackupSchemaBoundaryTest(unittest.TestCase):
    """Trusted DDL comparison only; stdlib SQLite is NOT an encryption fake."""

    def connection(self, schema):
        connection = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(connection.close)
        connection.executescript(schema)
        return connection

    def expected(self):
        db = self.connection(SCHEMA_SQL)
        db.execute(backup.MANIFEST_SCHEMA)
        db.execute(backup.MATERIAL_SCHEMA)
        return backup._schema(db)

    def assert_header_check_is_read_only(self, connection, *, valid):
        before = tuple(connection.execute("PRAGMA " + name).fetchone()[0]
                       for name in ("user_version", "application_id", "auto_vacuum"))
        changes = connection.total_changes
        statements = []
        connection.set_trace_callback(statements.append)
        try:
            if valid:
                backup._require_headers(connection)
            else:
                with self.assertRaises(MemoryError) as caught:
                    backup._require_headers(connection)
                self.assertEqual(caught.exception.code, "backup_invalid")
        finally:
            connection.set_trace_callback(None)
        self.assertTrue(statements)
        self.assertTrue(all(sql in {"PRAGMA user_version", "PRAGMA application_id", "PRAGMA auto_vacuum"}
                            for sql in statements))
        self.assertEqual(connection.total_changes, changes)
        self.assertEqual(tuple(connection.execute("PRAGMA " + name).fetchone()[0]
                               for name in ("user_version", "application_id", "auto_vacuum")), before)

    def test_current_bootstrap_header_contract_is_accepted_without_writes(self):
        # Exact production DDL sets application_id through the imported schema;
        # Store.bootstrap then sets user_version. This is not native-cipher proof.
        source = self.connection(SCHEMA_SQL)
        source.execute("PRAGMA user_version=5")
        self.assertEqual(source.execute("PRAGMA application_id").fetchone()[0], APPLICATION_ID)
        self.assert_header_check_is_read_only(source, valid=True)

    def test_default_mismatched_or_unsupported_headers_fail_without_repair(self):
        for pragma, value in (("application_id", 0), ("application_id", 123),
                              ("user_version", 0), ("user_version", 4), ("user_version", 6),
                              ("auto_vacuum", 1), ("auto_vacuum", 2)):
            with self.subTest(pragma=pragma, value=value):
                # auto_vacuum must be configured before tables are first created.
                source = self.connection("PRAGMA auto_vacuum=%d;" % (value if pragma == "auto_vacuum" else 0))
                source.executescript(SCHEMA_SQL)
                source.execute("PRAGMA user_version=5")
                if pragma != "auto_vacuum":
                    source.execute("PRAGMA " + pragma + "=%d" % value)
                self.assertEqual(source.execute("PRAGMA " + pragma).fetchone()[0], value)
                self.assert_header_check_is_read_only(source, valid=False)

    def test_exact_fresh_schema_only_until_migration_allowlist_is_reviewed(self):
        source = self.connection(SCHEMA_SQL)
        migrated = self.connection((Path(__file__).parent / "fixtures" / "schema-v2.sql").read_text())
        migrated.execute("PRAGMA user_version=2")
        self.assertEqual(migrate(migrated, 2), 5)
        with patch.object(backup, "_expected_schema", return_value=self.expected()):
            backup._require_fresh_schema(source, backup=False)
            with self.assertRaises(MemoryError) as caught:
                backup._require_fresh_schema(migrated, backup=False)
            self.assertEqual(caught.exception.code, "backup_invalid")

    def test_extra_tables_triggers_or_missing_reserved_schema_are_rejected(self):
        source = self.connection(SCHEMA_SQL)
        with patch.object(backup, "_expected_schema", return_value=self.expected()):
            with self.assertRaises(MemoryError):
                backup._require_fresh_schema(source, backup=True)
            source.execute("CREATE TABLE unexpected(value TEXT)")
            with self.assertRaises(MemoryError):
                backup._require_fresh_schema(source, backup=False)
            source.execute("DROP TABLE unexpected")
            source.execute("CREATE TRIGGER unexpected AFTER INSERT ON projects BEGIN SELECT 1; END")
            with self.assertRaises(MemoryError):
                backup._require_fresh_schema(source, backup=False)

    def test_schema_text_and_object_count_are_bounded_before_fetch(self):
        oversized = self.connection("CREATE TABLE oversized(value TEXT DEFAULT '" + "x" * backup.MAX_SCHEMA_BYTES + "');")
        with self.assertRaises(MemoryError):
            backup._schema(oversized)
        many = self.connection("")
        for index in range(backup.MAX_SCHEMA_OBJECTS + 1):
            many.execute("CREATE TABLE bounded_%d(value INTEGER)" % index)
        with self.assertRaises(MemoryError):
            backup._schema(many)
        with self.assertRaises(MemoryError):
            backup._schema(many, "main; SELECT 1")

    def test_selected_metadata_requires_bounded_utf8_values_and_both_keys(self):
        connection = self.connection(SCHEMA_SQL)
        with self.assertRaises(MemoryError):
            backup._bounded_metadata(connection)
        values = {"vault_id": "vlt_fixture", "storage_mode": backup.BACKUP_STORAGE_MODE}
        connection.executemany("INSERT INTO metadata VALUES (?,?)", values.items())
        self.assertEqual(backup._bounded_metadata(connection), values)
        for value in ("", "é" * 65):
            connection.execute("UPDATE metadata SET value=? WHERE key='vault_id'", (value,))
            with self.assertRaises(MemoryError):
                backup._bounded_metadata(connection)

    def test_audit_bounds_precede_python_row_iteration(self):
        connection = self.connection(SCHEMA_SQL)
        connection.row_factory = sqlite3.Row
        storage.Store._append_audit_raw(connection, b"a" * 32, 1, "user_control", "synthetic",
                                       "scope_fixture", "target_fixture", "allowed", "ok", "2026-09-24")
        backup._require_bounded_audit(connection)
        for field in ("actor_kind", "operation", "scoped_id", "target_id", "policy_decision",
                      "result", "key_id", "occurred_at", "previous_mac", "mac"):
            with self.subTest(field=field):
                old = connection.execute("SELECT " + field + " FROM audit_events").fetchone()[0]
                connection.execute("UPDATE audit_events SET " + field + "=?", ("é" * (backup.MAX_AUDIT_CELL_BYTES // 2 + 1),))
                with self.assertRaises(MemoryError):
                    backup._require_bounded_audit(connection)
                connection.execute("UPDATE audit_events SET " + field + "=?", (old,))
        self.assertEqual(connection.execute("SELECT count(*) FROM audit_events").fetchone()[0], 1)
        before = connection.total_changes
        statements = []
        connection.set_trace_callback(statements.append)
        backup._require_bounded_audit(connection)
        connection.set_trace_callback(None)
        self.assertEqual(connection.total_changes, before)
        self.assertTrue(all(statement.startswith("SELECT ") for statement in statements))

    def test_audit_row_limit_is_explicit_and_read_only(self):
        connection = self.connection(SCHEMA_SQL)
        # Synthetic rows test a pure resource limit, not HMAC or cipher validity.
        connection.execute(
            "WITH RECURSIVE rows(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM rows WHERE n<?) "
            "INSERT INTO audit_events(event_seq,actor_kind,operation,scoped_id,target_id,policy_decision,"
            "result,key_id,occurred_at,previous_mac,mac) "
            "SELECT n,'user_control','fixture','scope_fixture','target_fixture','allowed','ok',"
            "'aud_v1','2026-09-24','GENESIS','x' FROM rows", (backup.MAX_AUDIT_EVENTS + 1,))
        with self.assertRaises(MemoryError):
            backup._require_bounded_audit(connection)
        connection.execute("DELETE FROM audit_events WHERE audit_seq=?", (backup.MAX_AUDIT_EVENTS + 1,))
        backup._require_bounded_audit(connection)


class BackupKeyBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="backup-key-contract-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.vault, self.staging, self.keys = [self.root / name for name in ("vault", "staging", "keys")]
        for directory in (self.vault, self.staging, self.keys):
            directory.mkdir(mode=0o700)
        self.source_key = self.write(self.vault / "storage.key", b"s" * 32)
        self.backup_key = self.write(self.keys / "recovery.key", b"b" * 32)

    @staticmethod
    def write(path, value):
        path.write_bytes(value)
        path.chmod(0o600)
        return path

    def pre_begin_store(self, failure=None):
        # Only the alias preflight is represented. Any SQL beyond it fails;
        # this cannot stand in for ATTACH, export, native encryption or commit.
        def execute(statement):
            if statement != "PRAGMA database_list":
                raise AssertionError("pure boundary fixture reached database work")
            return [(0, "main", str(self.vault / "continuum.db"))]
        return SimpleNamespace(data_dir=self.vault,
                               connection=SimpleNamespace(in_transaction=False, execute=execute),
                               begin=Mock(side_effect=failure), rollback=Mock())

    def test_owner_private_separate_key_is_read_without_copy_or_output(self):
        self.assertEqual(read_backup_key_file(self.backup_key, self.vault, self.staging), b"b" * 32)
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_key_in_vault_artifact_same_key_or_wrong_size_is_rejected(self):
        candidates = [self.write(self.vault / "backup.key", b"b" * 32),
                      self.write(self.staging / "backup.key", b"b" * 32),
                      self.write(self.keys / "same.key", b"s" * 32),
                      self.write(self.keys / "short.key", b"b" * 31),
                      self.write(self.keys / "long.key", b"b" * 33)]
        for path in candidates:
            with self.assertRaises(MemoryError) as caught:
                read_backup_key_file(path, self.vault, self.staging)
            self.assertEqual(caught.exception.code, "backup_key_unavailable")
            self.assertNotIn(str(path), str(caught.exception))

    def test_links_fifo_permissive_key_or_parent_fail_closed(self):
        symlink = self.keys / "alias.key"
        symlink.symlink_to(self.backup_key)
        fifo = self.keys / "fifo.key"
        os.mkfifo(fifo, 0o600)
        for path in (symlink, fifo):
            with self.assertRaises(MemoryError):
                read_backup_key_file(path, self.vault, self.staging)
        self.backup_key.chmod(0o644)
        with self.assertRaises(MemoryError):
            read_backup_key_file(self.backup_key, self.vault, self.staging)
        self.backup_key.chmod(0o600)
        self.keys.chmod(0o755)
        with self.assertRaises(MemoryError):
            read_backup_key_file(self.backup_key, self.vault, self.staging)
        self.keys.chmod(0o700)
        os.link(self.backup_key, self.keys / "hardlink.key")
        with self.assertRaises(MemoryError):
            read_backup_key_file(self.backup_key, self.vault, self.staging)

    def test_single_file_candidate_rejects_sidecars_before_any_native_open(self):
        candidate = self.write(self.staging / "backup.cdb", b"not-native-encrypted-evidence")
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(candidate) + suffix)
            for kind in ("regular", "dangling_symlink"):
                with self.subTest(suffix=suffix, kind=kind):
                    if kind == "regular":
                        self.write(sidecar, b"canary")
                    else:
                        sidecar.symlink_to(self.staging / "missing")
                    with patch.object(storage, "_require_sqlcipher_runtime") as native:
                        with self.assertRaises(MemoryError) as caught:
                            validate_candidate(candidate, b"b" * 32)
                        self.assertEqual(caught.exception.code, "backup_invalid")
                        native.assert_not_called()
                    self.assertTrue(os.path.lexists(sidecar))
                    sidecar.unlink()

    def test_failed_begin_leaves_private_residue_and_cannot_blindly_retry(self):
        # No fake cryptography: fail before ATTACH/any native encryption operation.
        store = self.pre_begin_store(RuntimeError("sensitive-driver-canary"))
        with self.assertRaises(MemoryError) as caught:
            backup.export_candidate(store, self.staging, self.backup_key, manifest()["revocation_checkpoint"])
        self.assertEqual(caught.exception.code, "backup_invalid")
        self.assertNotIn("canary", str(caught.exception))
        target = self.staging / "backup.cdb"
        self.assertEqual(target.read_bytes(), b"")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        store.rollback.assert_not_called()
        with self.assertRaises(MemoryError) as caught:
            backup.export_candidate(store, self.staging, self.backup_key, manifest()["revocation_checkpoint"])
        self.assertEqual(caught.exception.code, "backup_destination_exists")
        store.begin.assert_called_once()

    def test_orphan_sidecars_block_export_before_file_creation(self):
        store = self.pre_begin_store()
        target = self.staging / "backup.cdb"
        self.write(Path(str(target) + "-wal"), b"not-a-live-vault")
        with self.assertRaises(MemoryError) as caught:
            backup.export_candidate(store, self.staging, self.backup_key, manifest()["revocation_checkpoint"])
        self.assertEqual(caught.exception.code, "backup_invalid")
        self.assertFalse(target.exists())
        store.begin.assert_not_called()

    def test_destination_creation_failure_is_content_free_before_database_work(self):
        store = self.pre_begin_store()
        with patch.object(backup, "write_private", side_effect=OSError("sensitive-path-canary")) as create:
            with self.assertRaises(MemoryError) as caught:
                backup.export_candidate(store, self.staging, self.backup_key, manifest()["revocation_checkpoint"])
        create.assert_called_once_with(self.staging / "backup.cdb", b"")
        self.assertEqual(caught.exception.code, "backup_invalid")
        self.assertNotIn("canary", str(caught.exception))
        store.begin.assert_not_called()
        self.assertFalse((self.staging / "backup.cdb").exists())

    def test_control_capture_bounds_and_observed_changes_fail_closed(self):
        observed = backup._export_control_snapshot(self.backup_key, 32)
        self.assertEqual(observed[0], b"b" * 32)
        backup._export_control_unchanged(self.backup_key, 32, observed)
        with self.assertRaises(MemoryError):
            backup._export_control_snapshot(self.backup_key, 31)
        replacement = self.write(self.keys / "replacement.key", b"b" * 32)
        os.replace(replacement, self.backup_key)
        with self.assertRaises(MemoryError):
            backup._export_control_unchanged(self.backup_key, 32, observed)
        current = backup._export_control_snapshot(self.backup_key, 32)
        self.backup_key.chmod(0o644)
        with self.assertRaises(MemoryError):
            backup._export_control_unchanged(self.backup_key, 32, current)
        self.backup_key.chmod(0o600)
        optional = self.keys / "optional.policy"
        absent = backup._export_control_snapshot(optional, 32, optional=True)
        self.assertEqual(absent, (None, None))
        backup._export_control_unchanged(optional, 32, absent, optional=True)
        self.write(optional, b"new policy")
        with self.assertRaises(MemoryError):
            backup._export_control_unchanged(optional, 32, absent, optional=True)

    def test_nested_or_same_staging_directory_is_refused_before_creation(self):
        child = self.vault / "nested"
        child.mkdir(mode=0o700)
        for directory in (self.vault, child, self.root):
            with self.subTest(directory=directory):
                store = self.pre_begin_store()
                with self.assertRaises(MemoryError):
                    backup.export_candidate(store, directory, self.backup_key, manifest()["revocation_checkpoint"])
                self.assertFalse((directory / "backup.cdb").exists())
                store.begin.assert_not_called()

    def test_rotation_markers_and_legacy_residue_block_before_output(self):
        for directory in (self.vault, self.staging):
            for name in ("storage.rotation.json", "storage.key.next", ".storage.key.legacy.tmp"):
                with self.subTest(directory=directory, name=name):
                    marker = self.write(directory / name, b"synthetic-marker")
                    store = self.pre_begin_store()
                    with self.assertRaises(MemoryError):
                        backup.export_candidate(store, self.staging, self.backup_key, manifest()["revocation_checkpoint"])
                    self.assertFalse((self.staging / "backup.cdb").exists())
                    self.assertEqual(marker.read_bytes(), b"synthetic-marker")
                    store.begin.assert_not_called()
                    marker.unlink()

    def test_cancelled_begin_preserves_cancellation_and_private_residue(self):
        for index, kind in enumerate((KeyboardInterrupt, SystemExit)):
            directory = self.staging / str(index)
            directory.mkdir(mode=0o700)
            cancellation = kind("synthetic cancellation")
            store = self.pre_begin_store(cancellation)
            with self.assertRaises(kind) as caught:
                backup.export_candidate(store, directory, self.backup_key, manifest()["revocation_checkpoint"])
            self.assertIs(caught.exception, cancellation)
            self.assertEqual((directory / "backup.cdb").read_bytes(), b"")
            self.assertFalse(store.connection.in_transaction)

    def test_candidate_size_and_key_type_refuse_before_native_open(self):
        candidate = self.write(self.staging / "backup.cdb", b"")
        for size, key in ((0, b"b" * 32), (backup.MAX_BACKUP_BYTES + 1, b"b" * 32),
                          (1, b"b" * 31), (1, "b" * 32)):
            with candidate.open("r+b") as handle:
                handle.truncate(size)
            with patch.object(storage, "_require_sqlcipher_runtime") as native:
                with self.assertRaises(MemoryError):
                    validate_candidate(candidate, key)
                native.assert_not_called()
            self.assertEqual(candidate.stat().st_size, size)

    def test_missing_backend_is_an_error_without_plaintext_fallback(self):
        candidate = self.write(self.staging / "backup.cdb", b"synthetic-invalid-ciphertext")
        with patch.object(storage, "sqlite3", None):
            with self.assertRaises(MemoryError) as caught:
                validate_candidate(candidate, b"b" * 32)
        self.assertEqual(caught.exception.code, "backup_invalid")
        self.assertEqual(candidate.read_bytes(), b"synthetic-invalid-ciphertext")


if __name__ == "__main__":
    unittest.main()
