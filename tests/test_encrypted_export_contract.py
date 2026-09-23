"""Native export contract probe; this does not implement or certify vault backups.

Requires the reviewed continuum-sqlcipher3 0.6.2.post2 runtime. Missing or wrong
native dependencies fail; a skipped local test must never count as native proof.
"""

import os
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum_memory import storage
from continuum_memory.migrations import SCHEMA_VERSION
from tests import test_snapshot_forget as fixture


CANARY = "EXPORTCONTRACTCANARYce982754f510"
ALIAS = "continuum_backup"


class EncryptedExportContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        storage._require_sqlcipher_runtime()

    def setUp(self):
        self.export_temp = tempfile.TemporaryDirectory(prefix="continuum-export-contract-")
        self.addCleanup(self.export_temp.cleanup)
        self.export_root = Path(self.export_temp.name)
        temp_dir = self.export_root / "sqlite-temp"
        temp_dir.mkdir(mode=0o700)
        environment = patch.dict(os.environ, {"SQLITE_TMPDIR": str(temp_dir)})
        environment.start()
        self.addCleanup(environment.stop)
        self.fx = fixture.SnapshotForgetTest()
        self.fx.setUp()
        self.addCleanup(self.fx.tearDown)
        self.db = self.fx.store.connection
        self.assertEqual(self.db.execute("PRAGMA cipher_version").fetchone()[0],
                         "4.19.0 community")
        self.assertEqual(str(self.db.execute("PRAGMA cipher_status").fetchone()[0]), "1")
        self.assertEqual(self.db.execute("PRAGMA user_version").fetchone()[0], 5)
        self.assertEqual(SCHEMA_VERSION, 5)
        self.assertEqual(self.db.execute("PRAGMA application_id").fetchone()[0], 1129143636)
        self.assertEqual(self.db.execute("PRAGMA temp_store").fetchone()[0], 2)

        # Real owner operations create receipts, an audit chain, and an FTS row
        # whose rowid need not start at one after deletion.
        discarded = self.fx.remember("discarded export entry", "Synthetic discarded evidence")
        self.live = self.fx.remember("retained export entry", "Synthetic " + CANARY)
        self.fx.approve(operation="forget", target_id=discarded["assertion_id"])
        self.fx.context(CANARY)
        for table in ("admin_results", "deletion_receipts", "audit_events", "assertion_fts"):
            self.assertGreater(self.db.execute("SELECT count(*) FROM " + table).fetchone()[0], 0)
        self.assertEqual(self.fx.store.verify_audit()["status"], "valid")
        self.db.execute("CREATE TEMP TABLE export_temp_canary(body TEXT NOT NULL)")
        self.db.execute("INSERT INTO export_temp_canary VALUES (?)", (CANARY,))
        self.db.commit()
        self.source_key = self.fx.store.files["storage_key"].read_bytes()
        self.assertEqual(len(self.source_key), 32)
        self.backup_key = secrets.token_bytes(32)
        while self.backup_key == self.source_key:
            self.backup_key = secrets.token_bytes(32)
        self.before = self._snapshot(self.db)
        self.private_files = self._private_source_files()

    @staticmethod
    def _snapshot(connection):
        schema = [tuple(row) for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name")]
        tables = [row[1] for row in connection.execute("PRAGMA main.table_list")
                  if row[2] in {"table", "virtual"}
                  and (not row[1].startswith("sqlite_") or row[1] == "sqlite_sequence")]
        rows = {}
        for table in tables:
            # Names come from our synthetic schema, never from a caller. Quote
            # them so this comparison also handles any future unusual identifier.
            quoted = '"' + table.replace('"', '""') + '"'
            columns = "rowid,*" if table == "assertion_fts" else "*"
            rows[table] = sorted(
                (tuple(row) for row in connection.execute("SELECT " + columns + " FROM " + quoted)),
                key=repr,
            )
        return {
            "schema": schema,
            "rows": rows,
            "headers": tuple(connection.execute("PRAGMA " + name).fetchone()[0]
                             for name in ("user_version", "application_id", "auto_vacuum")),
        }

    def _private_source_files(self):
        database = self.fx.store.files["db"]
        database_files = {database, Path(str(database) + "-wal"), Path(str(database) + "-shm")}
        return {str(path.relative_to(self.fx.home)): path.read_bytes()
                for path in self.fx.home.rglob("*") if path.is_file() and path not in database_files}

    def _new_target(self, name):
        target = self.export_root / name
        descriptor = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        return target

    def _open_keyed(self, path, key):
        self.assertTrue(path.is_file())
        connection = storage.sqlite3.connect(path.as_uri() + "?mode=ro", uri=True,
                                             isolation_level=None)
        try:
            # Only the hex encoding of a fixed-size binary key is interpolated;
            # PRAGMA assignment has no parameter-binding form.
            self.assertEqual(len(key), 32)
            connection.execute('PRAGMA key = "x\'%s\'"' % key.hex())
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("SELECT count(*) FROM sqlite_schema").fetchone()
            return connection
        except BaseException:
            connection.close()
            raise

    def _assert_source_unchanged(self):
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(self._snapshot(self.db), self.before)
        self.assertEqual(self._private_source_files(), self.private_files)
        self.assertEqual(self.fx.store.files["storage_key"].read_bytes(), self.source_key)
        self.assertEqual(self.fx.store.verify_audit()["status"], "valid")
        self.assertEqual([tuple(row) for row in self.db.execute("SELECT * FROM export_temp_canary")],
                         [(CANARY,)])
        self.assertNotIn(ALIAS, [row[1] for row in self.db.execute("PRAGMA database_list")])

    def _assert_no_plaintext(self):
        for root in (self.fx.home, self.export_root):
            for path in root.rglob("*"):
                if path.is_file():
                    payload = path.read_bytes()
                    self.assertNotIn(CANARY.encode("ascii"), payload, str(path))
                    self.assertFalse(payload.startswith(b"SQLite format 3\x00"), str(path))
                    if root == self.export_root:
                        self.assertNotIn(self.source_key, payload, str(path))
                        self.assertNotIn(self.backup_key, payload, str(path))
        self.assertFalse((self.export_root / "storage.key").exists())

    def test_transactional_export_preserves_schema_receipts_and_distinct_key(self):
        # A quote in the destination exercises bound-path handling, not SQL text.
        target = self._new_target("backup ' synthetic.db")
        user_version, application_id, auto_vacuum = self.before["headers"]
        attached = False
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute("ATTACH DATABASE ? AS continuum_backup KEY ?",
                            (str(target), "x'%s'" % self.backup_key.hex()))
            attached = True
            self.assertEqual(str(self.db.execute("PRAGMA continuum_backup.cipher_status").fetchone()[0]), "1")
            self.db.execute("PRAGMA continuum_backup.auto_vacuum=%d" % auto_vacuum)
            self.db.execute("SELECT sqlcipher_export(?, ?)", (ALIAS, "main")).fetchall()
            # Reproduce the header-copy limitation before explicitly repairing it.
            self.assertEqual(self.db.execute("PRAGMA continuum_backup.user_version").fetchone()[0], 0)
            self.assertEqual(self.db.execute("PRAGMA continuum_backup.application_id").fetchone()[0], 0)
            self.db.execute("PRAGMA continuum_backup.user_version=%d" % user_version)
            self.db.execute("PRAGMA continuum_backup.application_id=%d" % application_id)
            self.assertTrue(self.db.in_transaction)
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        finally:
            if attached:
                self.db.execute("DETACH DATABASE continuum_backup")

        backup = self._open_keyed(target, self.backup_key)
        try:
            self.assertEqual(self._snapshot(backup), self.before)
            self.assertEqual(backup.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
            self.assertEqual(backup.execute("PRAGMA cipher_integrity_check").fetchall(), [])
            self.assertEqual(backup.execute("PRAGMA foreign_key_check").fetchall(), [])
            matches = backup.execute(
                "SELECT assertion_id FROM assertion_fts WHERE assertion_fts MATCH ?", (CANARY,)
            ).fetchall()
            self.assertEqual(matches, [(self.live["assertion_id"],)])
        finally:
            backup.close()
        for path, wrong_key in ((target, self.source_key),
                                (self.fx.store.files["db"], self.backup_key)):
            with self.assertRaises(storage.sqlite3.DatabaseError):
                unexpected = self._open_keyed(path, wrong_key)
                unexpected.close()
        self._assert_source_unchanged()
        self._assert_no_plaintext()

    def test_failed_export_rolls_back_without_accepting_partial_database(self):
        target = self._new_target("failed-export.db")
        attached = False
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute("ATTACH DATABASE ? AS continuum_backup KEY ?",
                            (str(target), "x'%s'" % self.backup_key.hex()))
            attached = True
            # A real destination-schema conflict forces native export to fail.
            # It is deliberately part of this transaction and must roll back too.
            self.db.execute("CREATE TABLE continuum_backup.metadata(unexpected TEXT)")
            with self.assertRaises(storage.sqlite3.DatabaseError):
                self.db.execute("SELECT sqlcipher_export(?, ?)", (ALIAS, "main")).fetchall()
        finally:
            self.db.rollback()
            if attached:
                self.db.execute("DETACH DATABASE continuum_backup")

        failed = self._open_keyed(target, self.backup_key)
        try:
            self.assertEqual(failed.execute("SELECT name FROM sqlite_schema").fetchall(), [])
            self.assertEqual(failed.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertEqual(failed.execute("PRAGMA application_id").fetchone()[0], 0)
        finally:
            failed.close()
        # No output publication marker is created; only the rejected scratch DB
        # may remain for inspection in this synthetic temporary directory.
        self._assert_source_unchanged()
        self._assert_no_plaintext()


if __name__ == "__main__":
    unittest.main()
