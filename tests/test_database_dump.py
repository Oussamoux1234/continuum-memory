"""The shared SQL dump observer must use the real encrypted connection."""

import tempfile
import unittest
from pathlib import Path

from continuum_memory import storage
from continuum_memory.storage import Store, paths
from tests.database_dump import database_dump


class NativeDatabaseDumpTest(unittest.TestCase):
    def test_native_snapshot_covers_values_and_fts_without_mutation(self):
        storage._require_sqlcipher_runtime()
        with tempfile.TemporaryDirectory(prefix="continuum-dump-fixture-") as temporary:
            home = Path(temporary)
            Store.bootstrap(home, [{"name": "dump", "path_hint": "/fixture/dump",
                                    "providers": ["codex"]}])
            store = Store(home)
            try:
                connection = store.connection
                self.assertEqual(connection.execute("PRAGMA cipher_version").fetchone()[0],
                                 storage.SQLCIPHER_VERSION)
                connection.execute("CREATE TABLE dump_probe (body TEXT, payload BLOB, absent TEXT)")
                connection.execute("INSERT INTO dump_probe VALUES (?,?,NULL)",
                                   ("dump ' quotation — 東京", b"\x00\x01\xff"))
                connection.execute("CREATE VIRTUAL TABLE dump_search USING fts5(body)")
                connection.execute("INSERT INTO dump_search VALUES (?)", ("DUMPSNAPSHOTFTSCANARY",))
                anchor = paths(home)["audit_head"].read_bytes()
                state = (connection.total_changes, connection.in_transaction,
                         connection.execute("PRAGMA schema_version").fetchone()[0])
                original = tuple(database_dump(connection))
                rendered = "\n".join(original)
                self.assertIn("dump '' quotation — 東京", rendered)
                self.assertIn("X'0001FF'", rendered)
                self.assertIn("NULL", rendered)
                self.assertIn("DUMPSNAPSHOTFTSCANARY", rendered)
                self.assertIn('"dump_search_data"', rendered)
                self.assertEqual(tuple(database_dump(connection)), original)
                self.assertEqual((connection.total_changes, connection.in_transaction,
                                  connection.execute("PRAGMA schema_version").fetchone()[0]), state)
                self.assertEqual(paths(home)["audit_head"].read_bytes(), anchor)
                self.assertEqual(tuple(connection.execute("SELECT body,payload,absent FROM dump_probe").fetchone()),
                                 ("dump ' quotation — 東京", b"\x00\x01\xff", None))
                connection.execute("UPDATE dump_probe SET payload=?", (b"changed",))
                changed = tuple(database_dump(connection))
                self.assertNotEqual(changed, original)
                connection.execute("UPDATE dump_search SET body=?", ("CHANGEDFTSCANARY",))
                self.assertNotEqual(tuple(database_dump(connection)), changed)
                self.assertEqual(store.verify_audit()["status"], "valid")
            finally:
                store.close()
