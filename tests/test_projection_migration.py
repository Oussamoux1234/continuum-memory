"""Exercise the shipped v2 schema, including interrupted upgrades and old receipts."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum_memory import storage
from continuum_memory.errors import MemoryError
from continuum_memory.kernel import Kernel
from continuum_memory.migrations import migrate
from continuum_memory.storage import Store, load_capability, paths


class ProjectionMigrationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="continuum-v2-upgrade-")
        self.home = Path(self.temp.name)
        schema = (Path(__file__).parent / "fixtures" / "schema-v2.sql").read_text()
        with patch.object(storage, "SCHEMA_SQL", schema), patch.object(storage, "SCHEMA_VERSION", 2):
            boot = Store.bootstrap(self.home, [{"name": "alpha", "path_hint": "/synthetic/alpha",
                                                "providers": ["codex", "claude"]}])
        self.project = boot["projects"][0]["id"]
        self.cap_path = Path(boot["projects"][0]["capabilities"]["codex"])
        self.db = sqlite3.connect(str(paths(self.home)["db"]))
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        scope = self.db.execute("SELECT id FROM scopes WHERE project_id=?", (self.project,)).fetchone()[0]
        self.db.execute("INSERT INTO claim_threads VALUES ('mem_migration',?,?, 'engine','engine','2027-01-01',4)",
                        (self.project, scope))
        for aid, body, seq, retired, disclosure in (
            ("asr_visible1", "Engine uses SQLite.", 4, None, "*"),
            ("asr_hidden00", "Engine uses secret backend.", 5, None, "claude"),
            ("asr_visible2", "Engine uses Postgres.", 6, 8, "codex"),
            ("asr_visible3", "Engine uses SQLite.", 8, None, "codex"),
        ):
            self.db.execute("INSERT INTO assertion_versions(id,thread_id,project_id,body,admission,epistemic,lifecycle,"
                            "authority,classification,retention,valid_precision,recorded_at,ingest_seq,retired_at,retired_seq,created_by) "
                            "VALUES (?,'mem_migration',?,?,'accepted','asserted',?,'data','internal','forever','unknown',"
                            "'2027-01-01',?,?,?,'user_control')",
                            (aid, self.project, body, "superseded" if retired else "active", seq,
                             "2027-01-02" if retired else None, retired))
            self.db.execute("INSERT INTO assertion_disclosures VALUES (?,?)", (aid, disclosure))
            self.db.execute("INSERT INTO assertion_fts VALUES (?,?,'engine',?)", (aid, self.project, body))
        self.db.execute("UPDATE sequence SET value=8")
        self.db.execute("INSERT INTO recalls VALUES ('rcl_oldreceipt',?,'codex','opaque','[\"asr_visible2\"]',6,1,'2027-01-01')",
                        (self.project,))
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_v2_upgrade_preserves_versions_and_reconstructs_conflicts_without_cache(self):
        before = [dict(row) for row in self.db.execute("SELECT * FROM assertion_versions ORDER BY id")]
        self.assertEqual(self.db.execute("PRAGMA user_version").fetchone()[0], 2)
        store = Store(self.home)
        try:
            self.assertEqual(store.connection.execute("PRAGMA user_version").fetchone()[0], 3)
            self.assertEqual([dict(row) for row in store.connection.execute("SELECT * FROM assertion_versions ORDER BY id")], before)
            kernel = Kernel(store, approval_public_key_provider=lambda uid: None)
            codex = store.authenticate(load_capability(self.cap_path)["token"])
            self.assertEqual(kernel.status(codex, {})["projection_watermark"], 3)
            current = kernel.context(codex, {"query": "engine", "max_tokens": 2048})
            self.assertEqual(current["open_conflicts"], [])
            past = kernel.context(codex, {"query": "engine", "as_of_recorded": 2, "max_tokens": 2048})
            self.assertEqual({row["version_id"] for row in past["open_conflicts"][0]["members"]},
                             {"asr_visible1", "asr_visible2"})
            with self.assertRaises(MemoryError) as old:
                kernel.get(codex, {"recall_id": "rcl_oldreceipt", "ids": ["asr_visible2"]})
            self.assertEqual(old.exception.code, "not_found")
            self.assertEqual(store.connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(store.connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(store.verify_audit()["status"], "valid")
        finally:
            store.close()
        reopened = Store(self.home)
        reopened.close()

    def test_interrupted_migration_rolls_back_schema_and_receipts_then_retries(self):
        self.db.set_authorizer(lambda action, *args: sqlite3.SQLITE_DENY
                               if action == sqlite3.SQLITE_ALTER_TABLE else sqlite3.SQLITE_OK)
        with self.assertRaises(sqlite3.DatabaseError):
            migrate(self.db, 2)
        # Python 3.9 does not support None to disable this callback.
        self.db.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
        self.assertEqual(self.db.execute("PRAGMA user_version").fetchone()[0], 2)
        self.assertIsNone(self.db.execute("SELECT name FROM sqlite_master WHERE name='audience_sequences'").fetchone())
        self.assertEqual(self.db.execute("SELECT result_ids_json FROM recalls").fetchone()[0], '["asr_visible2"]')
        self.assertEqual(migrate(self.db, 2), 3)
        self.assertEqual(migrate(self.db, 2), 3)
        self.assertEqual(self.db.execute("SELECT result_ids_json FROM recalls").fetchone()[0], "[]")

    def test_unsupported_schema_is_rejected_without_mutation(self):
        self.db.execute("PRAGMA user_version=999")
        with self.assertRaises(MemoryError) as caught:
            Store(self.home)
        self.assertEqual(caught.exception.code, "schema_mismatch")
        self.assertEqual(self.db.execute("PRAGMA user_version").fetchone()[0], 999)


if __name__ == "__main__":
    unittest.main()
