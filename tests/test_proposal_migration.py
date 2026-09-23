"""Upgrade the actual v3 schema without silently erasing data during migration."""
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from continuum_memory import storage
from continuum_memory.errors import MemoryError
from continuum_memory.kernel import Kernel
from continuum_memory.migrations import SCHEMA_VERSION, migrate
from continuum_memory.storage import Store, load_capability, paths


class ProposalMigrationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="continuum-v3-upgrade-")
        self.home = Path(self.temp.name)
        schema = (Path(__file__).parent / "fixtures" / "schema-v3.sql").read_text()
        with patch.object(storage, "SCHEMA_SQL", schema), patch.object(storage, "SCHEMA_VERSION", 3):
            boot = Store.bootstrap(self.home, [{"name": "alpha", "path_hint": "/synthetic/alpha", "providers": ["codex"]}])
        self.project = boot["projects"][0]["id"]
        self.cap_path = Path(boot["projects"][0]["capabilities"]["codex"])
        self.db = sqlite3.connect(str(paths(self.home)["db"]))
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        scope = self.db.execute("SELECT id FROM scopes WHERE project_id=?", (self.project,)).fetchone()[0]
        cap = self.db.execute("SELECT id FROM capabilities WHERE project_id=? AND provider='codex'", (self.project,)).fetchone()[0]
        for sequence, status, name, retention in (
            (10, "proposed", "pending", "forever"),
            (11, "rejected", "rejected", "forever"),
            (12, "proposed", "expired", "2027-01-02T00:00:00.000000Z"),
        ):
            row = {
                "id": "prp_legacy_" + name, "project_id": self.project, "scope_id": scope,
                "subject": "legacy-" + name, "subject_key": "legacy-" + name, "body": "legacy-" + name + "-body",
                "evidence_body": "legacy-" + name + "-evidence", "evidence_locator": "legacy-" + name + "-locator",
                "classification": "internal", "retention": retention, "disclosure_json": '["codex"]',
                "valid_precision": "unknown", "status": status, "source_agent": "codex", "source_capability_id": cap,
                "idempotency_key": "legacy-" + name + "-delivery", "request_digest": "opaque-legacy-digest",
                "created_at": "2027-01-01T00:00:00.000000Z", "created_seq": sequence,
            }
            self.db.execute("INSERT INTO proposals(" + ",".join(row) + ") VALUES (" + ",".join("?" for _ in row) + ")", list(row.values()))
            self.db.execute("INSERT INTO provenance_activities VALUES (?,?,?,'agent_proposal','codex','memory_propose',"
                            "'schema-1','[]','opaque-legacy-digest','2027-01-01',?)",
                            ("prv_legacy_" + name, self.project, row["id"], sequence))
        self.db.execute("UPDATE sequence SET value=12")
        self.db.execute("INSERT INTO recalls(id,project_id,provider,query_digest,result_ids_json,watermark,allows_historical,"
                        "created_at,temporal_mode,as_of_recorded,as_of_valid) "
                        "VALUES ('rcl_v3receipt',?,'codex','opaque','[]',0,1,'2027-01-01','history',0,NULL)", (self.project,))
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_v3_upgrade_preserves_rows_receipts_then_policy_purges_terminal_drafts(self):
        proposals = [dict(row) for row in self.db.execute("SELECT * FROM proposals ORDER BY id")]
        recalls = [dict(row) for row in self.db.execute("SELECT * FROM recalls")]
        store = Store(self.home)
        try:
            self.assertEqual(store.connection.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
            self.assertEqual([dict(row) for row in store.connection.execute("SELECT * FROM proposals ORDER BY id")], proposals)
            self.assertEqual([dict(row) for row in store.connection.execute("SELECT * FROM recalls")], recalls)
            kernel = Kernel(store, now_provider=lambda: datetime(2027, 1, 3, tzinfo=timezone.utc),
                            approval_public_key_provider=lambda uid: None)
            control = store.authenticate(load_capability(paths(self.home)["control"])["token"])
            codex = store.authenticate(load_capability(self.cap_path)["token"])
            self.assertEqual([p["proposal_id"] for p in kernel.inbox(control, {"project": self.project})["proposals"]], ["prp_legacy_pending"])
            for name in ("rejected", "expired"):
                self.assertIsNone(store.connection.execute("SELECT id FROM proposals WHERE id=?", ("prp_legacy_" + name,)).fetchone())
                self.assertIsNone(store.connection.execute("SELECT id FROM provenance_activities WHERE target_id=?", ("prp_legacy_" + name,)).fetchone())
                with self.assertRaises(MemoryError) as retry:
                    kernel.propose(codex, {"subject": "new", "claim": "new", "evidence": "new", "source_handle": "new",
                        "disclosure": ["codex"], "idempotency_key": "legacy-" + name + "-delivery"})
                self.assertEqual(retry.exception.code, "delivery_suppressed")
            self.assertEqual(store.connection.execute("SELECT count(*) FROM proposal_tombstones").fetchone()[0], 2)
            self.assertNotIn("legacy-rejected", "\n".join(store.connection.iterdump()))
            self.assertNotIn("legacy-expired", "\n".join(store.connection.iterdump()))
            self.assertEqual(store.connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(store.connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(store.verify_audit()["status"], "valid")
        finally:
            store.close()
        reopened = Store(self.home)
        reopened.close()

    def test_v3_interrupted_upgrade_rolls_back_and_retries_atomically(self):
        before = list(self.db.iterdump())
        self.db.set_authorizer(lambda action, name, *args: sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_CREATE_INDEX and name == "idx_proposals_delivery" else sqlite3.SQLITE_OK)
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                migrate(self.db, 3)
        finally:
            self.db.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
        self.assertEqual(self.db.execute("PRAGMA user_version").fetchone()[0], 3)
        self.assertEqual(list(self.db.iterdump()), before)
        self.assertIsNone(self.db.execute("SELECT name FROM sqlite_master WHERE name='proposal_tombstones'").fetchone())
        self.assertEqual(migrate(self.db, 3), SCHEMA_VERSION)
        self.assertEqual(migrate(self.db, 3), SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()
