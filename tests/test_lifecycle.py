import json
import unittest

from continuum_memory.errors import MemoryError
from fixtures.harness import EphemeralHarness


class LifecycleIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = EphemeralHarness()
        self.codex = self.harness.mcp("alpha", "codex")
        self.claude = self.harness.mcp("alpha", "claude")
        self.project = self.harness.projects["alpha"]["id"]

    def tearDown(self) -> None:
        self.harness.close()

    def test_cross_agent_correction_conflict_forget_and_replay(self) -> None:
        forged = self.codex.call_raw(
            "memory_propose",
            {
                "subject": "database",
                "claim": "This project uses SQLite because it stays offline.",
                "evidence": "Architecture decision",
                "source_handle": "fixture:codex",
                "disclosure": ["codex", "claude"],
                "idempotency_key": "proposal-forged-0001",
                "accepted": True,
            },
        )
        self.assertEqual(forged["error"]["code"], -32602)
        self.assertEqual(
            self.harness.control.call("inbox", {"project": self.project})["proposals"], []
        )

        proposal_args = {
            "subject": "database",
            "claim": "This project uses SQLite because it stays offline.",
            "evidence": "Architecture decision",
            "source_handle": "fixture:codex",
            "classification": "internal",
            "retention": "forever",
            "disclosure": ["codex", "claude"],
            "valid_precision": "unknown",
            "idempotency_key": "proposal-codex-0001",
        }
        proposed = self.codex.call("memory_propose", proposal_args)
        replayed = self.codex.call("memory_propose", proposal_args)
        self.assertEqual(proposed["proposal_id"], replayed["proposal_id"])
        self.assertTrue(replayed["replayed"])
        inbox = self.harness.control.call("inbox", {"project": self.project})
        self.assertEqual(len(inbox["proposals"]), 1)
        self.assertEqual(inbox["proposals"][0]["source_agent"], "codex")

        approval = self.harness.approve(
            {
                "operation": "accept_proposal",
                "project": self.project,
                "proposal_id": proposed["proposal_id"],
            }
        )
        accepted = approval["result"]
        self.assertEqual(accepted["authority"], "data")
        with self.assertRaises(MemoryError) as replay_error:
            self.harness.replay(approval)
        self.assertEqual(replay_error.exception.code, "approval_replay")

        recalled = self.claude.call("memory_search", {"query": "SQLite", "limit": 5})
        self.assertEqual(recalled["status"], "ok")
        old_version = recalled["cards"][0]["version_id"]
        self.assertEqual(old_version, accepted["assertion_id"])
        full = self.claude.call(
            "memory_get", {"recall_id": recalled["recall_id"], "ids": [old_version]}
        )["records"][0]
        self.assertEqual(full["provenance"]["source_agent"], "codex")
        self.assertEqual(full["evidence"]["body"], "Architecture decision")

        corrected = self.harness.approve(
            {
                "operation": "correct",
                "project": self.project,
                "target_id": old_version,
                "claim": "This project uses PostgreSQL because deployment now requires shared access.",
                "evidence": "User correction after deployment review",
                "evidence_locator": "fixture:user-correction",
            }
        )["result"]
        current = self.claude.call("memory_search", {"query": "PostgreSQL", "limit": 5})
        self.assertEqual(current["cards"][0]["version_id"], corrected["assertion_id"])
        feedback_reason = "deletion-regression-feedback-canary"
        self.claude.call(
            "memory_feedback",
            {
                "recall_id": current["recall_id"],
                "item_id": corrected["assertion_id"],
                "label": "wrong",
                "reason": feedback_reason,
            },
        )
        old_now = self.claude.call("memory_search", {"query": "SQLite", "limit": 5})
        self.assertEqual(old_now["status"], "no_matches")
        as_recorded = self.claude.call(
            "memory_search",
            {
                "query": "SQLite",
                "limit": 5,
                "temporal_mode": "current",
                "as_of_recorded": accepted["recorded_seq"],
            },
        )
        self.assertEqual(as_recorded["cards"][0]["version_id"], old_version)
        history = self.harness.control.call(
            "show", {"project": self.project, "id": accepted["memory_id"], "history": True}
        )
        self.assertEqual([item["version_id"] for item in history["versions"]], [old_version, corrected["assertion_id"]])
        self.assertEqual(history["versions"][0]["lifecycle"], "superseded")

        incompatible = self.harness.approve(
            {
                "operation": "remember",
                "project": self.project,
                "subject": "database",
                "claim": "This project uses MySQL because the hosting standard requires it.",
                "evidence": "Conflicting hosting requirement",
                "evidence_locator": "fixture:conflict",
                "classification": "internal",
                "retention": "forever",
                "disclosure": ["codex", "claude"],
                "valid_precision": "unknown",
            }
        )["result"]
        self.assertIsNotNone(incompatible["conflict_id"])
        context = self.claude.call(
            "memory_context", {"query": "database project uses", "max_tokens": 2048, "max_bytes": 8192}
        )
        self.assertEqual(context["verified_current"], [])
        self.assertEqual(len(context["open_conflicts"]), 1)
        self.assertEqual(len(context["open_conflicts"][0]["members"]), 2)
        self.assertFalse(context["memory_contract"]["may_authorize_actions"])

        forgotten = self.harness.approve(
            {
                "operation": "forget",
                "project": self.project,
                "target_id": corrected["assertion_id"],
            }
        )["result"]
        self.assertTrue(forgotten["content_free_receipt"])
        self.assertEqual(forgotten["feedback_rows_deleted"], 1)
        self.assertGreaterEqual(forgotten["recall_records_pruned"], 1)
        with self.assertRaises(MemoryError) as stale_recall:
            self.claude.call(
                "memory_get",
                {"recall_id": current["recall_id"], "ids": [corrected["assertion_id"]]},
            )
        self.assertEqual(stale_recall.exception.code, "not_found")
        for term in ("SQLite", "PostgreSQL", "MySQL"):
            result = self.claude.call(
                "memory_search", {"query": term, "limit": 5, "temporal_mode": "history"}
            )
            self.assertEqual(result["status"], "no_matches")
        with self.assertRaises(MemoryError) as missing:
            self.harness.control.call(
                "show", {"project": self.project, "id": accepted["memory_id"], "history": True}
            )
        self.assertEqual(missing.exception.code, "not_found")
        inspection_store = self.harness.open_store()
        connection = inspection_store.connection
        try:
            self.assertEqual(connection.execute("SELECT count(*) FROM assertion_fts").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT count(*) FROM feedback").fetchone()[0], 0)
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM feedback WHERE reason=?", (feedback_reason,)
                ).fetchone()[0],
                0,
            )
            deleted_ids = {old_version, corrected["assertion_id"], incompatible["assertion_id"]}
            for (encoded_ids,) in connection.execute("SELECT result_ids_json FROM recalls"):
                self.assertTrue(deleted_ids.isdisjoint(json.loads(encoded_ids)))
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM provenance_activities WHERE target_id IN (?,?,?,?)",
                    (
                        proposed["proposal_id"],
                        old_version,
                        corrected["assertion_id"],
                        incompatible["assertion_id"],
                    ),
                ).fetchone()[0],
                0,
            )
            receipt = connection.execute("SELECT * FROM deletion_receipts").fetchone()
            self.assertIsNotNone(receipt)
            encoded_receipt = json.dumps(tuple(receipt))
            self.assertNotIn("SQLite", encoded_receipt)
            self.assertNotIn("PostgreSQL", encoded_receipt)
        finally:
            inspection_store.close()
        audit = self.harness.control.call("audit_verify", {})
        self.assertEqual(audit["status"], "valid")
        self.assertEqual(audit["sqlite_integrity"], "ok")
        self.assertEqual(audit["sqlcipher_integrity"], "ok")


if __name__ == "__main__":
    unittest.main()
