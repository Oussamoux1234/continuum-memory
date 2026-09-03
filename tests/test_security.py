import sqlite3
import unittest

from continuum_memory.errors import MemoryError
from continuum_memory.security import sign_grant
from continuum_memory.storage import load_capability, paths
from fixtures.harness import EphemeralHarness


class SecurityBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = EphemeralHarness()
        self.project = self.harness.projects["alpha"]["id"]
        self.codex = self.harness.mcp("alpha", "codex")

    def tearDown(self) -> None:
        self.harness.close()

    def test_secret_rejected_before_proposal_persistence(self) -> None:
        secret = "AKIA" + "ABCDEFGHIJKLMNOP"
        response = self.codex.call_raw(
            "memory_propose",
            {
                "subject": "credential",
                "claim": "The credential is %s" % secret,
                "evidence": "Synthetic canary",
                "source_handle": "fixture:secret",
                "disclosure": ["codex"],
                "idempotency_key": "secret-canary-0001",
            },
        )
        self.assertTrue(response["result"]["isError"])
        self.assertEqual(response["result"]["structuredContent"]["error"]["code"], "secret_rejected")
        connection = sqlite3.connect(str(self.harness.data_dir / "continuum.db"))
        try:
            self.assertEqual(connection.execute("SELECT count(*) FROM proposals").fetchone()[0], 0)
            for table, column in (("proposals", "body"), ("evidence", "body"), ("assertion_versions", "body")):
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) FROM %s WHERE %s LIKE ?" % (table, column), ("%%%s%%" % secret,)
                    ).fetchone()[0],
                    0,
                )
        finally:
            connection.close()

    def test_idempotency_conflict_and_fts_syntax_are_bounded(self) -> None:
        base = {
            "subject": "query safety",
            "claim": "Moonstone is a synthetic term.",
            "evidence": "Synthetic evidence",
            "source_handle": "fixture:query",
            "disclosure": ["codex"],
            "idempotency_key": "query-safety-0001",
        }
        self.codex.call("memory_propose", base)
        changed = dict(base, claim="A different body under the same key.")
        with self.assertRaises(MemoryError) as conflict:
            self.codex.call("memory_propose", changed)
        self.assertEqual(conflict.exception.code, "idempotency_conflict")
        result = self.codex.call("memory_search", {"query": "\") OR * --", "limit": 5})
        self.assertEqual(result["status"], "no_matches")

    def test_changed_preview_and_agent_admin_are_rejected(self) -> None:
        proposed = self.codex.call(
            "memory_propose",
            {
                "subject": "preview binding",
                "claim": "The original exact body.",
                "evidence": "Synthetic evidence",
                "source_handle": "fixture:preview",
                "disclosure": ["codex"],
                "idempotency_key": "preview-binding-0001",
            },
        )
        challenge = self.harness.control.call(
            "admin_preview",
            {
                "operation": "accept_proposal",
                "project": self.project,
                "proposal_id": proposed["proposal_id"],
            },
        )
        control = load_capability(paths(self.harness.data_dir)["control"])
        grant = sign_grant(
            control["token"].encode("ascii"),
            challenge["nonce"],
            challenge["operation"],
            challenge["preview_digest"],
        )
        changed = dict(challenge["preview"])
        changed["claim"] = "A changed body after preview."
        with self.assertRaises(MemoryError) as mismatch:
            self.harness.control.call(
                "admin_apply",
                {
                    "nonce": challenge["nonce"],
                    "preview_digest": challenge["preview_digest"],
                    "grant": grant,
                    "preview": changed,
                },
            )
        self.assertEqual(mismatch.exception.code, "approval_mismatch")
        inbox = self.harness.control.call("inbox", {"project": self.project})
        self.assertEqual(inbox["proposals"][0]["status"], "proposed")

    def test_feedback_does_not_mutate_truth(self) -> None:
        accepted = self.harness.approve(
            {
                "operation": "remember",
                "project": self.project,
                "subject": "feedback target",
                "claim": "Feedback is separate from accepted truth.",
                "evidence": "Synthetic evidence",
                "evidence_locator": "fixture:feedback",
                "classification": "internal",
                "retention": "forever",
                "disclosure": ["codex"],
                "valid_precision": "unknown",
            }
        )["result"]
        search = self.codex.call("memory_search", {"query": "Feedback separate", "limit": 5})
        result = self.codex.call(
            "memory_feedback",
            {
                "recall_id": search["recall_id"],
                "item_id": accepted["assertion_id"],
                "label": "wrong",
                "reason": "Synthetic feedback only",
            },
        )
        self.assertFalse(result["truth_mutated"])
        current = self.codex.call("memory_search", {"query": "Feedback separate", "limit": 5})
        self.assertEqual(current["cards"][0]["version_id"], accepted["assertion_id"])


if __name__ == "__main__":
    unittest.main()
