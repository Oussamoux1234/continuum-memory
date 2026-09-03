import unittest

from continuum_memory.errors import MemoryError
from fixtures.harness import EphemeralHarness


class IsolationAndTemporalTest(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = EphemeralHarness()

    def tearDown(self) -> None:
        self.harness.close()

    def test_project_and_provider_filters_prevent_disclosure(self) -> None:
        alpha = self.harness.projects["alpha"]["id"]
        accepted = self.harness.approve(
            {
                "operation": "remember",
                "project": alpha,
                "subject": "private build system",
                "claim": "Alpha uses Moonstone internally.",
                "evidence": "Synthetic fixture",
                "evidence_locator": "fixture:alpha",
                "classification": "internal",
                "retention": "forever",
                "disclosure": ["codex"],
                "valid_precision": "unknown",
            }
        )["result"]
        alpha_codex = self.harness.mcp("alpha", "codex")
        alpha_claude = self.harness.mcp("alpha", "claude")
        beta_codex = self.harness.mcp("beta", "codex")
        allowed = alpha_codex.call("memory_search", {"query": "Moonstone", "limit": 5})
        self.assertEqual(allowed["status"], "ok")
        self.assertEqual(alpha_claude.call("memory_search", {"query": "Moonstone", "limit": 5})["status"], "no_matches")
        self.assertEqual(beta_codex.call("memory_search", {"query": "Moonstone", "limit": 5})["status"], "no_matches")
        copied_id = accepted["assertion_id"]
        self.assertEqual(beta_codex.call("memory_search", {"query": copied_id, "limit": 5})["status"], "no_matches")
        with self.assertRaises(MemoryError) as cross_get:
            beta_codex.call(
                "memory_get", {"recall_id": allowed["recall_id"], "ids": [copied_id]}
            )
        self.assertEqual(cross_get.exception.code, "not_found")
        status = alpha_claude.call("memory_status", {})
        self.assertNotIn("claim_count", status)
        self.assertEqual(status["project_bound"], alpha)

    def test_valid_time_and_recorded_time_are_independent(self) -> None:
        alpha = self.harness.projects["alpha"]["id"]
        accepted = self.harness.approve(
            {
                "operation": "remember",
                "project": alpha,
                "subject": "support window",
                "claim": "Version two was supported during 2025.",
                "evidence": "Late-arriving release archive",
                "evidence_locator": "fixture:archive",
                "classification": "internal",
                "retention": "forever",
                "disclosure": ["codex"],
                "valid_precision": "interval",
                "valid_from": "2025-01-01",
                "valid_to": "2025-12-31",
            }
        )["result"]
        client = self.harness.mcp("alpha", "codex")
        during = client.call(
            "memory_search", {"query": "supported", "limit": 5, "as_of_valid": "2025-06-01"}
        )
        after = client.call(
            "memory_search", {"query": "supported", "limit": 5, "as_of_valid": "2026-06-01"}
        )
        before_recording = client.call(
            "memory_search",
            {"query": "supported", "limit": 5, "as_of_recorded": accepted["recorded_seq"] - 1},
        )
        self.assertEqual(during["status"], "ok")
        self.assertEqual(after["status"], "no_matches")
        self.assertEqual(before_recording["status"], "no_matches")


if __name__ == "__main__":
    unittest.main()
