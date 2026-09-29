"""Actual UTF-8 MCP lifecycle and failure cleanup on every native runtime."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fixtures.harness import EphemeralHarness


class HarnessPortabilityTest(unittest.TestCase):
    def test_non_ascii_claim_crosses_two_real_mcp_processes_exactly(self):
        with EphemeralHarness() as harness:
            author = harness.mcp("alpha", "codex")
            reader = harness.mcp("alpha", "claude")
            claim = "Décision: mémoire partagée — 東京 — مرحبا — 🧠"
            evidence = "Révision humaine synthétique — دليل"
            proposal = author.call("memory_propose", {
                "subject": "Unicode fixture", "claim": claim, "evidence": evidence,
                "source_handle": "fixture:unicode", "disclosure": ["codex", "claude"],
                "idempotency_key": "unicode-fixture-001",
            })
            accepted = harness.approve({"operation": "accept_proposal",
                "project": harness.projects["alpha"]["id"], "proposal_id": proposal["proposal_id"]})["result"]
            found = reader.call("memory_search", {"query": "Unicode fixture"})
            full = reader.call("memory_get", {"recall_id": found["recall_id"],
                "ids": [accepted["assertion_id"]]})["records"][0]
            self.assertEqual(full["claim"], claim)
            self.assertEqual(full["evidence"]["body"], evidence)

    def test_failed_daemon_start_reaps_process_and_removes_only_fixture(self):
        original = tempfile.TemporaryDirectory
        created = []

        def track(**options):
            temporary = original(**options)
            created.append(Path(temporary.name))
            return temporary

        with patch("fixtures.harness.tempfile.TemporaryDirectory", side_effect=track):
            with self.assertRaisesRegex(RuntimeError, "daemon failed"):
                EphemeralHarness(daemon_module="fixtures.nonexistent_synthetic_daemon")
        self.assertEqual(len(created), 1)
        self.assertFalse(created[0].exists())
