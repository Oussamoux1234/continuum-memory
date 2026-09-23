"""The v3 read contract is identical through both existing MCP fixture modes."""

import unittest

from fixtures.harness import EphemeralHarness


class TruthfulContextMcpTest(unittest.TestCase):
    def test_modern_and_legacy_clients_traverse_scoped_search_pages(self):
        with EphemeralHarness() as harness:
            project = harness.projects["alpha"]["id"]
            for i in range(4):
                harness.approve({"operation": "remember", "project": project, "subject": "paging %d" % i,
                    "claim": "Paging evidence.", "evidence": "Synthetic only."})
            for provider in ("codex", "claude"):
                client = harness.mcp("alpha", provider)
                if provider == "claude":
                    client.request_legacy("initialize", {"protocolVersion": "2025-11-25",
                        "capabilities": {}, "clientInfo": {"name": "pagination-fixture", "version": "1"}})

                def call(arguments):
                    if provider == "codex":
                        return client.call("memory_search", arguments)
                    return client.request_legacy("tools/call", {"name": "memory_search", "arguments": arguments})[
                        "result"]["structuredContent"]

                first = call({"query": "paging", "limit": 2})
                second = call({"query": "paging", "limit": 2, "cursor": first["next_cursor"]})
                self.assertEqual(second["completeness"], "complete")
                ids = [card["version_id"] for page in (first, second) for card in page["cards"]]
                self.assertEqual(len(set(ids)), 4)

    def test_modern_and_legacy_clients_receive_truthful_categories(self):
        with EphemeralHarness() as harness:
            project = harness.projects["alpha"]["id"]
            harness.approve({"operation": "remember", "project": project, "subject": "engine",
                "claim": "Engine uses SQLite.", "evidence": "Synthetic fixture only.",
                "valid_precision": "interval", "valid_from": "2028-01-01", "valid_to": "2028-01-31"})
            for provider in ("codex", "claude"):
                with self.subTest(provider=provider):
                    client = harness.mcp("alpha", provider)
                    args = {"query": "engine", "as_of_valid": "2028-01-15", "max_tokens": 2048}
                    if provider == "codex":
                        result = client.call("memory_context", args)
                    else:
                        client.request_legacy("initialize", {"protocolVersion": "2025-11-25",
                            "capabilities": {}, "clientInfo": {"name": "v3-context-fixture", "version": "1"}})
                        result = client.request_legacy("tools/call", {
                            "name": "memory_context", "arguments": args})["result"]["structuredContent"]
                    self.assertEqual(result["response_version"], 3)
                    self.assertNotIn("verified_current", result)
                    card = result["accepted_claims"][0]
                    self.assertEqual(card["epistemic"], "asserted")
                    self.assertEqual(card["applicability"], {
                        "status": "within_declared_interval", "as_of": "2028-01-15T00:00:00.000000Z"})
                    self.assertFalse(result["memory_contract"]["may_authorize_actions"])


if __name__ == "__main__":
    unittest.main()
