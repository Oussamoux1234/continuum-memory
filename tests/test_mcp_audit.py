import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from continuum_memory.storage import Store
from fixtures.harness import EphemeralHarness


class McpAndAuditTest(unittest.TestCase):
    def test_second_daemon_fails_closed(self) -> None:
        with EphemeralHarness() as harness:
            root = Path(__file__).resolve().parents[1]
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(root / "src")
            completed = subprocess.run(
                [sys.executable, "-m", "continuum_memory.daemon", "--data-dir", str(harness.data_dir)],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("already_running", completed.stderr)

    def test_modern_mcp_surface_is_exact_and_strict(self) -> None:
        with EphemeralHarness() as harness:
            client = harness.mcp("alpha", "codex")
            discovery = client.discover()
            self.assertEqual(discovery["protocolVersion"], "2026-07-28")
            names = [tool["name"] for tool in client.tools()]
            self.assertEqual(
                names,
                [
                    "memory_context",
                    "memory_search",
                    "memory_get",
                    "memory_propose",
                    "memory_feedback",
                    "memory_status",
                ],
            )
            self.assertNotIn("memory_accept", names)
            malformed = client.call_raw("memory_status", {"project": harness.projects["beta"]["id"]})
            self.assertEqual(malformed["error"]["code"], -32602)
            oversized = client.call_raw("memory_search", {"query": "x" * 257})
            self.assertEqual(oversized["error"]["code"], -32602)

    def test_pinned_legacy_initialization_is_negotiated(self) -> None:
        with EphemeralHarness() as harness:
            client = harness.mcp("alpha", "codex")
            initialized = client.request_legacy(
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "legacy-fixture", "version": "1"},
                },
            )
            self.assertEqual(initialized["result"]["protocolVersion"], "2025-11-25")
            tools = client.request_legacy("tools/list", {})
            self.assertEqual(len(tools["result"]["tools"]), 6)

    def test_audit_detects_internal_tamper(self) -> None:
        with tempfile.TemporaryDirectory(prefix="continuum-audit-test-") as temp:
            data_dir = Path(temp)
            Store.bootstrap(
                data_dir,
                [{"name": "audit", "path_hint": "/fixture/audit", "providers": ["codex"]}],
            )
            tamper_store = Store(data_dir)
            connection = tamper_store.connection
            try:
                connection.execute("UPDATE audit_events SET operation='tampered' WHERE audit_seq=1")
                connection.commit()
            finally:
                tamper_store.close()
            store = Store(data_dir)
            try:
                result = store.verify_audit()
                self.assertEqual(result["status"], "invalid_event_mac")
                self.assertEqual(result["first_invalid_audit_seq"], 1)
            finally:
                store.close()

    def test_context_obeys_conservative_byte_budget(self) -> None:
        with EphemeralHarness() as harness:
            project = harness.projects["alpha"]["id"]
            for index in range(4):
                harness.approve(
                    {
                        "operation": "remember",
                        "project": project,
                        "subject": "bounded context %d" % index,
                        "claim": "Context item %d has enough repeated material to exercise deterministic packing." % index,
                        "evidence": "Synthetic fixture evidence %d" % index,
                        "evidence_locator": "fixture:budget-%d" % index,
                        "classification": "internal",
                        "retention": "forever",
                        "disclosure": ["codex"],
                        "valid_precision": "unknown",
                    }
                )
            client = harness.mcp("alpha", "codex")
            result = client.call(
                "memory_context", {"query": "Context item", "max_tokens": 128, "max_bytes": 512}
            )
            encoded = len(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            self.assertLessEqual(encoded, 512)
            self.assertEqual(result["byte_budget"], 512)
            self.assertEqual(result["completeness"], "partial")


if __name__ == "__main__":
    unittest.main()
