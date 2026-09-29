"""CLI sequencing and hostile reply tests; real process coverage is separate."""

import copy
import io
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from continuum_memory import cli
from continuum_memory.errors import MemoryError


class CliRecoveryControlTest(unittest.TestCase):
    def setUp(self):
        self.locator = {"version": 1, "vault_id": "vlt_fixture", "nonce": "gnt_fixture", "binding": "a" * 64}
        self.challenge = {"nonce": "gnt_fixture", "vault_id": "vlt_fixture", "operation": "remember",
                          "preview_digest": "b" * 64, "preview": {"claim": "private-body-canary"},
                          "recovery_locator": copy.deepcopy(self.locator)}
        self.receipt = {"receipt_id": "gnt_fixture", "operation": "remember", "committed": True,
                        "result": {"assertion_id": "asr_fixture"}, "audit_anchor": "valid"}
        self.result = {"assertion_id": "asr_fixture", "commit": {
            "status": "committed", "receipt_id": "gnt_fixture", "audit_anchor": "synced"}}
        self.events = []
        self.client = Mock(data_dir=Path("unused-unit-fixture"))
        self.client.call.side_effect = self.call
        self.broker = self.enterContext(patch.object(cli, "broker_for_challenge"))
        self.broker.return_value.authorize.side_effect = self.authorize
        self.persist = self.enterContext(patch.object(cli, "persist_locator", side_effect=self.publish))
        self.apply = self.result
        self.recovery = self.receipt

    def authorize(self, challenge):
        self.events.append("approve")
        return "private-grant-canary"

    def publish(self, home, locator):
        self.events.append("persist")
        self.assertEqual(locator, self.locator)

    def call(self, method, params):
        self.events.append(method)
        if method == "admin_preview":
            return self.challenge
        if method == "admin_apply":
            value = self.apply
        else:
            self.assertEqual(method, "admin_recover")
            self.assertEqual(params, self.locator)
            value = self.recovery
        if isinstance(value, Exception):
            raise value
        return value

    def admin(self):
        return cli._admin(self.client, {"operation": "remember"})

    def assert_unknown(self):
        with self.assertRaises(MemoryError) as caught:
            self.admin()
        self.assertEqual(caught.exception.code, "operation_outcome_unknown")
        self.assertEqual(caught.exception.details, {"nonce": "gnt_fixture"})
        serialized = json.dumps(caught.exception.as_dict())
        for private in (self.locator["binding"], self.challenge["preview_digest"], "private-body", "private-grant"):
            self.assertNotIn(private, serialized)

    def test_approve_then_durable_publish_then_exactly_one_apply(self):
        self.assertEqual(self.admin(), self.result)
        self.assertEqual(self.events, ["admin_preview", "approve", "persist", "admin_apply"])
        self.persist.assert_called_once_with(self.client.data_dir, self.locator)

    def test_unsupported_malformed_or_mismatched_locator_never_reaches_broker(self):
        original = copy.deepcopy(self.challenge)
        variants = [None, {}, dict(self.locator, nonce="gnt_another"),
                    dict(self.locator, vault_id="vlt_another"), dict(self.locator, version=True)]
        for value in variants:
            with self.subTest(value=value):
                self.challenge = copy.deepcopy(original)
                if value is None:
                    del self.challenge["recovery_locator"]
                else:
                    self.challenge["recovery_locator"] = value
                with self.assertRaises(MemoryError):
                    self.admin()
                self.broker.assert_not_called()
                self.persist.assert_not_called()
        self.assertNotIn("admin_apply", self.events)

    def test_broker_mutation_cannot_retarget_original_request_or_locator(self):
        original = copy.deepcopy(self.challenge)
        def mutate(challenge):
            self.authorize(challenge)
            for value in (challenge, self.challenge):
                value["nonce"] = "gnt_another"
                value["recovery_locator"]["nonce"] = "gnt_another"
                value["preview"]["claim"] = "modified"
            return "private-grant-canary"
        self.broker.return_value.authorize.side_effect = mutate
        self.assertEqual(self.admin(), self.result)
        request = self.client.call.call_args.args[1]
        self.assertEqual(request["nonce"], original["nonce"])
        self.assertEqual(request["preview"], original["preview"])
        self.persist.assert_called_once_with(self.client.data_dir, self.locator)

    def test_cancellation_never_publishes_or_applies(self):
        self.broker.return_value.authorize.side_effect = MemoryError("approval_cancelled", "Cancelled.")
        with self.assertRaises(MemoryError):
            self.admin()
        self.persist.assert_not_called()
        self.assertEqual(self.events, ["admin_preview"])

    def test_publication_failure_never_applies_or_queries_and_exposes_only_nonce(self):
        for failure in (OSError("private-io-canary"), MemoryError("unsafe_file", "private-io-canary")):
            with self.subTest(failure=type(failure)):
                self.events.clear()
                self.persist.side_effect = failure
                self.assert_unknown()
                self.assertEqual(self.events, ["admin_preview", "approve"])

    def test_ambiguous_apply_uses_one_read_only_lookup_including_windows(self):
        failures = [MemoryError(code, "private-error-canary") for code in (
            "unavailable", "invalid_response", "internal_error", "response_too_large",
            "committed_audit_degraded", "pipe_timeout", "pipe_unavailable", "invalid_frame",
            "pipe_identity_unavailable", "pipe_impersonated_context", "unsafe_owner", "windows_boundary_error")]
        failures.append(OSError("private-error-canary"))
        for failure in failures:
            with self.subTest(failure=str(failure)):
                self.events.clear()
                self.apply = failure
                self.assertTrue(self.admin()["commit"]["recovered"])
                self.assertEqual(self.events, ["admin_preview", "approve", "persist", "admin_apply", "admin_recover"])

    def test_windows_post_transmission_identity_loss_remains_unknown_if_recovery_fails(self):
        for code in ("pipe_identity_unavailable", "pipe_impersonated_context", "unsafe_owner", "windows_boundary_error"):
            with self.subTest(code=code):
                self.events.clear()
                self.apply = MemoryError(code, "private-identity-canary")
                self.recovery = MemoryError(code, "private-identity-canary")
                self.assert_unknown()
                self.assertEqual(self.events, ["admin_preview", "approve", "persist", "admin_apply", "admin_recover"])

    def test_semantic_refusal_does_not_retry_or_lookup(self):
        self.apply = MemoryError("approval_replay", "Already used.")
        with self.assertRaises(MemoryError) as refused:
            self.admin()
        self.assertEqual(refused.exception.code, "approval_replay")
        self.assertEqual(self.events, ["admin_preview", "approve", "persist", "admin_apply"])

    def test_malformed_apply_success_requires_recovery(self):
        for value in (None, [], {}, {"commit": {}},
                      {"commit": dict(self.result["commit"], receipt_id="gnt_wrong")},
                      {"commit": dict(self.result["commit"], audit_anchor=None)}):
            with self.subTest(value=value):
                self.events.clear()
                self.apply = value
                self.assertTrue(self.admin()["commit"]["recovered"])
                self.assertEqual(self.events.count("admin_apply"), 1)
                self.assertEqual(self.events.count("admin_recover"), 1)

    def test_missing_malformed_or_mismatched_receipts_never_claim_success(self):
        self.apply = MemoryError("unavailable", "synthetic")
        variants = [None, {}, MemoryError("not_found", "private-error-canary"), OSError("private-error-canary"),
                    dict(self.receipt, committed=1), dict(self.receipt, receipt_id="gnt_another"),
                    dict(self.receipt, operation="forget"), dict(self.receipt, result=[]),
                    dict(self.receipt, audit_anchor=None)]
        variants.extend({key: value for key, value in self.receipt.items() if key != missing} for missing in self.receipt)
        for value in variants:
            with self.subTest(value=value):
                self.events.clear()
                self.recovery = value
                self.assert_unknown()
                self.assertEqual(self.events.count("admin_apply"), 1)
                self.assertEqual(self.events.count("admin_recover"), 1)

    def test_recover_status_is_page_scoped_and_never_authorizes(self):
        for known in (True, False):
            with self.subTest(known=known):
                self.events.clear()
                self.recovery = self.receipt if known else MemoryError("not_found", "private-error-canary")
                with patch.object(cli, "load_locators", return_value={"locators": [self.locator], "next_cursor": "gnt_fixture"}):
                    result = cli._recover(self.client, limit=1)
                self.assertEqual(result["status"], "complete" if known else "unresolved")
                self.assertEqual(result["scope"], "page")
                self.assertTrue(result["has_more"])
                self.assertEqual(self.events, ["admin_recover"])
                self.broker.assert_not_called()
                self.persist.assert_not_called()

    def test_empty_page_does_not_invent_an_operation_outcome(self):
        with patch.object(cli, "load_locators", return_value={"locators": [], "next_cursor": None}):
            result = cli._recover(self.client)
        self.assertEqual(result, {"status": "complete", "scope": "page", "operations": [],
                                  "next_cursor": None, "has_more": False})
        self.client.call.assert_not_called()

    def test_recover_exit_status_preserves_unknown(self):
        for status, code in (("complete", 0), ("unresolved", 2)):
            with patch.object(cli, "run", return_value={"status": status}), patch("sys.stdout", new=io.StringIO()) as out:
                self.assertEqual(cli.main(["--json", "recover"]), code)
                self.assertEqual(json.loads(out.getvalue())["status"], status)


if __name__ == "__main__":
    unittest.main()
