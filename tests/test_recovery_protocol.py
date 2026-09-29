"""Owner-authenticated, content-free durable receipt recovery protocol."""

import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum_memory.client import DaemonClient
from continuum_memory.daemon import RequestHandler
from continuum_memory.errors import MemoryError
from continuum_memory.kernel import Kernel
from continuum_memory.recovery_locator import validate_locator
from continuum_memory.security import canonical_json, now_iso, read_private, replace_private, sign_grant, token_hash
from continuum_memory.storage import Store, paths
from fixtures.harness import EphemeralHarness, private_test_home
from tests import test_proposal_erasure as erasure


class RecoveryProtocolTest(unittest.TestCase):
    def setUp(self):
        self.fx = erasure.ProposalErasureTest()
        self.fx.setUp()
        self.addCleanup(self.fx.tearDown)

    def call(self, method, params, token=None):
        # Exercise production frame validation, authentication and dispatch; a
        # fabricated in-memory capability must not stand in for these checks.
        request = {"id": 1, "method": method, "params": params,
                   "auth": {"token": self.fx.control["token"] if token is None else token}}
        raw = RequestHandler(self.fx.store, self.fx.kernel).handle(canonical_json(request).encode())
        return DaemonClient._response(raw)

    def challenge(self, **changes):
        return self.call("admin_preview", dict(
            {"operation": "remember", "project": self.fx.project,
             "subject": "durable-protocol-canary", "claim": "durable-protocol-canary claim",
             "evidence": "durable-protocol-canary evidence"}, **changes))

    @staticmethod
    def legacy(challenge):
        return {"nonce": challenge["nonce"], "preview_digest": challenge["preview_digest"]}

    def apply(self, challenge, token=None):
        token = self.fx.control["token"] if token is None else token
        return self.call("admin_apply", {
            **self.legacy(challenge), "preview": challenge["preview"],
            "grant": sign_grant(token.encode("ascii"), challenge["nonce"],
                                challenge["operation"], challenge["preview_digest"])}, token)

    def recover(self, challenge, token=None):
        return self.call("admin_recover", challenge["recovery_locator"], token)

    def assert_error(self, code, method, params, token=None):
        with self.assertRaises(MemoryError) as caught:
            self.call(method, params, token)
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn("canary", canonical_json(caught.exception.as_dict()))

    def test_preview_locator_has_exact_independently_computed_binding(self):
        challenge = self.challenge()
        # Independent oracle: do not reuse results._binding, Store.keyed_digest
        # or canonical_json, so field/domain/separator regressions are detected.
        payload = json.dumps([challenge["nonce"], self.fx.control["id"], self.fx.project,
                              challenge["preview_digest"]], ensure_ascii=False,
                             sort_keys=True, separators=(",", ":")).encode("utf-8")
        preview_key = hmac.new(self.fx.store.audit_key, b"admin-result-request-v1\x00" + payload,
                               hashlib.sha256).hexdigest()
        wrapper = json.dumps([1, self.fx.store.vault_id, challenge["nonce"], self.fx.control["id"], preview_key],
                             ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(self.fx.store.audit_key, b"admin-recovery-locator-v1\x00" + wrapper,
                            hashlib.sha256).hexdigest()
        locator = challenge["recovery_locator"]
        self.assertEqual(locator, {"version": 1, "vault_id": self.fx.store.vault_id,
                                   "nonce": challenge["nonce"], "binding": expected})
        self.assertEqual(validate_locator(locator), locator)
        self.assertIsNot(validate_locator(locator), locator)
        self.assertNotIn(challenge["preview_digest"], canonical_json(locator))
        self.assertNotIn("canary", canonical_json(locator))
        self.assertEqual(self.fx.store.connection.execute("SELECT count(*) FROM admin_results").fetchone()[0], 0)
        result = self.apply(challenge)
        self.assert_error("not_found", "admin_recover", dict(locator, binding=preview_key))
        self.assertEqual(self.recover(challenge)["result"]["assertion_id"], result["assertion_id"])

    def test_missing_receipt_is_not_completion_and_both_lookups_preserve_replay_rules(self):
        challenge = self.challenge()
        self.assert_error("not_found", "admin_recover", challenge["recovery_locator"])
        self.assert_error("not_found", "admin_result", self.legacy(challenge))
        result = self.apply(challenge)
        expected = {"receipt_id": challenge["nonce"], "operation": "remember", "committed": True,
                    "result": {key: value for key, value in result.items() if key != "commit"},
                    "audit_anchor": "valid"}
        before = list(self.fx.store.connection.iterdump())
        self.assertEqual(self.recover(challenge), expected)
        self.assertEqual(self.call("admin_result", self.legacy(challenge)), expected)
        with self.assertRaises(MemoryError) as replay:
            self.apply(challenge)
        self.assertEqual(replay.exception.code, "approval_replay")
        self.assertEqual(list(self.fx.store.connection.iterdump()), before)

    def test_descriptor_rejects_extra_missing_fields_and_noncanonical_types_without_content(self):
        challenge = self.challenge()
        locator = challenge["recovery_locator"]
        cases = [None, [], "durable-protocol-canary", 1, True, {},
                 dict(locator, **{"durable-protocol-canary": "ignored"}),
                 dict(locator, preview_digest=challenge["preview_digest"])]
        cases.extend({key: value for key, value in locator.items() if key != omitted} for omitted in locator)
        for version in (True, False, 1.0, "1", 0, 2, None, []):
            cases.append(dict(locator, version=version))
        for field in ("vault_id", "nonce"):
            for value in (None, True, 1, [], "short", "x" * 129, "invalid space", "canary\x00value", "\ud800"):
                cases.append(dict(locator, **{field: value}))
        for binding in (None, True, 64, [], "a" * 63, "a" * 65, "A" * 64, "g" * 64, "é" * 64, "\ud800" * 64):
            cases.append(dict(locator, binding=binding))
        for index, value in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(MemoryError) as caught:
                    validate_locator(value)
                self.assertEqual(caught.exception.as_dict(), {
                    "code": "invalid_request", "message": "The recovery locator is invalid."})
                # Escaped surrogates are valid JSON transport input and must be
                # rejected by the descriptor validator without a Unicode crash.
                request = {"id": 1, "method": "admin_recover", "params": value,
                           "auth": {"token": self.fx.control["token"]}}
                raw = RequestHandler(self.fx.store, self.fx.kernel).handle(json.dumps(request).encode())
                reply = json.loads(raw)
                self.assertEqual(reply["error"]["code"], "invalid_request")
                self.assertNotIn("canary", canonical_json(reply))

    def test_swapped_real_nonce_binding_and_vault_are_not_receipts(self):
        first = self.challenge()
        second = self.challenge(project=self.fx.projects["beta"]["id"])
        first_result = self.apply(first)
        second_result = self.apply(second)
        a, b = first["recovery_locator"], second["recovery_locator"]
        self.assertNotEqual(a["binding"], b["binding"])
        self.assertNotEqual(first_result["assertion_id"], second_result["assertion_id"])
        for locator in (dict(a, nonce=b["nonce"]), dict(a, binding=b["binding"]),
                        dict(a, vault_id="vlt_wrong_vault"), dict(a, nonce="gnt_absent_receipt"),
                        dict(a, binding="0" * 64)):
            self.assert_error("not_found", "admin_recover", locator)
        self.assertEqual(self.recover(first)["result"]["assertion_id"], first_result["assertion_id"])
        self.assertEqual(self.recover(second)["result"]["assertion_id"], second_result["assertion_id"])

    def test_copied_key_and_receipt_cannot_be_retargeted_to_relabelled_vault(self):
        challenge = self.challenge()
        self.apply(challenge)
        expected_receipt = self.recover(challenge)
        with tempfile.TemporaryDirectory(prefix="continuum-relabelled-fixture-") as temporary:
            destination = private_test_home(temporary)
            Store.bootstrap(destination, [{"name": "synthetic", "path_hint": "/fixture", "providers": ["codex"]}])
            cloned = Store(destination)
            try:
                # Actual synthetic DB/key copy, not a mock of the expected
                # binding or capability. Only the copied vault ID is relabeled.
                self.fx.store.connection.backup(cloned.connection)
                cloned.connection.execute("UPDATE metadata SET value=? WHERE key='vault_id'",
                                          ("vlt_relabelled_synthetic_copy",))
            finally:
                cloned.close()
            for name in ("audit_key", "audit_head", "control"):
                replace_private(paths(destination)[name], read_private(paths(self.fx.home)[name]))
            with self.assertRaises(MemoryError) as incomplete:
                Store(destination)
            self.assertEqual(incomplete.exception.code, "initialization_incomplete")
            # Explicit synthetic same-user tampering: initialization records
            # are not a same-UID security boundary. Relabel both records so the
            # original receipt-binding checks below remain independently tested.
            for kind in ("claim", "complete"):
                record = {"version": 1, "kind": kind, "vault_id": "vlt_relabelled_synthetic_copy"}
                replace_private(destination / ("bootstrap." + kind),
                                (canonical_json(record) + "\n").encode())
            copied = Store(destination)
            try:
                handler = RequestHandler(copied, Kernel(copied))
                def recover(method, params):
                    request = {"id": 1, "method": method, "params": params,
                               "auth": {"token": self.fx.control["token"]}}
                    return DaemonClient._response(handler.handle(canonical_json(request).encode()))
                self.assertNotEqual(copied.vault_id, self.fx.store.vault_id)
                self.assertEqual(copied.audit_key, self.fx.store.audit_key)
                # Positive control: receipt, capability and MAC really survived
                # copying. Legacy lookup behavior remains unchanged.
                self.assertEqual(recover("admin_result", self.legacy(challenge)), expected_receipt)
                for locator in (challenge["recovery_locator"],
                                dict(challenge["recovery_locator"], vault_id=copied.vault_id)):
                    with self.assertRaises(MemoryError) as refused:
                        recover("admin_recover", locator)
                    self.assertEqual(refused.exception.code, "not_found")
            finally:
                copied.close()

    def test_locator_requires_original_live_control_authentication_at_request_boundary(self):
        challenge = self.challenge()
        result = self.apply(challenge)
        locator = challenge["recovery_locator"]
        alternate_token = "synthetic_second_owner_capability_only"
        self.fx.store.connection.execute(
            "INSERT INTO capabilities(id,token_hash,project_id,provider,permissions_json,created_at) "
            "VALUES (?,?,NULL,'user_control','[\"control\",\"read\"]',?)",
            ("cap_second_synthetic_owner", token_hash(alternate_token), now_iso()))
        # Prove the other token is real, current control authority, not merely an
        # invalid credential that would hide a missing receipt-capability check.
        self.assertEqual(self.call("approval_info", {}, alternate_token)["vault_id"], self.fx.store.vault_id)
        self.assert_error("not_found", "admin_recover", locator, alternate_token)
        self.assert_error("forbidden", "admin_recover", locator, self.fx.codex["token"])
        self.assert_error("unauthorized", "admin_recover", locator, locator["binding"])
        self.assert_error("unauthorized", "admin_recover", locator, "")
        self.assertEqual(self.recover(challenge)["result"]["assertion_id"], result["assertion_id"])
        self.fx.store.connection.execute("UPDATE capabilities SET revoked_at=? WHERE id=?",
                                         (now_iso(), self.fx.control["id"]))
        self.assert_error("unauthorized", "admin_recover", locator)

    def test_receipt_tampering_cannot_be_reported_as_completed(self):
        challenge = self.challenge()
        self.apply(challenge)
        row = dict(self.fx.store.connection.execute(
            "SELECT * FROM admin_results WHERE nonce=?", (challenge["nonce"],)).fetchone())
        changes = {"result_json": "{}", "receipt_mac": "0" * 64, "operation": "forget",
                   "created_at": "1900-01-01T00:00:00Z", "project_id": self.fx.projects["beta"]["id"]}
        for field, value in changes.items():
            with self.subTest(field=field):
                # Field names come only from the fixed test matrix above.
                self.fx.store.connection.execute("UPDATE admin_results SET " + field + "=? WHERE nonce=?",
                                                 (value, challenge["nonce"]))
                try:
                    self.assert_error("integrity_error", "admin_recover", challenge["recovery_locator"])
                finally:
                    self.fx.store.connection.execute("UPDATE admin_results SET " + field + "=? WHERE nonce=?",
                                                     (row[field], challenge["nonce"]))
        self.assertTrue(self.recover(challenge)["committed"])

    def test_recovery_survives_challenge_cleanup_forget_and_reopen_without_raw_digest(self):
        challenge = self.challenge()
        result = self.apply(challenge)
        original = self.recover(challenge)
        deletion = self.fx.preview("forget", target_id=result["assertion_id"])
        self.assertIsNone(self.fx.store.connection.execute(
            "SELECT nonce FROM admin_challenges WHERE nonce=?", (challenge["nonce"],)).fetchone())
        self.apply(deletion)
        self.fx.reopen()
        # Receipt metadata is immutable even after its historical target has
        # been forgotten; recovering it must never restore memory content.
        self.assertEqual(self.recover(challenge), original)
        self.assertEqual(self.call("admin_result", self.legacy(challenge)), original)
        self.assertEqual(self.fx.store.connection.execute("SELECT count(*) FROM assertion_versions").fetchone()[0], 0)
        dump = "\n".join(self.fx.store.connection.iterdump())
        self.assertNotIn("durable-protocol-canary", dump)
        self.assertNotIn(challenge["preview_digest"], dump)

    def test_recovery_reports_receipt_and_degraded_anchor_without_reapplying(self):
        challenge = self.challenge()
        with patch.object(self.fx.store, "sync_audit_head", side_effect=OSError("synthetic anchor failure")):
            result = self.apply(challenge)
        self.assertEqual(result["commit"]["audit_anchor"], "degraded")
        receipt = self.recover(challenge)
        self.assertEqual(receipt, self.call("admin_result", self.legacy(challenge)))
        self.assertEqual(receipt["audit_anchor"], "external_anchor_stale")
        self.assertEqual(receipt["result"]["assertion_id"], result["assertion_id"])
        self.call("audit_reconcile", {})
        self.assertEqual(self.recover(challenge)["audit_anchor"], "valid")
        self.assertEqual(self.fx.store.connection.execute("SELECT count(*) FROM assertion_versions").fetchone()[0], 1)


class RecoveryProtocolTransportTest(unittest.TestCase):
    def test_real_daemon_client_recovers_identical_receipt_and_refuses_agent(self):
        with EphemeralHarness() as harness:
            operation = harness.approve({"operation": "remember", "project": harness.projects["alpha"]["id"],
                                         "subject": "recovery fixture", "claim": "Synthetic test only."})
            challenge = operation["challenge"]
            locator = challenge["recovery_locator"]
            receipt = harness.control.call("admin_recover", locator)
            self.assertEqual(receipt, harness.control.call("admin_result", {
                "nonce": challenge["nonce"], "preview_digest": challenge["preview_digest"]}))
            self.assertTrue(receipt["committed"])
            self.assertEqual(receipt["result"]["assertion_id"], operation["result"]["assertion_id"])
            agent = DaemonClient(harness.data_dir, Path(harness.projects["alpha"]["capabilities"]["codex"]))
            with self.assertRaises(MemoryError) as denied:
                agent.call("admin_recover", locator)
            self.assertEqual(denied.exception.code, "forbidden")


if __name__ == "__main__":
    unittest.main()
