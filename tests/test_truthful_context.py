"""Issue #17: acceptance, recorded verification and declared validity are distinct."""

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from continuum_memory.errors import MemoryError
from continuum_memory.security import canonical_json
from tests import test_snapshot_forget as fixture


class TruthfulContextTest(unittest.TestCase):
    setUp = fixture.SnapshotForgetTest.setUp
    tearDown = fixture.SnapshotForgetTest.tearDown
    apply = fixture.SnapshotForgetTest.apply
    approve = fixture.SnapshotForgetTest.approve
    remember = fixture.SnapshotForgetTest.remember
    context = fixture.SnapshotForgetTest.context

    def test_future_accepted_assertion_is_not_verified_current(self):
        self.remember(valid_precision="interval", valid_from="2028-01-01", valid_to="2028-02-01")
        result = self.context()
        self.assertNotIn("verified_current", result)
        self.assertEqual(result["response_version"], 3)
        self.assertEqual(result["temporal_mode"], "current")
        card = result["accepted_claims"][0]
        self.assertEqual(card["admission"], "accepted")
        self.assertEqual(card["epistemic"], "asserted")
        self.assertEqual(card["applicability"], {
            "status": "not_yet_valid", "as_of": "2027-01-01T00:00:00.000000Z"})
        self.assertTrue(card["requires_current_verification"])

    def test_default_selection_keeps_unknown_and_out_of_interval_claims(self):
        cases = [
            ("unknown", {}, "unknown"),
            ("future", {"valid_precision": "open", "valid_from": "2028-01-01"}, "not_yet_valid"),
            ("past", {"valid_precision": "open", "valid_to": "2026-12-31"}, "no_longer_valid"),
            ("present", {"valid_precision": "interval", "valid_from": "2026-01-01",
                         "valid_to": "2028-01-01"}, "within_declared_interval"),
        ]
        for name, validity, expected in cases:
            with self.subTest(name=name):
                saved = self.remember(subject=name, **validity)
                card = self.context(saved["assertion_id"])["accepted_claims"][0]
                self.assertEqual(card["applicability"]["status"], expected)
                self.assertEqual(card["epistemic"], "asserted")
                if expected == "unknown":
                    self.assertIsNone(card["applicability"]["as_of"])

    def test_declared_bounds_are_inclusive_and_unknown_is_not_invented(self):
        cases = [
            ("interval-start", {"valid_precision": "interval", "valid_from": "2027-01-01",
                                "valid_to": "2027-01-02"}),
            ("interval-end", {"valid_precision": "interval", "valid_from": "2026-12-01",
                              "valid_to": "2027-01-01"}),
            ("instant", {"valid_precision": "instant", "valid_from": "2027-01-01"}),
            ("open-start", {"valid_precision": "open", "valid_from": "2027-01-01"}),
            ("open-end", {"valid_precision": "open", "valid_to": "2027-01-01"}),
        ]
        for name, validity in cases:
            with self.subTest(name=name):
                saved = self.remember(subject=name, **validity)
                card = self.context(saved["assertion_id"])["accepted_claims"][0]
                self.assertEqual(card["applicability"]["status"], "within_declared_interval")
        unknown = self.remember(subject="uncertain")
        self.assertEqual(self.context(unknown["assertion_id"], as_of_valid="2027-01-01")["status"], "no_matches")

    def test_history_and_recorded_snapshot_do_not_claim_current_truth(self):
        first = self.remember()
        point = self.context()["projection_watermark"]
        second = self.approve(operation="correct", target_id=first["assertion_id"], claim="Engine uses Postgres.")
        history = self.context(temporal_mode="history")
        self.assertEqual(history["temporal_mode"], "history")
        self.assertEqual({c["version_id"] for c in history["accepted_claims"]},
                         {first["assertion_id"], second["assertion_id"]})
        self.assertEqual({c["lifecycle"] for c in history["accepted_claims"]}, {"active", "superseded"})
        past = self.context(as_of_recorded=point)
        self.assertEqual([c["version_id"] for c in past["accepted_claims"]], [first["assertion_id"]])
        self.assertTrue(all(c["requires_current_verification"] for c in history["accepted_claims"]))

    def test_recorded_verified_observation_is_not_fresh_or_applicable_by_default(self):
        saved = self.remember(valid_precision="interval", valid_from="2025-01-01", valid_to="2025-02-01")
        # Fixture-only historical verification; no public verification writer exists.
        self.store.connection.execute("UPDATE assertion_versions SET epistemic='verified' WHERE id=?",
                                      (saved["assertion_id"],))
        self.store.connection.execute(
            "INSERT INTO attestations(id,assertion_id,principal,role,method,attested_at) VALUES (?,?,?,'validator',?,?)",
            ("att_fixture_validator", saved["assertion_id"], "fixture:independent-observer",
             "synthetic_check", "2026-12-01T00:00:00.000000Z"))
        card = self.context()["accepted_claims"][0]
        self.assertEqual(card["epistemic"], "verified")
        self.assertEqual(card["applicability"]["status"], "no_longer_valid")
        self.assertTrue(card["requires_current_verification"])
        self.assertFalse(self.context()["memory_contract"]["may_authorize_actions"])

    def test_retention_expired_history_is_not_current_but_validity_is_separate(self):
        saved = self.remember(retention="2027-01-02", valid_precision="open", valid_from="2026-01-01")
        self.now = datetime(2027, 1, 3, tzinfo=timezone.utc)
        self.assertEqual(self.context()["status"], "no_matches")
        card = self.context(temporal_mode="history")["accepted_claims"][0]
        self.assertEqual(card["version_id"], saved["assertion_id"])
        self.assertEqual(card["lifecycle"], "expired")
        self.assertEqual(card["applicability"]["status"], "within_declared_interval")

    def test_receipt_get_reassesses_default_clock_but_preserves_explicit_valid_instant(self):
        saved = self.remember(valid_precision="interval", valid_from="2028-01-01", valid_to="2028-01-31")
        default = self.kernel.search(self.codex, {"query": "engine"})
        explicit = self.kernel.search(self.codex, {"query": "engine", "as_of_valid": "2028-01-15"})
        self.now = datetime(2029, 1, 1, tzinfo=timezone.utc)
        for recall, expected in ((default, "no_longer_valid"), (explicit, "within_declared_interval")):
            with self.subTest(expected=expected):
                card = self.kernel.get(self.codex, {"recall_id": recall["recall_id"],
                                                   "ids": [saved["assertion_id"]]})["records"][0]
                self.assertEqual(card["applicability"]["status"], expected)
        self.assertEqual(explicit["cards"][0]["applicability"]["as_of"], "2028-01-15T00:00:00.000000Z")

    def test_one_applicability_instant_is_shared_across_cards_conflicts_and_get(self):
        first = self.remember(valid_precision="open", valid_from="2026-01-01")
        second = self.remember(claim="Engine uses Postgres.", valid_precision="open", valid_from="2026-01-01")
        third = self.remember(subject="engine separate", valid_precision="open", valid_from="2026-01-01")
        tick = [0]

        def advancing_time():
            tick[0] += 1
            return datetime(2027, 1, 1, microsecond=tick[0], tzinfo=timezone.utc)

        with patch.object(self.kernel, "_now_provider", advancing_time):
            context = self.context()
            cards = context["accepted_claims"] + context["open_conflicts"][0]["members"]
            self.assertEqual(len({c["applicability"]["as_of"] for c in cards}), 1)
            records = self.kernel.get(self.codex, {"recall_id": context["recall_id"],
                "ids": [first["assertion_id"], second["assertion_id"], third["assertion_id"]]})["records"]
            self.assertEqual(len({c["applicability"]["as_of"] for c in records}), 1)

    def test_search_limit_is_honest_and_overflow_is_not_authorized_by_receipt(self):
        saved = [self.remember(subject="engine %d" % i) for i in range(3)]
        exact_limit = self.kernel.search(self.codex, {"query": "engine", "limit": 3})
        self.assertEqual(exact_limit["completeness"], "complete")
        limited = self.kernel.search(self.codex, {"query": "engine", "limit": 2})
        self.assertEqual(limited["completeness"], "partial")
        self.assertEqual(len(limited["cards"]), 2)
        omitted = set(s["assertion_id"] for s in saved) - {c["version_id"] for c in limited["cards"]}
        with self.assertRaises(MemoryError) as caught:
            self.kernel.get(self.codex, {"recall_id": limited["recall_id"], "ids": list(omitted)})
        self.assertEqual(caught.exception.code, "not_found")
        exact_id = self.kernel.search(self.codex, {"query": saved[0]["assertion_id"], "limit": 1})
        self.assertEqual(exact_id["completeness"], "complete")

    def test_hidden_overflow_does_not_make_visible_search_partial(self):
        self.remember(disclosure=["codex"])
        before = self.kernel.search(self.codex, {"query": "engine", "limit": 1})
        for i in range(3):
            self.remember(subject="engine hidden %d" % i, disclosure=["claude"])
        after = self.kernel.search(self.codex, {"query": "engine", "limit": 1})
        before.pop("recall_id")
        after.pop("recall_id")
        self.assertEqual(before, after)
        self.assertEqual(after["completeness"], "complete")

    def test_overflow_only_conflict_does_not_expand_or_enter_receipt(self):
        omitted = self.remember(subject="engine omitted")
        self.remember(subject="engine omitted", claim="Engine uses Postgres.")
        for i in range(2):
            self.remember(subject="engine selected %d" % i)
        with patch("continuum_memory.kernel.MAX_RESULTS", 2):
            result = self.context()
        self.assertEqual(result["completeness"], "partial")
        self.assertEqual(result["open_conflicts"], [])
        self.assertNotIn(omitted["assertion_id"], canonical_json(result))
        with self.assertRaises(MemoryError):
            self.kernel.get(self.codex, {"recall_id": result["recall_id"], "ids": [omitted["assertion_id"]]})

    def test_stored_epistemic_labels_are_not_promoted_by_acceptance(self):
        saved = self.remember()
        for label in ("asserted", "verified", "disputed", "refuted"):
            with self.subTest(label=label):
                self.store.connection.execute("UPDATE assertion_versions SET epistemic=? WHERE id=?",
                                              (label, saved["assertion_id"]))
                card = self.context()["accepted_claims"][0]
                self.assertEqual(card["admission"], "accepted")
                self.assertEqual(card["epistemic"], label)
                self.assertTrue(card["requires_current_verification"])

    def test_context_result_limit_and_byte_budget_are_both_partial(self):
        for i in range(3):
            self.remember(subject="engine %d" % i)
        with patch("continuum_memory.kernel.MAX_RESULTS", 2):
            result = self.context()
            self.assertEqual(result["completeness"], "partial")
            self.assertEqual(len(result["accepted_claims"]), 2)
            # Pagination must not produce a zero-progress continuation.
            with self.assertRaises(MemoryError) as caught:
                self.kernel.context(self.codex, {"query": "engine", "max_tokens": 128, "max_bytes": 512})
            self.assertEqual(caught.exception.code, "budget_too_small")
        with self.assertRaises(MemoryError) as caught:
            self.kernel.context(self.codex, {"query": "engine", "max_tokens": 64})
        self.assertEqual(caught.exception.code, "budget_too_small")

    def test_response_schema_describes_new_contract_and_conflict_cards(self):
        schema = json.loads((Path(__file__).resolve().parents[1] / "schemas/context-response.schema.json").read_text())
        self.assertEqual(schema["properties"]["response_version"], {"const": 3})
        self.assertNotIn("verified_current", schema["properties"])
        self.assertFalse(schema["additionalProperties"])
        self.remember()
        self.remember(claim="Engine uses Postgres.")
        result = self.context()
        self.assertTrue(set(schema["required"]).issubset(result))
        self.assertTrue(set(result).issubset(schema["properties"]))
        card_schema = schema["$defs"]["card"]
        self.assertTrue(set(card_schema["required"]).issubset(result["open_conflicts"][0]["members"][0]))


if __name__ == "__main__":
    unittest.main()
