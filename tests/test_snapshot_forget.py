"""Regressions for independent-review F1–F3 and equal-body conflict F6.

Synthetic data and the explicit test-only approval seam; no real agent profiles.
"""
import copy
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from continuum_memory.errors import MemoryError
from continuum_memory.kernel import Kernel
from continuum_memory.security import sign_grant
from continuum_memory.storage import Store, load_capability, paths


class SnapshotForgetTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="continuum-snapshot-")
        self.home = Path(self.temp.name)
        boot = Store.bootstrap(self.home, [
            {"name": name, "path_hint": "/synthetic/" + name, "providers": ["codex", "claude"]}
            for name in ("alpha", "beta")
        ])
        self.projects = {p["name"]: p for p in boot["projects"]}
        self.project = self.projects["alpha"]["id"]
        self.store = Store(self.home)
        self.now = datetime(2027, 1, 1, tzinfo=timezone.utc)
        self.kernel = Kernel(self.store, now_provider=lambda: self.now,
                             approval_public_key_provider=lambda uid: None,
                             allow_prototype_approval=True)
        self.control = self.store.authenticate(load_capability(paths(self.home)["control"])["token"])
        self.codex = self.store.authenticate(load_capability(
            Path(self.projects["alpha"]["capabilities"]["codex"]))["token"])

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def apply(self, challenge):
        return self.kernel.admin_apply(self.control, {
            "nonce": challenge["nonce"], "preview_digest": challenge["preview_digest"],
            "preview": challenge["preview"],
            "grant": sign_grant(self.control["token"].encode("ascii"), challenge["nonce"],
                                challenge["operation"], challenge["preview_digest"]),
        })

    def approve(self, **params):
        params.setdefault("project", self.project)
        return self.apply(self.kernel.admin_preview(self.control, params))

    def remember(self, subject="engine", claim="Engine uses SQLite.", **params):
        return self.approve(operation="remember", subject=subject, claim=claim,
                            evidence="Synthetic evidence", **params)

    def context(self, query="engine", **params):
        return self.kernel.context(self.codex, dict(query=query, max_tokens=2048, **params))

    def preview_forget(self, target):
        return self.kernel.admin_preview(self.control, {
            "operation": "forget", "project": self.project, "target_id": target})

    def test_past_snapshot_excludes_later_conflict_and_retirement_metadata(self):
        first = self.remember()
        before = self.kernel.search(self.codex, {"query": "engine"})
        point = before["cards"][0]["recorded_interval"]["from_seq"]
        second = self.remember(claim="Engine uses Postgres.")
        self.approve(operation="correct", target_id=first["assertion_id"], claim="Engine uses MySQL.")
        past = self.context(as_of_recorded=point)
        self.assertEqual(past["open_conflicts"], [])
        self.assertEqual([c["version_id"] for c in past["accepted_claims"]], [first["assertion_id"]])
        card = past["accepted_claims"][0]
        self.assertEqual(card["lifecycle"], "active")
        self.assertIsNone(card["recorded_interval"]["to_seq"])
        self.assertIsNone(card["recorded_interval"]["retired_at"])
        got = self.kernel.get(self.codex, {"recall_id": past["recall_id"], "ids": [first["assertion_id"]]})
        self.assertIsNone(got["records"][0]["conflict_id"])
        self.assertEqual(got["records"][0]["lifecycle"], "active")
        self.assertNotIn(second["assertion_id"], str(past))

    def test_conflict_history_survives_correction_and_equal_body_resolution(self):
        first = self.remember()
        second = self.remember(claim="Engine uses Postgres.")
        before = self.context()
        point = before["projection_watermark"]
        corrected = self.approve(operation="correct", target_id=second["assertion_id"],
                                 claim="Engine uses SQLite.")
        after = self.context()
        self.assertEqual(after["open_conflicts"], [])
        self.assertEqual(len(after["accepted_claims"]), 2)
        past = self.context(as_of_recorded=point)
        members = past["open_conflicts"][0]["members"]
        self.assertEqual({c["version_id"] for c in members}, {first["assertion_id"], second["assertion_id"]})
        self.assertNotIn(corrected["assertion_id"], str(past))
        self.assertEqual(past["open_conflicts"], before["open_conflicts"])

    def test_expiry_resolves_current_conflict_but_preserves_past_snapshot(self):
        self.remember()
        self.remember(claim="Engine uses Postgres.", retention="2027-01-02")
        before = self.context()
        self.now = datetime(2027, 1, 3, tzinfo=timezone.utc)
        self.assertEqual(self.context()["open_conflicts"], [])
        past = self.context(as_of_recorded=before["projection_watermark"])
        self.assertEqual(past["open_conflicts"], before["open_conflicts"])

    def test_valid_time_nonoverlap_and_combined_snapshot(self):
        first = self.remember(valid_precision="interval", valid_from="2025-01-01", valid_to="2025-02-01")
        point = self.context()["projection_watermark"]
        self.remember(claim="Engine uses Postgres.", valid_precision="interval",
                      valid_from="2027-01-01", valid_to="2027-02-01")
        self.assertEqual(self.context()["open_conflicts"], [])
        past = self.context(as_of_recorded=point, as_of_valid="2025-01-15")
        self.assertEqual(past["open_conflicts"], [])
        self.assertEqual([c["version_id"] for c in past["accepted_claims"]], [first["assertion_id"]])
        self.assertEqual(self.context(as_of_valid="2026-01-01")["status"], "no_matches")

    def test_history_does_not_conflict_noncoexistent_corrections(self):
        first = self.remember()
        self.approve(operation="correct", target_id=first["assertion_id"], claim="Engine uses Postgres.")
        history = self.context(temporal_mode="history")
        self.assertEqual(history["open_conflicts"], [])
        self.assertEqual(len(history["accepted_claims"]), 2)

    @staticmethod
    def normalized(value):
        value = copy.deepcopy(value)
        value.pop("recall_id", None)
        return value

    def observable(self):
        search = self.kernel.search(self.codex, {"query": "apple banana engine"})
        return [self.normalized(search), self.normalized(self.context("apple banana engine")),
                self.kernel.status(self.codex, {}),
                self.kernel.get(self.codex, {"recall_id": search["recall_id"],
                                            "ids": [search["cards"][0]["version_id"]]})]

    def test_hidden_mutations_do_not_change_content_order_conflicts_or_metadata(self):
        self.remember("A", "apple apple apple", disclosure=["codex"])
        self.remember("B", "banana banana banana", disclosure=["codex"])
        self.remember(disclosure=["codex"])
        before = self.observable()
        for project, disclosure in ((self.projects["beta"]["id"], ["*"]),
                                    (self.project, ["claude"])):
            with self.subTest(project=project, disclosure=disclosure):
                for n in range(15):
                    self.remember("hidden %s %d" % (project, n), "banana", project=project,
                                  disclosure=disclosure, retention="2027-01-02")
                hidden = self.remember(claim="Engine uses hidden backend.", project=project,
                                       disclosure=disclosure)
                self.assertEqual(self.observable(), before)
                revised = self.approve(operation="correct", project=project,
                                       target_id=hidden["assertion_id"], claim="Engine uses secret backend.")
                self.assertEqual(self.observable(), before)
                # Forget is thread-wide. A shared-subject forget also changes
                # visible state, so use a wholly hidden thread for this mutation.
                separate = self.remember("hidden deletion", "Only hidden state.", project=project, disclosure=disclosure)
                self.approve(operation="forget", project=project, target_id=separate["assertion_id"])
                self.assertEqual(self.observable(), before)
        self.now = datetime(2027, 1, 3, tzinfo=timezone.utc)
        self.assertEqual(self.observable(), before)

    def test_provider_timeline_has_no_global_gaps_and_owner_sees_disputes(self):
        self.remember(disclosure=["codex"])
        self.remember(claim="Engine uses secret backend.", disclosure=["claude"])
        visible = self.remember("second", "Another visible assertion.", disclosure=["codex"])
        searched = self.kernel.search(self.codex, {"query": visible["assertion_id"]})
        self.assertEqual(searched["projection_watermark"], 2)
        self.assertEqual(searched["cards"][0]["recorded_interval"]["from_seq"], 2)
        owner = self.kernel.context(self.control, {"project": self.project, "query": "engine", "max_tokens": 2048})
        self.assertEqual(len(owner["open_conflicts"][0]["members"]), 2)

    def test_hidden_proposal_review_does_not_advance_visible_timeline(self):
        self.remember(disclosure=["codex"])
        before = self.observable()
        claude = self.store.authenticate(load_capability(
            Path(self.projects["alpha"]["capabilities"]["claude"]))["token"])
        proposal = self.kernel.propose(claude, {"subject": "hidden proposal", "claim": "Hidden draft.",
            "evidence": "Synthetic", "source_handle": "fixture:hidden", "disclosure": ["claude"],
            "idempotency_key": "hidden-proposal-0001"})
        self.assertEqual(self.observable(), before)
        self.approve(operation="reject_proposal", proposal_id=proposal["proposal_id"])
        self.assertEqual(self.observable(), before)

    def test_forget_and_reopen_do_not_renumber_surviving_audience_snapshots(self):
        first = self.remember()
        second = self.remember("second", "Second visible claim.")
        before = self.kernel.search(self.codex, {"query": second["assertion_id"]})
        point = before["cards"][0]["recorded_interval"]["from_seq"]
        self.apply(self.preview_forget(first["assertion_id"]))
        self.store.close()
        self.store = Store(self.home)
        self.kernel = Kernel(self.store, now_provider=lambda: self.now, approval_public_key_provider=lambda uid: None)
        after = self.kernel.search(self.codex, {"query": second["assertion_id"]})
        self.assertEqual(after["cards"], before["cards"])
        self.assertEqual(after["projection_watermark"], before["projection_watermark"] + 1)
        past = self.context("second", as_of_recorded=point)
        self.assertEqual(past["accepted_claims"][0]["version_id"], second["assertion_id"])

    def test_forget_rejects_added_version_without_deleting_anything(self):
        first = self.remember()
        challenge = self.preview_forget(first["assertion_id"])
        self.approve(operation="correct", target_id=first["assertion_id"], claim="Engine uses Postgres.")
        database_before = list(self.store.connection.iterdump())
        with self.assertRaises(MemoryError) as caught:
            self.apply(challenge)
        self.assertEqual(caught.exception.code, "stale_preview")
        self.assertEqual(list(self.store.connection.iterdump()), database_before)
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM assertion_versions").fetchone()[0], 2)
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM deletion_receipts").fetchone()[0], 0)
        fresh = self.preview_forget(first["assertion_id"])
        self.assertEqual(fresh["preview"]["version_count"], 2)
        self.apply(fresh)
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM assertion_versions").fetchone()[0], 0)
        with self.assertRaises(MemoryError) as replay:
            self.apply(fresh)
        self.assertEqual(replay.exception.code, "approval_replay")

    def test_forget_rechecks_dependents_and_does_not_stale_on_unrelated_writes(self):
        first = self.remember()
        recall = self.kernel.search(self.codex, {"query": "engine"})
        for mutation in ("feedback", "recall", "proposal", "retirement"):
            with self.subTest(mutation=mutation):
                challenge = self.preview_forget(first["assertion_id"])
                if mutation == "feedback":
                    self.kernel.feedback(self.codex, {"recall_id": recall["recall_id"],
                        "item_id": first["assertion_id"], "label": "wrong", "reason": "Synthetic feedback"})
                elif mutation == "recall":
                    self.kernel.search(self.codex, {"query": "engine"})
                elif mutation == "proposal":
                    self.kernel.propose(self.codex, {"subject": "engine", "claim": "Proposed engine change.",
                        "evidence": "Synthetic", "source_handle": "fixture:proposal", "disclosure": ["codex"],
                        "idempotency_key": "stale-proposal-0001"})
                else:
                    self.approve(operation="correct", target_id=first["assertion_id"], claim="Engine uses Postgres.")
                with self.assertRaises(MemoryError) as caught:
                    self.apply(challenge)
                self.assertEqual(caught.exception.code, "stale_preview")
                self.assertEqual(self.store.connection.execute("SELECT count(*) FROM deletion_receipts").fetchone()[0], 0)
        fresh = self.preview_forget(first["assertion_id"])
        self.remember("unrelated", "Unrelated visible state.")
        self.apply(fresh)
        self.assertEqual(self.kernel.search(self.codex, {"query": "unrelated"})["status"], "ok")

    def test_forget_detects_new_shared_evidence_reference_from_another_connection(self):
        first = self.remember()
        other = self.remember("other", "Other evidence owner.")
        challenge = self.preview_forget(first["assertion_id"])
        evidence_id = challenge["preview"]["affected_set"]["owned_evidence"][0]["id"]
        second_store = Store(self.home)
        try:
            second_store.begin()
            second_store.connection.execute("INSERT INTO evidence_refs VALUES (?,?)", (evidence_id, other["assertion_id"]))
            second_store.commit()
        finally:
            second_store.close()
        database_before = list(self.store.connection.iterdump())
        with self.assertRaises(MemoryError) as caught:
            self.apply(challenge)
        self.assertEqual(caught.exception.code, "stale_preview")
        self.assertEqual(list(self.store.connection.iterdump()), database_before)
        fresh = self.preview_forget(first["assertion_id"])
        self.assertEqual(fresh["preview"]["affected_set"]["owned_evidence"], [])
        self.assertEqual(fresh["preview"]["affected_set"]["retained_evidence_precondition"], [{"id": evidence_id}])
        self.apply(fresh)
        self.assertIsNotNone(self.store.connection.execute("SELECT id FROM evidence WHERE id=?", (evidence_id,)).fetchone())
        self.apply(self.preview_forget(other["assertion_id"]))
        self.assertIsNone(self.store.connection.execute("SELECT id FROM evidence WHERE id=?", (evidence_id,)).fetchone())

    def test_valid_boundaries_and_hidden_provenance_references(self):
        hidden = self.remember(disclosure=["claude"], valid_precision="interval",
                               valid_from="2027-01-01", valid_to="2027-01-02")
        visible = self.approve(operation="correct", target_id=hidden["assertion_id"],
                               claim="Engine uses visible backend.", disclosure=["codex"])
        search = self.kernel.search(self.codex, {"query": "engine", "as_of_valid": "2027-01-02"})
        self.assertEqual(len(search["cards"]), 1)
        self.assertEqual(search["cards"][0]["recorded_interval"]["from_seq"], 1)
        record = self.kernel.get(self.codex, {"recall_id": search["recall_id"], "ids": [visible["assertion_id"]]})
        self.assertNotIn(hidden["assertion_id"], str(record))
        self.assertEqual(self.context(as_of_valid="2027-01-02T00:00:00.000001Z")["status"], "no_matches")


if __name__ == "__main__":
    unittest.main()
