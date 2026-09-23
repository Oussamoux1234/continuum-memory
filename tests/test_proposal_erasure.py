"""Synthetic proposal erasure/retry regressions for issue #16."""
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from continuum_memory.errors import MemoryError
from continuum_memory.kernel import Kernel
from continuum_memory.security import sign_grant, token_hash
from continuum_memory.storage import Store, load_capability, paths


class ProposalErasureTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="continuum-proposal-erasure-")
        self.home = Path(self.temp.name)
        boot = Store.bootstrap(self.home, [
            {"name": name, "path_hint": "/synthetic/" + name, "providers": ["codex", "claude"]}
            for name in ("alpha", "beta")])
        self.projects = {p["name"]: p for p in boot["projects"]}
        self.project = self.projects["alpha"]["id"]
        self.now = datetime(2027, 1, 1, tzinfo=timezone.utc)
        self.reopen()

    def reopen(self):
        if hasattr(self, "store"):
            self.store.close()
        self.store = Store(self.home)
        self.kernel = Kernel(self.store, now_provider=lambda: self.now,
                             approval_public_key_provider=lambda uid: None, allow_prototype_approval=True)
        self.control = self.store.authenticate(load_capability(paths(self.home)["control"])["token"])
        self.codex = self.agent("alpha", "codex")

    def agent(self, project, provider):
        return self.store.authenticate(load_capability(Path(self.projects[project]["capabilities"][provider]))["token"])

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    @staticmethod
    def delivery(**changes):
        return dict({"subject": "subject-erasure-canary", "claim": "body-erasure-canary",
                     "evidence": "evidence-erasure-canary", "source_handle": "locator-erasure-canary",
                     "disclosure": ["codex"], "idempotency_key": "delivery-erasure-canary"}, **changes)

    def preview(self, operation, **params):
        params.setdefault("project", self.project)
        return self.kernel.admin_preview(self.control, dict(operation=operation, **params))

    def apply(self, challenge, kernel=None, capability=None):
        return (kernel or self.kernel).admin_apply(capability or self.control, {
            "nonce": challenge["nonce"], "preview_digest": challenge["preview_digest"], "preview": challenge["preview"],
            "grant": sign_grant(self.control["token"].encode("ascii"), challenge["nonce"],
                                challenge["operation"], challenge["preview_digest"]),
        })

    def approve(self, operation, **params):
        return self.apply(self.preview(operation, **params))

    def assert_suppressed(self, delivery, capability=None):
        before = list(self.store.connection.iterdump())
        with self.assertRaises(MemoryError) as error:
            self.kernel.propose(capability or self.codex, delivery)
        self.assertEqual(error.exception.code, "delivery_suppressed")
        self.assertNotIn("canary", json.dumps(error.exception.as_dict()))
        self.assertEqual(list(self.store.connection.iterdump()), before)

    def assert_erased(self):
        # Logical erasure across every live table, including FTS and tombstones.
        # This deliberately makes no physical/WAL-overwrite claim.
        self.assertNotIn("erasure-canary", "\n".join(self.store.connection.iterdump()))

    def test_pending_proposal_is_purged_on_retention_and_retry_is_suppressed(self):
        delivery = self.delivery(retention="2027-01-02")
        self.kernel.propose(self.codex, delivery)
        self.now = datetime(2027, 1, 2, tzinfo=timezone.utc)
        inbox = self.kernel.inbox(self.control, {"project": self.project})
        self.assertEqual(inbox["proposals"], [])
        self.assert_erased()
        self.assert_suppressed(delivery)
        self.reopen()
        self.assert_suppressed(delivery)

    def test_owner_forgets_standalone_proposal_with_exact_preview_and_one_shot_grant(self):
        proposed = self.kernel.propose(self.codex, self.delivery())
        challenge = self.preview("forget", target_id=proposed["proposal_id"])
        self.assertEqual(challenge["preview"]["target_kind"], "proposal")
        self.assertEqual(challenge["preview"]["affected_set"]["proposals"], [{"id": proposed["proposal_id"]}])
        result = self.apply(challenge)
        self.assertTrue(result["content_free_receipt"])
        self.assert_erased()
        self.assert_suppressed(self.delivery())
        with self.assertRaises(MemoryError) as error:
            self.apply(challenge)
        self.assertEqual(error.exception.code, "approval_replay")

    def test_rejection_purges_content_and_terminal_retry_survives_reopen(self):
        proposed = self.kernel.propose(self.codex, self.delivery())
        result = self.approve("reject_proposal", proposal_id=proposed["proposal_id"])
        self.assertEqual(result["review_status"], "rejected")
        self.assertTrue(result["content_purged"])
        self.assert_erased()
        self.reopen()
        self.assert_suppressed(self.delivery())
        self.assertEqual(self.kernel.inbox(self.control, {"project": self.project, "status": "rejected"})["proposals"], [])

    def test_accepted_then_forgotten_delivery_cannot_recreate_erased_content(self):
        proposed = self.kernel.propose(self.codex, self.delivery())
        accepted = self.approve("accept_proposal", proposal_id=proposed["proposal_id"])
        recalled = self.kernel.search(self.codex, {"query": "canary"})
        self.kernel.feedback(self.codex, {"recall_id": recalled["recall_id"], "item_id": accepted["assertion_id"],
                                         "label": "wrong", "reason": "feedback-erasure-canary"})
        self.approve("forget", target_id=accepted["assertion_id"])
        self.assert_erased()
        self.reopen()
        self.assert_suppressed(self.delivery())
        with self.assertRaises(MemoryError) as missing:
            self.kernel.get(self.codex, {"recall_id": recalled["recall_id"], "ids": [accepted["assertion_id"]]})
        self.assertEqual(missing.exception.code, "not_found")

    def test_duplicate_reordered_delivery_and_new_key_contract(self):
        delivery = self.delivery()
        first = self.kernel.propose(self.codex, delivery)
        duplicate = self.kernel.propose(self.codex, dict(reversed(list(delivery.items()))))
        self.assertEqual(duplicate["proposal_id"], first["proposal_id"])
        self.assertTrue(duplicate["replayed"])
        with self.assertRaises(MemoryError) as mismatch:
            self.kernel.propose(self.codex, self.delivery(claim="Different live body."))
        self.assertEqual(mismatch.exception.code, "idempotency_conflict")
        self.approve("forget", target_id=first["proposal_id"])
        self.assert_suppressed(self.delivery(claim="Different delayed body."))
        fresh = self.kernel.propose(self.codex, self.delivery(idempotency_key="new-deliberate-intent-0001"))
        self.assertFalse(fresh["replayed"])
        self.assertEqual(fresh["review_status"], "proposed")
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM assertion_versions").fetchone()[0], 0)

    def test_tombstones_are_project_provider_scoped(self):
        first = self.kernel.propose(self.codex, self.delivery())
        self.approve("reject_proposal", proposal_id=first["proposal_id"])
        self.assert_suppressed(self.delivery())
        for capability in (self.agent("alpha", "claude"), self.agent("beta", "codex")):
            result = self.kernel.propose(capability, self.delivery())
            self.assertFalse(result["replayed"])
        self.assert_suppressed(self.delivery())

    def test_forget_preview_stales_when_proposal_is_accepted(self):
        first = self.kernel.propose(self.codex, self.delivery())
        challenge = self.preview("forget", target_id=first["proposal_id"])
        other_store = Store(self.home)
        try:
            other_kernel = Kernel(other_store, now_provider=lambda: self.now,
                                  approval_public_key_provider=lambda uid: None, allow_prototype_approval=True)
            accepted = self.apply(self.preview("accept_proposal", proposal_id=first["proposal_id"]), kernel=other_kernel)
        finally:
            other_store.close()
        before = list(self.store.connection.iterdump())
        with self.assertRaises(MemoryError) as error:
            self.apply(challenge)
        self.assertEqual(error.exception.code, "stale_preview")
        self.assertEqual(list(self.store.connection.iterdump()), before)
        fresh = self.preview("forget", target_id=first["proposal_id"])
        self.assertEqual(fresh["preview"]["thread_id"], accepted["memory_id"])
        self.apply(fresh)
        self.assert_erased()

    def test_expiring_accepted_draft_preserves_canonical_history_until_owner_forget(self):
        proposed = self.kernel.propose(self.codex, self.delivery(retention="2027-01-02"))
        accepted = self.approve("accept_proposal", proposal_id=proposed["proposal_id"])
        self.now = datetime(2027, 1, 3, tzinfo=timezone.utc)
        self.kernel.status(self.codex, {})
        self.assertIsNone(self.store.connection.execute("SELECT id FROM proposals WHERE id=?", (proposed["proposal_id"],)).fetchone())
        history = self.kernel.search(self.codex, {"query": "canary", "temporal_mode": "history"})
        self.assertEqual(history["cards"][0]["version_id"], accepted["assertion_id"])
        self.assertEqual(history["cards"][0]["lifecycle"], "expired")
        # The original proposal ID still resolves through retained acceptance
        # provenance, so owner forget reviews and deletes the canonical thread.
        self.approve("forget", target_id=proposed["proposal_id"])
        self.assert_erased()
        self.assert_suppressed(self.delivery(retention="2027-01-02"))

    def test_agents_cannot_authorize_proposal_erasure_or_review(self):
        proposed = self.kernel.propose(self.codex, self.delivery())
        challenge = self.preview("forget", target_id=proposed["proposal_id"])
        for operation in ("forget", "reject_proposal", "accept_proposal"):
            with self.subTest(operation=operation), self.assertRaises(MemoryError) as error:
                self.kernel.admin_preview(self.codex, {"operation": operation, "project": self.project,
                    "proposal_id": proposed["proposal_id"], "target_id": proposed["proposal_id"]})
            self.assertEqual(error.exception.code, "forbidden")
        with self.assertRaises(MemoryError) as captured_grant:
            self.apply(challenge, capability=self.codex)
        self.assertEqual(captured_grant.exception.code, "forbidden")
        self.assertIsNotNone(self.store.connection.execute("SELECT id FROM proposals").fetchone())

    def test_changing_capability_within_provider_does_not_bypass_suppression(self):
        proposed = self.kernel.propose(self.codex, self.delivery())
        self.approve("reject_proposal", proposal_id=proposed["proposal_id"])
        token = "synthetic-second-capability-token"
        self.store.begin()
        self.store.connection.execute("INSERT INTO capabilities(id,token_hash,project_id,provider,permissions_json,created_at) "
                                      "VALUES ('cap_second_fixture',?,?,'codex','[\"read\",\"propose\"]','2027-01-01')",
                                      (token_hash(token), self.project))
        self.store.commit()
        second = self.store.authenticate(token)
        self.assert_suppressed(self.delivery(), capability=second)

    def test_retry_rechecks_tombstone_after_concurrent_approved_delete(self):
        proposed = self.kernel.propose(self.codex, self.delivery())
        deletion = self.preview("forget", target_id=proposed["proposal_id"])
        other_store = Store(self.home)
        other_kernel = Kernel(other_store, now_provider=lambda: self.now,
                              approval_public_key_provider=lambda uid: None, allow_prototype_approval=True)
        original_begin = self.store.begin

        def delete_before_writer_lock():
            self.apply(deletion, kernel=other_kernel)
            original_begin()

        try:
            with patch.object(self.store, "begin", side_effect=delete_before_writer_lock):
                with self.assertRaises(MemoryError) as caught:
                    self.kernel.propose(self.codex, self.delivery())
            self.assertEqual(caught.exception.code, "delivery_suppressed")
            self.assert_erased()
            self.assertEqual(self.store.verify_audit()["status"], "valid")
        finally:
            other_store.close()

    def test_failed_purge_rolls_back_tombstone_content_and_grant_then_retries(self):
        proposed = self.kernel.propose(self.codex, self.delivery())
        deletion = self.preview("forget", target_id=proposed["proposal_id"])
        before = list(self.store.connection.iterdump())
        self.store.connection.set_authorizer(lambda action, table, *args: sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_DELETE and table == "proposals" else sqlite3.SQLITE_OK)
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                self.apply(deletion)
        finally:
            self.store.connection.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
        self.assertEqual(list(self.store.connection.iterdump()), before)
        self.apply(deletion)
        self.assert_erased()
        self.assert_suppressed(self.delivery())

    def test_dependency_change_stales_forget_and_reject_without_deleting(self):
        proposed = self.kernel.propose(self.codex, self.delivery())
        delete = self.preview("forget", target_id=proposed["proposal_id"])
        reject = self.preview("reject_proposal", proposal_id=proposed["proposal_id"])
        other = Store(self.home)
        try:
            other.begin()
            # A separately committed provenance repair changes a dependent row
            # without changing the proposal's body or status.
            other.connection.execute("UPDATE provenance_activities SET tool_version='repaired' WHERE target_id=?",
                                     (proposed["proposal_id"],))
            other.commit()
        finally:
            other.close()
        before = list(self.store.connection.iterdump())
        for challenge in (delete, reject):
            with self.assertRaises(MemoryError) as caught:
                self.apply(challenge)
            self.assertEqual(caught.exception.code, "stale_preview")
            self.assertEqual(list(self.store.connection.iterdump()), before)
        self.approve("forget", target_id=proposed["proposal_id"])
        self.assert_erased()

    def test_standalone_delete_preserves_other_drafts_and_independent_memory(self):
        first = self.kernel.propose(self.codex, self.delivery())
        second = self.kernel.propose(self.codex, self.delivery(idempotency_key="second-intent-0001"))
        memory = self.approve("remember", subject="subject-erasure-canary", claim="Independently accepted claim.")
        challenge = self.preview("forget", target_id=first["proposal_id"])
        self.assertEqual(challenge["preview"]["target_kind"], "proposal")
        self.apply(challenge)
        self.assert_suppressed(self.delivery())
        self.assertIsNotNone(self.store.connection.execute("SELECT id FROM proposals WHERE id=?", (second["proposal_id"],)).fetchone())
        self.assertIsNotNone(self.store.connection.execute("SELECT id FROM assertion_versions WHERE id=?", (memory["assertion_id"],)).fetchone())

    def test_thread_delete_preserves_evidence_referenced_by_another_memory(self):
        first = self.kernel.propose(self.codex, self.delivery())
        accepted = self.approve("accept_proposal", proposal_id=first["proposal_id"])
        other = self.approve("remember", subject="other subject", claim="Other claim.", evidence="Other evidence.")
        evidence_id = self.store.connection.execute("SELECT evidence_id FROM assertion_versions WHERE id=?", (accepted["assertion_id"],)).fetchone()[0]
        self.store.begin()
        self.store.connection.execute("INSERT INTO evidence_refs VALUES (?,?)", (evidence_id, other["assertion_id"]))
        self.store.commit()
        self.approve("forget", target_id=accepted["assertion_id"])
        self.assert_suppressed(self.delivery())
        self.assertIsNotNone(self.store.connection.execute("SELECT id FROM evidence WHERE id=?", (evidence_id,)).fetchone())
        self.approve("forget", target_id=other["assertion_id"])
        self.assert_erased()


if __name__ == "__main__":
    unittest.main()
