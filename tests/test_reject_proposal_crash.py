"""Real process death across one approved proposal rejection.

Synthetic plaintext SQLite evidence only, not OS-backed approval, encryption,
native Windows, power loss or physical erasure. A schema-valid synthetic legacy review attached
to the pending proposal exercises the real review FK cascade; normal proposal
creation does not create that review. Unrelated shared evidence must survive.
"""

import json
import os
import sys
import unittest
from pathlib import Path

from continuum_memory.errors import MemoryError
from continuum_memory.security import canonical_json, read_private
from continuum_memory.storage import paths
from tests.admin_crash_support import AdminCrashFixture, apply_child, snapshot


CANARY = "rejectdraftonlycanary"
SHARED_EVIDENCE = "keeper shared evidence independently retained"
LEGACY_REVIEW = "rvw_rejection_legacy_fixture"
BOUNDARIES = [
    "write:admin_challenges", "write:sequence", "write:proposal_tombstones",
    "write:provenance_activities", "write:proposals", "write:audit_events",
    "write:admin_results", "before_commit_1", "after_commit_1",
    "before_anchor_publish", "after_anchor_publish", "before_commit_2", "after_commit_2",
]


def rejection_child(home, crash_after, challenge):
    def unexpected_id(prefix):
        raise AssertionError("Rejection must not allocate a new fixture identifier")

    apply_child(home, crash_after, challenge, unexpected_id, [])


@unittest.skipIf(os.name == "nt", "POSIX fixture; native Windows rejection acceptance is separate")
class ProposalRejectionProcessCrashTest(AdminCrashFixture, unittest.TestCase):
    child_module = "tests.test_reject_proposal_crash"

    def setUp(self):
        self.setup_crash_fixture("continuum-rejection-crash-")
        self.agents = {provider: self.fx.agent("alpha", provider) for provider in ("codex", "claude")}

    def seed(self):
        self.delivery = self.fx.delivery(
            subject=CANARY + " subject", claim=CANARY + " rejected claim", evidence=SHARED_EVIDENCE,
            source_handle="fixture:" + CANARY, idempotency_key=CANARY + "-delivery",
            disclosure=["codex", "claude"])
        self.proposal = self.fx.kernel.propose(self.fx.codex, self.delivery)["proposal_id"]
        kept_proposal = self.fx.kernel.propose(self.fx.codex, self.fx.delivery(
            subject="keeperalpha decision", claim="keeperalpha accepted claim", evidence=SHARED_EVIDENCE,
            source_handle="fixture:keeper", idempotency_key="keeper-accepted-delivery",
            disclosure=["codex", "claude"]))["proposal_id"]
        self.kept = self.fx.approve("accept_proposal", proposal_id=kept_proposal)
        self.other_proposal = self.fx.kernel.propose(self.fx.codex, self.fx.delivery(
            subject="unrelated draft", claim="unrelated pending claim", evidence=SHARED_EVIDENCE,
            source_handle="fixture:pending", idempotency_key="keeper-pending-delivery"))["proposal_id"]
        self.beta = self.fx.approve("remember", project=self.fx.projects["beta"]["id"],
            subject="keeperbeta decision", claim="keeperbeta accepted claim", evidence=SHARED_EVIDENCE,
            disclosure=["codex", "claude"])
        self.recalls = {}
        for provider, capability in self.agents.items():
            recall = self.fx.kernel.search(capability, {"query": "keeperalpha"})
            self.assertEqual([card["version_id"] for card in recall["cards"]], [self.kept["assertion_id"]])
            self.recalls[provider] = recall["recall_id"]
            self.fx.kernel.feedback(capability, {"recall_id": recall["recall_id"],
                "item_id": self.kept["assertion_id"], "label": "helpful", "reason": "keeper feedback"})

        db = self.fx.store.connection
        # Explicit schema-valid legacy/import dependency, not a normal pending
        # proposal history or an assertion that a human reviewed this fixture.
        self.fx.store.begin()
        db.execute("INSERT INTO reviews(id,proposal_id,decision,actor,preview_digest,reviewed_at) "
                   "VALUES (?,?,'rejected','synthetic_legacy_import',?,?)",
                   (LEGACY_REVIEW, self.proposal, "0" * 64, "2027-01-01T00:00:00Z"))
        self.fx.store.commit()
        self.fx.preview("remember", subject="unused keeper preview", claim="not yet accepted")
        self.challenge = self.fx.preview("reject_proposal", proposal_id=self.proposal)
        self.assertTrue(self.challenge["preview"]["content_purge_on_rejection"])
        self.assertEqual(self.challenge["preview"]["affected_set"]["reviews"], [{"id": LEGACY_REVIEW}])
        self.assertEqual(self.challenge["preview"]["affected_set"]["proposals"], [{"id": self.proposal}])
        self.assertTrue(self.challenge["preview"]["affected_set"]["provenance_activities"])
        self.assertEqual(self.challenge["preview"]["affected_set"]["accepted_assertions_precondition"], [])
        self.before_sequence = db.execute("SELECT value FROM sequence").fetchone()[0]
        self.target_request_digest = db.execute("SELECT request_digest FROM proposals WHERE id=?",
                                                (self.proposal,)).fetchone()[0]
        self.original_recall_ids = [row[0] for row in db.execute("SELECT id FROM recalls ORDER BY id")]
        self.retained = self.retained_rows(db)
        for name, rows in self.retained.items():
            self.assertTrue(rows, "Retained-state assertion would be vacuous: " + name)
        self.assertEqual(len(self.retained["reviews"]), 1)
        self.assertEqual(self.retained["reviews"][0]["decision"], "accepted")
        self.assertEqual([row["body"] for row in self.retained["evidence"]], [SHARED_EVIDENCE] * 2)
        self.counts = {table: db.execute("SELECT count(*) FROM " + table).fetchone()[0] for table in (
            "proposals", "reviews", "provenance_activities", "proposal_tombstones", "audit_events", "admin_results")}
        self.original = snapshot(db)
        self.old_anchor = read_private(paths(self.fx.home)["audit_head"])
        self.assert_integrity(self.fx.store)
        self.fx.store.close()
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse(os.path.lexists(str(paths(self.fx.home)["db"]) + suffix))

    def retained_rows(self, db):
        statements = {
            "proposals": ("SELECT * FROM proposals WHERE id!=?", (self.proposal,)),
            "reviews": ("SELECT * FROM reviews WHERE proposal_id!=?", (self.proposal,)),
            "provenance": ("SELECT * FROM provenance_activities WHERE target_id!=?", (self.proposal,)),
            "prior_audit": ("SELECT * FROM audit_events WHERE event_seq<=?", (self.before_sequence,)),
            "prior_results": ("SELECT * FROM admin_results WHERE nonce!=?", (self.challenge["nonce"],)),
            "prior_challenges": ("SELECT * FROM admin_challenges WHERE nonce!=?", (self.challenge["nonce"],)),
            "recalls": ("SELECT * FROM recalls WHERE id IN (" + ",".join("?" for _ in self.original_recall_ids)
                        + ")", self.original_recall_ids),
        }
        for table in ("capabilities", "claim_threads", "assertion_versions", "evidence", "evidence_refs",
                      "assertion_disclosures", "assertion_fts", "attestations", "consent_receipts",
                      "audience_sequences", "feedback"):
            statements[table] = ("SELECT * FROM " + table, ())
        return {name: sorted([dict(row) for row in db.execute(sql, args)], key=canonical_json)
                for name, (sql, args) in statements.items()}

    def assert_rejected_semantics(self, store, kernel, control):
        db = store.connection
        sequence = self.before_sequence + 1
        expected_result = {"proposal_id": self.proposal, "review_status": "rejected", "recorded_seq": sequence,
                           "content_purged": True, "delivery_retry": "suppressed"}
        self.assertEqual({key: value for key, value in self.rejected.items() if key != "commit"}, expected_result)
        self.assertEqual(self.rejected["commit"], {"status": "committed", "receipt_id": self.challenge["nonce"],
                                                   "audit_anchor": "synced"})
        self.assertEqual(kernel.admin_result(control, {"nonce": self.challenge["nonce"],
            "preview_digest": self.challenge["preview_digest"]})["result"], expected_result)
        self.assertEqual(db.execute("SELECT value FROM sequence").fetchone()[0], sequence)
        self.assertEqual(self.retained_rows(db), self.retained)
        for table, before in self.counts.items():
            delta = -1 if table in {"proposals", "reviews", "provenance_activities"} else 1
            self.assertEqual(db.execute("SELECT count(*) FROM " + table).fetchone()[0], before + delta, table)
        for sql in ("SELECT * FROM proposals WHERE id=?", "SELECT * FROM reviews WHERE proposal_id=?",
                    "SELECT * FROM provenance_activities WHERE target_id=?"):
            self.assertEqual(db.execute(sql, (self.proposal,)).fetchall(), [])
        tombstones = [dict(row) for row in db.execute("SELECT * FROM proposal_tombstones WHERE proposal_id=?",
                                                     (self.proposal,))]
        # Derive the expected digest independently from the purge implementation.
        self.assertEqual(tombstones, [{"project_id": self.fx.project, "provider": "codex",
            "delivery_digest": store.keyed_digest("proposal-delivery-v1", canonical_json(
                [self.fx.project, "codex", self.delivery["idempotency_key"]])),
            "proposal_id": self.proposal, "disposition": "rejected", "purged_seq": sequence}])
        self.assertEqual([tuple(row) for row in db.execute(
            "SELECT actor_kind,operation,scoped_id,target_id FROM audit_events WHERE event_seq=?", (sequence,))],
            [("user_control", "proposal_rejected", self.fx.project, self.proposal)])
        logical_dump = "\n".join(snapshot(db))
        self.assertNotIn(CANARY, logical_dump)
        self.assertNotIn(self.target_request_digest, logical_dump)
        self.assertIn(SHARED_EVIDENCE, logical_dump)
        self.assertEqual(db.execute("SELECT * FROM assertion_fts WHERE assertion_fts MATCH ?", (CANARY,)).fetchall(), [])
        self.assertEqual(kernel.inbox(control, {"project": self.fx.project, "status": "rejected"})["proposals"], [])
        for provider, original in self.agents.items():
            capability = store.authenticate(original["token"])
            kept = kernel.get(capability, {"recall_id": self.recalls[provider], "ids": [self.kept["assertion_id"]]})
            self.assertEqual(kept["records"][0]["claim"], "keeperalpha accepted claim")
            self.assertEqual(kept["records"][0]["evidence"]["body"], SHARED_EVIDENCE)
            for mode in ("current", "history"):
                self.assertEqual(kernel.search(capability, {"query": CANARY, "temporal_mode": mode})["cards"], [])
            with self.assertRaises(MemoryError) as forbidden:
                kernel.admin_preview(capability, {"operation": "reject_proposal", "project": self.fx.project,
                                                  "proposal_id": self.other_proposal})
            self.assertEqual(forbidden.exception.code, "forbidden")
        for delivery in (self.delivery, dict(self.delivery, claim="modified delayed body")):
            before = snapshot(db)
            with self.assertRaises(MemoryError) as suppressed:
                kernel.propose(store.authenticate(self.fx.codex["token"]), delivery)
            self.assertEqual(suppressed.exception.code, "delivery_suppressed")
            self.assertNotIn(CANARY, canonical_json(suppressed.exception.as_dict()))
            self.assertEqual(snapshot(db), before)

    def test_every_rejection_write_commit_and_anchor_exit_recovers_atomically(self):
        self.seed()
        reference = self.copied_vault("completed")
        recorded = self.run_child(reference)
        self.rejected = recorded["result"]
        # Reviewed from the operation, never learned from the successful run.
        self.assertEqual(recorded["boundaries"], BOUNDARIES)
        self.assert_crash_matrix(reference, recorded, self.assert_rejected_semantics)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--crash-child":
        rejection_child(Path(sys.argv[2]), int(sys.argv[3]), json.loads(sys.stdin.buffer.read()))
    else:
        unittest.main()
