"""Real process death across approved standalone-proposal forgetting.

Synthetic plaintext SQLite evidence only: no OS-backed human approval,
encryption, native Windows, power-loss or physical-erasure acceptance. An
explicitly synthetic legacy review makes the real review FK cascade nonvacuous.
Proposal evidence is inline; matching unrelated canonical evidence must survive.
"""

import hashlib
import hmac
import json
import os
import sys
import unittest
from pathlib import Path

from continuum_memory.errors import MemoryError
from continuum_memory.security import canonical_json, read_private
from continuum_memory.storage import paths
from tests.admin_crash_support import AdminCrashFixture, apply_child, snapshot


CANARY = "forgetdraftonlycanary"
SHARED_EVIDENCE = "keeper evidence independently retained after draft forget"
LEGACY_REVIEW = "rvw_forget_legacy_fixture"
DELETION_ID = "del_forget_proposal_fixture"
PROJECTIONS = ["proposal_content", "proposal_evidence", "proposal_reviews", "proposal_provenance"]
LIMITATIONS = ["no_managed_backups_in_slice", "no_physical_overwrite_guarantee"]
BOUNDARIES = [
    "write:admin_challenges", "write:sequence", "write:proposal_tombstones",
    "write:provenance_activities", "write:proposals", "write:deletion_receipts",
    "write:audit_events", "write:admin_results", "before_commit_1", "after_commit_1",
    "before_anchor_publish", "after_anchor_publish", "before_commit_2", "after_commit_2",
    "before_checkpoint", "after_checkpoint",
]


def forget_child(home, crash_after, challenge):
    def deletion_id(prefix):
        if prefix != "del":
            raise AssertionError("Proposal forgetting must allocate only the deletion receipt")
        return DELETION_ID

    apply_child(home, crash_after, challenge, deletion_id, ["del"])


@unittest.skipIf(os.name == "nt", "POSIX fixture; native Windows proposal-forget acceptance is separate")
class ProposalForgetProcessCrashTest(AdminCrashFixture, unittest.TestCase):
    child_module = "tests.test_forget_proposal_crash"

    def setUp(self):
        self.setup_crash_fixture("continuum-forget-proposal-crash-")
        self.environment["PYTHONWARNINGS"] = "error::ResourceWarning"
        self.agents = {provider: self.fx.agent("alpha", provider) for provider in ("codex", "claude")}

    def seed(self):
        self.delivery = self.fx.delivery(
            subject=CANARY + " subject", claim=CANARY + " forgotten claim", evidence=SHARED_EVIDENCE,
            source_handle="fixture:" + CANARY, idempotency_key=CANARY + "-delivery",
            disclosure=["codex", "claude"], retention="forever")
        self.proposal = self.fx.kernel.propose(self.fx.codex, self.delivery)["proposal_id"]
        kept_proposal = self.fx.kernel.propose(self.fx.codex, self.fx.delivery(
            subject="keeperalpha decision", claim="keeperalpha accepted claim", evidence=SHARED_EVIDENCE,
            source_handle="fixture:keeper", idempotency_key="keeper-accepted-delivery",
            disclosure=["codex", "claude"], retention="forever"))["proposal_id"]
        self.kept = self.fx.approve("accept_proposal", proposal_id=kept_proposal)
        self.other_proposal = self.fx.kernel.propose(self.fx.codex, self.fx.delivery(
            subject="unrelated draft", claim="unrelated pending claim", evidence=SHARED_EVIDENCE,
            source_handle="fixture:pending", idempotency_key="keeper-pending-delivery",
            retention="forever"))["proposal_id"]
        self.fx.approve("remember", project=self.fx.projects["beta"]["id"],
            subject="keeperbeta decision", claim="keeperbeta accepted claim", evidence=SHARED_EVIDENCE,
            disclosure=["codex", "claude"], retention="forever")
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
        self.fx.preview("remember", subject="unused keeper preview", claim="not yet accepted", retention="forever")
        self.challenge = self.fx.preview("forget", target_id=self.proposal)
        preview = self.challenge["preview"]
        self.assertEqual(preview["target_kind"], "proposal")
        self.assertEqual(preview["effects"], PROJECTIONS)
        self.assertEqual(preview["limitations"], LIMITATIONS)
        self.assertEqual(preview["affected_set"]["proposals"], [{"id": self.proposal}])
        self.assertEqual(preview["affected_set"]["reviews"], [{"id": LEGACY_REVIEW}])
        provenance = [{"id": row[0]} for row in db.execute(
            "SELECT id FROM provenance_activities WHERE target_id=? ORDER BY id", (self.proposal,))]
        self.assertEqual(len(provenance), 1)
        self.assertEqual(preview["affected_set"]["provenance_activities"], provenance)
        self.assertEqual(preview["affected_set"]["accepted_assertions_precondition"], [])
        self.before_sequence = db.execute("SELECT value FROM sequence").fetchone()[0]
        self.before_audit_counter = db.execute(
            "SELECT seq FROM sqlite_sequence WHERE name='audit_events'").fetchone()[0]
        self.target_request_digest = db.execute("SELECT request_digest FROM proposals WHERE id=?",
                                                (self.proposal,)).fetchone()[0]
        self.assertEqual(len(self.target_request_digest), 64)
        self.original_recall_ids = [row[0] for row in db.execute("SELECT id FROM recalls ORDER BY id")]
        self.retained = self.retained_rows(db)
        for name, rows in self.retained.items():
            self.assertTrue(rows, "Retained-state assertion would be vacuous: " + name)
        self.assertEqual(len(self.retained["reviews"]), 1)
        self.assertEqual(self.retained["reviews"][0]["decision"], "accepted")
        self.assertEqual([row["body"] for row in self.retained["evidence"]], [SHARED_EVIDENCE] * 2)
        self.counts = {table: db.execute("SELECT count(*) FROM " + table).fetchone()[0] for table in (
            "proposals", "reviews", "provenance_activities", "proposal_tombstones", "deletion_receipts",
            "audit_events", "admin_results")}
        self.original = snapshot(db)
        self.assertIn(CANARY, "\n".join(self.original))
        self.assertIn(self.target_request_digest, "\n".join(self.original))
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

    def assert_forgotten_semantics(self, store, kernel, control):
        db = store.connection
        before = snapshot(db)
        anchor = read_private(paths(store.data_dir)["audit_head"])
        sequence = self.before_sequence + 1
        expected_result = {"deletion_receipt_id": DELETION_ID, "target_id": self.proposal,
            "deletion_seq": sequence, "completion_state": "complete", "projection_kinds": PROJECTIONS,
            "content_free_receipt": True, "delivery_retry": "suppressed", "limitations": LIMITATIONS}
        self.assertEqual({key: value for key, value in self.forgotten.items() if key != "commit"}, expected_result)
        self.assertEqual(self.forgotten["commit"], {"status": "committed", "receipt_id": self.challenge["nonce"],
            "audit_anchor": "synced", "checkpoint": "complete"})
        legacy = kernel.admin_result(control, {"nonce": self.challenge["nonce"],
                                               "preview_digest": self.challenge["preview_digest"]})
        opaque = kernel.admin_recover(control, self.challenge["recovery_locator"])
        self.assertEqual(legacy, opaque)
        self.assertTrue(legacy["committed"])
        self.assertEqual(legacy["result"], expected_result)
        self.assertEqual(db.execute("SELECT value FROM sequence").fetchone()[0], sequence)
        self.assertEqual(db.execute("SELECT seq FROM sqlite_sequence WHERE name='audit_events'").fetchone()[0],
                         self.before_audit_counter + 1)
        self.assertEqual(self.retained_rows(db), self.retained)
        for table, count in self.counts.items():
            delta = -1 if table in {"proposals", "reviews", "provenance_activities"} else 1
            self.assertEqual(db.execute("SELECT count(*) FROM " + table).fetchone()[0], count + delta, table)
        for sql in ("SELECT * FROM proposals WHERE id=?", "SELECT * FROM reviews WHERE proposal_id=?",
                    "SELECT * FROM provenance_activities WHERE target_id=?"):
            self.assertEqual(db.execute(sql, (self.proposal,)).fetchall(), [])
        # Independently spell the domain-separated HMAC, not the purge helper.
        binding = json.dumps([self.fx.project, "codex", self.delivery["idempotency_key"]],
                             ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hmac.new(store.audit_key, b"proposal-delivery-v1\x00" + binding, hashlib.sha256).hexdigest()
        self.assertEqual([dict(row) for row in db.execute(
            "SELECT * FROM proposal_tombstones WHERE proposal_id=?", (self.proposal,))],
            [{"project_id": self.fx.project, "provider": "codex", "delivery_digest": digest,
              "proposal_id": self.proposal, "disposition": "forgotten", "purged_seq": sequence}])
        self.assertEqual([dict(row) for row in db.execute("SELECT * FROM deletion_receipts WHERE target_id=?",
                                                         (self.proposal,))],
            [{"id": DELETION_ID, "project_id": self.fx.project, "target_id": self.proposal,
              "projection_kinds_json": canonical_json(PROJECTIONS), "deletion_seq": sequence,
              "completion_state": "complete", "policy_version": "prototype-1",
              "deleted_at": "2027-01-01T00:00:00.000000Z"}])
        self.assertEqual([tuple(row) for row in db.execute(
            "SELECT actor_kind,operation,scoped_id,target_id FROM audit_events WHERE event_seq=?", (sequence,))],
            [("user_control", "proposal_forgotten", self.fx.project, self.proposal)])
        logical_dump = "\n".join(before)
        self.assertNotIn(CANARY, logical_dump)
        self.assertNotIn(self.target_request_digest, logical_dump)
        self.assertIn(SHARED_EVIDENCE, logical_dump)
        self.assertEqual(db.execute("SELECT * FROM assertion_fts WHERE assertion_fts MATCH ?", (CANARY,)).fetchall(), [])
        inbox = kernel.inbox(control, {"project": self.fx.project})
        self.assertNotIn(self.proposal, [proposal["proposal_id"] for proposal in inbox["proposals"]])
        for provider, original in self.agents.items():
            capability = store.authenticate(original["token"])
            kept = kernel.get(capability, {"recall_id": self.recalls[provider], "ids": [self.kept["assertion_id"]]})
            self.assertEqual(kept["records"][0]["claim"], "keeperalpha accepted claim")
            self.assertEqual(kept["records"][0]["evidence"]["body"], SHARED_EVIDENCE)
        for delivery in (self.delivery, dict(self.delivery, claim="modified delayed body")):
            with self.assertRaises(MemoryError) as suppressed:
                kernel.propose(store.authenticate(self.fx.codex["token"]), delivery)
            self.assertEqual(suppressed.exception.code, "delivery_suppressed")
            self.assertNotIn(CANARY, canonical_json(suppressed.exception.as_dict()))
            self.assertEqual(snapshot(db), before)
        self.assertEqual(snapshot(db), before)
        self.assertEqual(read_private(paths(store.data_dir)["audit_head"]), anchor)
        # Search deliberately creates new recalls. Run it only after proving
        # receipt reads, inbox/get and suppressed deliveries are write-free;
        # retained_rows separately protects every original recall byte-for-byte.
        for original in self.agents.values():
            capability = store.authenticate(original["token"])
            for mode in ("current", "history"):
                self.assertEqual(kernel.search(capability, {"query": CANARY, "temporal_mode": mode})["cards"], [])
        self.assertEqual(self.retained_rows(db), self.retained)

    def test_every_forget_write_commit_anchor_and_checkpoint_exit_recovers_atomically(self):
        self.seed()
        reference = self.copied_vault("completed")
        recorded = self.run_child(reference)
        self.forgotten = recorded["result"]
        # Reviewed directly from the operation, never learned from its result.
        self.assertEqual(recorded["boundaries"], BOUNDARIES)
        self.assert_crash_matrix(reference, recorded, self.assert_forgotten_semantics)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--crash-child":
        forget_child(Path(sys.argv[2]), int(sys.argv[3]), json.loads(sys.stdin.buffer.read()))
    else:
        unittest.main()
