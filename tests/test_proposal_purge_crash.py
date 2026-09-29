"""Held source-only crash-test preparation; not executed on this candidate.

Imported from MAIN 4b1eaf5. The original plaintext fixture description below
is historical context, not encrypted runtime or platform acceptance. Execution
requires separately approved native inputs and remains held.

Real process exits during finite proposal retention and legacy rejection purge.

Public inbox invokes the real lifecycle path. One accepted finite-retention draft
was legitimately corrected to a forever-retained canonical version before its
deadline; its original canonical version is superseded. Thus inbox has exactly
one proposal-purge transaction, with no subsequent assertion-expiry transaction.
Two rejected proposal/review rows are explicit legacy/import fixtures: modern
rejection erases the draft immediately and cannot create these historical rows.
Plaintext process-crash evidence only, not native Windows, physical erasure,
power loss, cryptographic storage or OS-backed human approval.
"""

import hashlib
import hmac
import json
import os
import sys
import unittest
from pathlib import Path

from continuum_memory.errors import MemoryError
from continuum_memory.proposals import check_delivery
from continuum_memory.security import canonical_json, read_private
from continuum_memory.storage import paths
from tests.admin_crash_support import snapshot
from tests.lifecycle_crash_support import LifecycleCrashFixture, LIFECYCLE_NOW, run_lifecycle_child


DEADLINE = "2027-01-02T00:00:00.000000Z"
PURGED_CANARIES = ("purgedraftonecanary", "purgedrafttwocanary", "purgedlegacycanary")
CANONICAL_SUBJECT = "canonicalpurgekeeper decision"
CANONICAL_ORIGINAL = "canonicalpurgekeeper original accepted claim"
CANONICAL_CURRENT = "canonicalpurgekeeper corrected forever claim"
BOUNDARIES = [
    "write:sequence", "write:proposal_tombstones", "write:provenance_activities", "write:proposals", "write:audit_events",
    "write:sequence", "write:proposal_tombstones", "write:provenance_activities", "write:proposals", "write:audit_events",
    "write:sequence", "write:proposal_tombstones", "write:provenance_activities", "write:proposals", "write:audit_events",
    "write:sequence", "write:proposal_tombstones", "write:provenance_activities", "write:proposals", "write:audit_events",
    "before_commit_1", "after_commit_1", "before_anchor_publish", "after_anchor_publish",
    "before_commit_2", "after_commit_2",
]


def purge_child(home, ordinal, request):
    run_lifecycle_child(home, ordinal, request, lambda kernel, control, payload: kernel.inbox(control, payload))


@unittest.skipIf(os.name == "nt", "POSIX plaintext purge crash fixture; native Windows acceptance is separate")
class ProposalPurgeProcessCrashTest(LifecycleCrashFixture, unittest.TestCase):
    child_module = "tests.test_proposal_purge_crash"

    def setUp(self):
        self.setup_crash_fixture("continuum-proposal-purge-crash-")
        self.agents = {provider: self.fx.agent("alpha", provider) for provider in ("codex", "claude")}

    def add_proposal(self, project, provider, *, key, subject, retention="forever", claim=None):
        capability = self.fx.agent(project, provider)
        delivery = self.fx.delivery(subject=subject, claim=claim or (subject + " claim"),
            evidence=subject + " evidence", source_handle="fixture:" + subject,
            idempotency_key=key, retention=retention, disclosure=["codex", "claude"])
        proposal = self.fx.kernel.propose(capability, delivery)["proposal_id"]
        return proposal, capability, delivery

    def seed(self):
        first = self.add_proposal("alpha", "codex", key="shared-project-delivery",
                                  subject=PURGED_CANARIES[0], retention=DEADLINE)
        second = self.add_proposal("alpha", "claude", key="shared-provider-delivery",
                                   subject=PURGED_CANARIES[1], retention=DEADLINE)
        accepted = self.add_proposal("alpha", "codex", key="accepted-finite-delivery",
                                     subject=CANONICAL_SUBJECT, claim=CANONICAL_ORIGINAL, retention=DEADLINE)
        self.accepted_proposal = accepted[0]
        self.accepted = self.fx.approve("accept_proposal", proposal_id=self.accepted_proposal)
        self.corrected = self.fx.approve("correct", target_id=self.accepted["assertion_id"],
            claim=CANONICAL_CURRENT, evidence="canonical correction evidence", retention="forever")
        rejected = self.add_proposal("alpha", "claude", key="legacy-rejected-delivery",
                                     subject=PURGED_CANARIES[2])
        self.targets = [first, second, accepted, rejected]
        self.target_ids = [item[0] for item in self.targets]
        self.keeper = self.add_proposal("alpha", "codex", key=second[2]["idempotency_key"],
                                       subject="otherproviderkeeper")
        keeper_accepted = self.add_proposal("alpha", "claude", key="keeper-accepted-delivery",
                                            subject="acceptedforeverkeeper")
        self.kept = self.fx.approve("accept_proposal", proposal_id=keeper_accepted[0])
        self.beta = self.add_proposal("beta", "codex", key=first[2]["idempotency_key"],
                                     subject="otherprojectkeeper")
        self.beta_legacy = self.add_proposal("beta", "claude", key="beta-legacy-rejected-delivery",
                                            subject="otherprojectlegacykeeper")
        self.recalls = {}
        for provider, capability in self.agents.items():
            recall = self.fx.kernel.search(capability, {"query": CANONICAL_SUBJECT, "temporal_mode": "history"})
            self.assertEqual({card["version_id"] for card in recall["cards"]},
                             {self.accepted["assertion_id"], self.corrected["assertion_id"]})
            self.recalls[provider] = recall["recall_id"]
            self.fx.kernel.feedback(capability, {"recall_id": recall["recall_id"],
                "item_id": self.corrected["assertion_id"], "label": "helpful", "reason": "retained canonical feedback"})
        self.fx.preview("remember", subject="unrelated unused preview", claim="unaccepted keeper preview")

        db = self.fx.store.connection
        # Explicit historical/import residue only. These two rows are not a
        # claim that modern rejection or real human approval produces residue.
        self.fx.store.begin()
        for proposal, review in ((rejected[0], "rvw_alpha_legacy_purge"),
                                 (self.beta_legacy[0], "rvw_beta_legacy_keeper")):
            db.execute("UPDATE proposals SET status='rejected',reviewed_at=? WHERE id=?",
                       ("2027-01-01T00:00:00.000000Z", proposal))
            db.execute("INSERT INTO reviews(id,proposal_id,decision,actor,preview_digest,reviewed_at) "
                       "VALUES (?,?,'rejected','synthetic_legacy_import',?,?)",
                       (review, proposal, "0" * 64, "2027-01-01T00:00:00.000000Z"))
        self.fx.store.commit()
        self.target_rows = [dict(row) for row in db.execute(
            "SELECT * FROM proposals WHERE project_id=? AND (status='rejected' OR "
            "(retention!='forever' AND retention<=?)) ORDER BY created_seq,id",
            (self.fx.project, LIFECYCLE_NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ")))]
        self.assertEqual([row["id"] for row in self.target_rows], self.target_ids)
        self.assertEqual([row["status"] for row in self.target_rows], ["proposed", "proposed", "accepted", "rejected"])
        self.assertEqual(db.execute("SELECT count(*) FROM assertion_versions WHERE project_id=? "
            "AND lifecycle='active' AND retired_seq IS NULL AND retention!='forever' AND retention<=?",
            (self.fx.project, LIFECYCLE_NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))).fetchone()[0], 0,
            "Inbox must not add a second assertion-expiry transaction")
        self.before_sequence = db.execute("SELECT value FROM sequence").fetchone()[0]
        self.counts = {table: db.execute("SELECT count(*) FROM " + table).fetchone()[0] for table in (
            "proposals", "reviews", "provenance_activities", "proposal_tombstones", "audit_events")}
        self.assertEqual(db.execute("SELECT count(*) FROM reviews WHERE proposal_id IN (?,?,?,?)",
                                   self.target_ids).fetchone()[0], 2)
        self.assertEqual(db.execute("SELECT count(*) FROM provenance_activities WHERE target_id IN (?,?,?,?)",
                                   self.target_ids).fetchone()[0], 4)
        self.retained = self.retained_rows(db)
        for name, rows in self.retained.items():
            self.assertTrue(rows, "Retained-state assertion would be vacuous: " + name)
        self.challenge = {"project": self.fx.project, "status": "proposed", "limit": 5}
        self.original = snapshot(db)
        self.old_anchor = read_private(paths(self.fx.home)["audit_head"])
        self.assertEqual(self.fx.store.verify_audit()["status"], "valid")
        self.assert_integrity(self.fx.store)
        self.fx.store.close()

    def retained_rows(self, db):
        placeholders = ",".join("?" for _ in self.target_ids)
        queries = {
            "proposals": ("SELECT * FROM proposals WHERE id NOT IN (" + placeholders + ")", self.target_ids),
            "reviews": ("SELECT * FROM reviews WHERE proposal_id NOT IN (" + placeholders + ")", self.target_ids),
            "provenance": ("SELECT * FROM provenance_activities WHERE target_id NOT IN (" + placeholders + ")", self.target_ids),
            "prior_audit": ("SELECT * FROM audit_events WHERE event_seq<=?", (self.before_sequence,)),
        }
        for table in ("projects", "scopes", "capabilities", "claim_threads", "assertion_versions", "evidence",
                      "evidence_refs", "assertion_disclosures", "assertion_fts", "attestations", "consent_receipts",
                      "audience_sequences", "relations", "recalls", "feedback", "admin_results", "admin_challenges"):
            queries[table] = ("SELECT * FROM " + table, ())
        return {name: sorted([dict(row) for row in db.execute(sql, args)], key=canonical_json)
                for name, (sql, args) in queries.items()}

    @staticmethod
    def expected_delivery_digest(store, project, provider, key):
        # Independent expected HMAC, not the purge/delivery helper under test.
        payload = b"proposal-delivery-v1\x00" + canonical_json([project, provider, key]).encode("utf-8")
        return hmac.new(store.audit_key, payload, hashlib.sha256).hexdigest()

    def assert_purged_semantics(self, store, kernel, control):
        db = store.connection
        original = snapshot(db)
        anchor = read_private(paths(store.data_dir)["audit_head"])
        self.assertEqual(self.retained_rows(db), self.retained)
        self.assertEqual(db.execute("SELECT value FROM sequence").fetchone()[0], self.before_sequence + 4)
        deltas = {"proposals": -4, "reviews": -2, "provenance_activities": -4,
                  "proposal_tombstones": 4, "audit_events": 4}
        for table, delta in deltas.items():
            self.assertEqual(db.execute("SELECT count(*) FROM " + table).fetchone()[0], self.counts[table] + delta, table)
        for name, field in (("proposals", "id"), ("reviews", "proposal_id"), ("provenance_activities", "target_id")):
            self.assertEqual(db.execute("SELECT * FROM " + name + " WHERE " + field + " IN (?,?,?,?)",
                                        self.target_ids).fetchall(), [])
        expected_tombstones, expected_audit = [], []
        for offset, row in enumerate(self.target_rows, start=1):
            sequence = self.before_sequence + offset
            disposition = "rejected" if row["status"] == "rejected" else "expired"
            expected_tombstones.append({"project_id": self.fx.project, "provider": row["source_agent"],
                "delivery_digest": self.expected_delivery_digest(store, self.fx.project, row["source_agent"],
                                                                 row["idempotency_key"]),
                "proposal_id": row["id"], "disposition": disposition, "purged_seq": sequence})
            expected_audit.append((sequence, "retention_policy", "proposal_" + disposition + "_purged",
                self.fx.project, row["id"], "allowed", "ok", LIFECYCLE_NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ")))
        self.assertEqual([dict(row) for row in db.execute("SELECT * FROM proposal_tombstones ORDER BY purged_seq")],
                         expected_tombstones)
        self.assertEqual([tuple(row) for row in db.execute("SELECT event_seq,actor_kind,operation,scoped_id,target_id,"
            "policy_decision,result,occurred_at FROM audit_events WHERE event_seq>? ORDER BY event_seq",
            (self.before_sequence,))], expected_audit)
        logical_dump = "\n".join(original)
        for canary in PURGED_CANARIES:
            self.assertNotIn(canary, logical_dump)
            self.assertEqual(db.execute("SELECT * FROM assertion_fts WHERE assertion_fts MATCH ?", (canary,)).fetchall(), [])
        for row in self.target_rows:
            self.assertNotIn(row["request_digest"], logical_dump)
        self.assertIn(CANONICAL_ORIGINAL, logical_dump)
        self.assertIn(CANONICAL_CURRENT, logical_dump)
        self.assertEqual(kernel.inbox(control, self.challenge), self.completed_result)
        self.assertEqual(kernel.inbox(control, dict(self.challenge, status="rejected"))["proposals"], [])
        history = kernel.show(control, {"project": self.fx.project, "id": self.accepted["memory_id"], "history": True})
        self.assertEqual([item["version_id"] for item in history["versions"]],
                         [self.accepted["assertion_id"], self.corrected["assertion_id"]])
        self.assertEqual([item["claim"] for item in history["versions"]], [CANONICAL_ORIGINAL, CANONICAL_CURRENT])
        self.assertEqual([item["lifecycle"] for item in history["versions"]], ["superseded", "active"])
        self.assertEqual(history["versions"][0]["provenance_activities"][0]["input_ids"], [self.accepted_proposal])
        for provider, original_capability in self.agents.items():
            capability = store.authenticate(original_capability["token"])
            records = kernel.get(capability, {"recall_id": self.recalls[provider],
                "ids": [self.accepted["assertion_id"], self.corrected["assertion_id"]]})["records"]
            self.assertEqual([item["claim"] for item in records], [CANONICAL_ORIGINAL, CANONICAL_CURRENT])
            self.assertTrue(all(item["authority"] == "data" and item["evidence"]["body"] for item in records))
        for _, original_capability, delivery in self.targets:
            capability = store.authenticate(original_capability["token"])
            for delayed in (delivery, dict(delivery, claim="changed delayed body", retention="forever")):
                before = snapshot(db)
                with self.assertRaises(MemoryError) as suppressed:
                    kernel.propose(capability, delayed)
                self.assertEqual(suppressed.exception.code, "delivery_suppressed")
                self.assertEqual(snapshot(db), before)
                self.assertEqual(read_private(paths(store.data_dir)["audit_head"]), anchor)
        # Same raw delivery keys in other scopes stay usable. Do not call a beta
        # lifecycle entry: its deliberately retained rejected legacy row is due.
        for keeper in (self.keeper, self.beta):
            _, capability, delivery = keeper
            digest = self.expected_delivery_digest(store, capability["project_id"], capability["provider"],
                                                   delivery["idempotency_key"])
            self.assertIsNone(check_delivery(store, capability["project_id"], capability["provider"], digest))
        replay = kernel.propose(store.authenticate(self.keeper[1]["token"]), self.keeper[2])
        self.assertEqual(replay, {"proposal_id": self.keeper[0], "review_status": "proposed", "replayed": True})
        self.assertEqual(snapshot(db), original, "Recovery reads, repeats and delayed deliveries must add no logical writes")
        self.assertEqual(read_private(paths(store.data_dir)["audit_head"]), anchor)

    def test_every_finite_purge_write_commit_and_anchor_exit_is_atomic(self):
        self.seed()
        reference = self.copied_vault("completed")
        recorded = self.run_child(reference)
        self.assertEqual(recorded["boundaries"], BOUNDARIES)
        self.completed_result = recorded["result"]
        self.assertEqual(self.completed_result["status"], "ok")
        self.assertEqual([item["proposal_id"] for item in self.completed_result["proposals"]], [self.keeper[0]])
        self.assertEqual(self.completed_result["proposals"][0]["claim"], self.keeper[2]["claim"])
        self.assert_lifecycle_crash_matrix(reference, recorded, self.assert_purged_semantics)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--crash-child":
        purge_child(Path(sys.argv[2]), int(sys.argv[3]), json.loads(sys.stdin.buffer.read()))
    else:
        unittest.main()

