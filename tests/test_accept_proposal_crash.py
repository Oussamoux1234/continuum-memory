"""Real process death while accepting one reviewed, agent-authored proposal.

Plaintext SQLite process-crash evidence only. Approval is the explicit synthetic
prototype fixture, not OS-backed presence or permission for an agent to act.
Native Windows, encrypted storage, power loss and backup recovery are not covered.
"""

import json
import os
import sys
import unittest
from collections import Counter
from pathlib import Path

from continuum_memory.errors import MemoryError
from continuum_memory.security import canonical_json, digest_json, read_private
from continuum_memory.storage import paths
from tests.admin_crash_support import AdminCrashFixture, apply_child, snapshot


SUBJECT = "acceptproposalcanary decision"
BODY = "acceptproposalcanary reviewed project decision"
EVIDENCE = "acceptproposalcanary original agent evidence"
KERNEL_TIME = "2027-01-01T00:00:00.000000Z"
PREFIXES = ["mem", "evd", "asr", "att", "att", "att", "cns", "prv", "rvw"]
BOUNDARIES = [
    "write:admin_challenges", "write:sequence", "write:claim_threads", "write:evidence",
    "write:assertion_versions", "write:assertion_disclosures", "write:assertion_disclosures",
    "write:evidence_refs", "write:assertion_fts", "write:attestations", "write:attestations",
    "write:attestations", "write:consent_receipts", "write:provenance_activities",
    "write:audience_sequences", "write:audience_sequences", "write:audit_events",
    "write:proposals", "write:reviews", "write:admin_results", "before_commit_1",
    "after_commit_1", "before_anchor_publish", "after_anchor_publish", "before_commit_2",
    "after_commit_2",
]


def acceptance_child(home, crash_after, challenge):
    counts = Counter()

    def acceptance_id(prefix):
        if prefix not in PREFIXES:
            raise AssertionError("Unexpected identifier generation outside acceptance fixture")
        counts[prefix] += 1
        return "%s_acceptance_crash_%d" % (prefix, counts[prefix])

    apply_child(home, crash_after, challenge, acceptance_id, PREFIXES)


@unittest.skipIf(os.name == "nt", "POSIX fixture; native Windows private-copy acceptance is separate")
class ProposalAcceptanceProcessCrashTest(AdminCrashFixture, unittest.TestCase):
    child_module = "tests.test_accept_proposal_crash"

    def setUp(self):
        self.setup_crash_fixture("continuum-acceptance-crash-")
        self.agents = {provider: self.fx.agent("alpha", provider) for provider in ("codex", "claude")}

    def seed(self):
        self.delivery = self.fx.delivery(subject=SUBJECT, claim=BODY, evidence=EVIDENCE,
            source_handle="fixture:agent-original", disclosure=["codex", "claude"])
        self.proposal = self.fx.kernel.propose(self.fx.codex, self.delivery)["proposal_id"]
        self.other_proposal = self.fx.kernel.propose(self.fx.codex, self.fx.delivery(
            subject="unrelated proposal", claim="unrelated pending content",
            idempotency_key="unrelated-pending-delivery"))["proposal_id"]
        self.kept = self.fx.approve("remember", subject="unrelated alpha", claim="keeper alpha claim",
                                   evidence="keeper alpha evidence", disclosure=["codex", "claude"])
        self.beta = self.fx.approve("remember", project=self.fx.projects["beta"]["id"],
                                   subject="unrelated beta", claim="keeper beta claim",
                                   evidence="keeper beta evidence", disclosure=["codex", "claude"])
        self.recalls = {}
        for provider, capability in self.agents.items():
            recall = self.fx.kernel.search(capability, {"query": SUBJECT})
            self.assertEqual(recall["cards"], [])  # A proposal is not accepted memory.
            self.recalls[provider] = recall["recall_id"]
        self.challenge = self.fx.preview("accept_proposal", proposal_id=self.proposal)
        db = self.fx.store.connection
        self.proposal_row = dict(db.execute("SELECT * FROM proposals WHERE id=?", (self.proposal,)).fetchone())
        self.before_sequence = db.execute("SELECT value FROM sequence").fetchone()[0]
        self.audiences = {provider: db.execute(
            "SELECT max(local_seq) FROM audience_sequences WHERE project_id=? AND provider=?",
            (self.fx.project, provider)).fetchone()[0] for provider in self.agents}
        self.counts = {table: db.execute("SELECT count(*) FROM " + table).fetchone()[0] for table in (
            "claim_threads", "assertion_versions", "evidence", "reviews", "consent_receipts",
            "provenance_activities", "attestations", "audit_events", "admin_results")}
        self.retained = self.retained_rows(db)
        for name, rows in self.retained.items():
            self.assertTrue(rows, "Retained-state assertion would be vacuous: " + name)
        self.original_recalls = [dict(row) for row in db.execute("SELECT * FROM recalls ORDER BY id")]
        self.original = snapshot(db)
        self.old_anchor = read_private(paths(self.fx.home)["audit_head"])
        self.assert_integrity(self.fx.store)
        self.assertNotIn("_acceptance_crash_", "\n".join(self.original))
        self.fx.store.close()
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse(os.path.lexists(str(paths(self.fx.home)["db"]) + suffix))

    def retained_rows(self, db):
        ids = [self.kept["assertion_id"], self.beta["assertion_id"]]
        statements = {
            "capabilities": ("SELECT * FROM capabilities ORDER BY id", ()),
            "threads": ("SELECT * FROM claim_threads WHERE id IN (?,?) ORDER BY id",
                        [self.kept["memory_id"], self.beta["memory_id"]]),
            "versions": ("SELECT * FROM assertion_versions WHERE id IN (?,?) ORDER BY id", ids),
            "evidence": ("SELECT * FROM evidence WHERE id IN (SELECT evidence_id FROM assertion_versions "
                         "WHERE id IN (?,?)) ORDER BY id", ids),
            "provenance": ("SELECT * FROM provenance_activities WHERE target_id IN (?,?,?,?) ORDER BY id",
                           ids + [self.proposal, self.other_proposal]),
            "other_proposal": ("SELECT * FROM proposals WHERE id=?", (self.other_proposal,)),
            "prior_audit": ("SELECT * FROM audit_events WHERE event_seq<=? ORDER BY audit_seq",
                            (self.before_sequence,)),
            "beta_audiences": ("SELECT * FROM audience_sequences WHERE project_id=? ORDER BY provider,local_seq",
                               (self.fx.projects["beta"]["id"],)),
        }
        for table in ("assertion_disclosures", "evidence_refs", "attestations", "consent_receipts", "assertion_fts"):
            statements[table] = ("SELECT * FROM " + table + " WHERE assertion_id IN (?,?)", ids)
        return {name: sorted([dict(row) for row in db.execute(sql, args)], key=canonical_json)
                for name, (sql, args) in statements.items()}

    def assert_accepted_semantics(self, store, kernel, control):
        db = store.connection
        assertion = self.accepted["assertion_id"]
        sequence = self.before_sequence + 1
        self.assertEqual(self.accepted["proposal_id"], self.proposal)
        self.assertEqual(self.accepted["review_status"], "accepted")
        self.assertEqual(self.accepted["authority"], "data")
        self.assertEqual(self.accepted["recorded_seq"], sequence)
        self.assertIsNone(self.accepted["supersedes"])
        self.assertIsNone(self.accepted["conflict_id"])
        self.assertEqual(self.retained_rows(db), self.retained)
        for table, count in self.counts.items():
            self.assertEqual(db.execute("SELECT count(*) FROM " + table).fetchone()[0],
                             count + (3 if table == "attestations" else 1), table)
        self.assertEqual(db.execute("SELECT value FROM sequence").fetchone()[0], sequence)
        proposal = dict(db.execute("SELECT * FROM proposals WHERE id=?", (self.proposal,)).fetchone())
        self.assertEqual(proposal, dict(self.proposal_row, status="accepted", reviewed_at=KERNEL_TIME,
                                       accepted_assertion_id=assertion))
        review = db.execute("SELECT * FROM reviews WHERE proposal_id=?", (self.proposal,)).fetchall()
        self.assertEqual(len(review), 1)
        self.assertEqual((review[0]["decision"], review[0]["actor"], review[0]["preview_digest"],
                          review[0]["reviewed_at"]),
                         ("accepted", "user_control", digest_json(self.challenge["preview"]), KERNEL_TIME))
        thread = dict(db.execute("SELECT * FROM claim_threads WHERE id=?",
                                 (self.accepted["memory_id"],)).fetchone())
        self.assertEqual((thread["subject"], thread["project_id"], thread["created_seq"]),
                         (SUBJECT, self.fx.project, sequence))
        row = dict(db.execute("SELECT * FROM assertion_versions WHERE id=?", (assertion,)).fetchone())
        for field, expected in dict(thread_id=thread["id"], project_id=self.fx.project, body=BODY,
                                    admission="accepted", epistemic="asserted", lifecycle="active",
                                    authority="data", created_by="codex", ingest_seq=sequence,
                                    recorded_at=KERNEL_TIME, retired_seq=None, retired_at=None).items():
            self.assertEqual(row[field], expected, field)
        for field in ("classification", "retention", "valid_precision", "valid_from", "valid_to"):
            self.assertEqual(row[field], self.proposal_row[field], field)
        self.assertEqual({item[0] for item in db.execute(
            "SELECT provider FROM assertion_disclosures WHERE assertion_id=?", (assertion,))}, {"codex", "claude"})
        evidence = dict(db.execute("SELECT * FROM evidence WHERE id=?", (row["evidence_id"],)).fetchone())
        for field, expected in dict(body=EVIDENCE, locator="fixture:agent-original", project_id=self.fx.project,
                                    trust_tier="agent_provided", source_agent="codex",
                                    observed_at=KERNEL_TIME, created_seq=sequence).items():
            self.assertEqual(evidence[field], expected, field)
        self.assertEqual(evidence["body_fingerprint"], store.keyed_digest("evidence-body", EVIDENCE))
        self.assertEqual([tuple(item) for item in db.execute(
            "SELECT evidence_id FROM evidence_refs WHERE assertion_id=?", (assertion,))], [(row["evidence_id"],)])
        self.assertEqual({tuple(item) for item in db.execute(
            "SELECT principal,role,method FROM attestations WHERE assertion_id=?", (assertion,))}, {
                ("codex", "author", "proposal"), ("memoryd", "recorder", "serialized_writer"),
                ("user_control", "authorizer", "prototype_terminal_grant")})
        consent = db.execute("SELECT * FROM consent_receipts WHERE assertion_id=?", (assertion,)).fetchall()
        self.assertEqual(len(consent), 1)
        self.assertEqual(consent[0]["payload_digest"], digest_json(self.challenge["preview"]))
        self.assertEqual(set(json.loads(consent[0]["disclosure_json"])), {"codex", "claude"})
        self.assertEqual(json.loads(consent[0]["evidence_ids_json"]), [row["evidence_id"]])
        provenance = db.execute("SELECT * FROM provenance_activities WHERE target_id=?", (assertion,)).fetchall()
        self.assertEqual(len(provenance), 1)
        self.assertEqual((provenance[0]["activity_type"], provenance[0]["actor"],
                          json.loads(provenance[0]["input_ids_json"])), ("proposal_acceptance", "codex", [self.proposal]))
        self.assertEqual(provenance[0]["output_fingerprint"], store.keyed_digest("assertion-output", BODY))
        self.assertEqual([tuple(item) for item in db.execute(
            "SELECT actor_kind,operation,scoped_id,target_id FROM audit_events WHERE event_seq=?", (sequence,))],
            [("user_control", "assertion_accepted", self.fx.project, assertion)])
        self.assertEqual([item[0] for item in db.execute(
            "SELECT assertion_id FROM assertion_fts WHERE assertion_fts MATCH 'acceptproposalcanary'")], [assertion])
        for provider in self.agents:
            self.assertEqual([tuple(item) for item in db.execute(
                "SELECT local_seq,recorded_seq FROM audience_sequences WHERE project_id=? AND provider=? "
                "AND local_seq>?", (self.fx.project, provider, self.audiences[provider]))],
                [(self.audiences[provider] + 1, sequence)])
        for original in self.original_recalls:
            self.assertEqual(dict(db.execute("SELECT * FROM recalls WHERE id=?", (original["id"],)).fetchone()), original)
        for provider, original in self.agents.items():
            capability = store.authenticate(original["token"])
            with self.assertRaises(MemoryError) as no_retroactive_authority:
                kernel.get(capability, {"recall_id": self.recalls[provider], "ids": [assertion]})
            self.assertEqual(no_retroactive_authority.exception.code, "not_found")
            recalled = kernel.search(capability, {"query": SUBJECT})
            self.assertEqual([card["version_id"] for card in recalled["cards"]], [assertion])
            result = kernel.get(capability, {"recall_id": recalled["recall_id"], "ids": [assertion]})
            self.assertEqual(result["records"][0]["claim"], BODY)
            self.assertEqual(result["records"][0]["evidence"]["body"], EVIDENCE)
            self.assertEqual(result["records"][0]["authority"], "data")
            # Accepting agent-authored data never promotes its capability to control.
            with self.assertRaises(MemoryError) as no_agent_control:
                kernel.admin_preview(capability, {"operation": "remember", "project": self.fx.project})
            self.assertEqual(no_agent_control.exception.code, "forbidden")
        before_replay = snapshot(db)
        replay = kernel.propose(store.authenticate(self.fx.codex["token"]), self.delivery)
        self.assertEqual(replay, {"proposal_id": self.proposal, "review_status": "accepted", "replayed": True})
        self.assertEqual(snapshot(db), before_replay)

    def test_every_acceptance_write_commit_and_anchor_exit_recovers_atomically(self):
        self.seed()
        reference = self.copied_vault("completed")
        recorded = self.run_child(reference)
        self.accepted = recorded["result"]
        # This exact operation-specific trace is reviewed, never learned at run time.
        self.assertEqual(recorded["boundaries"], BOUNDARIES)
        self.assert_crash_matrix(reference, recorded, self.assert_accepted_semantics)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--crash-child":
        acceptance_child(Path(sys.argv[2]), int(sys.argv[3]), json.loads(sys.stdin.buffer.read()))
    else:
        unittest.main()
