"""Real process death while recording one owner-authored, reviewed claim.

Plaintext SQLite and synthetic prototype approval only, not OS-backed presence,
native Windows, encryption, power loss, backup recovery or conflict variants.
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
from tests.admin_crash_support import AdminCrashFixture, apply_child, fixture_params, snapshot


SUBJECT = "remembercrashcanary decision"
BODY = "remembercrashcanary owner project decision"
EVIDENCE = "remembercrashcanary reviewed owner evidence"
KERNEL_TIME = "2027-01-01T00:00:00.000000Z"
PREFIXES = ["mem", "evd", "asr", "att", "att", "att", "cns", "prv"]
BOUNDARIES = [
    "write:admin_challenges", "write:sequence", "write:claim_threads", "write:evidence",
    "write:assertion_versions", "write:assertion_disclosures", "write:assertion_disclosures",
    "write:evidence_refs", "write:assertion_fts", "write:attestations", "write:attestations",
    "write:attestations", "write:consent_receipts", "write:provenance_activities",
    "write:audience_sequences", "write:audience_sequences", "write:audit_events",
    "write:admin_results", "before_commit_1", "after_commit_1", "before_anchor_publish",
    "after_anchor_publish", "before_commit_2", "after_commit_2",
]


def remember_child(home, crash_after, challenge):
    counts = Counter()

    def remember_id(prefix):
        if prefix not in PREFIXES:
            raise AssertionError("Unexpected identifier generation outside remember fixture")
        counts[prefix] += 1
        return "%s_remember_crash_%d" % (prefix, counts[prefix])

    apply_child(home, crash_after, challenge, remember_id, PREFIXES)


@unittest.skipIf(os.name == "nt", "POSIX fixture; native Windows acceptance is separate")
class RememberProcessCrashTest(AdminCrashFixture, unittest.TestCase):
    child_module = "tests.test_remember_crash"

    def setUp(self):
        self.setup_crash_fixture("continuum-remember-crash-")
        self.agents = {provider: self.fx.agent("alpha", provider) for provider in ("codex", "claude")}
        self.beta_agents = {provider: self.fx.agent("beta", provider) for provider in self.agents}

    def seed(self):
        proposed = self.fx.kernel.propose(self.fx.codex, self.fx.delivery(
            subject="unrelated alpha", claim="keeper alpha claim", evidence="keeper alpha evidence",
            disclosure=["codex", "claude"]))
        self.kept = self.fx.approve("accept_proposal", proposal_id=proposed["proposal_id"])
        self.fx.kernel.propose(self.fx.codex, self.fx.delivery(
            subject="unrelated pending", claim="keeper pending claim", evidence="keeper pending evidence",
            idempotency_key="remember-unrelated-pending"))
        self.beta = self.fx.approve("remember", project=self.fx.projects["beta"]["id"],
            subject="unrelated beta", claim="keeper beta claim", evidence="keeper beta evidence",
            disclosure=["codex", "claude"])
        self.recalls = {}
        for provider, capability in self.agents.items():
            recalled = self.fx.kernel.search(capability, {"query": SUBJECT})
            self.assertEqual(recalled["cards"], [])
            self.recalls[provider] = recalled["recall_id"]
        self.challenge = self.fx.preview("remember", subject=SUBJECT, claim=BODY, evidence=EVIDENCE,
            evidence_locator="fixture:owner-original", disclosure=["codex", "claude"],
            classification="confidential", retention="2028-01-01", valid_precision="interval",
            valid_from="2026-12-01", valid_to="2027-02-01")
        db = self.fx.store.connection
        self.before_sequence = db.execute("SELECT value FROM sequence").fetchone()[0]
        self.audiences = {provider: db.execute(
            "SELECT max(local_seq) FROM audience_sequences WHERE project_id=? AND provider=?",
            (self.fx.project, provider)).fetchone()[0] for provider in self.agents}
        self.counts = {table: db.execute("SELECT count(*) FROM " + table).fetchone()[0] for table in (
            "claim_threads", "assertion_versions", "evidence", "reviews", "proposals", "consent_receipts",
            "provenance_activities", "attestations", "audit_events", "admin_results")}
        self.retained = self.retained_rows(db)
        for name, rows in self.retained.items():
            self.assertTrue(rows, "Retained-state assertion would be vacuous: " + name)
        self.original_recalls = [dict(row) for row in db.execute("SELECT * FROM recalls ORDER BY id")]
        self.original = snapshot(db)
        self.old_anchor = read_private(paths(self.fx.home)["audit_head"])
        self.assert_integrity(self.fx.store)
        self.assertNotIn("_remember_crash_", "\n".join(self.original))
        self.fx.store.close()
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse(os.path.lexists(str(paths(self.fx.home)["db"]) + suffix))

    def retained_rows(self, db):
        ids = [self.kept["assertion_id"], self.beta["assertion_id"]]
        statements = {
            "capabilities": ("SELECT * FROM capabilities ORDER BY id", ()),
            "projects": ("SELECT * FROM projects ORDER BY id", ()),
            "scopes": ("SELECT * FROM scopes ORDER BY id", ()),
            "threads": ("SELECT * FROM claim_threads WHERE id IN (?,?) ORDER BY id",
                        [self.kept["memory_id"], self.beta["memory_id"]]),
            "versions": ("SELECT * FROM assertion_versions WHERE id IN (?,?) ORDER BY id", ids),
            "evidence": ("SELECT * FROM evidence WHERE id IN (SELECT evidence_id FROM assertion_versions "
                         "WHERE id IN (?,?)) ORDER BY id", ids),
            "provenance": ("SELECT * FROM provenance_activities WHERE created_seq<=? ORDER BY id",
                           (self.before_sequence,)),
            "proposals": ("SELECT * FROM proposals ORDER BY id", ()),
            "reviews": ("SELECT * FROM reviews ORDER BY id", ()),
            "prior_audit": ("SELECT * FROM audit_events WHERE event_seq<=? ORDER BY audit_seq",
                            (self.before_sequence,)),
            "beta_audiences": ("SELECT * FROM audience_sequences WHERE project_id=? ORDER BY provider,local_seq",
                               (self.fx.projects["beta"]["id"],)),
        }
        for table in ("assertion_disclosures", "evidence_refs", "attestations", "consent_receipts", "assertion_fts"):
            statements[table] = ("SELECT * FROM " + table + " WHERE assertion_id IN (?,?)", ids)
        return {name: sorted([dict(row) for row in db.execute(sql, args)], key=canonical_json)
                for name, (sql, args) in statements.items()}

    def assert_remembered_semantics(self, store, kernel, control):
        db = store.connection
        assertion = self.remembered["assertion_id"]
        preview = self.challenge["preview"]
        sequence = self.before_sequence + 1
        self.assertEqual(self.remembered["authority"], "data")
        self.assertEqual(self.remembered["recorded_seq"], sequence)
        self.assertIsNone(self.remembered["supersedes"])
        self.assertIsNone(self.remembered["conflict_id"])
        self.assertEqual(self.retained_rows(db), self.retained)
        for table, count in self.counts.items():
            delta = 0 if table in ("reviews", "proposals") else 3 if table == "attestations" else 1
            self.assertEqual(db.execute("SELECT count(*) FROM " + table).fetchone()[0], count + delta, table)
        self.assertEqual(db.execute("SELECT value FROM sequence").fetchone()[0], sequence)
        thread = dict(db.execute("SELECT * FROM claim_threads WHERE id=?",
                                 (self.remembered["memory_id"],)).fetchone())
        for field, expected in dict(subject=SUBJECT, project_id=self.fx.project,
                                    scope_id=preview["scope"]["id"], created_seq=sequence,
                                    created_at=KERNEL_TIME).items():
            self.assertEqual(thread[field], expected, field)
        row = dict(db.execute("SELECT * FROM assertion_versions WHERE id=?", (assertion,)).fetchone())
        expected_fields = dict(thread_id=thread["id"], project_id=self.fx.project, body=BODY,
            admission="accepted", epistemic="asserted", lifecycle="active", authority="data",
            created_by="user_control", ingest_seq=sequence, recorded_at=KERNEL_TIME,
            retired_seq=None, retired_at=None, classification="confidential",
            retention="2028-01-01T00:00:00.000000Z", valid_precision="interval",
            valid_from="2026-12-01T00:00:00.000000Z", valid_to="2027-02-01T00:00:00.000000Z")
        for field, expected in expected_fields.items():
            self.assertEqual(row[field], expected, field)
        self.assertEqual({item[0] for item in db.execute(
            "SELECT provider FROM assertion_disclosures WHERE assertion_id=?", (assertion,))}, {"codex", "claude"})
        evidence = dict(db.execute("SELECT * FROM evidence WHERE id=?", (row["evidence_id"],)).fetchone())
        for field, expected in dict(body=EVIDENCE, locator="fixture:owner-original", project_id=self.fx.project,
                                    trust_tier="user_authored", source_agent="user_control",
                                    observed_at=KERNEL_TIME, created_seq=sequence).items():
            self.assertEqual(evidence[field], expected, field)
        self.assertEqual(evidence["body_fingerprint"], store.keyed_digest("evidence-body", EVIDENCE))
        self.assertEqual([tuple(item) for item in db.execute(
            "SELECT evidence_id FROM evidence_refs WHERE assertion_id=?", (assertion,))], [(row["evidence_id"],)])
        self.assertEqual({tuple(item) for item in db.execute(
            "SELECT principal,role,method FROM attestations WHERE assertion_id=?", (assertion,))}, {
                ("user_control", "author", "terminal"), ("memoryd", "recorder", "serialized_writer"),
                ("user_control", "authorizer", "prototype_terminal_grant")})
        consent = db.execute("SELECT * FROM consent_receipts WHERE assertion_id=?", (assertion,)).fetchall()
        self.assertEqual(len(consent), 1)
        for field, expected in dict(payload_digest=digest_json(preview), scope_id=preview["scope"]["id"],
                                    classification="confidential", retention=row["retention"],
                                    policy_version=preview["policy_version"], authorized_at=KERNEL_TIME).items():
            self.assertEqual(consent[0][field], expected, field)
        self.assertEqual(set(json.loads(consent[0]["disclosure_json"])), {"codex", "claude"})
        self.assertEqual(json.loads(consent[0]["evidence_ids_json"]), [row["evidence_id"]])
        provenance = db.execute("SELECT * FROM provenance_activities WHERE target_id=?", (assertion,)).fetchall()
        self.assertEqual(len(provenance), 1)
        self.assertEqual((provenance[0]["activity_type"], provenance[0]["actor"],
                          json.loads(provenance[0]["input_ids_json"])), ("user_remember", "user_control", []))
        self.assertEqual(provenance[0]["output_fingerprint"], store.keyed_digest("assertion-output", BODY))
        self.assertEqual([tuple(item) for item in db.execute(
            "SELECT actor_kind,operation,scoped_id,target_id FROM audit_events WHERE event_seq=?", (sequence,))],
            [("user_control", "assertion_accepted", self.fx.project, assertion)])
        self.assertEqual([item[0] for item in db.execute(
            "SELECT assertion_id FROM assertion_fts WHERE assertion_fts MATCH 'remembercrashcanary'")], [assertion])
        for provider in self.agents:
            self.assertEqual([tuple(item) for item in db.execute(
                "SELECT local_seq,recorded_seq FROM audience_sequences WHERE project_id=? AND provider=? "
                "AND local_seq>?", (self.fx.project, provider, self.audiences[provider]))],
                [(self.audiences[provider] + 1, sequence)])
        for original in self.original_recalls:
            self.assertEqual(dict(db.execute("SELECT * FROM recalls WHERE id=?", (original["id"],)).fetchone()), original)
        locator = {"nonce": self.challenge["nonce"], "preview_digest": self.challenge["preview_digest"]}
        self.assertEqual(kernel.admin_result(control, locator)["operation"], "remember")
        for provider, original in self.agents.items():
            capability = store.authenticate(original["token"])
            # A reviewed memory is still data; neither it nor a captured owner
            # grant may promote an agent to administrative/receipt authority.
            before_denied = snapshot(db)
            for method, params in (
                (kernel.admin_preview, {"operation": "remember", "project": self.fx.project}),
                (kernel.admin_apply, fixture_params(control, self.challenge)),
                (kernel.admin_result, locator),
            ):
                with self.assertRaises(MemoryError) as denied:
                    method(capability, params)
                self.assertEqual(denied.exception.code, "forbidden")
                self.assertEqual(snapshot(db), before_denied)
            with self.assertRaises(MemoryError) as prior_recall:
                kernel.get(capability, {"recall_id": self.recalls[provider], "ids": [assertion]})
            self.assertEqual(prior_recall.exception.code, "not_found")
            recalled = kernel.search(capability, {"query": SUBJECT})
            self.assertEqual([card["version_id"] for card in recalled["cards"]], [assertion])
            result = kernel.get(capability, {"recall_id": recalled["recall_id"], "ids": [assertion]})
            self.assertEqual(len(result["records"]), 1)
            record = result["records"][0]
            self.assertEqual((record["claim"], record["evidence"]["body"], record["authority"]), (BODY, EVIDENCE, "data"))
            self.assertEqual(record["evidence"]["trust_tier"], "user_authored")
            beta = store.authenticate(self.beta_agents[provider]["token"])
            other = kernel.search(beta, {"query": SUBJECT})
            self.assertEqual(other["cards"], [])
            with self.assertRaises(MemoryError) as cross_project:
                kernel.get(beta, {"recall_id": other["recall_id"], "ids": [assertion]})
            self.assertEqual(cross_project.exception.code, "not_found")

    def test_every_remember_write_commit_and_anchor_exit_recovers_atomically(self):
        self.seed()
        reference = self.copied_vault("completed")
        recorded = self.run_child(reference)
        self.remembered = recorded["result"]
        # Source-reviewed inventory; never infer the expected trace from the run.
        self.assertEqual(recorded["boundaries"], BOUNDARIES)
        self.assert_crash_matrix(reference, recorded, self.assert_remembered_semantics)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--crash-child":
        remember_child(Path(sys.argv[2]), int(sys.argv[3]), json.loads(sys.stdin.buffer.read()))
    else:
        unittest.main()
