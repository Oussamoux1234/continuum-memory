"""Real process death across one approved, audience-narrowing correction.

Plaintext SQLite process-crash evidence only: no native encryption, privileged
approval, host power-loss, key rotation, backup or physical-erasure claim.
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


SUBJECT = "correctioncanary decision"
OLD_BODY = "correctionold original decision"
NEW_BODY = "correctionnew revised decision"
NEW_EVIDENCE = "correctionnew reviewed evidence"
KERNEL_TIME = "2027-01-01T00:00:00.000000Z"
PREFIXES = ["evd", "asr", "att", "att", "att", "cns", "prv", "rel"]


def correction_child(home, crash_after, challenge):
    counts = Counter()

    def correction_id(prefix):
        if prefix not in PREFIXES:
            raise AssertionError("Unexpected identifier generation outside the correction fixture")
        counts[prefix] += 1
        return "%s_correction_crash_%d" % (prefix, counts[prefix])

    apply_child(home, crash_after, challenge, correction_id, PREFIXES)


class CorrectionProcessCrashTest(AdminCrashFixture, unittest.TestCase):
    child_module = "tests.test_correction_crash"

    def setUp(self):
        self.setup_crash_fixture("continuum-correction-crash-")
        self.agents = {provider: self.fx.agent("alpha", provider) for provider in ("codex", "claude")}
        self.recalls = {}

    def seed(self):
        proposal = self.fx.kernel.propose(self.fx.codex, self.fx.delivery(
            subject=SUBJECT, claim=OLD_BODY, evidence="correctionold agent evidence",
            source_handle="fixture:original-agent", disclosure=["codex", "claude"]))
        self.old = self.fx.approve("accept_proposal", proposal_id=proposal["proposal_id"])
        self.kept = self.fx.approve("remember", subject="unrelated alpha", claim="keeper alpha claim",
                                   evidence="keeper alpha evidence", disclosure=["codex", "claude"])
        self.beta = self.fx.approve("remember", project=self.fx.projects["beta"]["id"],
                                   subject="unrelated beta", claim="keeper beta claim",
                                   evidence="keeper beta evidence", disclosure=["codex", "claude"])
        for provider, capability in self.agents.items():
            for mode in ("current", "history"):
                recall = self.fx.kernel.search(capability, {"query": SUBJECT, "temporal_mode": mode})
                self.assertEqual([card["version_id"] for card in recall["cards"]], [self.old["assertion_id"]])
                self.recalls[provider, mode] = recall["recall_id"]
            pinned = self.fx.kernel.search(capability, {
                "query": SUBJECT, "as_of_recorded": recall["projection_watermark"]})
            self.assertEqual([card["version_id"] for card in pinned["cards"]], [self.old["assertion_id"]])
            self.recalls[provider, "snapshot"] = pinned["recall_id"]
        self.challenge = self.fx.preview("correct", target_id=self.old["assertion_id"],
            claim=NEW_BODY, evidence=NEW_EVIDENCE, evidence_locator="fixture:owner-correction",
            disclosure=["codex"])
        db = self.fx.store.connection
        self.old_row = dict(db.execute("SELECT * FROM assertion_versions WHERE id=?",
                                       (self.old["assertion_id"],)).fetchone())
        self.before_sequence = db.execute("SELECT value FROM sequence").fetchone()[0]
        self.audiences = {provider: db.execute(
            "SELECT max(local_seq) FROM audience_sequences WHERE project_id=? AND provider=?",
            (self.fx.project, provider)).fetchone()[0] for provider in self.agents}
        self.retained = self.retained_rows(db)
        self.original_recalls = [dict(row) for row in db.execute("SELECT * FROM recalls ORDER BY id")]
        self.original = snapshot(db)
        self.old_anchor = read_private(paths(self.fx.home)["audit_head"])
        self.assert_integrity(self.fx.store)
        # Deterministic new IDs must never replace/collide with seed identifiers.
        self.assertNotIn("_correction_crash_", "\n".join(self.original))
        self.fx.store.close()
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse(os.path.lexists(str(paths(self.fx.home)["db"]) + suffix))

    def retained_rows(self, db):
        ids = [self.old["assertion_id"], self.kept["assertion_id"], self.beta["assertion_id"]]
        statements = {
            "threads": ("SELECT * FROM claim_threads ORDER BY id", ()),
            "unrelated_versions": ("SELECT * FROM assertion_versions WHERE id IN (?,?) ORDER BY id", ids[1:]),
            "evidence": ("SELECT * FROM evidence WHERE id IN (SELECT evidence_id FROM assertion_versions "
                         "WHERE id IN (?,?,?)) ORDER BY id", ids),
            "provenance": ("SELECT * FROM provenance_activities WHERE target_id IN (?,?,?) ORDER BY id", ids),
            "proposals": ("SELECT * FROM proposals ORDER BY id", ()),
            "reviews": ("SELECT * FROM reviews ORDER BY id", ()),
            "beta_audiences": ("SELECT * FROM audience_sequences WHERE project_id=? ORDER BY provider,local_seq",
                               (self.fx.projects["beta"]["id"],)),
        }
        for table in ("assertion_disclosures", "evidence_refs", "attestations", "consent_receipts", "assertion_fts"):
            statements[table] = ("SELECT * FROM " + table + " WHERE assertion_id IN (?,?,?)", ids)
        return {name: sorted([dict(row) for row in db.execute(sql, args)], key=canonical_json)
                for name, (sql, args) in statements.items()}

    def assert_corrected_semantics(self, store, kernel, control):
        db = store.connection
        old_id, new_id = self.old["assertion_id"], self.corrected["assertion_id"]
        sequence = self.before_sequence + 1
        self.assertEqual(self.corrected["memory_id"], self.old["memory_id"])
        self.assertEqual(self.corrected["supersedes"], old_id)
        self.assertEqual(self.corrected["recorded_seq"], sequence)
        self.assertEqual(self.corrected["authority"], "data")
        self.assertIsNone(self.corrected["conflict_id"])
        self.assertEqual(self.retained_rows(db), self.retained)
        self.assertEqual(dict(db.execute("SELECT * FROM assertion_versions WHERE id=?", (old_id,)).fetchone()),
                         dict(self.old_row, lifecycle="superseded", retired_at=KERNEL_TIME, retired_seq=sequence))
        new = dict(db.execute("SELECT * FROM assertion_versions WHERE id=?", (new_id,)).fetchone())
        self.assertEqual([tuple(row) for row in db.execute(
            "SELECT id FROM assertion_versions WHERE thread_id=? ORDER BY ingest_seq", (self.old["memory_id"],))],
            [(old_id,), (new_id,)])
        for field, expected in dict(thread_id=self.old["memory_id"], project_id=self.fx.project,
                                    body=NEW_BODY, admission="accepted", epistemic="asserted", lifecycle="active",
                                    authority="data", created_by="user_control", ingest_seq=sequence,
                                    recorded_at=KERNEL_TIME, retired_seq=None, retired_at=None).items():
            self.assertEqual(new[field], expected, field)
        for field in ("classification", "retention", "valid_precision", "valid_from", "valid_to"):
            self.assertEqual(new[field], self.old_row[field], field)
        self.assertEqual([tuple(row) for row in db.execute(
            "SELECT provider FROM assertion_disclosures WHERE assertion_id=?", (new_id,))], [("codex",)])
        evidence = dict(db.execute("SELECT * FROM evidence WHERE id=?", (new["evidence_id"],)).fetchone())
        for field, expected in dict(body=NEW_EVIDENCE, locator="fixture:owner-correction", project_id=self.fx.project,
                                    trust_tier="user_authored", source_agent="user_control",
                                    observed_at=KERNEL_TIME, created_seq=sequence).items():
            self.assertEqual(evidence[field], expected, field)
        self.assertEqual(evidence["body_fingerprint"], store.keyed_digest("evidence-body", NEW_EVIDENCE))
        self.assertEqual([tuple(row) for row in db.execute(
            "SELECT evidence_id FROM evidence_refs WHERE assertion_id=?", (new_id,))], [(new["evidence_id"],)])
        self.assertEqual({tuple(row) for row in db.execute(
            "SELECT principal,role,method FROM attestations WHERE assertion_id=?", (new_id,))}, {
                ("user_control", "author", "terminal"), ("memoryd", "recorder", "serialized_writer"),
                ("user_control", "authorizer", "prototype_terminal_grant")})
        consent = db.execute("SELECT * FROM consent_receipts WHERE assertion_id=?", (new_id,)).fetchall()
        self.assertEqual(len(consent), 1)
        self.assertEqual(consent[0]["payload_digest"], digest_json(self.challenge["preview"]))
        self.assertEqual(json.loads(consent[0]["disclosure_json"]), ["codex"])
        self.assertEqual(json.loads(consent[0]["evidence_ids_json"]), [new["evidence_id"]])
        provenance = db.execute("SELECT * FROM provenance_activities WHERE target_id=?", (new_id,)).fetchall()
        self.assertEqual(len(provenance), 1)
        self.assertEqual((provenance[0]["activity_type"], provenance[0]["actor"],
                          json.loads(provenance[0]["input_ids_json"])), ("user_correction", "user_control", [old_id]))
        self.assertEqual(provenance[0]["output_fingerprint"], store.keyed_digest("assertion-output", NEW_BODY))
        self.assertEqual([tuple(row) for row in db.execute(
            "SELECT project_id,from_assertion_id,to_assertion_id,kind,created_seq FROM relations")],
            [(self.fx.project, new_id, old_id, "supersedes", sequence)])
        for provider in self.agents:
            self.assertEqual([tuple(row) for row in db.execute(
                "SELECT local_seq,recorded_seq FROM audience_sequences WHERE project_id=? AND provider=? "
                "AND local_seq>?", (self.fx.project, provider, self.audiences[provider]))],
                [(self.audiences[provider] + 1, sequence)])
        self.assertEqual(db.execute("SELECT value FROM sequence").fetchone()[0], sequence)
        for query, expected in (("correctionold", old_id), ("correctionnew", new_id)):
            self.assertEqual([row[0] for row in db.execute(
                "SELECT assertion_id FROM assertion_fts WHERE assertion_fts MATCH ?", (query,))], [expected])
        # Correction does not rewrite prior delivery records or their authority.
        for original in self.original_recalls:
            self.assertEqual(dict(db.execute("SELECT * FROM recalls WHERE id=?", (original["id"],)).fetchone()), original)
        history = kernel.show(control, {"project": self.fx.project, "id": self.old["memory_id"], "history": True})
        self.assertEqual({row["version_id"] for row in history["versions"]}, {old_id, new_id})
        for provider, original in self.agents.items():
            capability = store.authenticate(original["token"])
            for mode in ("current", "history"):
                expected = {new_id} if mode == "current" else {old_id, new_id}
                if provider == "claude":
                    expected = set() if mode == "current" else {old_id}
                recalled = kernel.search(capability, {"query": SUBJECT, "temporal_mode": mode})
                self.assertEqual({row["version_id"] for row in recalled["cards"]}, expected)
                with self.assertRaises(MemoryError) as never_authorized:
                    kernel.get(capability, {"recall_id": self.recalls[provider, mode], "ids": [new_id]})
                self.assertEqual(never_authorized.exception.code, "not_found")
            with self.assertRaises(MemoryError) as superseded:
                kernel.get(capability, {"recall_id": self.recalls[provider, "current"], "ids": [old_id]})
            self.assertEqual(superseded.exception.code, "not_found")
            historical = kernel.get(capability, {"recall_id": self.recalls[provider, "history"], "ids": [old_id]})
            self.assertEqual(historical["records"][0]["claim"], OLD_BODY)
            self.assertEqual(historical["records"][0]["evidence"]["body"], "correctionold agent evidence")
            pinned = kernel.get(capability, {"recall_id": self.recalls[provider, "snapshot"], "ids": [old_id]})
            self.assertEqual(pinned["records"][0]["claim"], OLD_BODY)
            self.assertEqual(pinned["records"][0]["lifecycle"], "active")
            with self.assertRaises(MemoryError) as not_in_snapshot:
                kernel.get(capability, {"recall_id": self.recalls[provider, "snapshot"], "ids": [new_id]})
            self.assertEqual(not_in_snapshot.exception.code, "not_found")
            if provider == "claude":
                self.assertNotIn(NEW_BODY, canonical_json(recalled))
                self.assertNotIn(NEW_EVIDENCE, canonical_json(historical))

    def test_every_correction_write_commit_and_anchor_exit_recovers_atomically(self):
        self.seed()
        reference = self.copied_vault("completed")
        recorded = self.run_child(reference)
        self.corrected = recorded["result"]
        # Exact successful trace independently reviewed before freezing. Changes
        # to SQL ordering/counts require deliberate inventory review, not a rerun.
        self.assertEqual(recorded["boundaries"], [
            "write:admin_challenges", "write:sequence", "write:evidence", "write:assertion_versions",
            "write:assertion_disclosures", "write:evidence_refs", "write:assertion_fts",
            "write:attestations", "write:attestations", "write:attestations", "write:consent_receipts",
            "write:provenance_activities", "write:assertion_versions", "write:relations",
            "write:audience_sequences", "write:audience_sequences", "write:audit_events", "write:admin_results",
            "before_commit_1", "after_commit_1", "before_anchor_publish", "after_anchor_publish",
            "before_commit_2", "after_commit_2"])
        self.assert_crash_matrix(reference, recorded, self.assert_corrected_semantics)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--crash-child":
        correction_child(Path(sys.argv[2]), int(sys.argv[3]), json.loads(sys.stdin.buffer.read()))
    else:
        unittest.main()
