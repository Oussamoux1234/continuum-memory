"""Real process death during one complete, approved synthetic thread forget.

The engine, cascades, FTS, audit MACs and receipts are real. Only fixture clocks,
the new deletion-receipt ID and the point of abrupt process exit are controlled.
This is plaintext SQLite/process-crash evidence, not physical erasure or backup
revocation, host power-loss durability, or native encrypted-provider evidence.
"""

import json
import os
import sys
import unittest
from collections import Counter
from pathlib import Path

from continuum_memory.errors import MemoryError
from continuum_memory.security import canonical_json, read_private
from continuum_memory.storage import paths
from tests.admin_crash_support import AdminCrashFixture, apply_child, snapshot


CANARY = "forgetcanary"


def forget_child(home, crash_after, challenge):
    def deletion_id(prefix):
        if prefix != "del":
            raise AssertionError("Unexpected identifier generation outside the forget fixture")
        return "del_forget_crash_fixture"

    apply_child(home, crash_after, challenge, deletion_id, ["del"])


class ThreadForgetProcessCrashTest(AdminCrashFixture, unittest.TestCase):
    child_module = "tests.test_forget_crash"

    def setUp(self):
        self.setup_crash_fixture("continuum-forget-crash-")
        self.deliveries = []
        self.recalls = {}
        self.agents = {provider: self.fx.agent("alpha", provider) for provider in ("codex", "claude")}

    def seed(self):
        first = self.fx.delivery(subject=CANARY + " subject", claim=CANARY + " original fixture",
            evidence=CANARY + " original evidence", source_handle=CANARY + " locator",
            idempotency_key=CANARY + "-accepted-delivery", disclosure=["codex", "claude"])
        self.deliveries.append(first)
        proposed = self.fx.kernel.propose(self.fx.codex, first)
        accepted = self.fx.approve("accept_proposal", proposal_id=proposed["proposal_id"])
        self.thread = accepted["memory_id"]
        corrected = self.fx.approve("correct", target_id=accepted["assertion_id"],
            claim=CANARY + " corrected fixture", evidence=CANARY + " correction evidence")
        conflict = self.fx.approve("remember", subject=first["subject"],
            claim=CANARY + " conflicting fixture", evidence=CANARY + " conflict evidence",
            disclosure=["codex", "claude"])
        self.assertEqual(conflict["memory_id"], self.thread)
        self.assertIsNotNone(conflict["conflict_id"])  # Real derived projection.
        self.targets = {result["assertion_id"] for result in (accepted, corrected, conflict)}
        # Modern conflicts are derived, not persisted. Seed valid legacy rows
        # before the approved deletion scope so their FK cascades are non-vacuous.
        # This is explicitly synthetic legacy state, not migration/API evidence.
        self.fx.store.begin()
        self.fx.store.connection.execute(
            "INSERT INTO conflicts VALUES ('cnf_legacy_fixture',?,?,'open',?,NULL)",
            (self.fx.project, self.thread, conflict["recorded_seq"]))
        for assertion in (corrected["assertion_id"], conflict["assertion_id"]):
            self.fx.store.connection.execute(
                "INSERT INTO conflict_members VALUES ('cnf_legacy_fixture',?)", (assertion,))
        self.fx.store.commit()
        self.kept = self.fx.approve("remember", subject="unrelated fixture",
            claim="keepcanary independent fixture", evidence="keepcanary independent evidence",
            disclosure=["codex", "claude"])
        other = self.fx.approve("remember", project=self.fx.projects["beta"]["id"],
            subject="other project", claim="keepcanary project isolation", evidence="keepcanary beta")
        self.kept_ids = [self.kept["assertion_id"], other["assertion_id"]]
        self.kept_threads = [self.kept["memory_id"], other["memory_id"]]
        pending = dict(first, idempotency_key=CANARY + "-pending-delivery", claim=CANARY + " pending body")
        self.deliveries.append(pending)
        self.fx.kernel.propose(self.fx.codex, pending)
        for provider, capability in self.agents.items():
            recall = self.fx.kernel.search(capability, {"query": "fixture", "temporal_mode": "history"})
            self.recalls[provider] = recall["recall_id"]
            recalled = {card["version_id"] for card in recall["cards"]}
            self.assertTrue(self.targets <= recalled)
            self.assertIn(self.kept["assertion_id"], recalled)
        for target in sorted(self.targets | {self.kept["assertion_id"]}):
            self.fx.kernel.feedback(self.fx.codex, {"recall_id": self.recalls["codex"],
                "item_id": target, "label": "wrong",
                "reason": (CANARY if target in self.targets else "keepcanary") + " feedback"})
        self.challenge = self.fx.preview("forget", target_id=self.thread)
        self.assert_integrity(self.fx.store)
        scope = self.challenge["preview"]["affected_set"]
        # Ensure every deletion/cascade assertion is exercised, not vacuously true.
        for field in ("threads", "versions", "attestations", "consent_receipts", "feedback", "disclosures",
                      "evidence_refs", "owned_evidence", "proposals", "reviews", "provenance_activities",
                      "relations", "conflicts", "conflict_members", "fts", "recalls_to_prune"):
            self.assertTrue(scope[field], field)
        self.assertEqual(len(scope["versions"]), 3)
        self.assertEqual(len(scope["proposals"]), 2)
        self.scope = scope
        self.retained = self.retained_rows(self.fx.store.connection)
        self.original_recalls = [dict(row) for row in self.fx.store.connection.execute("SELECT * FROM recalls")]
        self.original = snapshot(self.fx.store.connection)
        self.old_anchor = read_private(paths(self.fx.home)["audit_head"])
        self.fx.store.close()  # No live SQLite handle/WAL writer is copied.
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse(os.path.lexists(str(paths(self.fx.home)["db"]) + suffix))

    def retained_rows(self, db):
        # These are explicitly unrelated pre-existing objects, not a successful
        # forget implementation reused as the semantic oracle.
        statements = {
            "threads": ("SELECT * FROM claim_threads WHERE id IN (?,?)", self.kept_threads),
            "versions": ("SELECT * FROM assertion_versions WHERE id IN (?,?)", self.kept_ids),
            "evidence": ("SELECT * FROM evidence WHERE id IN (SELECT evidence_id FROM assertion_versions WHERE id IN (?,?))", self.kept_ids),
            "provenance": ("SELECT * FROM provenance_activities WHERE target_id IN (?,?)", self.kept_ids),
        }
        for table in ("assertion_disclosures", "evidence_refs", "attestations", "consent_receipts", "feedback", "assertion_fts"):
            statements[table] = ("SELECT * FROM " + table + " WHERE assertion_id IN (?,?)", self.kept_ids)
        return {name: sorted([dict(row) for row in db.execute(sql, args)], key=canonical_json)
                for name, (sql, args) in statements.items()}

    def assert_target_rows_erased(self, db):
        # Fixed reviewed table/column names; identifiers stay bound parameters.
        groups = {"threads": ("claim_threads", "id"), "versions": ("assertion_versions", "id"),
                  "owned_evidence": ("evidence", "id"), "proposals": ("proposals", "id"),
                  "reviews": ("reviews", "id"), "provenance_activities": ("provenance_activities", "id"),
                  "relations": ("relations", "id"), "conflicts": ("conflicts", "id"),
                  "attestations": ("attestations", "id"), "consent_receipts": ("consent_receipts", "id"),
                  "feedback": ("feedback", "id"), "disclosures": ("assertion_disclosures", "assertion_id"),
                  "evidence_refs": ("evidence_refs", "assertion_id"), "fts": ("assertion_fts", "assertion_id"),
                  "conflict_members": ("conflict_members", "assertion_id")}
        for name, (table, column) in groups.items():
            identifiers = {row[column] for row in self.scope[name]}
            self.assertTrue(identifiers, name)
            for identifier in identifiers:
                self.assertEqual(db.execute("SELECT count(*) FROM " + table + " WHERE " + column + "=?",
                                            (identifier,)).fetchone()[0], 0, name)
        for proposal in self.scope["proposals"]:
            rows = [tuple(row) for row in db.execute(
                "SELECT disposition FROM proposal_tombstones WHERE proposal_id=?", (proposal["id"],))]
            self.assertEqual(rows, [("forgotten",)])
        for original in self.original_recalls:
            expected = dict(original, result_ids_json=canonical_json([
                identifier for identifier in json.loads(original["result_ids_json"]) if identifier not in self.targets]))
            current = db.execute("SELECT * FROM recalls WHERE id=?", (original["id"],)).fetchone()
            self.assertEqual(dict(current), expected)
        self.assertEqual(self.retained_rows(db), self.retained)

    def assert_erased_without_resurrection(self, store, kernel, control):
        self.assert_target_rows_erased(store.connection)
        database = "\n".join(snapshot(store.connection))
        self.assertNotIn(CANARY, database)
        self.assertIn("keepcanary", database)
        self.assertEqual(store.connection.execute(
            "SELECT assertion_id FROM assertion_fts WHERE assertion_fts MATCH ?", (CANARY,)).fetchall(), [])
        for provider, original in self.agents.items():
            capability = store.authenticate(original["token"])
            for target in self.targets:
                with self.assertRaises(MemoryError) as missing:
                    kernel.get(capability, {"recall_id": self.recalls[provider], "ids": [target]})
                self.assertEqual(missing.exception.code, "not_found")
            kept = kernel.get(capability, {"recall_id": self.recalls[provider],
                                          "ids": [self.kept["assertion_id"]]})
            self.assertEqual(kept["records"][0]["claim"], "keepcanary independent fixture")
            for mode in ("current", "history"):
                self.assertEqual(kernel.search(capability, {"query": CANARY, "temporal_mode": mode})["cards"], [])
        for delivery in self.deliveries:
            before = snapshot(store.connection)
            with self.assertRaises(MemoryError) as suppressed:
                kernel.propose(store.authenticate(self.agents["codex"]["token"]), delivery)
            self.assertEqual(suppressed.exception.code, "delivery_suppressed")
            self.assertEqual(snapshot(store.connection), before)
        with self.assertRaises(MemoryError) as missing:
            kernel.show(control, {"project": self.fx.project, "id": self.thread, "history": True})
        self.assertEqual(missing.exception.code, "not_found")

    def test_every_forget_write_commit_anchor_and_checkpoint_exit_recovers_atomically(self):
        self.seed()
        reference = self.copied_vault("completed")
        recorded = self.run_child(reference)
        boundaries = recorded["boundaries"]
        expected_writes = {"admin_challenges", "sequence", "audience_sequences", "feedback", "recalls",
                           "assertion_fts", "provenance_activities", "proposal_tombstones", "proposals",
                           "claim_threads", "evidence", "deletion_receipts", "audit_events", "admin_results"}
        self.assertEqual({label[6:] for label in boundaries if label.startswith("write:")}, expected_writes)
        self.assertEqual(Counter(label for label in boundaries if label.startswith("write:")), {
            "write:admin_challenges": 1, "write:sequence": 1, "write:audience_sequences": 2,
            "write:feedback": 3, "write:recalls": 2, "write:assertion_fts": 3,
            "write:provenance_activities": 5, "write:proposal_tombstones": 2, "write:proposals": 2,
            "write:claim_threads": 1, "write:evidence": 3, "write:deletion_receipts": 1,
            "write:audit_events": 1, "write:admin_results": 1})
        self.assertEqual(boundaries.count("before_commit_1"), 1)
        self.assertEqual(boundaries[boundaries.index("before_commit_1"):], [
            "before_commit_1", "after_commit_1", "before_anchor_publish", "after_anchor_publish",
            "before_commit_2", "after_commit_2", "before_checkpoint", "after_checkpoint"])
        self.assert_crash_matrix(reference, recorded, self.assert_erased_without_resurrection)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--crash-child":
        forget_child(Path(sys.argv[2]), int(sys.argv[3]), json.loads(sys.stdin.buffer.read()))
    else:
        unittest.main()
