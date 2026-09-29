"""Held source-only crash-test preparation; not executed on this candidate.

Imported from MAIN 4b1eaf5. The original plaintext fixture description below
is historical context, not encrypted runtime or platform acceptance. Execution
requires separately approved native inputs and remains held.

Actual agent-read-triggered retention expiry under bounded process death.

Plaintext SQLite, POSIX processes and synthetic approval only. This is not
physical erasure, native Windows, encryption, rotation or backup-freshness proof.
"""

import json
import os
import sys
import unittest
from pathlib import Path

from continuum_memory.errors import MemoryError
from continuum_memory.security import canonical_json, read_private
from continuum_memory.storage import load_capability, paths
from tests.admin_crash_support import snapshot
from tests.lifecycle_crash_support import LifecycleCrashFixture, run_lifecycle_child


QUERY = "retentioncrash"
SUBJECT = QUERY + " conflicting decision"
EXPIRED_AT = "2027-01-03T00:00:00.000000Z"
CONFLICT = "cnf_retention_legacy_fixture"
KEPT_CONFLICT = "cnf_retention_kept_fixture"
BETA_CONFLICT = "cnf_retention_beta_fixture"
BOUNDARIES = [
    "write:sequence", "write:assertion_versions", "write:audience_sequences", "write:audit_events",
    "write:sequence", "write:assertion_versions", "write:audience_sequences", "write:audience_sequences",
    "write:audit_events", "write:conflicts", "before_commit_1", "after_commit_1",
    "before_anchor_publish", "after_anchor_publish", "before_commit_2", "after_commit_2",
]


def expire_via_agent_status(kernel, _control, request):
    # Derive the capability from this copied vault, never the original seed.
    capability_file = paths(kernel.store.data_dir)["caps"] / (request["project"] + ".codex.cap")
    capability = kernel.store.authenticate(load_capability(capability_file)["token"])
    if capability["project_id"] != request["project"] or capability["provider"] != "codex":
        raise AssertionError("Synthetic retention trigger has the wrong project/provider")
    return kernel.status(capability, {})


@unittest.skipIf(os.name == "nt", "POSIX process-exit matrix; native Windows acceptance is separate")
class RetentionProcessCrashTest(LifecycleCrashFixture, unittest.TestCase):
    child_module = "tests.test_retention_crash"

    def setUp(self):
        self.setup_crash_fixture("continuum-retention-crash-")
        self.agents = {provider: self.fx.agent("alpha", provider) for provider in ("codex", "claude")}

    def seed(self):
        self.due = []
        for index, disclosure in enumerate((["codex"], ["codex", "claude"]), 1):
            result = self.fx.approve("remember", subject=SUBJECT,
                claim=QUERY + " due decision %d" % index,
                evidence=QUERY + " retained evidence %d" % index,
                evidence_locator="fixture:retention-%d" % index,
                retention="2027-01-02" if index == 1 else "2027-01-03", disclosure=disclosure)
            self.due.append(result)
        self.assertEqual(self.due[0]["memory_id"], self.due[1]["memory_id"])
        self.assertIsNotNone(self.due[1]["conflict_id"])
        self.kept = self.fx.approve("remember", subject=QUERY + " forever survivor",
            claim=QUERY + " forever retained claim", evidence=QUERY + " forever evidence",
            disclosure=["codex", "claude"])
        self.kept_other = self.fx.approve("remember", subject=QUERY + " forever survivor",
            claim=QUERY + " alternate forever claim", evidence=QUERY + " alternate forever evidence",
            disclosure=["codex", "claude"])
        self.assertEqual(self.kept["memory_id"], self.kept_other["memory_id"])
        self.future = self.fx.approve("remember", subject=QUERY + " future survivor",
            claim=QUERY + " future retained claim", evidence=QUERY + " future evidence",
            retention="2027-02-01", disclosure=["codex", "claude"])
        self.beta = self.fx.approve("remember", project=self.fx.projects["beta"]["id"],
            subject=QUERY + " other project", claim=QUERY + " beta still active",
            evidence=QUERY + " beta evidence", retention="2027-01-02", disclosure=["codex", "claude"])
        self.beta_other = self.fx.approve("remember", project=self.fx.projects["beta"]["id"],
            subject=QUERY + " other project", claim=QUERY + " alternate beta still active",
            evidence=QUERY + " alternate beta evidence", retention="2027-01-02", disclosure=["codex", "claude"])
        self.assertEqual(self.beta["memory_id"], self.beta_other["memory_id"])
        self.retired = self.fx.approve("remember", subject=QUERY + " already retired control",
            claim=QUERY + " superseded before expiry", evidence=QUERY + " superseded evidence",
            retention="2027-01-02", disclosure=["codex", "claude"])
        self.replacement = self.fx.approve("correct", target_id=self.retired["assertion_id"],
            claim=QUERY + " forever corrected replacement", evidence=QUERY + " corrected evidence",
            retention="forever", disclosure=["codex", "claude"])
        self.fx.kernel.propose(self.fx.codex, self.fx.delivery(
            subject="unrelated pending", claim="keeper pending draft", evidence="keeper pending evidence",
            idempotency_key="retention-unrelated-pending", retention="forever"))

        db = self.fx.store.connection
        self.due_ids = [item["assertion_id"] for item in self.due]
        self.old_versions = {identifier: dict(db.execute("SELECT * FROM assertion_versions WHERE id=?",
                                                        (identifier,)).fetchone()) for identifier in self.due_ids}
        for index, identifier in enumerate(self.due_ids):
            row = self.old_versions[identifier]
            self.assertEqual(row["lifecycle"], "active")
            self.assertIsNone(row["retired_at"])
            self.assertIsNone(row["retired_seq"])
            self.assertEqual(row["retention"], "2027-01-0%dT00:00:00.000000Z" % (index + 2))
            disclosure = {item[0] for item in db.execute(
                "SELECT provider FROM assertion_disclosures WHERE assertion_id=?", (identifier,))}
            self.assertEqual(disclosure, {"codex"} if index == 0 else {"codex", "claude"})

        # Modern conflict projection is derived from the real active versions
        # above. This stored cache is explicitly synthetic legacy state, not
        # current API output or migration evidence; it exercises resolution.
        self.fx.store.begin()
        for conflict_id, project, pair in (
                (CONFLICT, self.fx.project, self.due),
                (KEPT_CONFLICT, self.fx.project, (self.kept, self.kept_other)),
                (BETA_CONFLICT, self.fx.projects["beta"]["id"], (self.beta, self.beta_other))):
            db.execute("INSERT INTO conflicts VALUES (?,?,?,'open',?,NULL)",
                       (conflict_id, project, pair[0]["memory_id"], pair[1]["recorded_seq"]))
            for item in pair:
                row = db.execute("SELECT lifecycle,retired_seq FROM assertion_versions WHERE id=?",
                                 (item["assertion_id"],)).fetchone()
                self.assertEqual(tuple(row), ("active", None))
                db.execute("INSERT INTO conflict_members VALUES (?,?)", (conflict_id, item["assertion_id"]))
        self.fx.store.commit()
        self.old_conflict = dict(db.execute("SELECT * FROM conflicts WHERE id=?", (CONFLICT,)).fetchone())
        retired = db.execute("SELECT lifecycle,retired_seq,retention FROM assertion_versions WHERE id=?",
                             (self.retired["assertion_id"],)).fetchone()
        self.assertEqual(tuple(retired), ("superseded", self.replacement["recorded_seq"],
                                          "2027-01-02T00:00:00.000000Z"))
        self.survivor_ids = {item["assertion_id"] for item in (
            self.kept, self.kept_other, self.future, self.replacement)}

        self.recalls = {}
        for provider, capability in self.agents.items():
            for mode in ("current", "history"):
                expected = self.visible_due(provider) | self.survivor_ids
                if mode == "history":
                    expected.add(self.retired["assertion_id"])
                recalled = self.fx.kernel.search(capability, {"query": QUERY, "temporal_mode": mode})
                self.assertEqual({card["version_id"] for card in recalled["cards"]}, expected)
                self.assertTrue(recalled["cards"])
                self.recalls[provider, mode] = recalled["recall_id"]
        self.original_recall_ids = list(self.recalls.values())
        # This matrix isolates expiry: proposal-purge work must not open a
        # preceding transaction or account for any of the observed boundaries.
        self.assertEqual(db.execute("SELECT count(*) FROM proposals WHERE project_id=? AND "
            "(status='rejected' OR (retention!='forever' AND retention<=?))",
            (self.fx.project, EXPIRED_AT)).fetchone()[0], 0)
        self.challenge = {"project": self.fx.project}
        self.before_sequence = db.execute("SELECT value FROM sequence").fetchone()[0]
        self.audiences = {provider: db.execute(
            "SELECT max(local_seq) FROM audience_sequences WHERE project_id=? AND provider=?",
            (self.fx.project, provider)).fetchone()[0] for provider in self.agents}
        self.retained = self.retained_rows(db)
        for name, rows in self.retained.items():
            self.assertTrue(rows, "Retained-state assertion would be vacuous: " + name)
        self.original = snapshot(db)
        self.old_anchor = read_private(paths(self.fx.home)["audit_head"])
        self.assert_integrity(self.fx.store)
        self.fx.store.close()
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse(os.path.lexists(str(paths(self.fx.home)["db"]) + suffix))

    def visible_due(self, provider):
        return set(self.due_ids if provider == "codex" else self.due_ids[1:])

    def retained_rows(self, db):
        statements = {
            "unrelated_versions": ("SELECT * FROM assertion_versions WHERE id NOT IN (?,?) ORDER BY id", self.due_ids),
            "unaffected_conflicts": ("SELECT * FROM conflicts WHERE id IN (?,?) ORDER BY id",
                (KEPT_CONFLICT, BETA_CONFLICT)),
            "prior_audit": ("SELECT * FROM audit_events WHERE event_seq<=? ORDER BY audit_seq",
                (self.before_sequence,)),
            "beta_audiences": ("SELECT * FROM audience_sequences WHERE project_id=? ORDER BY provider,local_seq",
                (self.fx.projects["beta"]["id"],)),
            "old_recalls": ("SELECT * FROM recalls WHERE id IN (?,?,?,?) ORDER BY id", self.original_recall_ids),
        }
        # All rows of these tables must survive retention. In particular expiry
        # does not physically erase evidence, alter consent, or create a new
        # human approval / administrative result merely because an agent reads.
        for table in ("projects", "scopes", "capabilities", "claim_threads", "evidence", "evidence_refs",
                      "assertion_disclosures", "assertion_fts", "attestations", "consent_receipts",
                      "provenance_activities", "proposals", "admin_results", "admin_challenges", "conflict_members",
                      "relations"):
            statements[table] = ("SELECT * FROM " + table, ())
        return {name: sorted([dict(row) for row in db.execute(sql, args)], key=canonical_json)
                for name, (sql, args) in statements.items()}

    def assert_expired_semantics(self, store, kernel, _control):
        db = store.connection
        self.assertEqual(self.retained_rows(db), self.retained)
        self.assertEqual(db.execute("SELECT value FROM sequence").fetchone()[0], self.before_sequence + 2)
        self.assertEqual(db.execute("SELECT count(*) FROM assertion_versions").fetchone()[0], 9)
        for offset, identifier in enumerate(self.due_ids, 1):
            self.assertEqual(dict(db.execute("SELECT * FROM assertion_versions WHERE id=?", (identifier,)).fetchone()),
                dict(self.old_versions[identifier], lifecycle="expired", retired_at=EXPIRED_AT,
                     retired_seq=self.before_sequence + offset))
        self.assertEqual(dict(db.execute("SELECT * FROM conflicts WHERE id=?", (CONFLICT,)).fetchone()),
                         dict(self.old_conflict, status="resolved", resolved_seq=self.before_sequence + 2))
        self.assertEqual([tuple(row) for row in db.execute(
            "SELECT event_seq,actor_kind,operation,scoped_id,target_id,occurred_at FROM audit_events "
            "WHERE event_seq>? ORDER BY event_seq", (self.before_sequence,))], [
                (self.before_sequence + index, "retention_policy", "assertion_expired", self.fx.project,
                 identifier, EXPIRED_AT) for index, identifier in enumerate(self.due_ids, 1)])
        for provider in self.agents:
            offsets = (1, 2) if provider == "codex" else (2,)
            self.assertEqual([tuple(row) for row in db.execute(
                "SELECT local_seq,recorded_seq FROM audience_sequences WHERE project_id=? AND provider=? "
                "AND local_seq>? ORDER BY local_seq", (self.fx.project, provider, self.audiences[provider]))],
                [(self.audiences[provider] + index, self.before_sequence + offset)
                 for index, offset in enumerate(offsets, 1)])

        # Real status re-entry must be a read-only fixed point, including when
        # invoked by the provider that could see only the second due version.
        before_reads = snapshot(db)
        anchor = read_private(paths(store.data_dir)["audit_head"])
        for provider, original in self.agents.items():
            capability = store.authenticate(original["token"])
            first = kernel.status(capability, {})
            self.assertEqual(kernel.status(capability, {}), first)
            self.assertEqual(first["projection_watermark"], self.audiences[provider] + len(self.visible_due(provider)))
            self.assertEqual(snapshot(db), before_reads)
            self.assertEqual(read_private(paths(store.data_dir)["audit_head"]), anchor)

        survivors = self.survivor_ids
        for provider, original in self.agents.items():
            capability = store.authenticate(original["token"])
            visible = self.visible_due(provider)
            for identifier in self.due_ids:
                with self.assertRaises(MemoryError) as current_missing:
                    kernel.get(capability, {"recall_id": self.recalls[provider, "current"], "ids": [identifier]})
                self.assertEqual(current_missing.exception.code, "not_found")
                if identifier not in visible:
                    with self.assertRaises(MemoryError) as never_disclosed:
                        kernel.get(capability, {"recall_id": self.recalls[provider, "history"], "ids": [identifier]})
                    self.assertEqual(never_disclosed.exception.code, "not_found")
                    continue
                record = kernel.get(capability, {
                    "recall_id": self.recalls[provider, "history"], "ids": [identifier]})["records"][0]
                self.assertEqual((record["claim"], record["lifecycle"], record["authority"]),
                                 (self.old_versions[identifier]["body"], "expired", "data"))
                original_evidence = next(row for row in self.retained["evidence"]
                                         if row["id"] == self.old_versions[identifier]["evidence_id"])
                self.assertEqual(record["evidence"]["body"], original_evidence["body"])
            current = kernel.search(capability, {"query": QUERY})
            self.assertEqual({card["version_id"] for card in current["cards"]}, survivors)
            historical = kernel.search(capability, {"query": QUERY, "temporal_mode": "history"})
            self.assertEqual({card["version_id"] for card in historical["cards"]},
                             survivors | visible | {self.retired["assertion_id"]})
            self.assertEqual({card["version_id"] for card in historical["cards"] if card["lifecycle"] == "expired"},
                             visible)
            self.assertNotIn(self.beta["assertion_id"], {card["version_id"] for card in historical["cards"]})
            self.assertNotIn(self.beta_other["assertion_id"], {card["version_id"] for card in historical["cards"]})

    def test_every_expiry_write_commit_and_anchor_exit_preserves_complete_lifecycle(self):
        self.seed()
        reference = self.copied_vault("completed")
        recorded = self.run_child(reference)
        # Source-reviewed inventory; never derive expected points from a run.
        self.assertEqual(recorded["boundaries"], BOUNDARIES)
        self.assertEqual(recorded["result"]["provider"], "codex")
        self.assertEqual(recorded["result"]["project_bound"], self.fx.project)
        self.assertEqual(recorded["result"]["projection_watermark"], self.audiences["codex"] + 2)
        self.assert_lifecycle_crash_matrix(reference, recorded, self.assert_expired_semantics)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--crash-child":
        run_lifecycle_child(Path(sys.argv[2]), int(sys.argv[3]), json.loads(sys.stdin.buffer.read()),
                            expire_via_agent_status)
    else:
        unittest.main()

