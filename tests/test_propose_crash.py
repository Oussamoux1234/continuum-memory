"""Held source-only crash-test preparation; not executed on this candidate.

Imported from MAIN 1e0bb0f. The original plaintext fixture description below
is historical context, not encrypted runtime or platform acceptance. Execution
requires separately approved native inputs and remains held.

Real process death during agent proposal creation, before owner acceptance.

Synthetic plaintext SQLite process-crash evidence only; not native Windows,
encrypted storage, OS-backed approval, host power loss or backup recovery.
"""

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum_memory import kernel as kernel_module, storage
from continuum_memory.errors import MemoryError
from continuum_memory.security import canonical_json, read_private
from continuum_memory.storage import Store, load_capability, paths
from tests.admin_crash_support import (
    AdminCrashFixture, BoundaryConnection, FIXED_TIME, fixture_kernel, snapshot,
)


SUBJECT = "proposecrashcanary decision"
BODY = "proposecrashcanary unreviewed project claim"
EVIDENCE = "proposecrashcanary original agent evidence"
LOCATOR = "fixture:propose-original"
DELIVERY_KEY = "propose-crash-delivery"
PROPOSAL_ID = "prp_propose_crash_1"
PROVENANCE_ID = "prv_propose_crash_1"
KERNEL_TIME = "2027-01-01T00:00:00.000000Z"
BOUNDARIES = [
    "write:sequence", "write:proposals", "write:provenance_activities", "write:audit_events",
    "before_commit_1", "after_commit_1", "before_anchor_publish", "after_anchor_publish",
    "before_commit_2", "after_commit_2",
]
REPLAY_BOUNDARIES = ["before_commit_1", "after_commit_1"]
CREATED = {"proposal_id": PROPOSAL_ID, "review_status": "proposed", "replayed": False}
REPLAYED = dict(CREATED, replayed=True)


def propose_child(home, crash_after, request):
    store = Store(home)
    try:
        capability = store.authenticate(load_capability(
            paths(home)["caps"] / request["capability_file"])["token"])
        observed = BoundaryConnection(store.connection, crash_after)
        store.connection = observed
        kernel = fixture_kernel(store)
        publish = store._sync_audit_head_raw

        def publish_anchor(connection, path):
            observed.tick("before_anchor_publish")
            publish(connection, path)
            observed.tick("after_anchor_publish")

        identifiers = {"prp": PROPOSAL_ID, "prv": PROVENANCE_ID}

        def proposal_id(prefix):
            if prefix not in identifiers:
                raise AssertionError("Unexpected proposal fixture identifier")
            return identifiers[prefix]

        # Only synthetic IDs/time and observation faultpoints are replaced.
        # Capability checks, proposal logic, SQLite and audit publication are real.
        with patch.object(kernel_module, "random_id", side_effect=proposal_id) as identifier, \
                patch.object(storage, "now_iso", return_value=FIXED_TIME), \
                patch.object(store, "_sync_audit_head_raw", side_effect=publish_anchor):
            try:
                result = kernel.propose(capability, request["delivery"])
            except MemoryError as exc:
                if exc.code != "idempotency_conflict":
                    raise
                outcome = {"error": exc.code}
                prefixes = ["prp"]
            else:
                outcome = {"result": result}
                prefixes = ["prp"] if result["replayed"] else ["prp", "prv"]
            if [call.args for call in identifier.call_args_list] != [(prefix,) for prefix in prefixes]:
                raise AssertionError("Unexpected proposal identifier inventory")
        print(json.dumps(dict(outcome, boundaries=observed.boundaries)), flush=True)
    finally:
        store.close()


@unittest.skipIf(os.name == "nt", "POSIX fixture; native Windows acceptance is separate")
class ProposalCreationProcessCrashTest(AdminCrashFixture, unittest.TestCase):
    child_module = "tests.test_propose_crash"

    def setUp(self):
        self.setup_crash_fixture("continuum-propose-crash-")
        self.environment["PYTHONWARNINGS"] = "error::ResourceWarning"
        self.agents = {(project, provider): self.fx.agent(project, provider)
                       for project in ("alpha", "beta") for provider in ("codex", "claude")}

    def seed(self):
        self.delivery = self.fx.delivery(
            subject=SUBJECT, claim=BODY, evidence=EVIDENCE, source_handle=LOCATOR,
            disclosure=["codex", "claude"], classification="confidential", retention="2028-01-01",
            valid_precision="interval", valid_from="2026-12-01", valid_to="2027-02-01",
            idempotency_key=DELIVERY_KEY)
        pending = self.fx.kernel.propose(self.fx.codex, self.fx.delivery(
            subject="keeper accepted alpha", claim="keeper canonical alpha",
            evidence="keeper evidence alpha", idempotency_key="keeper-accepted-alpha",
            disclosure=["codex", "claude"]))
        self.fx.approve("accept_proposal", proposal_id=pending["proposal_id"])
        self.fx.approve("remember", project=self.fx.projects["beta"]["id"],
                        subject="keeper beta", claim="keeper canonical beta",
                        evidence="keeper evidence beta", disclosure=["codex", "claude"])
        self.fx.kernel.propose(self.fx.codex, self.fx.delivery(
            subject="keeper pending alpha", claim="keeper pending content",
            idempotency_key="keeper-pending-alpha"))
        # The same key under another provider or project must not capture this
        # delivery. Keep both controls nonempty and different from the target.
        for project, provider in (("alpha", "claude"), ("beta", "codex")):
            self.fx.kernel.propose(self.agents[project, provider], self.fx.delivery(
                subject="keeper scoped delivery", claim="keeper scoped content",
                idempotency_key=DELIVERY_KEY, disclosure=[provider]))
        self.recalls = {}
        for identity, capability in self.agents.items():
            recall = self.fx.kernel.search(capability, {"query": SUBJECT})
            self.assertEqual(recall["cards"], [])
            self.recalls[identity] = recall["recall_id"]
        self.challenge = {
            "capability_file": Path(self.fx.projects["alpha"]["capabilities"]["codex"]).name,
            "delivery": self.delivery,
        }
        db = self.fx.store.connection
        self.before_sequence = db.execute("SELECT value FROM sequence").fetchone()[0]
        self.before_audit_sequence = db.execute(
            "SELECT seq FROM sqlite_sequence WHERE name='audit_events'").fetchone()[0]
        self.counts = {name: db.execute("SELECT count(*) FROM " + name).fetchone()[0]
                       for name in ("proposals", "provenance_activities", "audit_events")}
        self.retained = self.retained_rows(db)
        for name in ("proposals", "provenance_activities", "audit_events", "projects", "scopes",
                     "capabilities", "claim_threads", "assertion_versions", "evidence", "assertion_fts",
                     "assertion_disclosures", "evidence_refs", "attestations", "consent_receipts",
                     "reviews", "recalls", "audience_sequences", "admin_challenges", "admin_results"):
            self.assertTrue(self.retained[name], "Retained control would be vacuous: " + name)
        self.original = snapshot(db)
        self.old_anchor = read_private(paths(self.fx.home)["audit_head"])
        self.assert_integrity(self.fx.store)
        self.assertNotIn("_propose_crash_", "\n".join(self.original))
        self.fx.store.close()

    def copied_vault(self, name):
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse(os.path.lexists(str(paths(self.fx.home)["db"]) + suffix))
        return super().copied_vault(name)

    def retained_rows(self, db):
        # Preserve every existing row, including FTS shadows, not only selected
        # canonical columns. Only these additions and the independently checked
        # vault/audit sequence increments are permitted by proposal creation.
        exclusions = {
            "proposals": ("id!=?", (PROPOSAL_ID,)),
            "provenance_activities": ("id!=?", (PROVENANCE_ID,)),
            "audit_events": ("event_seq<=?", (self.before_sequence,)),
            "sqlite_sequence": ("name!='audit_events'", ()),
        }
        tables = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        retained = {}
        for name in tables:
            if name == "sequence":
                continue
            # Names come from the synthetic schema, still quote them as identifiers.
            sql = 'SELECT * FROM "' + name.replace('"', '""') + '"'
            arguments = ()
            if name in exclusions:
                condition, arguments = exclusions[name]
                sql += " WHERE " + condition
            retained[name] = sorted([tuple(row) for row in db.execute(sql, arguments)], key=repr)
        return retained

    def assert_pending_semantics(self, store, kernel, control):
        db = store.connection
        before = snapshot(db)
        anchor = read_private(store.files["audit_head"])
        sequence = self.before_sequence + 1
        self.assertEqual(db.execute("SELECT value FROM sequence").fetchone()[0], sequence)
        self.assertEqual(db.execute("SELECT seq FROM sqlite_sequence WHERE name='audit_events'").fetchone()[0],
                         self.before_audit_sequence + 1)
        self.assertEqual(self.retained_rows(db), self.retained)
        for table, count in self.counts.items():
            self.assertEqual(db.execute("SELECT count(*) FROM " + table).fetchone()[0], count + 1, table)
        normalized = dict(subject=SUBJECT, claim=BODY, evidence=EVIDENCE, source_handle=LOCATOR,
            classification="confidential", retention="2028-01-01T00:00:00.000000Z",
            disclosure=["claude", "codex"], valid_precision="interval",
            valid_from="2026-12-01T00:00:00.000000Z", valid_to="2027-02-01T00:00:00.000000Z")
        fingerprint = store.keyed_digest("proposal-request", canonical_json(normalized))
        row = db.execute("SELECT * FROM proposals WHERE id=?", (PROPOSAL_ID,)).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(dict(row), dict(
            id=PROPOSAL_ID, project_id=self.fx.project, scope_id=self.fx.projects["alpha"]["scope_id"],
            subject=SUBJECT, subject_key=SUBJECT, body=BODY, evidence_body=EVIDENCE, evidence_locator=LOCATOR,
            classification="confidential", retention=normalized["retention"],
            disclosure_json=canonical_json(["claude", "codex"]), valid_precision="interval",
            valid_from=normalized["valid_from"], valid_to=normalized["valid_to"], status="proposed",
            source_agent="codex", source_capability_id=self.fx.codex["id"], idempotency_key=DELIVERY_KEY,
            request_digest=fingerprint, created_at=KERNEL_TIME, created_seq=sequence,
            reviewed_at=None, accepted_assertion_id=None))
        provenance = db.execute("SELECT * FROM provenance_activities WHERE target_id=?", (PROPOSAL_ID,)).fetchall()
        self.assertEqual([dict(item) for item in provenance], [dict(
            id=PROVENANCE_ID, project_id=self.fx.project, target_id=PROPOSAL_ID,
            activity_type="agent_proposal", actor="codex", tool_name="memory_propose", tool_version="schema-1",
            input_ids_json="[]", output_fingerprint=fingerprint, created_at=KERNEL_TIME, created_seq=sequence)])
        self.assertEqual([tuple(item) for item in db.execute(
            "SELECT audit_seq,actor_kind,operation,scoped_id,target_id,policy_decision,result,occurred_at "
            "FROM audit_events WHERE event_seq=?", (sequence,))],
            [(self.before_audit_sequence + 1, "agent", "proposal_created", self.fx.project,
              PROPOSAL_ID, "allowed", "ok", FIXED_TIME)])
        self.assertEqual(db.execute(
            "SELECT assertion_id FROM assertion_fts WHERE assertion_fts MATCH 'proposecrashcanary'").fetchall(), [])
        owner_inbox = kernel.inbox(control, {"project": self.fx.project, "limit": 5})["proposals"]
        target = [item for item in owner_inbox if item["proposal_id"] == PROPOSAL_ID]
        self.assertEqual(len(target), 1)
        self.assertEqual((target[0]["claim"], target[0]["evidence"], target[0]["status"],
                          target[0]["scope"], target[0]["source_agent"]),
                         (BODY, {"body": EVIDENCE, "source_handle": LOCATOR}, "proposed", "project", "codex"))
        self.assertNotIn(PROPOSAL_ID, [item["proposal_id"] for item in kernel.inbox(
            control, {"project": self.fx.projects["beta"]["id"], "limit": 5})["proposals"]])
        for identity, original in self.agents.items():
            capability = store.authenticate(original["token"])
            with self.assertRaises(MemoryError) as missing:
                kernel.get(capability, {"recall_id": self.recalls[identity], "ids": [PROPOSAL_ID]})
            self.assertEqual(missing.exception.code, "not_found")
            for method, request in (
                (kernel.inbox, {"project": self.fx.project}),
                (kernel.admin_preview, {"operation": "accept_proposal", "project": self.fx.project,
                                        "proposal_id": PROPOSAL_ID}),
            ):
                with self.assertRaises(MemoryError) as denied:
                    method(capability, request)
                self.assertEqual(denied.exception.code, "forbidden")
        self.assertEqual(snapshot(db), before)
        self.assertEqual(read_private(store.files["audit_head"]), anchor)

    def run_delivery(self, home, delivery):
        with patch.object(self, "challenge", dict(self.challenge, delivery=delivery)):
            return self.run_child(home)

    def assert_replay_and_conflict(self, home, expected, anchor):
        replay_delivery = dict(reversed(list(self.delivery.items())))
        replay_delivery["disclosure"] = ["claude", "codex", "codex"]
        self.assertEqual(self.run_delivery(home, replay_delivery),
                         {"boundaries": REPLAY_BOUNDARIES, "result": REPLAYED})
        conflict = dict(self.delivery, claim=BODY + " changed")
        self.assertEqual(self.run_delivery(home, conflict),
                         {"boundaries": [], "error": "idempotency_conflict"})
        with self.opened(home) as (store, kernel, control):
            self.assertEqual(snapshot(store.connection), expected)
            self.assertEqual(read_private(paths(home)["audit_head"]), anchor)
            self.assertEqual(store.verify_audit()["status"], "valid")
            self.assert_pending_semantics(store, kernel, control)
            self.assert_integrity(store)

    def test_every_proposal_write_commit_and_anchor_exit_recovers_atomically(self):
        self.seed()
        reference = self.copied_vault("completed")
        recorded = self.run_child(reference)
        # Never learn the expected statement inventory from the operation itself.
        self.assertEqual(recorded, {"boundaries": BOUNDARIES, "result": CREATED})
        with self.opened(reference) as (store, kernel, control):
            expected = snapshot(store.connection)
            new_anchor = read_private(paths(reference)["audit_head"])
            self.assertNotEqual(expected, self.original)
            self.assertNotEqual(new_anchor, self.old_anchor)
            self.assertEqual(store.verify_audit()["status"], "valid")
            self.assert_integrity(store)
            self.assert_pending_semantics(store, kernel, control)
        self.assert_replay_and_conflict(reference, expected, new_anchor)
        committed_at = BOUNDARIES.index("after_commit_1") + 1
        published_at = BOUNDARIES.index("after_anchor_publish") + 1
        for ordinal, boundary in enumerate(BOUNDARIES, 1):
            with self.subTest(ordinal=ordinal, boundary=boundary):
                home = self.copied_vault("crash-%02d" % ordinal)
                self.assertEqual(self.run_child(home, ordinal), {"ordinal": ordinal, "boundary": boundary})
                committed = ordinal >= committed_at
                published = ordinal >= published_at
                prior = expected if committed else self.original
                with self.opened(home) as (store, kernel, control):
                    # Reconciliation or application reads cannot hide partial state:
                    # inspect all rows and anchor bytes before either is permitted.
                    self.assertEqual(snapshot(store.connection), prior)
                    self.assertEqual(read_private(paths(home)["audit_head"]),
                                     new_anchor if published else self.old_anchor)
                    self.assert_integrity(store)
                    self.assertEqual(store.verify_audit()["status"],
                                     "external_anchor_stale" if committed and not published else "valid")
                    self.assertEqual(kernel.audit_reconcile(control, {})["status"], "valid")
                    self.assertEqual(snapshot(store.connection), prior)
                    self.assertEqual(read_private(paths(home)["audit_head"]),
                                     new_anchor if committed else self.old_anchor)
                retried = self.run_child(home)
                self.assertEqual(retried, {"boundaries": REPLAY_BOUNDARIES if committed else BOUNDARIES,
                                           "result": REPLAYED if committed else CREATED})
                self.assert_replay_and_conflict(home, expected, new_anchor)
                with self.opened(home) as (store, kernel, control):
                    self.assertEqual(snapshot(store.connection), expected)
                    self.assertEqual(read_private(paths(home)["audit_head"]), new_anchor)
                    self.assert_pending_semantics(store, kernel, control)
                    self.assert_integrity(store)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--crash-child":
        propose_child(Path(sys.argv[2]), int(sys.argv[3]), json.loads(sys.stdin.buffer.read()))
    else:
        unittest.main()

