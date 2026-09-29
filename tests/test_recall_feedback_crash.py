"""Real process death during public search/context recall and agent feedback.

These APIs have no idempotency or durable-result receipt contract. A retry here
is permitted ONLY by the test's known pre-commit crash location; this is not
guidance for an ambiguous client timeout. Committed operations are never replayed.
Plaintext SQLite and synthetic prototype-approved seed data only: no native
Windows, encryption, OS-backed presence, power-loss or backup-recovery claim.
"""

import hashlib
import hmac
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


QUERY = "recallcrashcanary"
CLAIM = "recallcrashcanary accepted project constraint"
EVIDENCE = "reviewed recall crash fixture evidence"
REASON = "synthetic critical feedback does not change canonical truth"
KERNEL_TIME = "2027-01-01T00:00:00.000000Z"
IDS = {"search": "rcl_search_crash_fixture", "context": "rcl_context_crash_fixture",
       "feedback": "fbk_feedback_crash_fixture"}
RECALL_BOUNDARIES = ["write:recalls", "before_commit_1", "after_commit_1"]
FEEDBACK_BOUNDARIES = [
    "write:sequence", "write:feedback", "write:audit_events", "before_commit_1", "after_commit_1",
    "before_anchor_publish", "after_anchor_publish", "before_commit_2", "after_commit_2",
]


def recall_feedback_child(home, crash_after, request):
    operation = request["operation"]
    prefix = "fbk" if operation == "feedback" else "rcl"
    if operation not in IDS:
        raise AssertionError("Unexpected crash-fixture operation")
    store = Store(home)
    try:
        # Read the copied synthetic capability; no token is sent on stdin/stdout.
        capability = store.authenticate(load_capability(home / request["capability_file"])["token"])
        observed = BoundaryConnection(store.connection, crash_after)
        store.connection = observed
        kernel = fixture_kernel(store)
        publish = store._sync_audit_head_raw

        def publish_anchor(connection, path):
            observed.tick("before_anchor_publish")
            publish(connection, path)
            observed.tick("after_anchor_publish")

        def fixture_identifier(requested_prefix):
            if requested_prefix != prefix:
                raise AssertionError("Unexpected identifier prefix in crash fixture")
            return IDS[operation]

        # IDs and synthetic clocks alone are fixed across closed-vault copies.
        # Real SQLite execution, audit MACs and anchor publication are unchanged.
        with patch.object(kernel_module, "random_id", side_effect=fixture_identifier) as identifier, \
                patch.object(storage, "now_iso", return_value=FIXED_TIME), \
                patch.object(store, "_sync_audit_head_raw", side_effect=publish_anchor):
            result = getattr(kernel, operation)(capability, request["params"])
            if [call.args for call in identifier.call_args_list] != [(prefix,)]:
                raise AssertionError("Unexpected identifier inventory in crash fixture")
        print(json.dumps({"boundaries": observed.boundaries, "result": result}), flush=True)
    finally:
        store.close()


@unittest.skipIf(os.name == "nt", "POSIX plaintext crash fixture; native Windows acceptance is separate")
class RecallFeedbackProcessCrashTest(AdminCrashFixture, unittest.TestCase):
    child_module = "tests.test_recall_feedback_crash"

    def setUp(self):
        self.setup_crash_fixture("continuum-recall-feedback-crash-")

    def seed(self, operation):
        self.operation = operation
        self.agents = {name: self.fx.agent(project, provider) for name, project, provider in (
            ("target", "alpha", "codex"), ("provider", "alpha", "claude"), ("project", "beta", "codex"))}
        proposed = self.fx.kernel.propose(self.agents["target"], self.fx.delivery(
            subject=QUERY, claim=CLAIM, evidence=EVIDENCE, source_handle="fixture:recall-crash-target",
            idempotency_key="recall-crash-target", disclosure=["codex"]))
        self.target = self.fx.approve("accept_proposal", proposal_id=proposed["proposal_id"])
        self.provider_only = self.fx.approve("remember", subject=QUERY, claim="provider-only keeper claim",
            evidence="provider-only keeper evidence", disclosure=["claude"], retention="forever")
        self.other_project = self.fx.approve("remember", project=self.fx.projects["beta"]["id"],
            subject=QUERY, claim="other-project keeper claim", evidence="other-project keeper evidence",
            disclosure=["codex"], retention="forever")
        self.unmatched = self.fx.approve("remember", subject="different unrelated constraint",
            claim="unmatched keeper claim", evidence="unmatched keeper evidence", disclosure=["codex"],
            retention="forever")
        self.seed_recalls = {}
        for name, expected in (("target", self.target), ("provider", self.provider_only),
                               ("project", self.other_project)):
            recall = self.fx.kernel.search(self.agents[name], {"query": QUERY})
            self.assertEqual([card["version_id"] for card in recall["cards"]], [expected["assertion_id"]])
            self.seed_recalls[name] = recall["recall_id"]
            self.fx.kernel.feedback(self.agents[name], {"recall_id": recall["recall_id"],
                "item_id": expected["assertion_id"], "label": "helpful", "reason": name + " retained control"})
        self.fx.kernel.propose(self.agents["target"], self.fx.delivery(subject="unrelated pending draft",
            claim="pending keeper claim", evidence="pending keeper evidence", idempotency_key="unrelated-pending"))
        self.fx.preview("remember", subject="unused owner preview", claim="unused owner proposal")
        params = {"query": QUERY}
        if operation == "context":
            params.update(max_tokens=2048, max_bytes=8192)
        elif operation == "feedback":
            params = {"recall_id": self.seed_recalls["target"], "item_id": self.target["assertion_id"],
                      "label": "wrong", "reason": REASON}
        self.challenge = {"operation": operation, "params": params, "capability_file": str(
            Path(self.fx.projects["alpha"]["capabilities"]["codex"]).relative_to(self.fx.home))}
        db = self.fx.store.connection
        # One isolated transaction: no lifecycle mutation may precede it.
        for table in ("assertion_versions", "proposals"):
            self.assertEqual(db.execute("SELECT count(*) FROM " + table + " WHERE retention!='forever'").fetchone()[0], 0)
        self.assertEqual(db.execute("SELECT count(*) FROM proposals WHERE status='rejected'").fetchone()[0], 0)
        self.before_sequence = db.execute("SELECT value FROM sequence").fetchone()[0]
        self.before_audit_sequence = db.execute("SELECT seq FROM sqlite_sequence WHERE name='audit_events'").fetchone()[0]
        self.watermark = db.execute("SELECT max(local_seq) FROM audience_sequences WHERE project_id=? AND provider='codex'",
                                    (self.fx.project,)).fetchone()[0]
        self.retained = self.retained_rows(db)
        for table in ("assertion_versions", "assertion_fts", "evidence", "provenance_activities", "attestations",
                      "consent_receipts", "assertion_disclosures", "audience_sequences", "proposals", "reviews",
                      "admin_challenges", "admin_results", "recalls", "feedback", "audit_events"):
            self.assertTrue(self.retained[table], "Retained-state assertion would be vacuous: " + table)
        self.original = snapshot(db)
        self.assertNotIn(IDS[operation], "\n".join(self.original))
        self.old_anchor = read_private(paths(self.fx.home)["audit_head"])
        self.assertEqual(self.fx.store.verify_audit()["status"], "valid")
        self.assert_integrity(self.fx.store)
        self.fx.store.close()
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse(os.path.lexists(str(paths(self.fx.home)["db"]) + suffix))

    def retained_rows(self, db):
        # Independently preserve every non-mutated row, including FTS shadows,
        # empty tables and unrelated rows in the operation's mutated tables.
        tables = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        retained = {}
        for table in tables:
            if table == "sequence" and self.operation == "feedback":
                continue
            sql = 'SELECT * FROM "' + table.replace('"', '""') + '"'
            args = ()
            if table == "feedback" and self.operation == "feedback":
                sql += " WHERE id!=?"
                args = (IDS[self.operation],)
            elif table == "recalls" and self.operation != "feedback":
                sql += " WHERE id!=?"
                args = (IDS[self.operation],)
            elif table == "audit_events" and self.operation == "feedback":
                sql += " WHERE event_seq<=?"
                args = (self.before_sequence,)
            elif table == "sqlite_sequence" and self.operation == "feedback":
                # SQLite advances the audited table's AUTOINCREMENT row within
                # the same transaction; verify its exact delta separately.
                sql += " WHERE name!='audit_events'"
            retained[table] = sorted([tuple(row) for row in db.execute(sql, args)], key=repr)
        return retained

    def assert_semantics(self, store, kernel, control):
        db = store.connection
        before = snapshot(db)
        anchor = read_private(paths(store.data_dir)["audit_head"])
        self.assertEqual(self.retained_rows(db), self.retained)
        delta = 1 if self.operation == "feedback" else 0
        self.assertEqual(db.execute("SELECT value FROM sequence").fetchone()[0], self.before_sequence + delta)
        self.assertEqual(db.execute("SELECT seq FROM sqlite_sequence WHERE name='audit_events'").fetchone()[0],
                         self.before_audit_sequence + delta)
        target = store.authenticate(self.agents["target"]["token"])
        if self.operation == "feedback":
            self.assertEqual(self.completed_result, {"status": "recorded", "feedback_id": IDS["feedback"],
                                                     "truth_mutated": False})
            row = dict(db.execute("SELECT * FROM feedback WHERE id=?", (IDS["feedback"],)).fetchone())
            self.assertEqual(row, {"id": IDS["feedback"], "project_id": self.fx.project,
                "recall_id": self.seed_recalls["target"], "assertion_id": self.target["assertion_id"],
                "label": "wrong", "reason": REASON, "source_capability_id": target["id"],
                "created_at": KERNEL_TIME, "created_seq": self.before_sequence + 1})
            self.assertEqual([tuple(row) for row in db.execute("SELECT event_seq,actor_kind,operation,scoped_id,target_id,"
                "policy_decision,result,occurred_at FROM audit_events WHERE event_seq>? ORDER BY event_seq",
                (self.before_sequence,))], [(self.before_sequence + 1, "agent", "feedback_recorded", self.fx.project,
                    IDS["feedback"], "allowed", "ok", FIXED_TIME)])
            recall_id = self.seed_recalls["target"]
        else:
            recall_id = IDS[self.operation]
            query_digest = hmac.new(store.audit_key, b"recall-query\x00" + QUERY.encode(), hashlib.sha256).hexdigest()
            row = dict(db.execute("SELECT * FROM recalls WHERE id=?", (recall_id,)).fetchone())
            self.assertEqual(row, {"id": recall_id, "project_id": self.fx.project, "provider": "codex",
                "query_digest": query_digest, "result_ids_json": canonical_json([self.target["assertion_id"]]),
                "watermark": self.watermark, "allows_historical": 0, "temporal_mode": "current",
                "as_of_recorded": None, "as_of_valid": None, "created_at": KERNEL_TIME})
            result = self.completed_result
            self.assertEqual((result["status"], result["completeness"], result["recall_id"]), ("ok", "complete", recall_id))
            self.assertEqual(result["projection_watermark"], self.watermark)
            self.assertEqual(result["recorded_sequence_domain"], "project_provider_v1")
            self.assertNotIn("next_cursor", result)
            cards = result["cards"] if self.operation == "search" else result["accepted_claims"]
            self.assertEqual([card["version_id"] for card in cards], [self.target["assertion_id"]])
            self.assertEqual([(card["claim"], card["authority"]) for card in cards], [(CLAIM, "data")])
            if self.operation == "context":
                self.assertEqual(result["open_conflicts"], [])
                self.assertEqual(result["omitted_items"], 0)
                self.assertLessEqual(len(canonical_json(result).encode()), result["byte_budget"])
        record = kernel.get(target, {"recall_id": recall_id, "ids": [self.target["assertion_id"]]})["records"]
        self.assertEqual([(item["claim"], item["evidence"]["body"], item["authority"], item["lifecycle"])
                          for item in record], [(CLAIM, EVIDENCE, "data", "active")])
        denied_requests = [(store.authenticate(self.agents[name]["token"]), self.target["assertion_id"])
                           for name in ("provider", "project")]
        denied_requests.extend((target, item["assertion_id"])
                               for item in (self.provider_only, self.other_project, self.unmatched))
        for capability, item in denied_requests:
            for method, params in ((kernel.get, {"recall_id": recall_id, "ids": [item]}),
                                   (kernel.feedback, {"recall_id": recall_id, "item_id": item, "label": "wrong"})):
                with self.assertRaises(MemoryError) as denied:
                    method(capability, params)
                self.assertEqual(denied.exception.code, "not_found")
                self.assertEqual(snapshot(db), before)
                self.assertEqual(read_private(paths(store.data_dir)["audit_head"]), anchor)
        self.assertEqual(snapshot(db), before)
        self.assertEqual(read_private(paths(store.data_dir)["audit_head"]), anchor)

    def assert_operation_crashes(self, operation):
        self.seed(operation)
        boundaries = FEEDBACK_BOUNDARIES if operation == "feedback" else RECALL_BOUNDARIES
        reference = self.copied_vault("completed")
        recorded = self.run_child(reference)
        self.assertEqual(recorded["boundaries"], boundaries)
        self.completed_result = recorded["result"]
        with self.opened(reference) as (store, kernel, control):
            expected = snapshot(store.connection)
            new_anchor = read_private(paths(reference)["audit_head"])
            if operation == "feedback":
                self.assertNotEqual(new_anchor, self.old_anchor)
            else:
                self.assertEqual(new_anchor, self.old_anchor)
            self.assertEqual(store.verify_audit()["status"], "valid")
            self.assert_integrity(store)
            self.assert_semantics(store, kernel, control)
        committed_at = boundaries.index("after_commit_1") + 1
        published_at = boundaries.index("after_anchor_publish") + 1 if operation == "feedback" else None
        for ordinal, label in enumerate(boundaries, 1):
            with self.subTest(operation=operation, ordinal=ordinal, boundary=label):
                home = self.copied_vault("crash-%02d" % ordinal)
                self.assertEqual(self.run_child(home, ordinal), {"ordinal": ordinal, "boundary": label})
                committed = ordinal >= committed_at
                published = published_at is not None and ordinal >= published_at
                with self.opened(home) as (store, kernel, control):
                    # Inspect before semantic APIs or recovery can conceal a defect.
                    self.assertEqual(snapshot(store.connection), expected if committed else self.original)
                    self.assertEqual(read_private(paths(home)["audit_head"]), new_anchor if published else self.old_anchor)
                    self.assert_integrity(store)
                    state = "external_anchor_stale" if operation == "feedback" and committed and not published else "valid"
                    self.assertEqual(store.verify_audit()["status"], state)
                    if operation == "feedback":
                        self.assertEqual(kernel.audit_reconcile(control, {})["status"], "valid")
                        self.assertEqual(snapshot(store.connection), expected if committed else self.original)
                        self.assertEqual(read_private(paths(home)["audit_head"]), new_anchor if committed else self.old_anchor)
                # Test instrumentation proves this attempt never committed. An
                # ordinary caller after a lost reply does NOT have this oracle.
                if not committed:
                    self.assertEqual(self.run_child(home), recorded)
                # A committed operation is deliberately NOT invoked again: IDs
                # are not client retry keys and there is no durable-result API.
                for _ in range(2):
                    with self.opened(home) as (store, kernel, control):
                        self.assertEqual(snapshot(store.connection), expected)
                        self.assertEqual(read_private(paths(home)["audit_head"]), new_anchor)
                        self.assertEqual(store.verify_audit()["status"], "valid")
                        self.assert_integrity(store)
                        self.assert_semantics(store, kernel, control)

    def test_search_recall_recording_survives_each_process_exit(self):
        self.assert_operation_crashes("search")

    def test_context_recall_recording_survives_each_process_exit(self):
        self.assert_operation_crashes("context")

    def test_feedback_survives_each_process_exit_without_truth_mutation(self):
        self.assert_operation_crashes("feedback")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--crash-child":
        recall_feedback_child(Path(sys.argv[2]), int(sys.argv[3]), json.loads(sys.stdin.buffer.read()))
    else:
        unittest.main()
