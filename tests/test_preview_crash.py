"""Held source-only preview matrix; NOT EXECUTED on this encrypted candidate.

Imported from MAIN PR48; native execution needs separately reviewed inputs and
authorization. The original plaintext description below is historical context,
not encrypted acceptance. No missing-runtime skip or fallback is provided.

Process death during preview challenge creation and global challenge GC.

Preview is neither approval nor an idempotent operation. Only known pre-commit
test cases retry; no committed preview is replayed and no target grant is made.
Existing canonical data uses synthetic prototype approval during fixture setup.
Plaintext POSIX SQLite process-crash evidence only, not encryption, native
Windows, OS-backed presence, power loss or ambiguous-client-timeout recovery.
"""

import hashlib
import hmac
import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from continuum_memory import kernel as kernel_module
from continuum_memory.errors import MemoryError
from continuum_memory.security import read_private
from continuum_memory.storage import Store, load_capability, paths
from tests.admin_crash_support import (
    AdminCrashFixture, BoundaryConnection, FIXED_NOW, fixture_kernel, snapshot,
)


EPOCH = int(FIXED_NOW.timestamp())
TTL = 120
NONCE = "gnt_preview_crash_fixture"
SUBJECT = "previewcrashcanary decision"
CLAIM = "previewcrashcanary remains an unaccepted agent draft"
EVIDENCE = "previewcrashcanary original draft evidence"
BOUNDARIES = ["write:admin_challenges", "write:admin_challenges", "before_commit_1", "after_commit_1"]


def encoded(value):
    # Independent expected serialization: do not reuse preview/digest helpers.
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def keyed(key, domain, value):
    return hmac.new(key, domain.encode("ascii") + b"\x00" + encoded(value), hashlib.sha256).hexdigest()


def preview_child(home, crash_after, request):
    store = Store(home)
    try:
        control = store.authenticate(load_capability(paths(home)["control"])["token"])
        observed = BoundaryConnection(store.connection, crash_after)
        store.connection = observed
        kernel = fixture_kernel(store)

        def nonce(prefix):
            if prefix != "gnt":
                raise AssertionError("Unexpected identifier prefix during preview creation")
            return NONCE

        # Do not change the subprocess deadline clock, generate any grant, or
        # replace SQL/approval behavior. Only this synthetic clock/nonce is fixed.
        with patch.object(kernel_module, "time", SimpleNamespace(time=lambda: EPOCH)), \
                patch.object(kernel_module, "random_id", side_effect=nonce) as identifier:
            result = kernel.admin_preview(control, request)
            if [call.args for call in identifier.call_args_list] != [("gnt",)]:
                raise AssertionError("Unexpected preview identifier inventory")
        print(json.dumps({"boundaries": observed.boundaries, "result": result}), flush=True)
    finally:
        store.close()


@unittest.skipIf(os.name == "nt", "POSIX keyed preview crash fixture; encrypted Windows is unsupported")
class PreviewProcessCrashTest(AdminCrashFixture, unittest.TestCase):
    child_module = "tests.test_preview_crash"

    def setUp(self):
        self.setup_crash_fixture("continuum-preview-crash-")

    def seed(self):
        self.receipts = []
        proposed = self.fx.kernel.propose(self.fx.codex, self.fx.delivery(
            subject="existing reviewed alpha", claim="existing alpha canonical claim",
            evidence="existing alpha canonical evidence", idempotency_key="preview-alpha-keeper",
            disclosure=["codex", "claude"]))
        alpha = self.apply_seed(self.fx.preview("accept_proposal", proposal_id=proposed["proposal_id"]))
        beta = self.apply_seed(self.fx.preview("remember", project=self.fx.projects["beta"]["id"],
            subject="existing reviewed beta", claim="existing beta canonical claim",
            evidence="existing beta canonical evidence", disclosure=["codex", "claude"]))
        for project, accepted in (("alpha", alpha), ("beta", beta)):
            capability = self.fx.agent(project, "codex")
            recall = self.fx.kernel.search(capability, {"query": accepted["assertion_id"]})
            self.assertEqual([card["version_id"] for card in recall["cards"]], [accepted["assertion_id"]])
            self.fx.kernel.feedback(capability, {"recall_id": recall["recall_id"],
                "item_id": accepted["assertion_id"], "label": "helpful", "reason": "retained control"})
        self.proposed = self.fx.kernel.propose(self.fx.codex, self.fx.delivery(
            subject=SUBJECT, claim=CLAIM, evidence=EVIDENCE, source_handle="fixture:preview-source",
            classification="confidential", retention="forever", disclosure=["codex", "claude"],
            valid_precision="interval", valid_from="2026-12-01", valid_to="2027-02-01",
            idempotency_key="preview-target-draft"))["proposal_id"]
        self.challenge = {"operation": "accept_proposal", "project": self.fx.project, "proposal_id": self.proposed}
        self.controls = {}
        # Descending creation clocks retain all real public previews without
        # direct deadline/used-row edits. Expiry equality must survive strict '<'.
        for kind, creation_time in (("live", EPOCH), ("used", EPOCH), ("equal", EPOCH - TTL),
                                    ("expired", EPOCH - TTL - 1)):
            for project in ("alpha", "beta"):
                with patch.object(kernel_module, "time", SimpleNamespace(time=lambda: creation_time)):
                    challenge = self.fx.preview("remember", project=self.fx.projects[project]["id"],
                        subject=kind + " " + project + " preview control", claim=kind + " " + project + " reviewed control",
                        evidence="synthetic preview control evidence", disclosure=["codex", "claude"])
                self.controls[(kind, project)] = challenge
        with patch.object(kernel_module, "time", SimpleNamespace(time=lambda: EPOCH)):
            for project in ("alpha", "beta"):
                self.apply_seed(self.controls[("used", project)])

        db = self.fx.store.connection
        self.old_challenges = [dict(row) for row in db.execute("SELECT * FROM admin_challenges ORDER BY nonce")]
        self.assertEqual(len(self.old_challenges), 8)
        for (kind, project), challenge in self.controls.items():
            row = next(row for row in self.old_challenges if row["nonce"] == challenge["nonce"])
            self.assertEqual(row["project_id"], self.fx.projects[project]["id"])
            self.assertEqual(row["expires_at"], EPOCH + TTL if kind in {"live", "used"} else EPOCH - (kind == "expired"))
            self.assertEqual(row["used_at"] is not None, kind == "used")
            self.assertEqual(row["preview_json"], "{}")
        self.removed = {challenge["nonce"] for (kind, _), challenge in self.controls.items() if kind in {"expired", "used"}}
        self.assertEqual(len(self.removed), 4)
        self.assertEqual({row["nonce"] for row in self.old_challenges if row["expires_at"] < EPOCH or row["used_at"] is not None},
                         self.removed)
        for table in ("assertion_versions", "proposals"):
            self.assertEqual(db.execute("SELECT count(*) FROM " + table + " WHERE retention!='forever'").fetchone()[0], 0)
        self.assertEqual(db.execute("SELECT count(*) FROM proposals WHERE status='rejected'").fetchone()[0], 0)

        proposal = dict(db.execute("SELECT * FROM proposals WHERE id=?", (self.proposed,)).fetchone())
        provenance = [dict(row) for row in db.execute("SELECT * FROM provenance_activities WHERE target_id=? ORDER BY id",
                                                     (self.proposed,))]
        self.assertEqual(len(provenance), 1)
        self.assertEqual(db.execute("SELECT * FROM reviews WHERE proposal_id=?", (self.proposed,)).fetchall(), [])
        self.assertEqual(proposal["status"], "proposed")
        state = {"proposals": [proposal], "reviews": [], "provenance_activities": provenance,
                 "accepted_assertions_precondition": []}
        self.expected_preview = {"schema_version": 1, "operation": "accept_proposal", "project_id": self.fx.project,
            "proposal_id": self.proposed, "scope": {"kind": "project", "id": proposal["scope_id"]},
            "subject": SUBJECT, "claim": CLAIM, "evidence": {"body": EVIDENCE, "source_handle": "fixture:preview-source"},
            "classification": "confidential", "retention": "forever", "disclosure": ["claude", "codex"],
            "valid_time": {"precision": "interval", "from": "2026-12-01T00:00:00.000000Z", "to": "2027-02-01T00:00:00.000000Z"},
            "source": {"author": "codex", "recorder": "agent_proposal"}, "policy_version": "prototype-1",
            "affected_set": {"proposals": [{"id": self.proposed}], "reviews": [],
                             "provenance_activities": [{"id": provenance[0]["id"]}], "accepted_assertions_precondition": []},
            "state_digest": keyed(self.fx.store.audit_key, "proposal-purge-scope-v1", state),
            "content_purge_on_rejection": False}
        self.digest = hashlib.sha256(encoded(self.expected_preview)).hexdigest()
        preview_key = keyed(self.fx.store.audit_key, "admin-result-request-v1",
                            [NONCE, self.fx.control["id"], self.fx.project, self.digest])
        locator = {"version": 1, "vault_id": self.fx.store.vault_id, "nonce": NONCE,
                   "binding": keyed(self.fx.store.audit_key, "admin-recovery-locator-v1",
                                    [1, self.fx.store.vault_id, NONCE, self.fx.control["id"], preview_key])}
        self.expected_response = {"operation": "accept_proposal", "nonce": NONCE, "preview_digest": self.digest,
            "recovery_locator": locator, "expires_at": EPOCH + TTL, "preview": self.expected_preview,
            "vault_id": self.fx.store.vault_id, "caller_uid": self.fx.store.owner_uid,
            "approval_boundary": "terminal_prototype_same_uid_not_resistant",
            "confirmation": "Type ACCEPT %s in an interactive terminal." % self.digest[:12],
            "prototype_boundary": "same_uid_shell_not_resistant"}
        self.new_challenge = {"nonce": NONCE, "operation": "accept_proposal", "project_id": self.fx.project,
            "preview_json": "{}", "preview_digest": self.digest, "expires_at": EPOCH + TTL, "used_at": None}
        self.expected_challenges = sorted([row for row in self.old_challenges if row["nonce"] not in self.removed]
                                         + [self.new_challenge], key=lambda row: row["nonce"])
        self.retained = self.retained_rows(db)
        for table in ("assertion_versions", "evidence", "assertion_fts", "assertion_disclosures", "attestations",
                      "consent_receipts", "provenance_activities", "proposals", "reviews", "recalls", "feedback",
                      "admin_results", "audit_events", "audience_sequences"):
            self.assertTrue(self.retained[table], "Retained-state assertion would be vacuous: " + table)
        self.assertEqual(len(self.receipts), 4)
        self.original = snapshot(db)
        self.assertNotIn(NONCE, "\n".join(self.original))
        self.old_anchor = read_private(paths(self.fx.home)["audit_head"])
        self.assertEqual(self.fx.store.verify_audit()["status"], "valid")
        self.assert_integrity(self.fx.store)
        self.fx.store.close()
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse(os.path.lexists(str(paths(self.fx.home)["db"]) + suffix))

    def apply_seed(self, challenge):
        result = self.fx.apply(challenge)
        self.receipts.append((challenge, {"receipt_id": challenge["nonce"], "operation": challenge["operation"],
            "committed": True, "result": {key: value for key, value in result.items() if key != "commit"},
            "audit_anchor": "valid"}))
        return result

    @staticmethod
    def retained_rows(db):
        tables = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name!='admin_challenges' ORDER BY name")]
        return {table: sorted([tuple(row) for row in db.execute('SELECT * FROM "' + table.replace('"', '""') + '"')], key=repr)
                for table in tables}

    def assert_semantics(self, store, kernel, control):
        db = store.connection
        before = snapshot(db)
        self.assertEqual(self.retained_rows(db), self.retained)
        self.assertEqual([dict(row) for row in db.execute("SELECT * FROM admin_challenges ORDER BY nonce")], self.expected_challenges)
        self.assertEqual(db.execute("SELECT status FROM proposals WHERE id=?", (self.proposed,)).fetchone()[0], "proposed")
        self.assertNotIn("previewcrashcanary", json.dumps(self.expected_challenges))
        self.assertNotIn(self.digest, json.dumps(self.expected_response["recovery_locator"]))
        for old, receipt in self.receipts:
            self.assertEqual(kernel.admin_result(control, {"nonce": old["nonce"], "preview_digest": old["preview_digest"]}), receipt)
            self.assertEqual(kernel.admin_recover(control, old["recovery_locator"]), receipt)
        target_result = {"nonce": NONCE, "preview_digest": self.digest}
        target_apply = dict(target_result, preview=self.expected_preview, grant="deliberately-invalid-no-approval-grant")
        with patch.object(kernel_module, "time", SimpleNamespace(time=lambda: EPOCH)):
            refusals = [(kernel.admin_result, control, target_result, "not_found"),
                        (kernel.admin_recover, control, self.expected_response["recovery_locator"], "not_found"),
                        (kernel.admin_apply, control, target_apply, "approval_invalid")]
            for project in ("alpha", "beta"):
                for provider in ("codex", "claude"):
                    original = self.fx.projects[project]["capabilities"][provider]
                    relative = Path(original).relative_to(self.fx.home)
                    agent = store.authenticate(load_capability(store.data_dir / relative)["token"])
                    refusals.extend((method, agent, params, "forbidden") for method, params in (
                        (kernel.admin_preview, self.challenge), (kernel.admin_apply, target_apply),
                        (kernel.admin_result, target_result), (kernel.admin_recover, self.expected_response["recovery_locator"])))
            for method, capability, params, code in refusals:
                with self.assertRaises(MemoryError) as refused:
                    method(capability, params)
                self.assertEqual(refused.exception.code, code)
                self.assertEqual(snapshot(db), before)
                self.assertEqual(read_private(paths(store.data_dir)["audit_head"]), self.old_anchor)
        self.assertEqual(snapshot(db), before)

    def test_preview_and_global_challenge_cleanup_survive_every_process_exit(self):
        self.seed()
        reference = self.copied_vault("completed")
        recorded = self.run_child(reference)
        self.assertEqual(recorded, {"boundaries": BOUNDARIES, "result": self.expected_response})
        with self.opened(reference) as (store, kernel, control):
            expected = snapshot(store.connection)
            self.assertEqual(read_private(paths(reference)["audit_head"]), self.old_anchor)
            self.assert_integrity(store)
            self.assertEqual(store.verify_audit()["status"], "valid")
            self.assert_semantics(store, kernel, control)
        for ordinal, label in enumerate(BOUNDARIES, 1):
            with self.subTest(ordinal=ordinal, boundary=label):
                home = self.copied_vault("crash-%d" % ordinal)
                self.assertEqual(self.run_child(home, ordinal), {"ordinal": ordinal, "boundary": label})
                committed = ordinal == 4
                with self.opened(home) as (store, kernel, control):
                    # Raw state first: no lookup, refused apply or reconciliation
                    # may conceal partial challenge cleanup/insertion.
                    self.assertEqual(snapshot(store.connection), expected if committed else self.original)
                    self.assertEqual(read_private(paths(home)["audit_head"]), self.old_anchor)
                    self.assert_integrity(store)
                    self.assertEqual(store.verify_audit()["status"], "valid")
                # Only our crash hook proves non-commit; a lost client reply does
                # not. Committed previews must not be blindly created again.
                if not committed:
                    self.assertEqual(self.run_child(home), recorded)
                for _ in range(2):
                    with self.opened(home) as (store, kernel, control):
                        self.assertEqual(snapshot(store.connection), expected)
                        self.assertEqual(read_private(paths(home)["audit_head"]), self.old_anchor)
                        self.assert_integrity(store)
                        self.assertEqual(store.verify_audit()["status"], "valid")
                        self.assert_semantics(store, kernel, control)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--crash-child":
        preview_child(Path(sys.argv[2]), int(sys.argv[3]), json.loads(sys.stdin.buffer.read()))
    else:
        unittest.main()
