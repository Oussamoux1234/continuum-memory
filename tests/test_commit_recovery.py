"""Synthetic failure injection: committed outcomes must not become failed actions."""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from continuum_memory import cli, storage
from continuum_memory.client import DaemonClient
from continuum_memory.errors import CommittedAuditError, MemoryError
from continuum_memory.kernel import Kernel
from continuum_memory.migrations import SCHEMA_VERSION, migrate
from continuum_memory.security import canonical_json, read_private, replace_private, sign_grant
from continuum_memory.storage import Store, paths
from fixtures.harness import EphemeralHarness
from tests import test_proposal_erasure as erasure

ROOT = Path(__file__).resolve().parents[1]


class CommitRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.fx = erasure.ProposalErasureTest()
        self.fx.setUp()
        self.addCleanup(self.fx.tearDown)

    def challenge(self, **changes):
        return self.fx.preview("remember", **dict(
            {"subject": "recovery-canary", "claim": "recovery-canary body", "evidence": "recovery-canary evidence"},
            **changes))

    @staticmethod
    def locator(challenge):
        return {"nonce": challenge["nonce"], "preview_digest": challenge["preview_digest"]}

    def lookup(self, challenge):
        return self.fx.kernel.admin_result(self.fx.control, self.locator(challenge))

    def test_postcommit_fault_returns_committed_receipt_then_reconciles(self):
        challenge = self.challenge()
        with patch.object(self.fx.store, "sync_audit_head", side_effect=OSError("private-error-canary")):
            result = self.fx.apply(challenge)
        self.assertEqual(result["commit"]["status"], "committed")
        self.assertEqual(result["commit"]["audit_anchor"], "degraded")
        self.assertNotIn("canary", canonical_json(result))
        receipt = self.lookup(challenge)
        self.assertEqual(receipt["audit_anchor"], "external_anchor_stale")
        self.assertEqual(receipt["result"]["assertion_id"], result["assertion_id"])
        self.assertEqual(self.fx.kernel.audit_reconcile(self.fx.control, {})["status"], "valid")
        self.assertEqual(self.lookup(challenge)["result"], receipt["result"])
        self.assertEqual(self.lookup(challenge)["audit_anchor"], "valid")
        with self.assertRaises(MemoryError) as replay:
            self.fx.apply(challenge)
        self.assertEqual(replay.exception.code, "approval_replay")

    def test_precommit_failure_rolls_back_receipt_action_and_grant(self):
        challenge = self.challenge()
        before = list(self.fx.store.connection.iterdump())
        self.fx.store.connection.set_authorizer(lambda action, table, *rest: sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_INSERT and table == "admin_results" else sqlite3.SQLITE_OK)
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                self.fx.apply(challenge)
        finally:
            self.fx.store.connection.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
        self.assertEqual(list(self.fx.store.connection.iterdump()), before)
        self.fx.apply(challenge)
        self.assertTrue(self.lookup(challenge)["committed"])

    def test_receipt_survives_reopen_challenge_cleanup_and_forget_without_content(self):
        challenge = self.challenge()
        result = self.fx.apply(challenge)
        original = self.lookup(challenge)["result"]
        self.fx.approve("forget", target_id=result["assertion_id"])
        self.assertIsNone(self.fx.store.connection.execute("SELECT nonce FROM admin_challenges WHERE nonce=?",
                                                        (challenge["nonce"],)).fetchone())
        self.fx.reopen()
        self.assertEqual(self.lookup(challenge)["result"], original)
        self.assertNotIn("recovery-canary", "\n".join(self.fx.store.connection.iterdump()))
        self.assertNotIn(challenge["preview_digest"], "\n".join(self.fx.store.connection.iterdump()))
        self.assertEqual(self.fx.store.connection.execute("SELECT count(*) FROM assertion_versions").fetchone()[0], 0)

    def test_receipt_scope_and_integrity_fail_closed(self):
        challenge = self.challenge()
        self.fx.apply(challenge)
        with self.assertRaises(MemoryError) as denied:
            self.fx.kernel.admin_result(self.fx.codex, self.locator(challenge))
        self.assertEqual(denied.exception.code, "forbidden")
        for capability, locator in (
            (dict(self.fx.control, id="cap_different_control"), self.locator(challenge)),
            (self.fx.control, dict(self.locator(challenge), preview_digest="0" * 64)),
            (self.fx.control, dict(self.locator(challenge), nonce="gnt_absent")),
        ):
            with self.assertRaises(MemoryError) as missing:
                self.fx.kernel.admin_result(capability, locator)
            self.assertEqual(missing.exception.code, "not_found")
        self.fx.store.connection.execute("UPDATE admin_results SET result_json='{}'")
        with self.assertRaises(MemoryError) as corrupt:
            self.lookup(challenge)
        self.assertEqual(corrupt.exception.code, "integrity_error")

    def test_each_owner_mutation_has_its_original_content_free_receipt(self):
        proposed = self.fx.kernel.propose(self.fx.codex, self.fx.delivery())
        accept = self.fx.preview("accept_proposal", proposal_id=proposed["proposal_id"])
        accepted = self.fx.apply(accept)
        correct = self.fx.preview("correct", target_id=accepted["assertion_id"], claim="corrected fixture")
        corrected = self.fx.apply(correct)
        second = self.fx.kernel.propose(self.fx.codex, self.fx.delivery(idempotency_key="second-fixture"))
        reject = self.fx.preview("reject_proposal", proposal_id=second["proposal_id"])
        rejected = self.fx.apply(reject)
        for challenge, result in ((accept, accepted), (correct, corrected), (reject, rejected)):
            self.assertEqual(self.lookup(challenge)["result"], {k:v for k,v in result.items() if k != "commit"})
        self.assertNotIn("erasure-canary", str(self.fx.store.connection.execute("SELECT result_json FROM admin_results").fetchall()))

    def test_audit_diagnostic_serializes_rows_and_anchor_and_releases_own_lock(self):
        other = Store(self.fx.home)
        self.addCleanup(other.close)
        other.connection.execute("PRAGMA busy_timeout=0")
        original = self.fx.store._verify_audit_locked
        def verify_with_competing_writer():
            with self.assertRaises(sqlite3.OperationalError): other.begin()
            return original()
        with patch.object(self.fx.store, "_verify_audit_locked", side_effect=verify_with_competing_writer):
            self.assertEqual(self.fx.store.verify_audit()["status"], "valid")
        other.begin()
        other.rollback()
        with patch.object(self.fx.store, "_verify_audit_locked", side_effect=OSError("synthetic")):
            with self.assertRaises(OSError): self.fx.store.verify_audit()
        other.begin()
        other.rollback()
        self.fx.store.begin()
        self.fx.store.verify_audit()
        self.assertTrue(self.fx.store.connection.in_transaction)
        self.fx.store.rollback()

    def test_late_writer_never_regresses_newer_anchor(self):
        first = self.challenge(subject="first")
        second = self.challenge(subject="second")
        other = Store(self.fx.home)
        self.addCleanup(other.close)
        other_kernel = Kernel(other, now_provider=lambda: self.fx.now,
                              approval_public_key_provider=lambda uid: None, allow_prototype_approval=True)
        original_sync = self.fx.store.sync_audit_head

        def second_writer_before_first_anchor():
            self.fx.apply(second, kernel=other_kernel)
            original_sync()

        with patch.object(self.fx.store, "sync_audit_head", side_effect=second_writer_before_first_anchor):
            self.fx.apply(first)
        anchor = json.loads(read_private(paths(self.fx.home)["audit_head"]))
        latest = self.fx.store.connection.execute("SELECT audit_seq,mac FROM audit_events ORDER BY audit_seq DESC LIMIT 1").fetchone()
        self.assertEqual(anchor, {"audit_seq": latest[0], "mac": latest[1]})
        self.assertEqual(self.fx.store.verify_audit()["status"], "valid")

    def test_reconcile_and_normal_writes_do_not_mask_bad_anchors(self):
        challenge = self.challenge()
        anchor_path = paths(self.fx.home)["audit_head"]
        original = read_private(anchor_path)
        variants = [b"[]", b'{"audit_seq":true,"mac":"GENESIS"}',
                    b'{"audit_seq":"1","mac":"GENESIS"}',
                    b'{"audit_seq":0,"audit_seq":0,"mac":"GENESIS"}',
                    canonical_json({"audit_seq":100, "mac":"0" * 64}).encode(),
                    canonical_json({"audit_seq":1, "mac":"0" * 64}).encode()]
        for raw in variants:
            with self.subTest(raw=raw):
                replace_private(anchor_path, raw)
                before = list(self.fx.store.connection.iterdump())
                for action in (lambda: self.fx.kernel.audit_reconcile(self.fx.control, {}),
                               lambda: self.fx.apply(challenge)):
                    with self.assertRaises(MemoryError) as blocked:
                        action()
                    self.assertEqual(blocked.exception.code, "audit_recovery_refused")
                    self.assertEqual(read_private(anchor_path), raw)
                    self.assertEqual(list(self.fx.store.connection.iterdump()), before)
        replace_private(anchor_path, original)
        # Simulate absent anchor without deleting a real file: change fixture path.
        with patch.dict(self.fx.store.files, audit_head=self.fx.home / "absent.head"):
            with self.assertRaises(MemoryError) as missing:
                self.fx.kernel.audit_reconcile(self.fx.control, {})
            self.assertEqual(missing.exception.code, "audit_recovery_refused")
        self.fx.store.connection.execute("UPDATE audit_events SET operation='tampered'")
        with self.assertRaises(MemoryError) as tampered:
            self.fx.kernel.audit_reconcile(self.fx.control, {})
        self.assertEqual(tampered.exception.code, "audit_recovery_refused")
        self.assertEqual(read_private(anchor_path), original)

    def test_stale_anchor_requires_exact_prefix_mac(self):
        challenge = self.challenge()
        with patch.object(self.fx.store, "sync_audit_head", side_effect=OSError("synthetic")):
            self.fx.apply(challenge)
        path = paths(self.fx.home)["audit_head"]
        anchor = json.loads(read_private(path))
        replace_private(path, canonical_json(dict(anchor, mac="0" * 64)).encode())
        self.assertEqual(self.fx.store.verify_audit()["status"], "anchor_mismatch")
        with self.assertRaises(MemoryError):
            self.fx.kernel.audit_reconcile(self.fx.control, {})

    def test_retention_preflight_commit_is_not_the_requested_action(self):
        self.fx.kernel.propose(self.fx.codex, self.fx.delivery(retention="2027-01-02"))
        challenge = self.challenge()
        self.fx.now = datetime(2027, 1, 3, tzinfo=timezone.utc)
        with patch.object(self.fx.store, "sync_audit_head", side_effect=OSError("synthetic")):
            with self.assertRaises(CommittedAuditError):
                self.fx.apply(challenge)
        self.assertEqual(self.fx.store.connection.execute("SELECT count(*) FROM assertion_versions").fetchone()[0], 0)
        with self.assertRaises(MemoryError) as absent:
            self.lookup(challenge)
        self.assertEqual(absent.exception.code, "not_found")

    def test_forget_checkpoint_failure_is_not_reported_as_failed_deletion(self):
        accepted = self.fx.apply(self.challenge())
        challenge = self.fx.preview("forget", target_id=accepted["assertion_id"])
        self.fx.store.connection.set_authorizer(lambda action, name, *rest: sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_PRAGMA and name == "wal_checkpoint" else sqlite3.SQLITE_OK)
        try:
            result = self.fx.apply(challenge)
        finally:
            self.fx.store.connection.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
        self.assertEqual(result["commit"]["checkpoint"], "deferred")
        self.assertTrue(self.lookup(challenge)["committed"])
        self.assertNotIn("recovery-canary", "\n".join(self.fx.store.connection.iterdump()))

    def test_process_crashes_around_commit_and_anchor_have_unambiguous_receipts(self):
        program = r'''
import json, os, sys
from pathlib import Path
from unittest.mock import patch
from continuum_memory.kernel import Kernel
from continuum_memory.storage import Store, paths, load_capability
from continuum_memory.security import sign_grant
home, point = Path(sys.argv[1]), sys.argv[2]
store = Store(home)
control = store.authenticate(load_capability(paths(home)["control"])["token"])
kernel = Kernel(store, approval_public_key_provider=lambda uid: None, allow_prototype_approval=True)
challenge = json.loads(sys.stdin.read())
params = {"nonce":challenge["nonce"], "preview_digest":challenge["preview_digest"], "preview":challenge["preview"],
          "grant":sign_grant(control["token"].encode("ascii"),challenge["nonce"],challenge["operation"],challenge["preview_digest"])}
sync = store.sync_audit_head
def interrupted_sync():
    if point == "after_anchor": sync()
    os._exit(73)
if point == "before_commit": store.commit = lambda **kwargs: os._exit(73)
else: store.sync_audit_head = interrupted_sync
kernel.admin_apply(control, params)
'''
        for point in ("before_commit", "after_commit", "after_anchor"):
            with self.subTest(point=point):
                challenge = self.challenge(subject=point)
                before = self.fx.store.connection.execute("SELECT count(*) FROM assertion_versions").fetchone()[0]
                completed = subprocess.run([sys.executable, "-c", program, str(self.fx.home), point],
                    input=canonical_json(challenge), text=True, capture_output=True, timeout=10,
                    env=dict(os.environ, PYTHONPATH=str(ROOT / "src")))
                self.assertEqual(completed.returncode, 73, completed.stderr)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(completed.stderr, "")
                self.fx.reopen()
                count = self.fx.store.connection.execute("SELECT count(*) FROM assertion_versions").fetchone()[0]
                if point == "before_commit":
                    self.assertEqual(count, before)
                    with self.assertRaises(MemoryError): self.lookup(challenge)
                else:
                    self.assertEqual(count, before + 1)
                    self.assertTrue(self.lookup(challenge)["committed"])
                    self.fx.kernel.audit_reconcile(self.fx.control, {})
                    self.assertEqual(self.lookup(challenge)["audit_anchor"], "valid")


class RecoveryMigrationTest(unittest.TestCase):
    def test_v4_upgrade_preserves_data_and_rolls_back_failed_ddl(self):
        schema = (ROOT / "tests/fixtures/schema-v4.sql").read_text()
        with tempfile.TemporaryDirectory(prefix="continuum-v4-recovery-") as temp:
            home = Path(temp)
            with patch.object(storage, "SCHEMA_SQL", schema), patch.object(storage, "SCHEMA_VERSION", 4):
                Store.bootstrap(home, [{"name":"fixture", "path_hint":"/fixture", "providers":["codex"]}])
            db = sqlite3.connect(str(paths(home)["db"]))
            try:
                before = list(db.iterdump())
                original_rows = {name: db.execute("SELECT * FROM " + name).fetchall()
                                 for name in ("projects", "capabilities", "metadata", "audit_events")}
                db.set_authorizer(lambda action, name, *rest: sqlite3.SQLITE_DENY
                    if action == sqlite3.SQLITE_CREATE_TABLE and name == "admin_results" else sqlite3.SQLITE_OK)
                with self.assertRaises(sqlite3.DatabaseError): migrate(db, 4)
                db.set_authorizer(lambda *args: sqlite3.SQLITE_OK)
                self.assertEqual(list(db.iterdump()), before)
                self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 4)
                self.assertEqual(migrate(db, 4), SCHEMA_VERSION)
                self.assertEqual(db.execute("SELECT count(*) FROM admin_results").fetchone()[0], 0)
                for name, rows in original_rows.items():
                    self.assertEqual(db.execute("SELECT * FROM " + name).fetchall(), rows)
                self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            finally:
                db.close()
            store = Store(home)
            store.close()


class RecoverySurfaceTest(unittest.TestCase):
    def test_daemon_and_cli_lookup_preserve_owner_only_authority(self):
        with EphemeralHarness() as harness:
            project = harness.projects["alpha"]["id"]
            result = harness.approve({"operation":"remember", "project":project,
                                      "subject":"fixture", "claim":"Only a synthetic claim."})
            challenge = result["challenge"]
            locator = {"nonce":challenge["nonce"], "preview_digest":challenge["preview_digest"]}
            receipt = harness.control.call("admin_result", locator)
            self.assertEqual(receipt["result"]["assertion_id"], result["result"]["assertion_id"])
            agent = DaemonClient(harness.data_dir, Path(harness.projects["alpha"]["capabilities"]["codex"]))
            for method, params in (("admin_result", locator), ("audit_reconcile", {})):
                with self.assertRaises(MemoryError) as denied: agent.call(method, params)
                self.assertEqual(denied.exception.code, "forbidden")
            completed = subprocess.run([sys.executable,"-m","continuum_memory.cli","--data-dir",str(harness.data_dir),
                "--json","result","--nonce",locator["nonce"],"--preview-digest",locator["preview_digest"]],
                text=True,capture_output=True,timeout=5,env=dict(os.environ,PYTHONPATH=str(ROOT / "src")))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout), receipt)

    def test_cli_recovers_lost_reply_without_repeating_mutation(self):
        challenge = {"nonce":"gnt_fixture", "preview_digest":"0"*64, "preview":{}}
        receipt = {"receipt_id":"gnt_fixture", "result":{"assertion_id":"asr_fixture"}, "audit_anchor":"valid"}
        for recovered in (True, False):
            calls = []
            class Client:
                def call(self, method, params):
                    calls.append(method)
                    if method == "admin_preview": return challenge
                    if method == "admin_apply": raise MemoryError("unavailable", "synthetic")
                    if recovered: return receipt
                    raise MemoryError("not_found", "synthetic")
            with patch.object(cli, "broker_for_challenge") as broker:
                broker.return_value.authorize.return_value = "synthetic-grant"
                if recovered:
                    result = cli._admin(Client(), {})
                    self.assertTrue(result["commit"]["recovered"])
                else:
                    with self.assertRaises(MemoryError) as unknown: cli._admin(Client(), {})
                    self.assertEqual(unknown.exception.code, "operation_outcome_unknown")
                    self.assertEqual(unknown.exception.details, {"nonce":"gnt_fixture", "preview_digest":"0"*64})
            self.assertEqual(calls, ["admin_preview", "admin_apply", "admin_result"])


if __name__ == "__main__":
    unittest.main()
