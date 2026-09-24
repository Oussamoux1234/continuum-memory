"""Real native rotation/recovery contracts with synthetic signed fixture proofs.

Missing native or RSA dependencies fail; these fixtures do not claim human presence.
"""

import hashlib
import hmac
import json
import os
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum_memory import storage, storage_rotation as rotation
from continuum_memory.client import DaemonClient
from continuum_memory.daemon_lock import DaemonLock
from continuum_memory.errors import MemoryError
from continuum_memory.kernel import Kernel
from continuum_memory.security import canonical_json, write_private
from continuum_memory.storage import Store, load_capability, paths
from fixtures.harness import McpFixtureClient
from fixtures.rotation import (
    ARTIFACT_NAMES, CANARY, CRASH_EXIT, RotationVault, SyntheticBroker,
    application_snapshot, boundary_fault, create_hot_journal, file_snapshot, make_proof_keys,
    open_keyed_readonly, synthetic_approval,
)


ROOT = Path(__file__).resolve().parents[1]


class StorageRotationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        storage._require_sqlcipher_runtime()
        cls.proof_temp = tempfile.TemporaryDirectory(prefix="continuum-rotation-proof-")
        cls.addClassCleanup(cls.proof_temp.cleanup)
        cls.proof_dir = Path(cls.proof_temp.name) / "proof"
        make_proof_keys(cls.proof_dir)

    def setUp(self):
        self.vault = RotationVault()
        self.addCleanup(self.vault.close)
        self.home = self.vault.home
        self.files = paths(self.home)

    def approved(self, action="rotate", broker=None):
        function = rotation.rotate_storage_key if action == "rotate" else rotation.recover_storage_key
        with synthetic_approval(self.proof_dir, broker):
            return function(self.home)

    def interrupt(self, boundary):
        with boundary_fault(boundary) as fired:
            with self.assertRaises((OSError, MemoryError)):
                self.approved()
        self.assertEqual(fired, [boundary])

    def child(self, action, boundary):
        return subprocess.run(
            [sys.executable, "-m", "fixtures.rotation", action, str(self.home),
             str(self.proof_dir), boundary],
            text=True, capture_output=True, timeout=30, env=self.environment(),
        )

    @staticmethod
    def environment():
        return dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT / "src"), str(ROOT)]),
                    PYTHONPYCACHEPREFIX=str(ROOT / "work" / "pycache"))

    def assert_pending(self):
        before = file_snapshot(self.home)
        for function in (lambda: Store(self.home), lambda: Store.bootstrap(self.home, [
            {"name": "fixture", "path_hint": "/fixture", "providers": ["codex"]}
        ])):
            with self.assertRaises(MemoryError) as caught:
                function()
            self.assertEqual(caught.exception.code, "rotation_pending")
        self.assertEqual(file_snapshot(self.home), before)

    def assert_clean_rotation(self, count=1):
        self.assertFalse(self.files["rotation_state"].exists())
        self.assertFalse(self.files["next_storage_key"].exists())
        key = self.files["storage_key"].read_bytes()
        self.assertEqual(len(key), 32)
        self.assertNotEqual(key, self.vault.old_key)
        self.assertEqual(self.files["storage_key"].stat().st_mode & 0o777, 0o600)
        with self.assertRaises(storage.sqlite3.DatabaseError):
            open_keyed_readonly(self.files["db"], self.vault.old_key)
        store = Store(self.home)
        try:
            self.assertEqual(application_snapshot(store.connection), self.vault.application)
            self.assertEqual(store.vault_id, self.vault.vault_id)
            self.assertEqual(store.connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(store.connection.execute("PRAGMA cipher_integrity_check").fetchall(), [])
            self.assertEqual(store.connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(store.verify_audit()["status"], "valid")
            rows = [tuple(row) for row in store.connection.execute("SELECT * FROM audit_events ORDER BY audit_seq")]
            self.assertEqual(rows[:-count], self.vault.audit_rows)
            self.assertEqual(len(rows), len(self.vault.audit_rows) + count)
            self.assertEqual(store.connection.execute("SELECT value FROM sequence").fetchone()[0],
                             self.vault.sequence + count)
            events = [dict(row) for row in store.connection.execute(
                "SELECT * FROM audit_events ORDER BY audit_seq DESC LIMIT ?", (count,))]
            for event in events:
                self.assertEqual(event["operation"], "storage_key_rotated")
                self.assertEqual(event["actor_kind"], "user_control")
                self.assertEqual(event["scoped_id"], self.vault.vault_id)
                self.assertEqual(event["policy_decision"], "os_approved")
                self.assertNotIn(CANARY, canonical_json(event))
                self.assertNotIn(key.hex(), canonical_json(event))
                self.assertNotIn(self.vault.old_key.hex(), canonical_json(event))
            metadata = dict(store.connection.execute("SELECT key,value FROM metadata"))
            for name, value in self.vault.metadata.items():
                self.assertEqual(metadata[name], value)
            self.assertEqual(set(metadata) - set(self.vault.metadata),
                             {"storage_generation", "storage_rotation_operation"})
            self.assertEqual(metadata["storage_generation"], events[0]["target_id"])
            self.assertEqual(metadata["storage_rotation_operation"], events[0]["target_id"])
            self.assertEqual(len({event["target_id"] for event in events}), count)
            control = store.authenticate(load_capability(self.files["control"])["token"])
            kernel = Kernel(store)
            self.assertEqual(kernel.status(control, {"project": self.vault.fx.project})["storage_generation"],
                             events[0]["target_id"])
            receipt = kernel.admin_result(control, self.vault.receipt_locator)
            self.assertEqual(receipt["result"], self.vault.receipt_result)
            agent = store.authenticate(load_capability(
                Path(self.vault.fx.projects["alpha"]["capabilities"]["codex"]))["token"])
            with self.assertRaises(MemoryError) as erased:
                kernel.propose(agent, self.vault.erased_delivery)
            self.assertEqual(erased.exception.code, "delivery_suppressed")
        finally:
            store.close()
        self.assertEqual(self.files["audit_key"].read_bytes(), self.vault.audit_key)
        self.assertEqual({name: (self.home / name).read_bytes() for name in self.vault.capabilities},
                         self.vault.capabilities)
        for name, (_mode, value) in file_snapshot(self.home).items():
            if isinstance(value, bytes) and name not in {"storage.key", "audit.key"}:
                self.assertNotIn(CANARY.encode(), value, name)
        return key

    def start_daemon(self):
        process = subprocess.Popen([sys.executable, "-m", "continuum_memory.daemon", "--data-dir", str(self.home)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.environment())

        def close():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()
        self.addCleanup(close)
        client = DaemonClient(self.home, self.files["control"])
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail("Fixture daemon exited: " + process.stderr.read().decode())
            try:
                client.call("status", {"project": self.vault.fx.project})
                return process
            except MemoryError:
                time.sleep(0.01)
        self.fail("Fixture daemon did not become ready")

    def test_rotation_preserves_application_receipts_and_real_mcp_reopen(self):
        store = Store(self.home)
        try:
            control = store.authenticate(load_capability(self.files["control"])["token"])
            self.assertEqual(Kernel(store).status(control, {"project": self.vault.fx.project})["storage_generation"],
                             "initial")
        finally:
            store.close()
        result = self.approved()
        new_key = self.assert_clean_rotation()
        encoded = canonical_json(result)
        self.assertNotIn(new_key.hex(), encoded)
        self.assertNotIn(self.vault.old_key.hex(), encoded)
        self.assertNotIn(CANARY, encoded)
        self.start_daemon()
        capability = Path(self.vault.fx.projects["alpha"]["capabilities"]["codex"])
        client = McpFixtureClient(self.home, capability, "rotation-fixture")
        self.addCleanup(client.close)
        self.assertFalse({"storage_rotate_key", "storage_recover_key"} & {tool["name"] for tool in client.tools()})
        self.assertIn("error", client.call_raw("storage_rotate_key", {}))
        self.assertEqual(self.files["storage_key"].read_bytes(), new_key)
        result = client.call("memory_search", {"query": CANARY})
        self.assertIn(self.vault.live["assertion_id"], [row["version_id"] for row in result["cards"]])
        self.assertNotIn("storage_generation", client.call("memory_status", {}))

    def test_two_rotations_preserve_one_event_per_operation(self):
        self.approved()
        first_key = self.assert_clean_rotation()
        self.approved()
        second_key = self.assert_clean_rotation(count=2)
        self.assertNotEqual(first_key, second_key)
        with self.assertRaises(storage.sqlite3.DatabaseError):
            open_keyed_readonly(self.files["db"], first_key)

    def test_generation_visibility_uses_capability_authority_not_provider_label(self):
        with tempfile.TemporaryDirectory(prefix="continuum-provider-authority-") as temporary:
            home = Path(temporary)
            boot = Store.bootstrap(home, [{"name": "authority", "path_hint": "/fixture/authority",
                                           "providers": ["user_control"]}])
            project = boot["projects"][0]
            with synthetic_approval(self.proof_dir):
                result = rotation.rotate_storage_key(home)
            store = Store(home)
            try:
                owner = store.authenticate(load_capability(paths(home)["control"])["token"])
                scoped = store.authenticate(load_capability(Path(project["capabilities"]["user_control"]))["token"])
                self.assertEqual(owner["provider"], scoped["provider"])
                self.assertIsNone(owner["project_id"])
                self.assertEqual(scoped["project_id"], project["id"])
                self.assertNotIn("control", scoped["permissions"])
                kernel = Kernel(store)
                self.assertEqual(kernel.status(owner, {"project": project["id"]})["storage_generation"],
                                 result["operation_id"])
                self.assertNotIn("storage_generation", kernel.status(scoped, {}))
            finally:
                store.close()

    def test_wrong_signed_fields_fail_before_rotation_state_or_key_changes(self):
        mutations = {
            "vault": {"vault_id": "vlt_wrong_fixture"},
            "caller": {"caller_uid": os.getuid() + 1},
            "operation": {"operation": "remember"},
            "digest": {"preview_digest": "0" * 64},
            "nonce": {"nonce": "gnt_wrong_fixture"},
            "expiry": {"expires_at": int(time.time()) - 1},
        }
        for label, update in mutations.items():
            with self.subTest(field=label):
                broker = SyntheticBroker(self.proof_dir, lambda fields, _challenge: fields.update(update))
                before = file_snapshot(self.home)
                with self.assertRaises(MemoryError):
                    self.approved(broker=broker)
                self.assertEqual(file_snapshot(self.home), before)
                self.assertFalse(self.files["rotation_state"].exists())
                self.assertFalse(self.files["next_storage_key"].exists())

    def test_unprovisioned_approval_fails_without_terminal_fallback(self):
        before = file_snapshot(self.home)
        with patch.object(rotation, "linux_public_key", return_value=None):
            with patch.object(rotation, "LinuxPolkitApprovalBroker") as broker:
                with self.assertRaises(MemoryError) as error:
                    rotation.rotate_storage_key(self.home)
                broker.assert_not_called()
        self.assertEqual(error.exception.code, "approval_broker_unavailable")
        self.assertEqual(file_snapshot(self.home), before)

    def test_each_native_phase_crash_recovers_with_no_duplicate_event(self):
        boundaries = ("next:after", "state:prepared", "rekey:before", "rekey:after",
                      "database_sync:before", "database_sync:after", "publish:before",
                      "publish:after", "record:before", "audit:after_commit", "audit:after_anchor",
                      "record:after", "state:published", "cleanup:next_unlinked", "cleanup:state_unlinked")
        for boundary in boundaries:
            with self.subTest(boundary=boundary):
                vault = RotationVault()
                previous = self.vault, self.home, self.files
                self.vault, self.home, self.files = vault, vault.home, paths(vault.home)
                try:
                    completed = self.child("rotate", boundary)
                    self.assertEqual(completed.returncode, CRASH_EXIT, completed.stderr)
                    self.assertNotIn(CANARY, completed.stdout + completed.stderr)
                    self.assertNotIn(vault.old_key.hex(), completed.stdout + completed.stderr)
                    pending = self.files["rotation_state"].exists() or self.files["next_storage_key"].exists()
                    if pending:
                        self.assert_pending()
                        self.approved("recover")
                    self.assert_clean_rotation()
                finally:
                    self.vault, self.home, self.files = previous
                    vault.close()

    def test_preparing_without_next_aborts_only_after_fresh_proof(self):
        completed = self.child("rotate", "state:preparing")
        self.assertEqual(completed.returncode, CRASH_EXIT, completed.stderr)
        self.assertFalse(self.files["next_storage_key"].exists())
        self.assert_pending()
        before = file_snapshot(self.home)
        with patch.object(rotation, "linux_public_key", return_value=None):
            with self.assertRaises(MemoryError):
                rotation.recover_storage_key(self.home)
        self.assertEqual(file_snapshot(self.home), before)
        with patch.object(Store, "_open_during_rotation", wraps=Store._open_during_rotation) as original_open:
            self.assertEqual(self.approved("recover")["status"], "aborted")
            original_open.assert_not_called()
        self.assertFalse(self.files["rotation_state"].exists())
        self.assertEqual(file_snapshot(self.home), {
            name: value for name, value in before.items() if name != self.files["rotation_state"].name
        })
        self.assertEqual(self.files["storage_key"].read_bytes(), self.vault.old_key)
        store = Store(self.home)
        try:
            self.assertEqual(application_snapshot(store.connection), self.vault.application)
            self.assertEqual(store.connection.execute("SELECT count(*) FROM audit_events").fetchone()[0],
                             len(self.vault.audit_rows))
        finally:
            store.close()

    def test_preparing_abort_preserves_preexisting_hot_journal_without_opening_original(self):
        completed = create_hot_journal(self.home)
        self.assertEqual(completed.returncode, CRASH_EXIT, completed.stderr)
        journal = self.home / "continuum.db-journal"
        self.assertGreater(journal.stat().st_size, 512)
        self.assertEqual(journal.read_bytes()[:8], bytes.fromhex("d9d505f920a163d7"))
        original = file_snapshot(self.home)
        completed = self.child("rotate", "state:preparing")
        self.assertEqual(completed.returncode, CRASH_EXIT, completed.stderr)
        self.assertEqual(file_snapshot(self.home, database_only=True), {
            name: value for name, value in original.items() if name in ARTIFACT_NAMES
        })
        self.assertFalse(self.files["next_storage_key"].exists())
        self.assert_pending()
        with patch.object(Store, "_open_during_rotation", wraps=Store._open_during_rotation) as original_open:
            self.assertEqual(self.approved("recover")["status"], "aborted")
            original_open.assert_not_called()
        self.assertEqual(file_snapshot(self.home), original)
        with self.assertRaises(MemoryError) as caught:
            Store(self.home)
        self.assertEqual(caught.exception.code, "storage_recovery_required")
        self.assertEqual(file_snapshot(self.home), original)

    def test_published_duplicate_key_and_missing_next_cleanup_are_idempotent(self):
        self.interrupt("state:published")
        self.assertEqual(self.files["storage_key"].read_bytes(), self.files["next_storage_key"].read_bytes())
        self.assert_pending()
        self.files["next_storage_key"].unlink()
        self.approved("recover")
        self.assert_clean_rotation()

    def test_orphan_next_key_blocks_store_bootstrap_and_recovery(self):
        write_private(self.files["next_storage_key"], os.urandom(32))
        self.assert_pending()
        before = file_snapshot(self.home)
        with self.assertRaises(MemoryError):
            self.approved("recover")
        self.assertEqual(file_snapshot(self.home), before)

    def test_missing_prepared_next_key_is_preserved_and_refused(self):
        self.interrupt("state:prepared")
        self.files["next_storage_key"].unlink()
        before = file_snapshot(self.home)
        self.assert_pending()
        with self.assertRaises(MemoryError):
            self.approved("recover")
        self.assertEqual(file_snapshot(self.home), before)

    def test_hot_journal_candidate_probes_use_independent_copies_and_preserve_source(self):
        completed = create_hot_journal(self.home)
        self.assertEqual(completed.returncode, CRASH_EXIT, completed.stderr)
        journal = Path(str(self.files["db"]) + "-journal")
        self.assertEqual(journal.read_bytes()[:8], bytes.fromhex("d9d505f920a163d7"))
        self.assertGreater(journal.stat().st_size, 512)
        before = file_snapshot(self.home)
        wrong = os.urandom(32)
        copied = {}
        fingerprint = rotation._fingerprint
        connect = storage._connect
        opened = []
        original_artifacts = file_snapshot(self.home, database_only=True)

        def inspect_copy(source, destination=None):
            result = fingerprint(source, destination)
            if destination is not None:
                copied.setdefault(destination.parent, set()).add(destination.name)
                self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
                self.assertNotIn(CANARY.encode(), destination.read_bytes())
            return result

        def inspect_open(database, key, *args, **kwargs):
            self.assertNotEqual(database, self.files["db"])
            self.assertEqual(database.name, self.files["db"].name)
            observed = file_snapshot(database.parent, database_only=True)
            self.assertEqual(observed, original_artifacts)
            for _mode, contents in observed.values():
                self.assertNotIn(CANARY.encode(), contents)
            opened.append(database)
            return connect(database, key, *args, **kwargs)

        with DaemonLock(self.home) as lock:
            lock.prepare_socket(self.files["socket"])
            snapshot = rotation._snapshot(self.home)
            with patch.object(rotation, "_fingerprint", side_effect=inspect_copy):
                with patch.object(storage, "_connect", side_effect=inspect_open):
                    results = rotation._probe_candidates(self.home, [wrong, self.vault.old_key, self.vault.old_key], snapshot)
        self.assertEqual(len(opened), 2)
        self.assertEqual(len(set(opened)), 2)
        self.assertEqual(len(copied), 2)
        for directory, names in copied.items():
            self.assertTrue({"continuum.db", "continuum.db-journal"} <= names)
            self.assertFalse(directory.exists())
        self.assertEqual(results, [(hashlib.sha256(self.vault.old_key).hexdigest(), {
            "vault_id": self.vault.vault_id, "generation": "initial", "rotation_operation": None,
        })])
        self.assertEqual(file_snapshot(self.home), before)
        self.approved()
        self.assert_clean_rotation()

    def test_committed_wal_candidate_copy_preserves_all_source_sidecars(self):
        store = Store(self.home)
        try:
            store.connection.execute("INSERT INTO metadata(key,value) VALUES ('wal_fixture',?)", (CANARY,))
            self.assertTrue(Path(str(self.files["db"]) + "-wal").exists())
            with DaemonLock(self.home) as lock:
                lock.prepare_socket(self.files["socket"])
                before = file_snapshot(self.home)
                snapshot = rotation._snapshot(self.home)
                valid = rotation._probe_candidates(self.home, [self.vault.old_key], snapshot)
                self.assertEqual(len(valid), 1)
                self.assertEqual(valid[0][1]["vault_id"], self.vault.vault_id)
                self.assertEqual(file_snapshot(self.home), before)
        finally:
            store.close()

    def test_neither_key_valid_preserves_corrupt_original_evidence(self):
        self.interrupt("state:prepared")
        damaged = bytearray(self.files["db"].read_bytes())
        damaged[128] ^= 0x80
        self.files["db"].write_bytes(damaged)
        before = file_snapshot(self.home)
        with self.assertRaises(MemoryError):
            self.approved("recover")
        self.assertEqual(file_snapshot(self.home), before)

    def test_unsafe_or_unsupported_sidecar_copy_state_is_refused_without_changes(self):
        for name, contents in (("continuum.db-mj-fixture", b"UNSUPPORTED-SUPER-JOURNAL"),
                               ("continuum.db-journal", b"SYNTHETIC-TRAILER" + bytes.fromhex("d9d505f920a163d7"))):
            with self.subTest(name=name):
                extra = self.home / name
                write_private(extra, contents)
                before = file_snapshot(self.home)
                with self.assertRaises(MemoryError):
                    self.approved()
                self.assertEqual(file_snapshot(self.home), before)
                extra.unlink()
        target = self.home / "private-sentinel"
        write_private(target, b"SYNTHETIC-SIDECAR-TARGET")
        for kind in ("symlink", "hardlink", "permissive"):
            with self.subTest(kind=kind):
                sidecar = self.home / "continuum.db-journal"
                if kind == "symlink":
                    sidecar.symlink_to(target.name)
                elif kind == "hardlink":
                    os.link(target, sidecar)
                else:
                    write_private(sidecar, b"SYNTHETIC-SIDECAR")
                    sidecar.chmod(0o644)
                before = file_snapshot(self.home)
                with self.assertRaises(MemoryError):
                    self.approved()
                self.assertEqual(file_snapshot(self.home), before)
                sidecar.unlink()

    def test_authenticated_state_schema_hash_and_vault_mismatches_fail_closed(self):
        self.interrupt("state:prepared")
        original = self.files["rotation_state"].read_bytes()
        state = json.loads(original)
        mutations = {
            "unknown_field": {"unexpected": "synthetic"},
            "boolean_version": {"schema_version": True},
            "phase": {"phase": "unknown"},
            "mode": {"storage_mode": "fixture-unsupported"},
            "vault": {"vault_id": "vlt_other_fixture"},
            "generation": {"current_generation": "rot_stale_generation"},
            "old_hash": {"old_key_sha256": "0" * 64},
            "new_hash": {"new_key_sha256": "0" * 64},
            "same_key": {"new_key_sha256": state["old_key_sha256"]},
        }
        malformed = {"invalid_json": b"{", "oversized": b"x" * 4097,
                     "invalid_mac": canonical_json(dict(state, mac="0" * 64)).encode()}
        for name, change in mutations.items():
            altered = dict(state, **change)
            payload = {key: value for key, value in altered.items() if key != "mac"}
            altered["mac"] = hmac.new(self.vault.audit_key, b"continuum-storage-rotation-v1\x00" +
                                      canonical_json(payload).encode(), hashlib.sha256).hexdigest()
            malformed[name] = canonical_json(altered).encode()
        for name, data in malformed.items():
            with self.subTest(case=name):
                self.files["rotation_state"].write_bytes(data)
                before = file_snapshot(self.home)
                with self.assertRaises(MemoryError):
                    self.approved("recover")
                self.assertEqual(file_snapshot(self.home), before)
        self.files["rotation_state"].write_bytes(original)
        self.approved("recover")
        self.assert_clean_rotation()

    def test_expiry_during_final_snapshot_hash_refuses_rotate_and_recovery(self):
        for action in ("rotate", "recover"):
            with self.subTest(action=action):
                if action == "recover":
                    self.interrupt("state:prepared")
                broker = SyntheticBroker(self.proof_dir)
                now = [int(time.time())]
                unchanged = rotation._unchanged

                def slow_hash(*args, **kwargs):
                    result = unchanged(*args, **kwargs)
                    if broker.challenges:
                        now[0] += 1000
                    return result

                before = file_snapshot(self.home)
                with patch.object(rotation.time, "time", side_effect=lambda: now[0]):
                    with patch.object(rotation, "_unchanged", side_effect=slow_hash):
                        with self.assertRaises(MemoryError) as error:
                            self.approved(action, broker)
                self.assertEqual(error.exception.code, "approval_expired")
                self.assertTrue(broker.grants)
                self.assertEqual(file_snapshot(self.home), before)

    def test_changed_state_during_real_proof_rejects_before_mutation(self):
        self.interrupt("state:prepared")
        original = self.files["rotation_state"].read_bytes()

        def changed(_fields, _challenge):
            self.files["rotation_state"].write_bytes(original + b" ")

        broker = SyntheticBroker(self.proof_dir, changed)
        database_before = file_snapshot(self.home, database_only=True)
        key_before = self.files["storage_key"].read_bytes()
        with self.assertRaises(MemoryError):
            self.approved("recover", broker)
        self.assertEqual(file_snapshot(self.home, database_only=True), database_before)
        self.assertEqual(self.files["storage_key"].read_bytes(), key_before)
        self.assertEqual(self.files["rotation_state"].read_bytes(), original + b" ")

    def test_a_rotation_grant_cannot_be_replayed_for_recovery(self):
        broker = SyntheticBroker(self.proof_dir)
        with boundary_fault("state:prepared"):
            with self.assertRaises(MemoryError):
                self.approved(broker=broker)
        grant = broker.grants[0]
        before = file_snapshot(self.home)
        with patch.object(broker, "authorize", return_value=grant):
            with self.assertRaises(MemoryError) as error:
                self.approved("recover", broker)
        self.assertEqual(error.exception.code, "approval_invalid")
        self.assertEqual(file_snapshot(self.home), before)
        self.approved("recover")
        self.assert_clean_rotation()

    def test_finish_requires_copied_new_key_validation_before_original_open(self):
        self.interrupt("state:prepared")
        completed = create_hot_journal(self.home, allow_unsupported=True)
        self.assertEqual(completed.returncode, CRASH_EXIT, completed.stderr)
        state = json.loads(self.files["rotation_state"].read_bytes())
        next_key = self.files["next_storage_key"].read_bytes()
        before = file_snapshot(self.home)
        with DaemonLock(self.home) as lock:
            lock.prepare_socket(self.files["socket"])
            # A claimed new-key outcome is insufficient: real copied probes must
            # detect that the original hot journal still recovers the old key.
            with self.assertRaises(MemoryError):
                rotation._finish(self.home, state, self.vault.audit_key, next_key,
                                 state["new_key_sha256"], lock)
        self.assertEqual(file_snapshot(self.home), before)

    def test_invalid_anchor_before_publication_preserves_old_active_key_and_state(self):
        self.interrupt("rekey:after")
        original_anchor = self.files["audit_head"].read_bytes()
        for corrupt in (b"not-json", canonical_json({"audit_seq": 999999, "mac": "0" * 64}).encode()):
            with self.subTest(anchor=corrupt):
                self.files["audit_head"].write_bytes(corrupt)
                before = file_snapshot(self.home)
                with self.assertRaises(MemoryError):
                    self.approved("recover")
                self.assertEqual(file_snapshot(self.home), before)
                self.assertEqual(self.files["storage_key"].read_bytes(), self.vault.old_key)
        self.files["audit_head"].write_bytes(original_anchor)
        self.approved("recover")
        self.assert_clean_rotation()

    def test_generation_without_matching_audit_event_refuses_before_key_publication(self):
        self.interrupt("rekey:after")
        state = json.loads(self.files["rotation_state"].read_bytes())
        connection = storage._connect(self.files["db"], self.files["next_storage_key"].read_bytes(),
                                      apply_hardening=True)
        try:
            for name in ("storage_generation", "storage_rotation_operation"):
                connection.execute("INSERT INTO metadata(key,value) VALUES (?,?)", (name, state["operation_id"]))
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(connection.execute("PRAGMA cipher_integrity_check").fetchall(), [])
            self.assertEqual(connection.execute("SELECT count(*) FROM audit_events WHERE operation='storage_key_rotated'")
                             .fetchone()[0], 0)
        finally:
            connection.close()
        before = file_snapshot(self.home)
        broker = SyntheticBroker(self.proof_dir)
        with self.assertRaises(MemoryError):
            self.approved("recover", broker)
        self.assertEqual(broker.challenges, [])
        self.assertEqual(file_snapshot(self.home), before)
        self.assertEqual(self.files["storage_key"].read_bytes(), self.vault.old_key)

    def test_matching_event_without_generation_refuses_before_key_publication(self):
        self.interrupt("rekey:after")
        state = json.loads(self.files["rotation_state"].read_bytes())
        next_key = self.files["next_storage_key"].read_bytes()
        for name in ARTIFACT_NAMES[1:]:
            self.assertFalse((self.home / name).exists())
        # Build the inconsistency with the real audit writer on an encrypted
        # fixture copy. No audit verifier or HMAC result is substituted.
        with tempfile.TemporaryDirectory(prefix="continuum-audit-generation-") as temporary:
            copy_home = Path(temporary)
            copy_files = paths(copy_home)
            write_private(copy_files["db"], self.files["db"].read_bytes())
            write_private(copy_files["storage_key"], next_key)
            write_private(copy_files["audit_key"], self.vault.audit_key)
            write_private(copy_files["audit_head"], self.files["audit_head"].read_bytes())
            store = Store(copy_home)
            try:
                store.begin()
                store.append_audit(store.next_sequence(), "user_control", "storage_key_rotated",
                                   self.vault.vault_id, state["operation_id"], policy_decision="os_approved")
                store.commit(sync_audit=True)
                self.assertEqual(store.verify_audit()["status"], "valid")
                self.assertEqual(store.connection.execute("SELECT count(*) FROM metadata WHERE key='storage_generation'")
                                 .fetchone()[0], 0)
            finally:
                store.close()
            self.files["db"].write_bytes(copy_files["db"].read_bytes())
            self.files["audit_head"].write_bytes(copy_files["audit_head"].read_bytes())
        before = file_snapshot(self.home)
        broker = SyntheticBroker(self.proof_dir)
        with self.assertRaises(MemoryError):
            self.approved("recover", broker)
        self.assertEqual(broker.challenges, [])
        self.assertEqual(file_snapshot(self.home), before)
        self.assertEqual(self.files["storage_key"].read_bytes(), self.vault.old_key)

    def test_key_rename_then_directory_fsync_failure_remains_recoverable(self):
        real_sync = os.fsync
        fired = []

        def fail_after_rename(fd):
            if (not fired and stat.S_ISDIR(os.fstat(fd).st_mode)
                    and self.files["storage_key"].read_bytes() != self.vault.old_key):
                fired.append(True)
                raise OSError("Synthetic directory sync failure after rename")
            return real_sync(fd)

        with patch.object(rotation.os, "fsync", side_effect=fail_after_rename):
            with self.assertRaises(MemoryError):
                self.approved()
        self.assertEqual(fired, [True])
        self.assertEqual(self.files["storage_key"].read_bytes(), self.files["next_storage_key"].read_bytes())
        self.assert_pending()
        self.approved("recover")
        self.assert_clean_rotation()

    def test_next_key_create_failure_and_cleanup_sync_failure_are_recoverable(self):
        original_write = rotation.write_private
        create_failures = []

        def fail_next(path, data):
            if path == self.files["next_storage_key"]:
                create_failures.append(path)
                raise OSError("Synthetic exclusive key creation failure")
            return original_write(path, data)

        with patch.object(rotation, "write_private", side_effect=fail_next):
            with self.assertRaises(MemoryError):
                self.approved()
        self.assertEqual(create_failures, [self.files["next_storage_key"]])
        self.assert_pending()
        self.assertFalse(self.files["next_storage_key"].exists())
        self.approved("recover")
        self.assertEqual(self.files["storage_key"].read_bytes(), self.vault.old_key)

        sync = storage._sync_private_directory
        fired = []

        def fail_cleanup(directory):
            state = self.files["rotation_state"]
            if (not fired and state.exists() and not self.files["next_storage_key"].exists()
                    and json.loads(state.read_bytes())["phase"] == "published"):
                fired.append(True)
                raise OSError("Synthetic cleanup directory sync failure")
            return sync(directory)

        with patch.object(storage, "_sync_private_directory", side_effect=fail_cleanup):
            with self.assertRaises(MemoryError):
                self.approved()
        self.assertEqual(fired, [True])
        self.assert_pending()
        self.approved("recover")
        self.assert_clean_rotation()

    def test_real_reader_blocks_checkpoint_and_preserves_key(self):
        store = Store(self.home)
        reader = storage._connect(self.files["db"], self.vault.old_key)
        try:
            reader.execute("BEGIN")
            reader.execute("SELECT count(*) FROM metadata").fetchone()
            store.connection.execute("INSERT INTO metadata(key,value) VALUES ('checkpoint_fixture','synthetic')")
            store.connection.execute("PRAGMA busy_timeout=1")
            self.assertEqual(store.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0], 1)
            with self.assertRaises(MemoryError):
                rotation._rekey_database(store, os.urandom(32))
            # A busy checkpoint can legitimately copy already-committed WAL pages;
            # the key and logical transaction must remain intact.
            self.assertEqual(self.files["storage_key"].read_bytes(), self.vault.old_key)
            self.assertEqual(store.connection.execute("SELECT value FROM metadata WHERE key='checkpoint_fixture'").fetchone()[0],
                             "synthetic")
            self.assertEqual(store.connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        finally:
            reader.close()
            store.close()

    def test_audit_insert_failure_rolls_back_generation_and_recovery_records_once(self):
        real_open = Store._open_during_rotation
        denied = []

        def deny_event(directory):
            store = real_open(directory)

            def authorizer(action, name, *args):
                if action == storage.sqlite3.SQLITE_INSERT and name == "audit_events":
                    denied.append(name)
                    return storage.sqlite3.SQLITE_DENY
                return storage.sqlite3.SQLITE_OK

            store.connection.set_authorizer(authorizer)
            return store

        with patch.object(Store, "_open_during_rotation", side_effect=deny_event):
            with self.assertRaises(MemoryError):
                self.approved()
        self.assertEqual(denied, ["audit_events"])
        self.assertNotEqual(self.files["storage_key"].read_bytes(), self.vault.old_key)
        self.assertEqual(self.files["storage_key"].read_bytes(), self.files["next_storage_key"].read_bytes())
        self.assert_pending()
        connection = open_keyed_readonly(self.files["db"], self.files["storage_key"].read_bytes())
        try:
            self.assertEqual(connection.execute("SELECT count(*) FROM metadata WHERE key IN "
                                                "('storage_generation','storage_rotation_operation')").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT count(*) FROM audit_events").fetchone()[0],
                             len(self.vault.audit_rows))
        finally:
            connection.close()
        self.approved("recover")
        self.assert_clean_rotation()

    def test_preparing_journal_directory_sync_failure_retains_abortable_state(self):
        original_sync = storage._sync_private_directory
        fired = []

        def fail_preparing(directory):
            if not fired and self.files["rotation_state"].exists() and not self.files["next_storage_key"].exists():
                fired.append(True)
                raise OSError("Synthetic preparing journal directory sync failure")
            return original_sync(directory)

        with patch.object(storage, "_sync_private_directory", side_effect=fail_preparing):
            with self.assertRaises(MemoryError):
                self.approved()
        self.assertEqual(fired, [True])
        self.assert_pending()
        self.approved("recover")
        self.assertEqual(self.files["storage_key"].read_bytes(), self.vault.old_key)
        self.assertFalse(self.files["rotation_state"].exists())

    def test_failed_next_key_fsync_is_repeated_before_recovery_rekeys(self):
        real_sync = os.fsync
        failed = []

        def is_next(fd):
            if not self.files["next_storage_key"].exists():
                return False
            opened, current = os.fstat(fd), self.files["next_storage_key"].stat()
            return (opened.st_dev, opened.st_ino) == (current.st_dev, current.st_ino)

        def fail_next_sync(fd):
            if not failed and is_next(fd):
                failed.append(True)
                raise OSError("Synthetic next-key file sync failure")
            return real_sync(fd)

        with patch.object(rotation.os, "fsync", side_effect=fail_next_sync):
            with self.assertRaises(MemoryError):
                self.approved()
        self.assertEqual(failed, [True])
        self.assertEqual(json.loads(self.files["rotation_state"].read_bytes())["phase"], "preparing")
        self.assertEqual(len(self.files["next_storage_key"].read_bytes()), 32)
        self.assertEqual(self.files["storage_key"].read_bytes(), self.vault.old_key)
        events = []
        rekey = rotation._rekey_database
        write_journal = rotation._write_journal
        open_store = Store._open_during_rotation
        home_info = self.home.stat()

        def tracked_sync(fd):
            result = real_sync(fd)
            info = os.fstat(fd)
            if is_next(fd):
                events.append("next_sync")
            if (info.st_dev, info.st_ino) == (home_info.st_dev, home_info.st_ino):
                events.append("directory_sync")
            return result

        def tracked_rekey(*args, **kwargs):
            events.append("rekey")
            return rekey(*args, **kwargs)

        def tracked_journal(directory, state, audit_key):
            result = write_journal(directory, state, audit_key)
            if state["phase"] == "prepared":
                events.append("prepared_sync")
            return result

        def tracked_open(directory):
            events.append("original_open")
            return open_store(directory)

        with patch.object(rotation.os, "fsync", side_effect=tracked_sync):
            with patch.object(rotation, "_rekey_database", side_effect=tracked_rekey):
                with patch.object(rotation, "_write_journal", side_effect=tracked_journal):
                    with patch.object(Store, "_open_during_rotation", side_effect=tracked_open):
                        self.approved("recover")
        self.assertIn("next_sync", events)
        self.assertIn("rekey", events)
        before_rekey = events[:events.index("rekey")]
        self.assertIn("next_sync", before_rekey)
        self.assertIn("directory_sync", before_rekey[before_rekey.index("next_sync") + 1:])
        self.assertLess(events.index("next_sync"), events.index("prepared_sync"))
        self.assertLess(events.index("prepared_sync"), events.index("original_open"))
        self.assertLess(events.index("original_open"), events.index("rekey"))
        self.assert_clean_rotation()

    def test_database_file_fsync_failure_keeps_old_key_until_approved_recovery(self):
        real_sync = os.fsync
        database_info = self.files["db"].stat()
        failed = []

        def fail_database_sync(fd):
            info = os.fstat(fd)
            if not failed and (info.st_dev, info.st_ino) == (database_info.st_dev, database_info.st_ino):
                failed.append(True)
                raise OSError("Synthetic database file sync failure")
            return real_sync(fd)

        with patch.object(rotation.os, "fsync", side_effect=fail_database_sync):
            with self.assertRaises(MemoryError):
                self.approved()
        self.assertEqual(failed, [True])
        self.assertEqual(self.files["storage_key"].read_bytes(), self.vault.old_key)
        self.assert_pending()
        self.approved("recover")
        self.assert_clean_rotation()

    def test_unsafe_state_and_candidate_key_files_are_not_replaced(self):
        self.interrupt("state:prepared")
        for name in ("rotation_state", "next_storage_key"):
            original = self.files[name].read_bytes()
            for kind in ("symlink", "hardlink", "permissive", "short", "wrong"):
                with self.subTest(file=name, kind=kind):
                    path = self.files[name]
                    target = self.home / "unsafe-fixture-target"
                    write_private(target, original)
                    path.unlink()
                    if kind == "symlink":
                        path.symlink_to(target.name)
                    elif kind == "hardlink":
                        os.link(target, path)
                    else:
                        write_private(path, b"short" if kind == "short" else os.urandom(32) if kind == "wrong" else original)
                        if kind == "permissive":
                            path.chmod(0o644)
                    before = file_snapshot(self.home)
                    with self.assertRaises(MemoryError):
                        self.approved("recover")
                    self.assertEqual(file_snapshot(self.home), before)
                    path.unlink()
                    target.unlink()
                    write_private(path, original)
        self.approved("recover")
        self.assert_clean_rotation()

    def test_running_and_stopped_daemon_reject_maintenance_before_database_changes(self):
        process = self.start_daemon()
        inode = (self.home / "memoryd.lock").stat().st_ino
        for stopped in (False, True):
            with self.subTest(stopped=stopped):
                if stopped:
                    process.send_signal(signal.SIGSTOP)
                try:
                    before = file_snapshot(self.home)
                    with self.assertRaises(MemoryError) as error:
                        self.approved()
                    self.assertEqual(error.exception.code, "already_running")
                    self.assertEqual(file_snapshot(self.home), before)
                    self.assertEqual((self.home / "memoryd.lock").stat().st_ino, inode)
                finally:
                    if stopped:
                        process.send_signal(signal.SIGCONT)

    def test_competing_rotation_process_loses_the_same_lease_before_mutation(self):
        program = '''
import sys
from pathlib import Path
from unittest.mock import patch
from continuum_memory.storage_rotation import rotate_storage_key
from fixtures.rotation import synthetic_approval
with synthetic_approval(Path(sys.argv[2])) as broker:
    authorize = broker.authorize
    def gated(challenge):
        grant = authorize(challenge)
        print("FIXTURE_PROOF_READY", flush=True)
        sys.stdin.readline()
        return grant
    with patch.object(broker, "authorize", side_effect=gated):
        rotate_storage_key(Path(sys.argv[1]))
'''
        process = subprocess.Popen([sys.executable, "-c", program, str(self.home), str(self.proof_dir)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env=self.environment())
        try:
            ready, _, _ = select.select([process.stdout], [], [], 10)
            self.assertTrue(ready, "Rotation child did not reach the proof gate")
            self.assertEqual(process.stdout.readline().strip(), "FIXTURE_PROOF_READY")
            inode = (self.home / "memoryd.lock").stat().st_ino
            before = file_snapshot(self.home)
            with self.assertRaises(MemoryError) as error:
                self.approved()
            self.assertEqual(error.exception.code, "already_running")
            self.assertEqual(file_snapshot(self.home), before)
            self.assertEqual((self.home / "memoryd.lock").stat().st_ino, inode)
            output, errors = process.communicate("continue\n", timeout=30)
            self.assertEqual(process.returncode, 0, errors)
            self.assertNotIn(self.vault.old_key.hex(), output + errors)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        self.assert_clean_rotation()

    def test_legacy_socket_is_never_adopted_by_maintenance(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.bind(str(self.files["socket"]))
            self.files["socket"].chmod(0o600)
        inode = self.files["socket"].stat().st_ino
        before = file_snapshot(self.home)
        for _attempt in range(2):
            with self.assertRaises(MemoryError) as error:
                self.approved()
            self.assertEqual(error.exception.code, "stale_socket_unverified")
            self.assertEqual(self.files["socket"].stat().st_ino, inode)
            self.assertEqual(file_snapshot(self.home), before)

    def test_plaintext_vault_is_not_converted(self):
        import sqlite3 as plaintext_sqlite3
        self.files["db"].unlink()
        connection = plaintext_sqlite3.connect(str(self.files["db"]))
        connection.execute("CREATE TABLE fixture(value TEXT)")
        connection.execute("INSERT INTO fixture VALUES (?)", (CANARY,))
        connection.commit()
        connection.close()
        self.files["db"].chmod(0o600)
        before = file_snapshot(self.home)
        with self.assertRaises(MemoryError):
            self.approved()
        self.assertEqual(file_snapshot(self.home), before)


if __name__ == "__main__":
    unittest.main()
