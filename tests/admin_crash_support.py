"""Shared mechanics for synthetic owner-operation process-crash tests only."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from continuum_memory import kernel as kernel_module, results, storage
from continuum_memory.errors import MemoryError
from continuum_memory.kernel import Kernel
from continuum_memory.security import (
    canonical_json, create_private_directory, ensure_private_directory,
    ensure_private_regular, read_private, sign_grant, write_private,
)
from continuum_memory.storage import Store, load_capability, paths
from tests import test_proposal_erasure as erasure


ROOT = Path(__file__).resolve().parents[1]
CRASH_EXIT = 73
FIXED_NOW = datetime(2027, 1, 1, tzinfo=timezone.utc)
FIXED_TIME = "2027-01-01T00:00:00Z"


def snapshot(connection):
    """Every logical row, including FTS shadow tables; not WAL byte layout."""
    return tuple(connection.iterdump())


def fixture_kernel(store):
    return Kernel(store, now_provider=lambda: FIXED_NOW,
                  approval_public_key_provider=lambda uid: None,
                  allow_prototype_approval=True)


def fixture_params(control, challenge):
    return {"nonce": challenge["nonce"], "preview_digest": challenge["preview_digest"],
            "preview": challenge["preview"],
            "grant": sign_grant(control["token"].encode("ascii"), challenge["nonce"],
                                challenge["operation"], challenge["preview_digest"])}


class BoundaryConnection:
    """Observe completed direct writes, never substitute for SQLite execution."""

    def __init__(self, connection, crash_after):
        self.connection = connection
        self.crash_after = crash_after
        self.boundaries = []
        self.commits = 0

    def tick(self, label):
        self.boundaries.append(label)
        if self.crash_after == len(self.boundaries):
            # Constant categories/ordinals only, never parameters or vault data.
            print(json.dumps({"ordinal": len(self.boundaries), "boundary": label}), flush=True)
            os._exit(CRASH_EXIT)  # No Python rollback, finally or connection close.

    def execute(self, sql, *arguments):
        normalized = " ".join(sql.split())
        checkpoint = normalized == "PRAGMA wal_checkpoint(TRUNCATE)"
        if checkpoint:
            self.tick("before_checkpoint")
        cursor = self.connection.execute(sql, *arguments)
        write = re.match(r"(UPDATE|DELETE FROM|INSERT(?: OR IGNORE)? INTO) ([a-z_]+)", normalized)
        if write:
            self.tick("write:" + write.group(2))
        elif normalized.split()[0] not in {"SELECT", "BEGIN", "PRAGMA"}:
            raise AssertionError("Uninventoried SQL operation in crash fixture")
        if checkpoint:
            self.tick("after_checkpoint")
        return cursor

    def commit(self):
        self.commits += 1
        self.tick("before_commit_%d" % self.commits)
        self.connection.commit()
        self.tick("after_commit_%d" % self.commits)

    def cursor(self, *args, **kwargs):
        raise AssertionError("Cursor mutation bypasses the reviewed crash inventory")

    def executemany(self, *args, **kwargs):
        raise AssertionError("Batched mutation requires a reviewed crash inventory")

    def executescript(self, *args, **kwargs):
        raise AssertionError("Implicit-commit scripts bypass the crash inventory")

    def __getattr__(self, name):
        return getattr(self.connection, name)


def apply_child(home, crash_after, challenge, identifier_factory, expected_prefixes):
    store = Store(home)
    try:
        control = store.authenticate(load_capability(paths(home)["control"])["token"])
        observed = BoundaryConnection(store.connection, crash_after)
        store.connection = observed
        kernel = fixture_kernel(store)
        publish = store._sync_audit_head_raw

        def publish_anchor(connection, path):
            observed.tick("before_anchor_publish")
            publish(connection, path)
            observed.tick("after_anchor_publish")

        # Repeatable output from identical closed-vault copies; real SQLite,
        # existing ledger IDs, signatures, digests and audit MACs are unchanged.
        with patch.object(kernel_module, "random_id", side_effect=identifier_factory) as identifier, \
                patch.object(storage, "now_iso", return_value=FIXED_TIME), \
                patch.object(results, "now_iso", return_value=FIXED_TIME), \
                patch.object(store, "_sync_audit_head_raw", side_effect=publish_anchor):
            result = kernel.admin_apply(control, fixture_params(control, challenge))
            if [call.args for call in identifier.call_args_list] != [(prefix,) for prefix in expected_prefixes]:
                raise AssertionError("Unexpected fixture identifier inventory")
        print(json.dumps({"boundaries": observed.boundaries, "result": result}), flush=True)
    finally:
        store.close()


class AdminCrashFixture:
    """TestCase mixin without discoverable tests or an alternate runtime path."""

    def setup_crash_fixture(self, prefix):
        self.fx = erasure.ProposalErasureTest()
        self.fx.setUp()
        self.addCleanup(self.fx.tearDown)
        self.temporary = tempfile.TemporaryDirectory(prefix=prefix)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.environment = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT / "src"), str(ROOT)]))

    def copied_vault(self, name):
        destination = self.root / name
        if os.name == "nt":
            def copy_private_directory(source, target):
                ensure_private_directory(source)
                # A closed synthetic vault needs a new protected DACL on every
                # directory; ordinary copytree does not preserve that boundary.
                create_private_directory(target)
                entries = list(source.iterdir())
                for entry in entries:
                    copied = target / entry.name
                    if entry.is_dir():
                        copy_private_directory(entry, copied)
                    else:
                        ensure_private_regular(entry)
                        original = entry.read_bytes()
                        # Claim a new private leaf exclusively, then copy bytes
                        # without the private-writer's 64 KiB payload limit.
                        write_private(copied, b"")
                        shutil.copyfile(entry, copied)
                        ensure_private_regular(copied)
                        ensure_private_regular(entry)
                        self.assertTrue(copied.read_bytes() == original, "Fixture copy changed private file bytes")
                        self.assertTrue(entry.read_bytes() == original, "Fixture copy changed source file bytes")
                ensure_private_directory(target)
                self.assertEqual({entry.name for entry in target.iterdir()}, {entry.name for entry in entries})

            copy_private_directory(self.fx.home, destination)
        else:
            shutil.copytree(self.fx.home, destination)
        return destination

    def run_child(self, home, ordinal=0):
        result = subprocess.run([sys.executable, "-m", self.child_module, "--crash-child",
                                 str(home), str(ordinal)], input=canonical_json(self.challenge).encode(),
                                env=self.environment, capture_output=True, timeout=15)
        self.assertEqual(result.stderr, b"")
        self.assertLess(len(result.stdout), 32768)
        self.assertEqual(result.returncode, CRASH_EXIT if ordinal else 0)
        return json.loads(result.stdout)

    @contextmanager
    def opened(self, home):
        store = Store(home)
        try:
            control = store.authenticate(load_capability(paths(home)["control"])["token"])
            yield store, fixture_kernel(store), control
        finally:
            store.close()

    def assert_integrity(self, store):
        self.assertEqual([tuple(row) for row in store.connection.execute("PRAGMA integrity_check")], [("ok",)])
        self.assertEqual(store.connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def assert_crash_matrix(self, reference, recorded, assert_semantics):
        boundaries = recorded["boundaries"]
        with self.opened(reference) as (store, kernel, control):
            expected = snapshot(store.connection)
            new_anchor = read_private(paths(reference)["audit_head"])
            self.assertNotEqual(self.old_anchor, new_anchor)
            self.assert_integrity(store)
            receipt = kernel.admin_result(control, {"nonce": self.challenge["nonce"],
                                                    "preview_digest": self.challenge["preview_digest"]})
            self.assertEqual(receipt["result"], {key: value for key, value in recorded["result"].items() if key != "commit"})
            self.assertTrue(receipt["committed"])
            assert_semantics(store, kernel, control)
        committed_at = boundaries.index("after_commit_1") + 1
        published_at = boundaries.index("after_anchor_publish") + 1
        locator = {"nonce": self.challenge["nonce"], "preview_digest": self.challenge["preview_digest"]}
        for ordinal, label in enumerate(boundaries, 1):
            with self.subTest(ordinal=ordinal, boundary=label):
                home = self.copied_vault("crash-%02d" % ordinal)
                self.assertEqual(self.run_child(home, ordinal), {"ordinal": ordinal, "boundary": label})
                committed = ordinal >= committed_at
                published = ordinal >= published_at
                with self.opened(home) as (store, kernel, control):
                    # Compare before recovery can conceal partial committed state.
                    self.assertEqual(snapshot(store.connection), expected if committed else self.original)
                    self.assertEqual(read_private(paths(home)["audit_head"]), new_anchor if published else self.old_anchor)
                    self.assert_integrity(store)
                    state = "external_anchor_stale" if committed and not published else "valid"
                    self.assertEqual(store.verify_audit()["status"], state)
                    used = store.connection.execute("SELECT used_at FROM admin_challenges WHERE nonce=?",
                                                    (self.challenge["nonce"],)).fetchone()[0]
                    self.assertEqual(used is not None, committed)
                    if committed:
                        found = kernel.admin_result(control, locator)
                        self.assertEqual(found["result"], receipt["result"])
                        self.assertEqual(found["audit_anchor"], state)
                    else:
                        with self.assertRaises(MemoryError) as absent:
                            kernel.admin_result(control, locator)
                        self.assertEqual(absent.exception.code, "not_found")
                    self.assertEqual(kernel.audit_reconcile(control, {})["status"], "valid")
                    self.assertEqual(snapshot(store.connection), expected if committed else self.original)
                if not committed:
                    self.assertEqual(self.run_child(home)["result"], recorded["result"])
                with self.opened(home) as (store, kernel, control):
                    self.assertEqual(snapshot(store.connection), expected)
                    self.assertEqual(read_private(paths(home)["audit_head"]), new_anchor)
                    self.assertEqual(kernel.admin_result(control, locator)["result"], receipt["result"])
                    with self.assertRaises(MemoryError) as replay:
                        kernel.admin_apply(control, fixture_params(control, self.challenge))
                    self.assertEqual(replay.exception.code, "approval_replay")
                    self.assertEqual(snapshot(store.connection), expected)
                    assert_semantics(store, kernel, control)
                    self.assert_integrity(store)
                with self.opened(home) as (store, kernel, control):
                    assert_semantics(store, kernel, control)
