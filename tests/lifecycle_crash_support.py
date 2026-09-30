"""Held source-only crash-test preparation; not executed on this candidate.

Imported from MAIN 4b1eaf5. The original plaintext fixture description below
is historical context, not encrypted runtime or platform acceptance. Execution
requires separately approved native inputs and remains held.

Process-exit mechanics for synthetic automatic lifecycle transactions only."""

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import patch

from continuum_memory import storage
from continuum_memory.kernel import Kernel
from continuum_memory.security import read_private
from continuum_memory.storage import Store, load_capability, paths
from tests.admin_crash_support import AdminCrashFixture, BoundaryConnection, snapshot


LIFECYCLE_NOW = datetime(2027, 1, 3, tzinfo=timezone.utc)
LIFECYCLE_TIME = "2027-01-03T00:00:00Z"


def lifecycle_kernel(store):
    return Kernel(store, now_provider=lambda: LIFECYCLE_NOW,
                  approval_public_key_provider=lambda uid: None,
                  allow_prototype_approval=True)


def run_lifecycle_child(home, crash_after, request, invoke):
    """Execute the real operation, observing writes without replacing SQLite."""
    store = Store(home)
    try:
        control = store.authenticate(load_capability(paths(home)["control"])["token"])
        observed = BoundaryConnection(store.connection, crash_after)
        store.connection = observed
        kernel = lifecycle_kernel(store)
        publish = store._sync_audit_head_raw

        def publish_anchor(connection, path):
            observed.tick("before_anchor_publish")
            publish(connection, path)
            observed.tick("after_anchor_publish")

        # Only time in this synthetic fixture is fixed. SQLite, audit MACs,
        # filesystem publication, identifiers and the actual operation are real.
        with patch.object(storage, "now_iso", return_value=LIFECYCLE_TIME), \
                patch.object(store, "_sync_audit_head_raw", side_effect=publish_anchor):
            result = invoke(kernel, control, request)
        print(json.dumps({"boundaries": observed.boundaries, "result": result}), flush=True)
    finally:
        store.close()


class LifecycleCrashFixture(AdminCrashFixture):
    """Reuse copying/subprocess mechanics, not owner-grant/receipt assumptions."""

    def copied_vault(self, name):
        # Never copy live SQLite companions as a pretend consistent snapshot.
        database = paths(self.fx.home)["db"]
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse(database.with_name(database.name + suffix).exists())
        return super().copied_vault(name)

    @contextmanager
    def opened(self, home):
        store = Store(home)
        try:
            control = store.authenticate(load_capability(paths(home)["control"])["token"])
            yield store, lifecycle_kernel(store), control
        finally:
            store.close()

    def assert_lifecycle_crash_matrix(self, reference, recorded, assert_semantics):
        boundaries = recorded["boundaries"]
        # These fixtures deliberately isolate ONE lifecycle SQL transaction and
        # its separately locked audit-anchor publication. A combined purge then
        # expiry request has two transactions and requires its own state oracle.
        self.assertEqual([item for item in boundaries if item.startswith("before_commit_")],
                         ["before_commit_1", "before_commit_2"])
        self.assertEqual(boundaries.count("before_anchor_publish"), 1)
        self.assertEqual(boundaries.count("after_anchor_publish"), 1)
        committed_at = boundaries.index("after_commit_1") + 1
        published_at = boundaries.index("after_anchor_publish") + 1
        with self.opened(reference) as (store, kernel, control):
            expected = snapshot(store.connection)
            new_anchor = read_private(paths(reference)["audit_head"])
            self.assertNotEqual(self.original, expected)
            self.assertNotEqual(self.old_anchor, new_anchor)
            self.assertEqual(store.verify_audit()["status"], "valid")
            self.assert_integrity(store)
            assert_semantics(store, kernel, control)

        for ordinal, label in enumerate(boundaries, 1):
            with self.subTest(ordinal=ordinal, boundary=label):
                home = self.copied_vault("crash-%02d" % ordinal)
                self.assertEqual(self.run_child(home, ordinal), {"ordinal": ordinal, "boundary": label})
                committed = ordinal >= committed_at
                published = ordinal >= published_at
                prior = expected if committed else self.original
                anchor = new_anchor if published else self.old_anchor
                with self.opened(home) as (store, kernel, control):
                    # No lifecycle-triggering reads or reconciliation before
                    # exact assertions: they could conceal incomplete changes.
                    self.assertEqual(snapshot(store.connection), prior)
                    self.assertEqual(read_private(paths(home)["audit_head"]), anchor)
                    self.assert_integrity(store)
                    status = "external_anchor_stale" if committed and not published else "valid"
                    self.assertEqual(store.verify_audit()["status"], status)
                    self.assertEqual(kernel.audit_reconcile(control, {})["status"], "valid")
                    self.assertEqual(snapshot(store.connection), prior)
                    self.assertEqual(read_private(paths(home)["audit_head"]),
                                     new_anchor if committed else self.old_anchor)

                retried = self.run_child(home)
                self.assertEqual(retried["result"], recorded["result"])
                self.assertEqual(retried["boundaries"], [] if committed else boundaries)
                with self.opened(home) as (store, kernel, control):
                    self.assertEqual(snapshot(store.connection), expected)
                    self.assertEqual(read_private(paths(home)["audit_head"]), new_anchor)
                    self.assertEqual(store.verify_audit()["status"], "valid")
                    self.assert_integrity(store)

                repeated = self.run_child(home)
                self.assertEqual(repeated, {"boundaries": [], "result": recorded["result"]})
                with self.opened(home) as (store, kernel, control):
                    self.assertEqual(snapshot(store.connection), expected)
                    self.assertEqual(read_private(paths(home)["audit_head"]), new_anchor)
                    assert_semantics(store, kernel, control)
                    self.assert_integrity(store)
                with self.opened(home) as (store, kernel, control):
                    assert_semantics(store, kernel, control)
                    self.assert_integrity(store)

