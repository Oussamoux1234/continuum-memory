"""Synthetic approval clocks must not turn slow crash matrices into expiry tests."""

import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from continuum_memory import kernel as kernel_module
from continuum_memory.errors import MemoryError
from tests.admin_crash_support import AdminCrashFixture, snapshot


class CrashApprovalClockTest(AdminCrashFixture, unittest.TestCase):
    child_module = "tests.test_forget_crash"

    def setUp(self):
        self.setup_crash_fixture("continuum-crash-clock-")

    def test_expired_real_grant_is_refused_but_synthetic_child_reaches_boundary(self):
        accepted = self.fx.approve("remember", subject="clock fixture", claim="synthetic clock claim")
        real_clock = kernel_module.time
        with patch.object(kernel_module, "time", SimpleNamespace(time=lambda: 1_700_000_000)):
            self.challenge = self.fx.preview("forget", target_id=accepted["memory_id"])
        self.assertIs(kernel_module.time, real_clock)
        self.assertLess(self.challenge["expires_at"], int(time.time()))
        expiry, used = self.fx.store.connection.execute(
            "SELECT expires_at,used_at FROM admin_challenges WHERE nonce=?",
            (self.challenge["nonce"],),
        ).fetchone()
        self.assertEqual(expiry, self.challenge["expires_at"])
        self.assertIsNone(used)
        before = snapshot(self.fx.store.connection)
        with self.assertRaises(MemoryError) as refused:
            self.fx.apply(self.challenge)
        self.assertEqual(refused.exception.code, "approval_expired")
        self.assertEqual(snapshot(self.fx.store.connection), before)
        self.fx.store.close()

        # The same original closed vault and grant reach the real subprocess
        # checkpoint with the test-only clock, without extending stored expiry.
        crashed = self.copied_vault("expired-crash")
        self.assertEqual(self.run_child(crashed, 1), {"ordinal": 1, "boundary": "write:admin_challenges"})
        with self.opened(crashed) as (store, _kernel, _control):
            self.assertEqual(snapshot(store.connection), before)
        completed = self.copied_vault("expired-complete")
        result = self.run_child(completed)
        self.assertEqual(result["result"]["commit"]["status"], "committed")
        self.assertEqual(result["result"]["commit"]["audit_anchor"], "synced")
        self.assertIs(kernel_module.time, real_clock)


if __name__ == "__main__":
    unittest.main()
