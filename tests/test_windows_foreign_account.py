"""Fixture guard contracts only; native two-account proof comes from its CI job."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from fixtures import windows_foreign_account as fixture


class ForeignAccountFixtureContractTest(unittest.TestCase):
    def test_environment_guard_refuses_before_loading_native_api(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(fixture.AcceptanceFailure, "scope_environment"):
                fixture.guard("owner", Path("unused"), "S-1-5-21-1-2-3-4", "S-1-5-21-1-2-3-5")

    def test_non_windows_host_cannot_run_account_acceptance(self):
        if os.name == "nt":
            self.skipTest("POSIX guard is verified on non-Windows")
        environment = {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64",
                       "RUNNER_ENVIRONMENT": "github-hosted", fixture.OPT_IN: "approved-disposable-account-v1",
                       "CONTINUUM_CI_OWNER_FIXTURE": "approved-process-only-v1"}
        with mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(fixture.AcceptanceFailure, "scope_environment"):
                fixture.guard("foreign", Path("unused"), "S-1-5-21-1-2-3-4", "S-1-5-21-1-2-3-5")

    def test_atomic_report_and_bounded_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture.publish(root, "report.json", {"positive": True})
            self.assertEqual(fixture.await_report(root, "report.json"), {"positive": True})
            self.assertFalse((root / "report.json.pending").exists())
            (root / "oversize.json").write_text(" " * 16385)
            with self.assertRaisesRegex(fixture.AcceptanceFailure, "coordination_size"):
                fixture.await_report(root, "oversize.json")
            with self.assertRaisesRegex(fixture.AcceptanceFailure, "coordination_timeout"):
                fixture.await_report(root, "missing.json", timeout=0)

    def test_missing_and_inaccessible_are_not_interchangeable(self):
        from continuum_memory.windows_boundary import INVALID_HANDLE
        api = mock.Mock()
        api.kernel.CreateFileW.return_value = INVALID_HANDLE
        with mock.patch.object(fixture.ctypes, "get_last_error", return_value=5, create=True):
            fixture.assert_denied(api, "synthetic", 0x80000000)
        for status in (2, 3, 32, 231):
            with self.subTest(status=status), mock.patch.object(
                fixture.ctypes, "get_last_error", return_value=status, create=True):
                with self.assertRaisesRegex(fixture.AcceptanceFailure, "foreign_denial_not_access_denied"):
                    fixture.assert_denied(api, "synthetic", 0x80000000)

    def test_successful_foreign_open_fails_and_closes_handle(self):
        api = mock.Mock()
        api.kernel.CreateFileW.return_value = 123
        with self.assertRaisesRegex(fixture.AcceptanceFailure, "foreign_access_admitted"):
            fixture.assert_denied(api, "synthetic", 0x80000000)
        api._close.assert_called_once_with(123)

    def test_acceptance_is_not_imported_by_production(self):
        for path in (fixture.ROOT / "src" / "continuum_memory").glob("*.py"):
            self.assertNotIn("windows_foreign_account", path.read_text(encoding="utf-8"), path.name)


if __name__ == "__main__":
    unittest.main()
