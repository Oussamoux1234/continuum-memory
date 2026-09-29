"""CI-process owner fixture contracts; native claims require hosted Windows."""

import os
import sys
import unittest
from unittest import mock

from fixtures import windows_test_owner as fixture


class OwnerFixtureGateTest(unittest.TestCase):
    def environment(self):
        return {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows",
                "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_ARCH": "X64",
                "GITHUB_WORKSPACE": str(fixture.ROOT),
                fixture.OPT_IN: "approved-process-only-v1"}

    def test_missing_or_wrong_gate_refuses_before_opening_token(self):
        for key in self.environment():
            environment = self.environment()
            environment[key] = "not-approved"
            with self.subTest(key=key), mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch.object(fixture, "_OwnerAPI") as api:
                with self.assertRaises(RuntimeError):
                    with fixture.temporary_owner():
                        self.fail("Unsafe fixture admitted")
                api.assert_not_called()

    def test_non_windows_host_refuses_without_loading_native_api(self):
        if os.name == "nt":
            self.skipTest("Non-Windows refusal is exercised on POSIX")
        with mock.patch.dict(os.environ, self.environment(), clear=True), \
                mock.patch.object(fixture, "_OwnerAPI") as api:
            with self.assertRaises(RuntimeError):
                with fixture.temporary_owner():
                    self.fail("Native mutation admitted on non-Windows")
            api.assert_not_called()

    def test_wrapper_accepts_no_arbitrary_command_or_sid_arguments(self):
        with mock.patch.object(sys, "argv", ["fixture", "arbitrary-command"]), \
                mock.patch.object(fixture, "temporary_owner") as owner:
            self.assertEqual(fixture.main(), 2)
            owner.assert_not_called()

    def test_fixture_is_not_imported_by_production(self):
        source = fixture.ROOT / "src" / "continuum_memory"
        for path in source.glob("*.py"):
            self.assertNotIn("windows_test_owner", path.read_text(encoding="utf-8"), path.name)


class OwnerFixtureStateTest(unittest.TestCase):
    """Injected orchestration faults only; these are not native token evidence."""

    class API:
        current, parent = "current", "parent"
        original, user, parent_owner = "original-owner", "user", "parent-owner"

        def __init__(self):
            self.value, self.calls, self.closed = self.original, [], False

        def open(self):
            return self

        def sid(self, data):
            return data

        def owner(self, token):
            return self.value if token == self.current else self.parent_owner

        def set_owner(self, data):
            self.calls.append(data)
            self.value = data

        def close(self):
            self.closed = True

    def test_exact_previous_owner_restored_after_body_failure(self):
        api = self.API()
        with mock.patch.object(fixture, "_guard_scope"), mock.patch.object(fixture, "_OwnerAPI", return_value=api):
            with self.assertRaisesRegex(ValueError, "body"):
                with fixture.temporary_owner() as evidence:
                    self.assertEqual(api.value, api.user)
                    raise ValueError("body")
        self.assertEqual(api.calls, [api.user, api.original])
        self.assertEqual(api.value, api.original)
        self.assertTrue(api.closed)
        self.assertTrue(evidence["restored"])

    def test_failed_open_never_sets_owner_and_closes_partial_handles(self):
        api = self.API()
        with mock.patch.object(fixture, "_guard_scope"), mock.patch.object(fixture, "_OwnerAPI", return_value=api), \
                mock.patch.object(api, "open", side_effect=RuntimeError("shared parent token")):
            with self.assertRaisesRegex(RuntimeError, "shared parent token"):
                with fixture.temporary_owner():
                    self.fail("Unsafe token entered")
        self.assertEqual(api.calls, [])
        self.assertTrue(api.closed)

    def test_restoration_failure_is_fatal_not_normal_completion(self):
        api = self.API()
        def setter(data):
            if data == api.original:
                raise RuntimeError("injected restore failure")
            api.value = data
        with mock.patch.object(fixture, "_guard_scope"), mock.patch.object(fixture, "_OwnerAPI", return_value=api), \
                mock.patch.object(api, "set_owner", side_effect=setter), \
                mock.patch.object(fixture.os, "_exit", side_effect=SystemExit(79)) as fatal:
            with self.assertRaises(SystemExit) as caught:
                with fixture.temporary_owner():
                    pass
        self.assertEqual(caught.exception.code, 79)
        fatal.assert_called_once_with(79)

    def test_update_failure_still_attempts_exact_restoration(self):
        api = self.API()
        def setter(data):
            api.calls.append(data)
            if data == api.user:
                raise RuntimeError("injected update failure")
            api.value = data
        with mock.patch.object(fixture, "_guard_scope"), mock.patch.object(fixture, "_OwnerAPI", return_value=api), \
                mock.patch.object(api, "set_owner", side_effect=setter):
            with self.assertRaisesRegex(RuntimeError, "injected update failure"):
                with fixture.temporary_owner():
                    self.fail("Failed update admitted")
        self.assertEqual(api.calls, [api.user, api.original])
        self.assertTrue(api.closed)


@unittest.skipUnless(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true",
                     "Real owner mutation proof requires explicitly opted-in hosted Windows CI")
class NativeOwnerFixtureTest(unittest.TestCase):
    def test_real_success_and_exception_restore_and_child_inherits_owner(self):
        evidence = fixture.preflight()
        self.assertTrue(evidence["restored_after_success"])
        self.assertTrue(evidence["restored_after_exception"])
        self.assertTrue(evidence["parent_unchanged"])
        self.assertTrue(evidence["child_owner_matches"])


if __name__ == "__main__":
    unittest.main()
