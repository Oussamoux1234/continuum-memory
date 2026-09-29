#!/usr/bin/env python3
"""Full application discovery with explicit Linux platform exclusions."""

import json
import platform
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "work" / "application-tests.json"
REQUIRED_MODULES = (
    "tests.test_encrypted_storage",
    "tests.test_encrypted_export_contract",
    "tests.test_storage_rotation",
    "tests.test_storage_key_custody",
    "tests.test_audit_validation",
    "tests.test_approval",
    "tests.test_lifecycle",
    "tests.test_provider_authority",
    "tests.test_pagination",
    "tests.test_encrypted_platform_contract",
    "tests.test_encrypted_recovery_compatibility",
    "tests.test_cli_recovery",
    "tests.test_cli_recovery_control",
    "tests.test_recovery_journal",
    "tests.test_recovery_protocol",
    "tests.test_anchor_publication_faults",
    "tests.test_accept_proposal_crash",
    "tests.test_correction_crash",
    "tests.test_forget_crash",
    "tests.test_remember_crash",
    "tests.test_reject_proposal_crash",
    "tests.test_sqlite_lock_preservation",
)


def linux_skip_inventory():
    """An explicit reviewed inventory; additions require changing this file's input."""
    value = json.loads((ROOT / "tests/platform-skips-linux.json").read_text())
    if not isinstance(value, dict) or len(value) != 91 or not all(
        isinstance(key, str) and isinstance(reason, str) and reason
        for key, reason in value.items()
    ):
        raise RuntimeError("invalid reviewed Linux platform-skip inventory")
    return value


def validate_report(report, *, python_minor=None):
    """Reject incomplete results and any exclusion beyond the reviewed native slices."""
    if not isinstance(report, dict) or type(report.get("schemaVersion")) is not int or report["schemaVersion"] != 1:
        raise RuntimeError("application test report schema is invalid")
    if report.get("platform") != "linux" or report.get("machine") != "x86_64":
        raise RuntimeError("application test report requires Linux x86-64")
    if python_minor is not None and report.get("pythonMinor") != python_minor:
        raise RuntimeError("application test report interpreter does not match")
    discovered, outcomes = report.get("discovered"), report.get("outcomes")
    if not isinstance(discovered, list) or not discovered or not all(
        isinstance(item, str) for item in discovered
    ) or len(set(discovered)) != len(discovered):
        raise RuntimeError("application discovery is missing or duplicated")
    if not isinstance(outcomes, list) or not all(isinstance(item, dict) for item in outcomes):
        raise RuntimeError("application test outcomes are invalid")
    ids = [item.get("id") for item in outcomes]
    if not all(isinstance(item, str) for item in ids) or len(set(ids)) != len(ids):
        raise RuntimeError("application test outcomes are missing or duplicated")
    if set(ids) != set(discovered) or type(report.get("testsRun")) is not int or report["testsRun"] != len(discovered):
        raise RuntimeError("application discovery and outcomes do not match")
    for module in REQUIRED_MODULES:
        if not any(item.startswith(module + ".") for item in discovered):
            raise RuntimeError("required application test suite is missing: " + module)
    skips = {}
    for outcome in outcomes:
        status = outcome.get("status")
        if status == "skipped":
            skips[outcome["id"]] = outcome.get("reason")
        elif status != "passed":
            raise RuntimeError("application test did not pass: " + outcome["id"])
    if skips != linux_skip_inventory():
        raise RuntimeError("application skips differ from the exact reviewed Linux inventory")
    return {"testsRun": len(discovered), "testsPassed": len(discovered) - len(skips),
            "platformTestsSkipped": len(skips), "unexpectedTestsSkipped": 0,
            "cryptoTestsSkipped": 0}


class ReportingResult(unittest.TextTestResult):
    """Retain parent-test outcomes, including failures inside subtests and fixtures."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes = []
        self._subtest_failed = set()

    def record(self, test, status, **fields):
        self.outcomes.append({"id": test.id(), "status": status, **fields})

    def addSuccess(self, test):
        super().addSuccess(test)
        self.record(test, "passed")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.record(test, "skipped", reason=reason)

    def addError(self, test, err):
        super().addError(test, err)
        self.record(test, "error")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.record(test, "failed")

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.record(test, "expectedFailure")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.record(test, "unexpectedSuccess")

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None and test.id() not in self._subtest_failed:
            self._subtest_failed.add(test.id())
            self.record(test, "subtestFailure")


def test_ids(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from test_ids(item)
        else:
            yield item.id()


def run_suite(suite, *, stream=None):
    discovered = list(test_ids(suite))
    result = unittest.TextTestRunner(verbosity=2, stream=stream, resultclass=ReportingResult).run(suite)
    return {"schemaVersion": 1, "platform": sys.platform, "machine": platform.machine(),
            "pythonMinor": "%d.%d" % sys.version_info[:2], "discovered": discovered,
            "testsRun": result.testsRun, "outcomes": result.outcomes}


def main():
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT))
    report = run_suite(suite)
    REPORT_PATH.parent.mkdir(exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(validate_report(report, python_minor="%d.%d" % sys.version_info[:2]), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
