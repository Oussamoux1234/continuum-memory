import io
import json
import sys
import unittest

from scripts.application_test_results import (
    REQUIRED_MODULES, linux_skip_inventory, run_suite, validate_report,
)
from scripts.verify_encrypted_application import require_complete_verification


def complete_report():
    """Synthetic report for policy tests; never represented as runtime evidence."""
    inventory = linux_skip_inventory()
    passed = [module + ".Synthetic.test_contract" for module in REQUIRED_MODULES]
    return {
        "schemaVersion": 1, "platform": "linux", "machine": "x86_64",
        "pythonMinor": "%d.%d" % sys.version_info[:2],
        "discovered": sorted(list(inventory) + passed),
        "testsRun": len(inventory) + len(passed),
        "outcomes": [{"id": name, "status": "skipped", "reason": reason}
                     for name, reason in inventory.items()]
                    + [{"id": name, "status": "passed"} for name in passed],
    }


class ApplicationTestPolicyTest(unittest.TestCase):
    def test_exact_platform_exclusions_and_required_suites_pass(self):
        summary = validate_report(complete_report())
        self.assertEqual(summary["platformTestsSkipped"], 91)
        self.assertEqual(summary["cryptoTestsSkipped"], 0)
        self.assertEqual(summary["testsPassed"], len(REQUIRED_MODULES))

    def test_unlisted_crypto_skip_and_changed_reason_fail(self):
        for index in (-1, 0):
            report = complete_report()
            report["outcomes"][index].update(status="skipped", reason="backend missing")
            with self.subTest(index=index), self.assertRaisesRegex(RuntimeError, "exact reviewed"):
                validate_report(report)

    def test_missing_platform_test_and_added_platform_skip_fail(self):
        missing = complete_report()
        deleted = missing["outcomes"].pop(0)["id"]
        missing["discovered"].remove(deleted)
        missing["testsRun"] -= 1
        extra = complete_report()
        item = dict(extra["outcomes"][0], id="tests.test_windows_pipe.NativePipeTest.test_new")
        extra["outcomes"].append(item)
        extra["discovered"].append(item["id"])
        extra["testsRun"] += 1
        for report in (missing, extra):
            with self.subTest(count=report["testsRun"]), self.assertRaisesRegex(RuntimeError, "exact reviewed"):
                validate_report(report)

    def test_missing_outcome_duplicate_discovery_and_duplicate_outcome_fail(self):
        for mutation in ("missing", "discovery", "outcome"):
            report = complete_report()
            if mutation == "missing":
                report["outcomes"].pop()
            elif mutation == "discovery":
                report["discovered"].append(report["discovered"][0])
            else:
                report["outcomes"].append(report["outcomes"][0])
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                validate_report(report)

    def test_required_crypto_suite_cannot_disappear(self):
        for module in REQUIRED_MODULES:
            report = complete_report()
            report["discovered"] = [name for name in report["discovered"] if not name.startswith(module + ".")]
            report["outcomes"] = [item for item in report["outcomes"] if not item["id"].startswith(module + ".")]
            # A required module may also contribute reviewed platform skips.
            report["testsRun"] = len(report["discovered"])
            with self.subTest(module=module), self.assertRaisesRegex(RuntimeError, "required application"):
                validate_report(report)

    def test_failure_loader_error_and_expected_failure_are_not_success(self):
        for status in ("failed", "error", "expectedFailure", "unexpectedSuccess", "subtestFailure"):
            report = complete_report()
            report["outcomes"][-1]["status"] = status
            with self.subTest(status=status), self.assertRaisesRegex(RuntimeError, "did not pass"):
                validate_report(report)
        report = complete_report()
        report["outcomes"].append({"id": "unittest.loader._FailedTest.test_broken", "status": "error"})
        with self.assertRaisesRegex(RuntimeError, "do not match"):
            validate_report(report)

    def test_schema_version_must_be_exact_integer(self):
        for value in (None, True, 1.0, "1", 2):
            report = complete_report()
            report["schemaVersion"] = value
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, "schema"):
                validate_report(report)

    def test_wrong_platform_abi_and_test_count_fail(self):
        for field, value in (("platform", "darwin"), ("machine", "arm64"), ("testsRun", True)):
            report = complete_report()
            report[field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                validate_report(report)
        with self.assertRaisesRegex(RuntimeError, "interpreter"):
            validate_report(complete_report(), python_minor="0.0")

    def test_demo_and_final_gate_still_required_with_structured_report(self):
        demo = {"status": "passed", "checks": {str(index): True for index in range(17)}}
        output = json.dumps(demo) + "\nverification: PASSED\n"
        evidence = require_complete_verification(output, complete_report())
        self.assertEqual(evidence["demoChecksPassed"], 17)
        self.assertEqual(evidence["testReport"]["outcomes"], complete_report()["outcomes"])
        for invalid in (json.dumps(demo), output + output,
                        output.replace('"16": true', '"16": false')):
            with self.subTest(output=invalid), self.assertRaises(RuntimeError):
                require_complete_verification(invalid, complete_report())

    def test_real_runner_records_subtest_failure_and_fixture_error(self):
        class Cases(unittest.TestCase):
            def test_pass(self):
                self.assertTrue(True)

            def test_subtest(self):
                for number in (1, 2):
                    with self.subTest(number=number):
                        self.assertEqual(number, 0)

            @unittest.skip("synthetic skip")
            def test_skip(self):
                self.fail("must not run")

        report = run_suite(unittest.defaultTestLoader.loadTestsFromTestCase(Cases), stream=io.StringIO())
        self.assertEqual(report["testsRun"], 3)
        self.assertEqual({item["status"] for item in report["outcomes"]}, {"passed", "skipped", "subtestFailure"})
        self.assertEqual(len(report["outcomes"]), 3)

        class BrokenFixture(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                raise RuntimeError("synthetic fixture error")

            def test_never_runs(self):
                self.fail("must not run")

        report = run_suite(unittest.defaultTestLoader.loadTestsFromTestCase(BrokenFixture), stream=io.StringIO())
        self.assertEqual(report["testsRun"], 0)
        self.assertEqual(report["outcomes"][0]["status"], "error")
        self.assertNotEqual(report["outcomes"][0]["id"], report["discovered"][0])


if __name__ == "__main__":
    unittest.main()
