"""Temporary candidate-bootstrap guards; synthetic bytes are never native wheels."""

import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.fetch_patched_sqlcipher_sources import (
    DEFAULT_MANIFEST,
    iter_downloads,
    load_json_strict,
    sha256,
    validate_manifest,
)
from scripts.inspect_patched_sqlcipher_wheel import validate_source_evidence
from scripts.test_patched_sqlcipher_install import require_regular_wheel
from scripts.verify_patched_sqlcipher_inputs import verify_bundle


ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_WHEEL = b"synthetic guard fixture only; not a wheel or candidate artifact\n"
SYNTHETIC_DIGEST = hashlib.sha256(SYNTHETIC_WHEEL).hexdigest()


class SqlcipherBootstrapGuardTest(unittest.TestCase):
    def setUp(self):
        self.manifest = load_json_strict(DEFAULT_MANIFEST)

    def run_cli(self, script, arguments, directory):
        environment = dict(os.environ, TMPDIR=str(directory), PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run(
            [sys.executable, "-B", "-I", str(ROOT / "scripts" / script), *arguments],
            cwd=directory,
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_null_artifact_hashes_require_explicit_bootstrap(self):
        self.assertTrue(self.manifest["expectedArtifacts"])
        self.assertTrue(all(item["sha256"] is None for item in self.manifest["expectedArtifacts"].values()))
        with self.assertRaisesRegex(RuntimeError, "SHA-256 must be locked"):
            validate_manifest(self.manifest)
        self.assertEqual(validate_manifest(self.manifest, allow_unlocked_bootstrap=True), self.manifest)
        with tempfile.TemporaryDirectory(prefix="continuum-bootstrap-guard-") as temporary:
            with self.assertRaisesRegex(RuntimeError, "SHA-256 must be locked"):
                verify_bundle(Path(temporary), DEFAULT_MANIFEST)

    def test_bootstrap_rejects_missing_zero_and_malformed_hashes(self):
        locked = copy.deepcopy(self.manifest)
        for target in locked["expectedArtifacts"].values():
            target["sha256"] = SYNTHETIC_DIGEST
        for artifact_key in locked["expectedArtifacts"]:
            for value in ("0" * 64, "invalid", "f" * 63, False, []):
                for bootstrap in (False, True):
                    with self.subTest(artifact=artifact_key, value=value, bootstrap=bootstrap):
                        changed = copy.deepcopy(locked)
                        changed["expectedArtifacts"][artifact_key]["sha256"] = value
                        with self.assertRaisesRegex(RuntimeError, "SHA-256 must be locked"):
                            validate_manifest(changed, allow_unlocked_bootstrap=bootstrap)
            for bootstrap in (False, True):
                with self.subTest(artifact=artifact_key, missing=True, bootstrap=bootstrap):
                    changed = copy.deepcopy(locked)
                    del changed["expectedArtifacts"][artifact_key]["sha256"]
                    with self.assertRaisesRegex(RuntimeError, "target fields changed"):
                        validate_manifest(changed, allow_unlocked_bootstrap=bootstrap)

    def test_regular_wheel_keeps_nonnull_digest_checks_in_both_modes(self):
        target = copy.deepcopy(self.manifest["expectedArtifacts"]["linuxCp311"])
        with tempfile.TemporaryDirectory(prefix="continuum-bootstrap-guard-") as temporary:
            directory = Path(temporary)
            wheel = directory / target["filename"]
            wheel.write_bytes(SYNTHETIC_WHEEL)
            for bootstrap in (False, True):
                with self.subTest(bootstrap=bootstrap):
                    target["sha256"] = SYNTHETIC_DIGEST
                    self.assertEqual(
                        require_regular_wheel(directory, target, allow_unlocked_bootstrap=bootstrap), wheel
                    )
                    for value in ("f" * 64, "0" * 64, "invalid"):
                        target["sha256"] = value
                        with self.assertRaisesRegex(RuntimeError, "SHA-256 does not match"):
                            require_regular_wheel(directory, target, allow_unlocked_bootstrap=bootstrap)
            target["sha256"] = None
            with self.assertRaisesRegex(RuntimeError, "SHA-256 does not match"):
                require_regular_wheel(directory, target)
            self.assertEqual(require_regular_wheel(directory, target, allow_unlocked_bootstrap=True), wheel)
            linked = directory / "hardlinked-copy"
            os.link(wheel, linked)
            with self.assertRaisesRegex(RuntimeError, "unlinked regular file"):
                require_regular_wheel(directory, target, allow_unlocked_bootstrap=True)

    def test_default_offline_install_rejects_null_manifest_before_creating_runtime(self):
        with tempfile.TemporaryDirectory(prefix="continuum-bootstrap-guard-") as temporary:
            directory = Path(temporary)
            for artifact_key in self.manifest["expectedArtifacts"]:
                with self.subTest(artifact=artifact_key):
                    result = self.run_cli(
                        "test_patched_sqlcipher_install.py",
                        ["--artifact-key", artifact_key, "--manifest", str(DEFAULT_MANIFEST),
                         "--wheelhouse", str(directory)],
                        directory,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("SHA-256 must be locked", result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(list(directory.iterdir()), [])

    def test_inspector_preserves_byte_comparison_before_native_inspection_or_evidence(self):
        with tempfile.TemporaryDirectory(prefix="continuum-bootstrap-guard-") as temporary:
            directory = Path(temporary)
            builds = [directory / "build-a", directory / "build-b"]
            filename = self.manifest["expectedArtifacts"]["linuxCp311"]["filename"]
            for index, build in enumerate(builds):
                build.mkdir()
                (build / filename).write_bytes(SYNTHETIC_WHEEL + bytes([index]))
            evidence = directory / "evidence"
            arguments = [
                "--artifact-key", "linuxCp311", "--manifest", str(DEFAULT_MANIFEST),
                "--build-a", str(builds[0]), "--build-b", str(builds[1]),
                "--evidence-dir", str(evidence), "--source-evidence", str(directory / "missing-source.json"),
                "--event", "pull_request", "--ref", "refs/pull/14/merge",
                "--repository-commit", "a" * 40, "--run-id", "12345", "--run-attempt", "1",
            ]
            strict = self.run_cli("inspect_patched_sqlcipher_wheel.py", arguments, directory)
            self.assertNotEqual(strict.returncode, 0)
            self.assertIn("SHA-256 must be locked", strict.stderr)
            result = self.run_cli(
                "inspect_patched_sqlcipher_wheel.py", [*arguments, "--allow-unlocked-bootstrap"], directory
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not byte-for-byte identical", result.stderr)
            self.assertNotIn("BadZipFile", result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertFalse(evidence.exists())

    def test_source_evidence_rejects_absence_failed_signatures_and_wrong_manifest(self):
        # A synthetic receipt tests structural binding only, never signature validity.
        expected = {
            "downloads": {label: {"filename": record["filename"], "sha256": record["sha256"]}
                          for label, record in iter_downloads(self.manifest)},
            "manifestSha256": sha256(DEFAULT_MANIFEST),
            "signatures": {
                label: {"primaryFingerprint": self.manifest["sources"][label]["signingKey"]["primaryFingerprint"],
                        "signatureVerified": True}
                for label in ("SQLCipher", "OpenSSL")
            },
            "status": "VERIFIED",
        }
        with tempfile.TemporaryDirectory(prefix="continuum-bootstrap-guard-") as temporary:
            path = Path(temporary) / "source-verification.json"
            with self.assertRaisesRegex(RuntimeError, "evidence is missing"):
                validate_source_evidence(path, self.manifest, DEFAULT_MANIFEST)
            path.write_text(json.dumps(expected), encoding="utf-8")
            self.assertEqual(validate_source_evidence(path, self.manifest, DEFAULT_MANIFEST), expected)
            rejected = []
            failed = copy.deepcopy(expected)
            failed["status"] = "FAILED"
            rejected.append(failed)
            wrong_manifest = copy.deepcopy(expected)
            wrong_manifest["manifestSha256"] = "f" * 64
            rejected.append(wrong_manifest)
            for label in ("SQLCipher", "OpenSSL"):
                failed_signature = copy.deepcopy(expected)
                failed_signature["signatures"][label]["signatureVerified"] = False
                rejected.append(failed_signature)
            for value in rejected:
                with self.subTest(value=value):
                    path.write_text(json.dumps(value), encoding="utf-8")
                    with self.assertRaisesRegex(RuntimeError, "does not bind every reviewed input"):
                        validate_source_evidence(path, self.manifest, DEFAULT_MANIFEST)

    def test_workflow_runs_all_gates_then_fails_without_upload(self):
        workflow = (ROOT / ".github/workflows/patched-sqlcipher-wheel.yml").read_text(encoding="utf-8")
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("continue-on-error", workflow)
        ordered_steps = (
            "Acquire and verify signed sources", "Independent network-disabled build A",
            "Independent network-disabled build B", "Compare and inspect locked native payload",
            "Test offline installation and encrypted runtime", "Capture immutable toolchain",
            "Report bootstrap digest and fail closed without artifact retention",
        )
        positions = [workflow.index("- name: " + step) for step in ordered_steps]
        self.assertEqual(positions, sorted(positions))
        last_step = re.split(r"(?m)^      - (?:name|uses): ", workflow)[-1]
        self.assertTrue(last_step.startswith(ordered_steps[-1]))
        self.assertNotIn("if:", last_step)
        self.assertIn("cat work/patched-sqlcipher/evidence/runtime.json", last_step)
        self.assertIn("cat work/patched-sqlcipher/evidence/source-verification.json", last_step)
        self.assertEqual(last_step.rstrip().splitlines()[-1].strip(), "exit 1")


if __name__ == "__main__":
    unittest.main()
