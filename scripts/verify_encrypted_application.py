#!/usr/bin/env python3
"""Run the complete application verifier with the strict native wheel offline."""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
# The workflow invokes this helper with -I from a read-only checkout.
sys.path.insert(0, str(ROOT))

from scripts.fetch_patched_sqlcipher_sources import (  # noqa: E402
    DEFAULT_MANIFEST,
    artifact_target,
    inspect_project_inputs,
    is_single_regular_file,
    load_json_strict,
    require_real_directory,
    sha256,
    validate_manifest,
)
from scripts.test_patched_sqlcipher_install import (  # noqa: E402
    require_regular_wheel,
    sanitized_environment,
)
from scripts.verify_patched_sqlcipher_inputs import verify_bundle  # noqa: E402


MAX_LOG_BYTES = 8 * 1024 * 1024
BACKEND_CHECK = """
import json
import sys
from importlib import metadata
from pathlib import Path
from sqlcipher3 import _sqlite3, dbapi2

prefix = Path(sys.prefix).resolve()
for module in (dbapi2, _sqlite3):
    Path(module.__file__).resolve().relative_to(prefix)
if metadata.version('continuum-sqlcipher3') != '0.6.2.post2':
    raise RuntimeError('unexpected native distribution')
connection = dbapi2.connect(':memory:')
try:
    cipher = connection.execute('PRAGMA cipher_version').fetchone()
    sqlite = connection.execute('SELECT sqlite_version()').fetchone()
finally:
    connection.close()
if cipher != ('4.19.0 community',) or sqlite != ('3.53.4',):
    raise RuntimeError('the strict SQLCipher backend is not active')
print(json.dumps({'cipherVersion': cipher[0], 'sqliteVersion': sqlite[0],
                  'modulePath': dbapi2.__file__, 'nativePath': _sqlite3.__file__}))
"""


def run_logged(command: list[str], cwd: Path, environment: dict[str, str]) -> str:
    """Keep CI output visible while bounding the text retained for result checks."""
    print("+ %s" % " ".join(command), flush=True)
    with subprocess.Popen(
        command,
        cwd=str(cwd),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    ) as process:
        lines = []
        size = 0
        try:
            assert process.stdout is not None
            for line in process.stdout:
                print(line, end="", flush=True)
                size += len(line.encode("utf-8"))
                if size > MAX_LOG_BYTES:
                    raise RuntimeError("application verification output exceeded its bound")
                lines.append(line)
            returncode = process.wait()
            if returncode:
                raise subprocess.CalledProcessError(returncode, command)
        except BaseException:
            process.kill()
            process.wait()
            raise
    return "".join(lines)


def copy_checkout(destination: Path, expected_commit: str, environment: dict[str, str]) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        raise RuntimeError("repository commit must be a full SHA-1")
    require_real_directory(ROOT / ".git", "normal Git checkout metadata")
    actual_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=str(ROOT), env=environment, text=True
    ).strip()
    if actual_commit != expected_commit:
        raise RuntimeError("read-only checkout does not match the workflow commit")

    def ignore_generated(directory: str, names: list[str]) -> list[str]:
        ignored = {"__pycache__"}
        if Path(directory) == ROOT:
            ignored.update({"work", "outputs", "build", "dist", ".venv"})
        ignored.update(name for name in names if name.endswith(".egg-info"))
        return sorted(set(names) & ignored)

    # Preserve normal Actions .git metadata for the verifier's git diff --check.
    # Copy symlinks as links instead of following them outside the checkout.
    shutil.copytree(ROOT, destination, symlinks=True, ignore=ignore_generated)
    (destination / "work").mkdir()
    copied_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=str(destination), env=environment, text=True
    ).strip()
    if copied_commit != expected_commit:
        raise RuntimeError("disposable checkout does not match the workflow commit")


def require_complete_verification(output: str) -> dict:
    summaries = re.findall(r"(?m)^Ran ([0-9]+) tests in [0-9.]+s$", output)
    if len(summaries) != 1 or int(summaries[0]) == 0:
        raise RuntimeError("full application test count is missing or ambiguous")
    if re.search(r"(?m)^OK \(|\.\.\. skipped\b", output):
        raise RuntimeError("application verification must not skip tests or expect failures")
    if len(re.findall(r"(?m)^OK$", output)) != 1:
        raise RuntimeError("full application tests did not report an unqualified success")
    if output.splitlines().count("verification: PASSED") != 1:
        raise RuntimeError("application verifier did not complete all gates")

    demos = []
    decoder = json.JSONDecoder()
    for match in re.finditer(r"(?m)^\{", output):
        try:
            value, _ = decoder.raw_decode(output[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and "checks" in value:
            demos.append(value)
    if len(demos) != 1:
        raise RuntimeError("application demo evidence is missing or ambiguous")
    demo = demos[0]
    checks = demo.get("checks")
    if (
        demo.get("status") != "passed"
        or not isinstance(checks, dict)
        or len(checks) != 17
        or not all(value is True for value in checks.values())
    ):
        raise RuntimeError("all 17 application demo checks must pass")
    return {"testsRun": int(summaries[0]), "testsSkipped": 0, "demoChecksPassed": len(checks)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-key", required=True)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--repository-commit", required=True)
    arguments = parser.parse_args()

    if sys.platform != "linux" or platform.machine() != "x86_64" or os.geteuid() == 0:
        raise RuntimeError("application CI requires a non-root native Linux x86-64 builder")
    sources = arguments.sources.absolute()
    wheelhouse = arguments.wheelhouse.absolute()
    require_real_directory(sources, "verified source bundle")
    require_real_directory(wheelhouse, "locked native wheelhouse")
    verify_bundle(sources, DEFAULT_MANIFEST)
    manifest = validate_manifest(load_json_strict(DEFAULT_MANIFEST))
    target = artifact_target(manifest, arguments.artifact_key)
    if (
        "%d.%d" % sys.version_info[:2] != target["pythonMinor"]
        or sys.implementation.cache_tag != "cpython-" + target["pythonAbi"].split("-")[0][2:]
    ):
        raise RuntimeError("application interpreter does not match the locked wheel ABI")
    native_wheel = require_regular_wheel(wheelhouse, target)
    inputs = [(native_wheel, target["sha256"])]
    for label in ("setuptools", "wheel"):
        record = manifest["buildDependencies"][label]
        path = sources / record["filename"]
        if not is_single_regular_file(path) or sha256(path) != record["sha256"]:
            raise RuntimeError("offline application build input changed: %s" % label)
        inputs.append((path, record["sha256"]))

    environment = sanitized_environment()
    for name in list(environment):
        if name.startswith("PIP_") or name.startswith("PYTHON"):
            environment.pop(name)
    environment.update(
        {
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    with tempfile.TemporaryDirectory(prefix="continuum-encrypted-application-") as temporary:
        temporary_root = Path(temporary)
        environment["HOME"] = str(temporary_root)
        checkout = temporary_root / "checkout"
        copy_checkout(checkout, arguments.repository_commit, environment)
        inspect_project_inputs(checkout, manifest)
        offline_wheels = temporary_root / "wheelhouse"
        offline_wheels.mkdir()
        requirements = temporary_root / "locked-wheels.txt"
        lines = []
        for source, digest in inputs:
            copied = offline_wheels / source.name
            shutil.copyfile(source, copied)
            if sha256(copied) != digest:
                raise RuntimeError("copied offline wheel digest changed")
            lines.append("%s --hash=sha256:%s" % (copied.as_uri(), digest))
        requirements.write_text("\n".join(lines) + "\n", encoding="utf-8")
        environment["CONTINUUM_SQLCIPHER_WHEELHOUSE"] = str(offline_wheels)
        virtualenv = temporary_root / "venv"
        run_logged([sys.executable, "-I", "-m", "venv", str(virtualenv)], temporary_root, environment)
        python = virtualenv / "bin" / "python"
        run_logged(
            [
                str(python), "-I", "-m", "pip", "--isolated", "install",
                "--no-index", "--no-cache-dir", "--no-compile", "--no-deps",
                "--no-build-isolation", "--only-binary=:all:", "--require-hashes",
                "--force-reinstall", "--requirement", str(requirements),
            ],
            temporary_root,
            environment,
        )
        backend = subprocess.check_output(
            [str(python), "-I", "-c", BACKEND_CHECK],
            cwd=str(temporary_root), env=environment, text=True,
        )
        backend_evidence = json.loads(backend)
        print("installed native backend: %s" % json.dumps(backend_evidence, sort_keys=True), flush=True)
        output = run_logged(
            # verify.py deliberately gives its test/demo subprocesses the copied
            # application's src path. Its direct-script imports need scripts/.
            [str(python), "-s", "scripts/verify.py"], checkout, environment
        )
        evidence = require_complete_verification(output)
        evidence.update(
            {
                "artifactKey": arguments.artifact_key,
                "repositoryCommit": arguments.repository_commit,
                "manifestSha256": sha256(DEFAULT_MANIFEST),
                "wheelSha256": target["sha256"],
                "buildDependencySha256": {
                    label: manifest["buildDependencies"][label]["sha256"]
                    for label in ("setuptools", "wheel")
                },
                "nativeBackend": backend_evidence,
                "status": "passed",
            }
        )
    print(json.dumps(evidence, sort_keys=True, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
