#!/usr/bin/env python3
"""Install one locked wheel offline and test it from outside the checkout."""

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Keep isolated-mode execution while importing only the reviewed helper module
# from the resolved read-only checkout used by the workflow.
sys.path.insert(0, str(ROOT))

from scripts.fetch_patched_sqlcipher_sources import (  # noqa: E402
    DEFAULT_MANIFEST,
    artifact_target,
    load_json_strict,
    sha256,
    validate_manifest,
)


def require_regular_wheel(wheelhouse: Path, target: dict) -> Path:
    candidates = sorted(wheelhouse.glob("*.whl"))
    if len(candidates) != 1 or candidates[0].name != target["filename"]:
        raise RuntimeError("wheelhouse must contain exactly the expected locked wheel")
    wheel = candidates[0]
    metadata = wheel.lstat()
    if wheel.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RuntimeError("locked wheel must be one unlinked regular file")
    if sha256(wheel) != target["sha256"]:
        raise RuntimeError("offline-install wheel SHA-256 does not match the manifest")
    return wheel


def sanitized_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in (
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONUSERBASE",
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    return environment


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-key", required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    arguments = parser.parse_args()

    manifest = validate_manifest(load_json_strict(arguments.manifest))
    target = artifact_target(manifest, arguments.artifact_key)
    actual_minor = "%d.%d" % sys.version_info[:2]
    expected_cache_tag = "cpython-%s" % target["pythonAbi"][2:5]
    if actual_minor != target["pythonMinor"] or sys.implementation.cache_tag != expected_cache_tag:
        raise RuntimeError("offline-install interpreter does not match the artifact target")
    wheelhouse = arguments.wheelhouse.absolute()
    if wheelhouse.is_symlink() or not wheelhouse.is_dir():
        raise RuntimeError("wheelhouse must be a real directory")
    wheel = require_regular_wheel(wheelhouse, target)

    environment = sanitized_environment()
    with tempfile.TemporaryDirectory(prefix="continuum-wheel-runtime-") as temporary:
        runtime_root = Path(temporary)
        virtualenv = runtime_root / "venv"
        subprocess.run(
            [sys.executable, "-I", "-m", "venv", str(virtualenv)],
            check=True,
            cwd=str(runtime_root),
            env=environment,
        )
        python = virtualenv / "bin" / "python"
        subprocess.run(
            [
                str(python),
                "-I",
                "-m",
                "pip",
                "--isolated",
                "install",
                "--no-cache-dir",
                "--no-compile",
                "--no-deps",
                "--no-index",
                str(wheel),
            ],
            check=True,
            cwd=str(runtime_root),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        result = subprocess.run(
            [str(python), "-I", str(ROOT / "scripts" / "test_patched_sqlcipher_runtime.py")],
            check=True,
            cwd=str(runtime_root),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    try:
        evidence = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("runtime test did not emit one JSON evidence document") from error
    if evidence.get("status") != "passed":
        raise RuntimeError("runtime test evidence did not pass")
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
