"""Validate the separate, exactly three-wheel encrypted application input set."""

import os
import platform
import sys
from pathlib import Path
from typing import List

from scripts.fetch_patched_sqlcipher_sources import (
    DEFAULT_MANIFEST,
    inspect_project_inputs,
    is_single_regular_file,
    load_json_strict,
    require_real_directory,
    sha256,
    validate_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE_REQUIREMENT = "continuum-sqlcipher3==0.6.2.post2"
PYTHON_REQUIREMENT = ">=3.11,<3.15"


def application_manifest() -> dict:
    return validate_manifest(load_json_strict(DEFAULT_MANIFEST))


def application_verification_wheels() -> List[Path]:
    """Require the reviewed native wheel and its two pinned backend tools."""
    directory = os.environ.get("CONTINUUM_SQLCIPHER_WHEELHOUSE")
    if not directory:
        raise RuntimeError("encrypted application verification requires its reviewed offline wheelhouse")
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise RuntimeError("encrypted application verification requires Linux x86-64")
    wheelhouse = Path(directory).absolute()
    require_real_directory(wheelhouse, "application wheelhouse")
    manifest = application_manifest()
    inspect_project_inputs(ROOT, manifest)
    target = "linuxCp%d%d" % sys.version_info[:2]
    if sys.implementation.name != "cpython" or target not in manifest["expectedArtifacts"]:
        raise RuntimeError("encrypted application verification requires a supported CPython ABI")
    locks = [manifest["expectedArtifacts"][target]] + [
        manifest["buildDependencies"][label] for label in ("setuptools", "wheel")
    ]
    if {path.name for path in wheelhouse.iterdir()} != {lock["filename"] for lock in locks}:
        raise RuntimeError("application wheelhouse must contain exactly the three reviewed wheels")
    wheels = []
    for lock in locks:
        path = wheelhouse / lock["filename"]
        if not is_single_regular_file(path):
            raise RuntimeError("application input must be an unlinked regular wheel")
        if sha256(path) != lock["sha256"]:
            raise RuntimeError("application input SHA-256 does not match the reviewed lock")
        wheels.append(path)
    return wheels
