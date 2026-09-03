#!/usr/bin/env python3
"""One-command supported local verification suite."""

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional


ROOT = Path(__file__).resolve().parents[1]
ENV = dict(os.environ)
ENV["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
ENV["PYTHONPYCACHEPREFIX"] = str(ROOT / "work" / "pycache")
ENV["PIP_NO_INDEX"] = "1"
ENV["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
EXPECTED_DISTRIBUTION = "continuum-memory"
EXPECTED_VERSION = "0.1.0.dev0"
MINIMUM_PYTHON = (3, 11)
EXCLUDED_PYTHON = (3, 15)
MAX_METADATA_BYTES = 1024 * 1024
REQUIRED_SDIST_FILES = (
    "docs/SQLCIPHER_STORAGE.md",
    "fixtures/prototype_daemon.py",
    "packaging/linux/approval-helper",
    "packaging/linux/install-polkit.sh",
    "packaging/linux/org.continuummemory.approval.policy",
    "requirements/sqlcipher-maintained.txt",
    "requirements/verification-tools.txt",
    "scripts/polkit_smoke.py",
    "src/continuum_memory/approval.py",
    "src/continuum_memory/polkit_helper.py",
    "tests/test_approval.py",
    "tests/test_encrypted_storage.py",
    "tests/test_verify.py",
)
EXPECTED_SQLCIPHER_WHEELS = {
    "sqlcipher3-0.6.2-cp311-cp311-macosx_11_0_arm64.whl": (
        "22e6502c364706fe64695219877f2bb01cdb25450bec81e69c8a08deff8c14ee"
    ),
    "sqlcipher3-0.6.2-cp311-cp311-manylinux_2_28_x86_64.whl": (
        "0f08e5bb5eb1ab93819c444ebec61fa3349e9690c14f5d0276fd4f61c3049fd9"
    ),
    "sqlcipher3-0.6.2-cp312-cp312-macosx_11_0_arm64.whl": (
        "bc2edd981e65783bc0d4e337704a9eb436871ab91c68af02ed76354876087642"
    ),
    "sqlcipher3-0.6.2-cp312-cp312-manylinux_2_28_x86_64.whl": (
        "6b26d28ca844dc2a69b8f74b390e940db47760f0be4c96d93337c57ae8250a48"
    ),
    "sqlcipher3-0.6.2-cp313-cp313-macosx_11_0_arm64.whl": (
        "8e1ff6079603dfd955d57c26dad5eab14f6baacdc643d8753dd651913ba789cf"
    ),
    "sqlcipher3-0.6.2-cp313-cp313-manylinux_2_28_x86_64.whl": (
        "9fb7109981583b631ac795e7e955d4bf78058f64b54c7f334ccc437adc322d4b"
    ),
    "sqlcipher3-0.6.2-cp314-cp314-macosx_11_0_arm64.whl": (
        "5c1f4a5805faa418c9c7290e6a556a8c5abae40ea59b04d76e960e33c257e618"
    ),
    "sqlcipher3-0.6.2-cp314-cp314-manylinux_2_28_x86_64.whl": (
        "e00988174ecd67ecd4537504c3df55bf8daeb75fce98401f099dff8e22c43ae1"
    ),
}
EXPECTED_BUILD_WHEELS = {
    "setuptools-80.9.0-py3-none-any.whl": (
        "062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922"
    ),
}


def run(command: List[str], environment: Optional[Dict[str, str]] = None) -> None:
    print("+ %s" % " ".join(command), flush=True)
    subprocess.run(command, cwd=str(ROOT), env=ENV if environment is None else environment, check=True)


def runtime_check(version: tuple[int, int] = sys.version_info[:2]) -> None:
    if version < MINIMUM_PYTHON or version >= EXCLUDED_PYTHON:
        raise RuntimeError("verification requires maintained CPython 3.11 through 3.14")


def schema_check() -> None:
    for path in sorted((ROOT / "schemas").glob("*.json")):
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        if value.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise RuntimeError("schema version missing: %s" % path)
        print("schema ok: %s" % path.relative_to(ROOT))


def whitespace_check() -> None:
    suffixes = {".py", ".md", ".toml", ".cfg", ".yml", ".json"}
    skipped = {".git", ".venv", "work", "outputs", "build", "dist", "__pycache__"}
    for directory, directories, filenames in os.walk(str(ROOT)):
        directories[:] = [
            item for item in directories if item not in skipped and not item.endswith(".egg-info")
        ]
        for filename in filenames:
            path = Path(directory) / filename
            if path.suffix not in suffixes:
                continue
            text = path.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), 1):
                if line.endswith(" ") or line.endswith("\t"):
                    raise RuntimeError("trailing whitespace: %s:%d" % (path.relative_to(ROOT), number))


def normalized_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def find_sdist(artifacts: Path) -> Path:
    archives = sorted(
        path for path in artifacts.iterdir() if path.is_file() and path.name.endswith(".tar.gz")
    )
    if len(archives) != 1:
        raise RuntimeError("expected exactly one source distribution, found %d" % len(archives))

    archive = archives[0]
    version_suffix = "-%s.tar.gz" % EXPECTED_VERSION
    if not archive.name.endswith(version_suffix):
        raise RuntimeError("source distribution has an unexpected name or version: %s" % archive.name)
    filename_distribution = archive.name[: -len(version_suffix)]
    if normalized_distribution_name(filename_distribution) != EXPECTED_DISTRIBUTION:
        raise RuntimeError("source distribution has an unexpected project name: %s" % archive.name)

    try:
        with tarfile.open(str(archive), mode="r:gz") as bundle:
            metadata_members = []
            for member in bundle.getmembers():
                parts = PurePosixPath(member.name).parts
                if member.isfile() and len(parts) == 2 and parts[-1] == "PKG-INFO":
                    metadata_members.append(member)
            if len(metadata_members) != 1:
                raise RuntimeError(
                    "source distribution must contain exactly one top-level PKG-INFO"
                )
            member = metadata_members[0]
            if member.size > MAX_METADATA_BYTES:
                raise RuntimeError("source distribution PKG-INFO is unexpectedly large")
            extracted = bundle.extractfile(member)
            if extracted is None:
                raise RuntimeError("source distribution PKG-INFO could not be read")
            with extracted:
                metadata = BytesParser().parsebytes(extracted.read())
    except (OSError, tarfile.TarError) as error:
        raise RuntimeError("invalid source distribution: %s" % archive.name) from error

    metadata_names = metadata.get_all("Name", [])
    metadata_versions = metadata.get_all("Version", [])
    if (
        len(metadata_names) != 1
        or normalized_distribution_name(metadata_names[0]) != EXPECTED_DISTRIBUTION
    ):
        raise RuntimeError("source distribution metadata has an unexpected project name")
    if len(metadata_versions) != 1 or metadata_versions[0] != EXPECTED_VERSION:
        raise RuntimeError("source distribution metadata has an unexpected version")
    return archive


def require_sdist_files(archive: Path, required: tuple[str, ...] = REQUIRED_SDIST_FILES) -> None:
    try:
        with tarfile.open(str(archive), mode="r:gz") as bundle:
            packaged_files = set()
            for member in bundle.getmembers():
                parts = PurePosixPath(member.name).parts
                if member.isfile() and len(parts) >= 2:
                    packaged_files.add(str(PurePosixPath(*parts[1:])))
    except (OSError, tarfile.TarError) as error:
        raise RuntimeError("invalid source distribution: %s" % archive.name) from error

    missing = sorted(set(required) - packaged_files)
    if missing:
        raise RuntimeError("source distribution is missing required files: %s" % ", ".join(missing))


def _find_hash_pinned_wheel(
    wheelhouse: Path,
    pattern: str,
    expected: Dict[str, str],
    label: str,
) -> Path:
    wheels = sorted(wheelhouse.glob(pattern)) if wheelhouse.is_dir() else []
    if len(wheels) != 1:
        raise RuntimeError("expected exactly one %s wheel, found %d" % (label, len(wheels)))
    wheel = wheels[0]
    info = wheel.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError("%s wheel must be a single regular file" % label)
    expected_digest = expected.get(wheel.name)
    if expected_digest is None:
        raise RuntimeError("unsupported %s wheel: %s" % (label, wheel.name))
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if digest != expected_digest:
        raise RuntimeError("%s wheel digest mismatch: %s" % (label, wheel.name))
    return wheel


def find_sqlcipher_wheel(
    wheelhouse: Path,
    expected: Dict[str, str] = EXPECTED_SQLCIPHER_WHEELS,
) -> Path:
    return _find_hash_pinned_wheel(
        wheelhouse,
        "sqlcipher3-*.whl",
        expected,
        "SQLCipher",
    )


def find_build_tool_wheel(wheelhouse: Path) -> Path:
    return _find_hash_pinned_wheel(
        wheelhouse,
        "setuptools-*.whl",
        EXPECTED_BUILD_WHEELS,
        "build-tool",
    )


def packaging_smoke() -> None:
    with tempfile.TemporaryDirectory(prefix="continuum-package-", dir=str(ROOT / "work")) as temp:
        artifacts = Path(temp) / "dist"
        artifacts.mkdir()
        run(
            [
                sys.executable,
                "setup.py",
                "--quiet",
                "sdist",
                "--dist-dir",
                str(artifacts),
            ]
        )
        archive = find_sdist(artifacts)
        require_sdist_files(archive)
        dependency = find_sqlcipher_wheel(ROOT / "work" / "dependencies")
        build_dependency = find_build_tool_wheel(ROOT / "work" / "build-dependencies")
        environment = str(Path(temp) / "venv")
        run([sys.executable, "-m", "venv", environment])
        python = str(Path(environment) / "bin" / "python")
        package_environment = dict(ENV)
        package_environment.pop("PYTHONPATH", None)
        run(
            [python, "-m", "pip", "install", "--no-cache-dir", "--no-deps", str(build_dependency)],
            package_environment,
        )
        run(
            [python, "-m", "pip", "install", "--no-cache-dir", "--no-deps", str(dependency)],
            package_environment,
        )
        run(
            [
                python,
                "-m",
                "pip",
                "install",
                "--no-build-isolation",
                "--no-cache-dir",
                "--no-deps",
                str(archive),
            ],
            package_environment,
        )
        run([str(Path(environment) / "bin" / "continuum"), "--version"], package_environment)
        run([str(Path(environment) / "bin" / "memoryd"), "--help"], package_environment)
        run([str(Path(environment) / "bin" / "continuum-mcp"), "--help"], package_environment)
        run(
            [str(Path(environment) / "bin" / "continuum-polkit-helper"), "--help"],
            package_environment,
        )


def main() -> int:
    runtime_check()
    schema_check()
    whitespace_check()
    run([sys.executable, "-m", "compileall", "-q", "src", "fixtures", "tests", "scripts"])
    run([sys.executable, "-W", "error::ResourceWarning", "-m", "unittest", "discover", "-s", "tests", "-v"])
    run([sys.executable, "-m", "fixtures.demo"])
    packaging_smoke()
    run(["git", "diff", "--check"])
    print("verification: PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
