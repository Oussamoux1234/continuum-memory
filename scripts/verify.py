#!/usr/bin/env python3
"""One-command supported local verification suite."""

import json
import os
import re
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
MAX_METADATA_BYTES = 1024 * 1024
REQUIRED_SDIST_FILES = (
    "docs/PATCHED_SQLCIPHER_WHEELS.md",
    "fixtures/prototype_daemon.py",
    "packaging/linux/approval-helper",
    "packaging/linux/install-polkit.sh",
    "packaging/linux/org.continuummemory.approval.policy",
    "packaging/sqlcipher/THIRD_PARTY_NOTICES.md",
    "packaging/sqlcipher/manifest.json",
    "packaging/sqlcipher/pyproject.toml",
    "packaging/sqlcipher/setup_continuum.py",
    "sbom/patched-sqlcipher-sources.spdx.json",
    "scripts/build_patched_sqlcipher_wheel.sh",
    "scripts/fetch_patched_sqlcipher_sources.py",
    "scripts/inspect_patched_sqlcipher_wheel.py",
    "scripts/polkit_smoke.py",
    "scripts/test_patched_sqlcipher_runtime.py",
    "scripts/verify_patched_sqlcipher_inputs.py",
    "src/continuum_memory/approval.py",
    "src/continuum_memory/polkit_helper.py",
    "tests/test_approval.py",
    "tests/test_sqlcipher_supply_chain.py",
    "tests/test_verify.py",
)


def run(command: List[str], environment: Optional[Dict[str, str]] = None) -> None:
    print("+ %s" % " ".join(command), flush=True)
    subprocess.run(command, cwd=str(ROOT), env=ENV if environment is None else environment, check=True)


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


def sqlcipher_supply_chain_check() -> None:
    try:
        from scripts.fetch_patched_sqlcipher_sources import load_json_strict, validate_manifest
    except ModuleNotFoundError:
        from fetch_patched_sqlcipher_sources import load_json_strict, validate_manifest

    manifest = validate_manifest(
        load_json_strict(ROOT / "packaging" / "sqlcipher" / "manifest.json")
    )
    if manifest["supportedSlice"].get("windowsSupported") is not False:
        raise RuntimeError("patched SQLCipher wheel must not claim Windows support")
    sbom = load_json_strict(ROOT / "sbom" / "patched-sqlcipher-sources.spdx.json")
    if sbom.get("spdxVersion") != "SPDX-2.3" or sbom.get("dataLicense") != "CC0-1.0":
        raise RuntimeError("patched SQLCipher source SBOM is invalid")
    packages = sbom.get("packages")
    if not isinstance(packages, list):
        raise RuntimeError("patched SQLCipher source SBOM package set changed")
    by_identifier = {item.get("SPDXID"): item for item in packages if isinstance(item, dict)}
    expected_identifiers = {
        "SPDXRef-Source-sqlcipher3",
        "SPDXRef-Source-SQLCipher",
        "SPDXRef-Source-SQLite",
        "SPDXRef-Source-OpenSSL",
        "SPDXRef-Build-IPC-Cmd",
        "SPDXRef-Build-Locale-Maketext-Simple",
        "SPDXRef-Build-Module-Load-Conditional",
        "SPDXRef-Build-Params-Check",
        "SPDXRef-Builder-manylinux",
        "SPDXRef-Build-setuptools",
        "SPDXRef-Build-wheel",
    }
    if len(packages) != len(by_identifier) or set(by_identifier) != expected_identifiers:
        raise RuntimeError("patched SQLCipher source SBOM package set changed")
    binding = by_identifier.get("SPDXRef-Source-sqlcipher3", {})
    if binding.get("licenseConcluded") != "NOASSERTION":
        raise RuntimeError("patched SQLCipher source SBOM overstates the binding license")
    print("patched SQLCipher supply-chain manifest: ok")


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
        environment = str(Path(temp) / "venv")
        run([sys.executable, "-m", "venv", environment])
        python = str(Path(environment) / "bin" / "python")
        package_environment = dict(ENV)
        package_environment.pop("PYTHONPATH", None)
        run(
            [python, "-m", "pip", "install", "--no-cache-dir", "--no-deps", str(archive)],
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
    schema_check()
    whitespace_check()
    sqlcipher_supply_chain_check()
    run([sys.executable, "-m", "compileall", "-q", "src", "fixtures", "tests", "scripts"])
    run([sys.executable, "-W", "error::ResourceWarning", "-m", "unittest", "discover", "-s", "tests", "-v"])
    run([sys.executable, "-m", "fixtures.demo"])
    packaging_smoke()
    run(["git", "diff", "--check"])
    print("verification: PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
