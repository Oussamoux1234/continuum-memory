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
import zipfile
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
MAX_NATIVE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_WHEEL_CONTENT_BYTES = 128 * 1024 * 1024
REQUIRED_SDIST_FILES = (
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "docs/RELEASE_READINESS.md",
    "docs/SQLCIPHER_STORAGE.md",
    "docs/architecture/010-encryption-dependency-decision.md",
    "fixtures/prototype_daemon.py",
    "packaging/linux/approval-helper",
    "packaging/linux/install-polkit.sh",
    "packaging/linux/org.continuummemory.approval.policy",
    "requirements/sqlcipher-maintained.txt",
    "requirements/spdx-validation-linux-py314.txt",
    "requirements/verification-tools.txt",
    "sbom/continuum-memory.spdx.json",
    "security/dependency-audit.json",
    "scripts/polkit_smoke.py",
    "src/continuum_memory/approval.py",
    "src/continuum_memory/polkit_helper.py",
    "tests/test_approval.py",
    "tests/test_encrypted_storage.py",
    "tests/test_verify.py",
    "third_party_licenses/OpenSSL-3.6.0.txt",
    "third_party_licenses/SQLCipher-4.12.0.txt",
    "third_party_licenses/sqlcipher3-0.6.2.txt",
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
EXPECTED_SPDX_VALIDATOR_WHEELS = {
    "beartype==0.22.9": "d16c9bbc61ea14637596c5f6fbff2ee99cbe3573e46a716401734ef50c3060c2",
    "boolean.py==5.0": "ef28a70bd43115208441b53a045d1549e2f0ec6e3d08a9d142cbc41c1938e8d9",
    "click==8.5.0": "255bc9599cf7748b4b1a446ccc735421bd08a2ae529a8b88597d3de5664ee360",
    "license-expression==30.4.4": "421788fdcadb41f049d2dc934ce666626265aeccefddd25e162a26f23bcbf8a4",
    "ply==3.11": "096f9b8350b65ebd2fd1346b12452efe5b9607f7482813ffca50c22722a807ce",
    "pyparsing==3.3.2": "850ba148bd908d7e2411587e247a1e4f0327839c40e2e5e6d05a007ecc69911d",
    "PyYAML==6.0.3": "c458b6d084f9b935061bc36216e8a69a7e293a2f1e68bf956dcd9e6cbcd143f5",
    "rdflib==7.6.0": "30c0a3ebf4c0e09215f066be7246794b6492e054e782d7ac2a34c9f70a15e0dd",
    "semantic-version==2.10.0": "de78a3b8e0feda74cabc54aab2da702113e33ac9d9eb9d2389bcf1f58b7d9177",
    "spdx-tools==0.8.5": "7c2d5865941be9d2e898f5b084e8d5422dd298dc5a29320ddb198fec304f59c4",
    "uritools==6.1.3": "136f113e76e53f85bf2d9cce0c3d40ceec775d0409e7d6de9b28f046a7d42838",
    "xmltodict==1.0.4": "a4a00d300b0e1c59fc2bfccb53d7b2e88c32f200df138a0dd2229f842497026a",
}
EXPECTED_LICENSE_FILE_DIGESTS = {
    "LICENSE": "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
    "third_party_licenses/OpenSSL-3.6.0.txt": (
        "7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a"
    ),
    "third_party_licenses/SQLCipher-4.12.0.txt": (
        "2a2826f6acf46fa650730cf42cbb22a642be33a7ef119c9c4f4bf6daf3bef48e"
    ),
    "third_party_licenses/sqlcipher3-0.6.2.txt": (
        "fa23cf250126548e90008fe92de4ee76d485bfbb3592f5be8aa731775892a960"
    ),
}
EXPECTED_SBOM_COMPONENTS = {
    "SPDXRef-Package-continuum-memory": (
        "continuum-memory",
        "0.1.0.dev0",
        "Apache-2.0",
        "Apache-2.0",
    ),
    "SPDXRef-Package-sqlcipher3": (
        "sqlcipher3",
        "0.6.2",
        "MIT",
        "NOASSERTION",
    ),
    "SPDXRef-Package-SQLCipher": (
        "SQLCipher Community Edition",
        "4.12.0",
        "BSD-3-Clause",
        "BSD-3-Clause",
    ),
    "SPDXRef-Package-SQLite": (
        "SQLite",
        "3.51.1",
        "LicenseRef-SQLite-Public-Domain",
        "LicenseRef-SQLite-Public-Domain",
    ),
    "SPDXRef-Package-OpenSSL": (
        "OpenSSL",
        "3.6.0",
        "Apache-2.0",
        "Apache-2.0",
    ),
    "SPDXRef-External-CPython": (
        "CPython runtime",
        "3.11-3.14",
        "NOASSERTION",
        "NOASSERTION",
    ),
    "SPDXRef-External-Apple-libSystem": (
        "Apple libSystem.B.dylib",
        "host-provided",
        "NOASSERTION",
        "NOASSERTION",
    ),
    "SPDXRef-External-manylinux-system-libraries": (
        "manylinux_2_28 system C libraries",
        "host-provided ABI >= 2.28",
        "NOASSERTION",
        "NOASSERTION",
    ),
}
EXPECTED_SBOM_WHEELS = {
    "sqlcipher3-0.6.2-cp311-cp311-macosx_11_0_arm64.whl": (
        "SPDXRef-Wheel-cp311-macos-arm64",
        "https://files.pythonhosted.org/packages/e5/4c/098cf3dd0af6ce4cfba88fbdeb63a3b156f4b7f0620f6cc5f35ecfb72607/sqlcipher3-0.6.2-cp311-cp311-macosx_11_0_arm64.whl",
    ),
    "sqlcipher3-0.6.2-cp311-cp311-manylinux_2_28_x86_64.whl": (
        "SPDXRef-Wheel-cp311-linux-x86-64",
        "https://files.pythonhosted.org/packages/72/b0/faa2a8fc9dc3210e0af31e57c5ec86e8a523eaa3d44e854aa8f95ff66d50/sqlcipher3-0.6.2-cp311-cp311-manylinux_2_28_x86_64.whl",
    ),
    "sqlcipher3-0.6.2-cp312-cp312-macosx_11_0_arm64.whl": (
        "SPDXRef-Wheel-cp312-macos-arm64",
        "https://files.pythonhosted.org/packages/2f/b7/b9e897cf9e4740ca148fb03b493fa708a9b729ccc0cd656099f16bc9f2fd/sqlcipher3-0.6.2-cp312-cp312-macosx_11_0_arm64.whl",
    ),
    "sqlcipher3-0.6.2-cp312-cp312-manylinux_2_28_x86_64.whl": (
        "SPDXRef-Wheel-cp312-linux-x86-64",
        "https://files.pythonhosted.org/packages/f5/03/d55fe69fb380dadb2f5d19b3eac9256218243cced6aa4696ef90d560d223/sqlcipher3-0.6.2-cp312-cp312-manylinux_2_28_x86_64.whl",
    ),
    "sqlcipher3-0.6.2-cp313-cp313-macosx_11_0_arm64.whl": (
        "SPDXRef-Wheel-cp313-macos-arm64",
        "https://files.pythonhosted.org/packages/56/0d/2cee40de57d47245de09382c64e649c8cc8e86fa549ecba7591633fabf20/sqlcipher3-0.6.2-cp313-cp313-macosx_11_0_arm64.whl",
    ),
    "sqlcipher3-0.6.2-cp313-cp313-manylinux_2_28_x86_64.whl": (
        "SPDXRef-Wheel-cp313-linux-x86-64",
        "https://files.pythonhosted.org/packages/f4/6b/874f72b6f3c3ebbe889e4279a0d422b7271ef7b3c63e45fae80a4ce16ec7/sqlcipher3-0.6.2-cp313-cp313-manylinux_2_28_x86_64.whl",
    ),
    "sqlcipher3-0.6.2-cp314-cp314-macosx_11_0_arm64.whl": (
        "SPDXRef-Wheel-cp314-macos-arm64",
        "https://files.pythonhosted.org/packages/f6/01/f3552874b158d83c15fb9d550576020cc42b34019d0daf3291b381fbfb01/sqlcipher3-0.6.2-cp314-cp314-macosx_11_0_arm64.whl",
    ),
    "sqlcipher3-0.6.2-cp314-cp314-manylinux_2_28_x86_64.whl": (
        "SPDXRef-Wheel-cp314-linux-x86-64",
        "https://files.pythonhosted.org/packages/ff/12/8d554633c3975f429e07cf07e136fb94ace10b460e1cb86b4c8019b7cdb4/sqlcipher3-0.6.2-cp314-cp314-manylinux_2_28_x86_64.whl",
    ),
}
SQLCIPHER_WHEEL_METADATA_DIGEST = (
    "09be93bd3c50a008a0d86a86d4d52ea79e4212033051cd31be1e0bf4dc840aa9"
)
SQLCIPHER_WHEEL_LICENSE_DIGEST = (
    "fa23cf250126548e90008fe92de4ee76d485bfbb3592f5be8aa731775892a960"
)
SQLCIPHER_NATIVE_MARKERS = (
    b"4.12.0",
    b"OpenSSL 3.6.0 1 Oct 2025",
    b"2025-11-28 17:28:25 281fc0e9afc38674b9b0991943b9e9d1e64c6cbdb133d35f6f5c87ff6af3alt1",
)
WHEEL_LICENSE_CONCLUSION = "NOASSERTION"
EXPECTED_OPENSSL_FINDING_COUNTS = {"High": 2, "Moderate": 10, "Low": 36}
EXPECTED_OPENSSL_FINDINGS_DIGEST = (
    "80b07579101a0ad4e10e897a9fa7b6516442f232d5f0186bb76b2e2c07a7cdee"
)
EXPECTED_OPENSSL_HIGH_FINDINGS = {"CVE-2025-15467", "CVE-2026-45447"}
EXPECTED_OPENSSL_MODERATE_FINDINGS = {
    "CVE-2025-11187",
    "CVE-2026-18798",
    "CVE-2026-31790",
    "CVE-2026-34182",
    "CVE-2026-34183",
    "CVE-2026-35188",
    "CVE-2026-42764",
    "CVE-2026-45445",
    "CVE-2026-63072",
    "CVE-2026-63076",
}
EXPECTED_AUDIT_DATE = "2026-09-05"
EXPECTED_REPLACEMENT_STATUS = "BLOCKED_NO_INSTALLABLE_ARTIFACT"
EXPECTED_MINIMUM_PATCHED_VERSIONS = {
    "OpenSSL": "3.6.4",
    "SQLCipher": "4.17.0",
    "SQLite": "3.53.2",
}
EXPECTED_PREFERRED_REPLACEMENT_VERSIONS = {
    "OpenSSL": "3.5.8",
    "SQLCipher": "4.18.0",
    "SQLite": "3.53.4",
}
EXPECTED_REVIEWED_REPLACEMENT_SOURCES = {
    "OpenSSL": {
        "commit": "f4dc4d58b48d346a8270183f89acf826d459b0ca",
        "sourceArchiveSha256": (
            "a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2"
        ),
        "sourceSignatureVerified": False,
        "version": "3.5.8",
    },
    "SQLCipher": {
        "commit": "63697beb0fafcb61faa7a3e6fd267036548ab11b",
        "embeddedSQLiteVersion": "3.53.4",
        "sourceArchiveSha256": (
            "20518a87ca38dc6565c3cb0d8a243d2abd3bd16c0f9a9a9e6bfdf2a487d01c90"
        ),
        "sourceSignatureVerified": False,
        "version": "4.18.0",
    },
    "sqlcipher3": {
        "latestPyPIVersion": "0.6.2",
        "masterCommit": "dfee7e5fe6a1422d9e5e23edc0727a2e1e2128ed",
        "masterOpenSSLRequirement": "3.6.0",
    },
}
REPLACEMENT_DECISION_DOCUMENT = "docs/architecture/010-encryption-dependency-decision.md"
REPRODUCIBLE_BUILD_EPOCH = "1700000000"


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


def load_json_strict(path: Path, label: str):
    def reject_duplicate_keys(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key: %s" % key)
            value[key] = item
        return value

    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle, object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("%s is missing or invalid" % label) from error


def hash_manifest_check(path: Path, expected: Dict[str, str], label: str) -> None:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise RuntimeError("%s hash manifest is missing or invalid" % label) from error

    logical_lines = []
    pending = ""
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        pending = "%s %s" % (pending, line) if pending else line
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        logical_lines.append(pending)
        pending = ""
    if pending:
        raise RuntimeError("%s hash manifest has an incomplete continuation" % label)

    entries = []
    pattern = re.compile(
        r"([A-Za-z0-9_.-]+)==([^\s]+)\s+--hash=sha256:([0-9a-f]{64})"
    )
    for line in logical_lines:
        match = pattern.fullmatch(line)
        if match is None:
            raise RuntimeError("%s hash manifest contains an unexpected directive" % label)
        entries.append(match.groups())
    actual = {"%s==%s" % (name, version): digest for name, version, digest in entries}
    if len(entries) != len(actual) or actual != expected:
        raise RuntimeError("%s hash manifest does not match the reviewed wheel set" % label)


def third_party_manifest_check(root: Path = ROOT) -> None:
    for relative_path, expected_digest in EXPECTED_LICENSE_FILE_DIGESTS.items():
        path = root / relative_path
        if not path.is_file():
            raise RuntimeError("required license file is missing: %s" % relative_path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected_digest:
            raise RuntimeError("required license file digest mismatch: %s" % relative_path)

    requirements_path = root / "requirements" / "sqlcipher-maintained.txt"
    try:
        requirements = requirements_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise RuntimeError("SQLCipher hash manifest is missing or invalid") from error
    recorded_hashes = set(re.findall(r"--hash=sha256:([0-9a-f]{64})(?:\s|$)", requirements))
    if recorded_hashes != set(EXPECTED_SQLCIPHER_WHEELS.values()):
        raise RuntimeError("SQLCipher hash manifest does not match the supported wheel set")
    hash_manifest_check(
        root / "requirements" / "spdx-validation-linux-py314.txt",
        EXPECTED_SPDX_VALIDATOR_WHEELS,
        "SPDX validator",
    )

    notice_path = root / "THIRD_PARTY_NOTICES.md"
    if not notice_path.is_file():
        raise RuntimeError("THIRD_PARTY_NOTICES.md is missing")
    notice = notice_path.read_text(encoding="utf-8")
    required_notice_text = (
        "sqlcipher3 0.6.2 metadata conflict",
        "SQLCipher 4.12.0",
        "SQLite 3.51.1",
        "OpenSSL 3.6.0",
        "/usr/lib/libSystem.B.dylib",
        "libc.so.6",
        "not redistributed",
        "NOASSERTION",
        "48 OpenSSL vendor advisories",
        "CVE-2026-11822",
        "no patched published sqlcipher3 wheel",
    )
    missing_notice_text = [value for value in required_notice_text if value not in notice]
    if missing_notice_text:
        raise RuntimeError(
            "THIRD_PARTY_NOTICES.md is missing required records: %s"
            % ", ".join(missing_notice_text)
        )

    sbom_path = root / "sbom" / "continuum-memory.spdx.json"
    sbom = load_json_strict(sbom_path, "SPDX inventory")

    if sbom.get("spdxVersion") != "SPDX-2.3" or sbom.get("dataLicense") != "CC0-1.0":
        raise RuntimeError("SPDX inventory has an unexpected document version or data license")
    if sbom.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise RuntimeError("SPDX inventory has an unexpected document identifier")

    package_list = sbom.get("packages")
    if not isinstance(package_list, list):
        raise RuntimeError("SPDX inventory packages must be a list")
    packages = {}
    for package in package_list:
        if not isinstance(package, dict) or not isinstance(package.get("SPDXID"), str):
            raise RuntimeError("SPDX inventory contains a malformed package")
        identifier = package["SPDXID"]
        if identifier in packages:
            raise RuntimeError("SPDX inventory contains a duplicate package: %s" % identifier)
        packages[identifier] = package

    for identifier, expected in EXPECTED_SBOM_COMPONENTS.items():
        package = packages.get(identifier)
        if package is None:
            raise RuntimeError("SPDX inventory is missing component: %s" % identifier)
        actual = (
            package.get("name"),
            package.get("versionInfo"),
            package.get("licenseDeclared"),
            package.get("licenseConcluded"),
        )
        if actual != expected:
            raise RuntimeError("SPDX component record mismatch: %s" % identifier)
        if package.get("filesAnalyzed") is not False:
            raise RuntimeError("SPDX component must state filesAnalyzed=false: %s" % identifier)

    wheel_packages = {
        package.get("name"): package
        for package in package_list
        if isinstance(package.get("name"), str) and package["name"].endswith(".whl")
    }
    if set(wheel_packages) != set(EXPECTED_SQLCIPHER_WHEELS):
        raise RuntimeError("SPDX inventory wheel set does not match the supported wheel set")
    for filename, expected_digest in EXPECTED_SQLCIPHER_WHEELS.items():
        expected_identifier, expected_url = EXPECTED_SBOM_WHEELS[filename]
        package = wheel_packages[filename]
        if package.get("SPDXID") != expected_identifier:
            raise RuntimeError("SPDX wheel identifier mismatch: %s" % filename)
        if package.get("downloadLocation") != expected_url:
            raise RuntimeError("SPDX wheel download location mismatch: %s" % filename)
        if package.get("licenseDeclared") != "NOASSERTION":
            raise RuntimeError("SPDX wheel must not overstate its declared aggregate license")
        if package.get("licenseConcluded") != WHEEL_LICENSE_CONCLUSION:
            raise RuntimeError("SPDX wheel license conclusion mismatch: %s" % filename)
        if package.get("filesAnalyzed") is not False:
            raise RuntimeError("SPDX wheel must state filesAnalyzed=false: %s" % filename)
        if package.get("checksums") != [
            {"algorithm": "SHA256", "checksumValue": expected_digest}
        ]:
            raise RuntimeError("SPDX wheel checksum mismatch: %s" % filename)

    expected_described = {"SPDXRef-Package-continuum-memory"}
    expected_described.update(identifier for identifier, _ in EXPECTED_SBOM_WHEELS.values())
    if set(sbom.get("documentDescribes", [])) != expected_described:
        raise RuntimeError("SPDX documentDescribes does not match the shipped inventory")

    extracted = sbom.get("hasExtractedLicensingInfos")
    if not isinstance(extracted, list):
        raise RuntimeError("SPDX extracted license records must be a list")
    extracted_ids = {item.get("licenseId") for item in extracted if isinstance(item, dict)}
    required_extracted_ids = {
        "LicenseRef-sqlcipher3-0.6.2",
        "LicenseRef-SQLite-Public-Domain",
    }
    if not required_extracted_ids.issubset(extracted_ids):
        raise RuntimeError("SPDX inventory is missing an extracted license record")

    relationship_list = sbom.get("relationships")
    if not isinstance(relationship_list, list):
        raise RuntimeError("SPDX inventory relationships must be a list")
    relationships = {
        (
            item.get("spdxElementId"),
            item.get("relationshipType"),
            item.get("relatedSpdxElement"),
        )
        for item in relationship_list
        if isinstance(item, dict)
    }
    required_relationships = {
        (
            "SPDXRef-Package-continuum-memory",
            "DEPENDS_ON",
            "SPDXRef-Package-sqlcipher3",
        ),
        (
            "SPDXRef-Package-sqlcipher3",
            "STATIC_LINK",
            "SPDXRef-Package-SQLCipher",
        ),
        (
            "SPDXRef-Package-SQLCipher",
            "CONTAINS",
            "SPDXRef-Package-SQLite",
        ),
        (
            "SPDXRef-Package-SQLCipher",
            "STATIC_LINK",
            "SPDXRef-Package-OpenSSL",
        ),
    }
    for filename, (identifier, _) in EXPECTED_SBOM_WHEELS.items():
        system_identifier = (
            "SPDXRef-External-Apple-libSystem"
            if "macosx" in filename
            else "SPDXRef-External-manylinux-system-libraries"
        )
        required_relationships.update(
            {
                (identifier, "CONTAINS", "SPDXRef-Package-sqlcipher3"),
                (identifier, "DEPENDS_ON", "SPDXRef-External-CPython"),
                (identifier, "DYNAMIC_LINK", system_identifier),
            }
        )
    missing_relationships = required_relationships - relationships
    if missing_relationships:
        raise RuntimeError("SPDX inventory is missing required dependency relationships")

    audit = load_json_strict(root / "security" / "dependency-audit.json", "dependency audit")
    if audit.get("schemaVersion") != 1 or audit.get("auditDate") != EXPECTED_AUDIT_DATE:
        raise RuntimeError("dependency audit has an unexpected schema or evidence date")
    release_decision = audit.get("releaseDecision")
    if not isinstance(release_decision, dict) or release_decision.get("status") != "BLOCKED":
        raise RuntimeError("dependency audit must preserve the blocked release decision")
    replacement = audit.get("replacementAssessment")
    if not isinstance(replacement, dict):
        raise RuntimeError("dependency audit replacement assessment is missing")
    if replacement.get("status") != EXPECTED_REPLACEMENT_STATUS:
        raise RuntimeError("dependency audit replacement status must fail closed")
    if replacement.get("selectedInstallableArtifact") is not None:
        raise RuntimeError("dependency audit must not identify an unreviewed installable artifact")
    if replacement.get("minimumPatchedVersions") != EXPECTED_MINIMUM_PATCHED_VERSIONS:
        raise RuntimeError("dependency audit minimum patched versions changed")
    if replacement.get("preferredReplacementVersions") != EXPECTED_PREFERRED_REPLACEMENT_VERSIONS:
        raise RuntimeError("dependency audit preferred replacement versions changed")
    if replacement.get("reviewedSourceCandidates") != EXPECTED_REVIEWED_REPLACEMENT_SOURCES:
        raise RuntimeError("dependency audit reviewed replacement source evidence changed")
    if replacement.get("publishedPatchedSqlcipher3WheelAvailable") is not False:
        raise RuntimeError("dependency audit overstates patched wheel availability")
    decision_path = root / REPLACEMENT_DECISION_DOCUMENT
    try:
        decision = decision_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise RuntimeError("encrypted-storage dependency decision is missing or invalid") from error
    required_decision_text = (
        "BLOCKED_NO_INSTALLABLE_ARTIFACT",
        "SQLCipher 4.18.0",
        "SQLite 3.53.4",
        "OpenSSL 3.5.8 LTS",
        "OpenSSL 3.6.4",
        "no replacement is selected",
        "explicit authorization",
    )
    missing_decision_text = [value for value in required_decision_text if value not in decision]
    if missing_decision_text:
        raise RuntimeError(
            "encrypted-storage dependency decision is missing required evidence: %s"
            % ", ".join(missing_decision_text)
        )
    components = audit.get("components")
    if not isinstance(components, dict):
        raise RuntimeError("dependency audit components must be an object")
    expected_versions = {
        "sqlcipher3": "0.6.2",
        "SQLCipher": "4.12.0",
        "SQLite": "3.51.1",
        "OpenSSL": "3.6.0",
    }
    for name, version in expected_versions.items():
        component = components.get(name)
        if not isinstance(component, dict) or component.get("version") != version:
            raise RuntimeError("dependency audit component mismatch: %s" % name)
    for name in ("sqlcipher3", "SQLCipher"):
        component = components[name]
        status = component.get("status")
        if (
            component.get("osvFindingCount") != 0
            or not isinstance(status, str)
            or "not-proof-of-safety" not in status
        ):
            raise RuntimeError("dependency audit overstates no-known-finding result: %s" % name)
    sqlite = components["SQLite"]
    if sqlite.get("findings") != ["CVE-2026-11822", "CVE-2026-11824"]:
        raise RuntimeError("dependency audit SQLite findings changed")
    if sqlite.get("fixedVersion") != "3.53.2":
        raise RuntimeError("dependency audit SQLite fixed version changed")
    openssl = components["OpenSSL"]
    findings = openssl.get("findings")
    if not isinstance(findings, dict):
        raise RuntimeError("dependency audit OpenSSL findings must be an object")
    counts = {severity: len(findings.get(severity, [])) for severity in EXPECTED_OPENSSL_FINDING_COUNTS}
    if counts != EXPECTED_OPENSSL_FINDING_COUNTS or openssl.get("findingCount") != sum(counts.values()):
        raise RuntimeError("dependency audit OpenSSL finding counts changed")
    if set(findings["High"]) != EXPECTED_OPENSSL_HIGH_FINDINGS:
        raise RuntimeError("dependency audit OpenSSL High findings changed")
    if set(findings["Moderate"]) != EXPECTED_OPENSSL_MODERATE_FINDINGS:
        raise RuntimeError("dependency audit OpenSSL Moderate findings changed")
    all_findings = [identifier for values in findings.values() for identifier in values]
    if len(all_findings) != len(set(all_findings)) or any(
        re.fullmatch(r"CVE-[0-9]{4}-[0-9]+", identifier) is None for identifier in all_findings
    ):
        raise RuntimeError("dependency audit OpenSSL findings are duplicated or malformed")
    findings_digest = hashlib.sha256("\n".join(sorted(all_findings)).encode("ascii")).hexdigest()
    if findings_digest != EXPECTED_OPENSSL_FINDINGS_DIGEST:
        raise RuntimeError("dependency audit OpenSSL finding identifiers changed")
    print("third-party license, SPDX, and vulnerability inventory: ok")


def inspect_sqlcipher_wheel(
    wheel: Path,
    expected_metadata_digest: str = SQLCIPHER_WHEEL_METADATA_DIGEST,
    expected_license_digest: str = SQLCIPHER_WHEEL_LICENSE_DIGEST,
    native_markers: tuple[bytes, ...] = SQLCIPHER_NATIVE_MARKERS,
) -> None:
    try:
        with zipfile.ZipFile(str(wheel), mode="r") as bundle:
            members = bundle.infolist()
            names = [member.filename for member in members]
            if len(names) != len(set(names)):
                raise RuntimeError("SQLCipher wheel contains duplicate archive members")
            content_size = 0
            for member in members:
                path = PurePosixPath(member.filename)
                if path.is_absolute() or ".." in path.parts:
                    raise RuntimeError("SQLCipher wheel contains an unsafe archive path")
                if not member.is_dir():
                    content_size += member.file_size
            if content_size > MAX_WHEEL_CONTENT_BYTES:
                raise RuntimeError("SQLCipher wheel payload is unexpectedly large")

            metadata_members = [
                name for name in names if name == "sqlcipher3-0.6.2.dist-info/METADATA"
            ]
            license_members = [
                name
                for name in names
                if name == "sqlcipher3-0.6.2.dist-info/licenses/LICENSE"
            ]
            native_members = [
                name
                for name in names
                if name.startswith("sqlcipher3/_sqlite3") and name.endswith(".so")
            ]
            if len(metadata_members) != 1 or len(license_members) != 1:
                raise RuntimeError("SQLCipher wheel metadata or license payload is incomplete")
            if len(native_members) != 1:
                raise RuntimeError("SQLCipher wheel must contain exactly one native extension")
            required_members = {"sqlcipher3/__init__.py", "sqlcipher3/dbapi2.py"}
            if not required_members.issubset(names):
                raise RuntimeError("SQLCipher wheel Python package payload is incomplete")
            native_name = native_members[0]
            unexpected_native = [
                name
                for name in names
                if name.lower().endswith((".so", ".dylib", ".dll", ".pyd"))
                and name != native_name
            ]
            if unexpected_native or any(".libs/" in name for name in names):
                raise RuntimeError("SQLCipher wheel contains an unrecorded native library")

            metadata_member = bundle.getinfo(metadata_members[0])
            license_member = bundle.getinfo(license_members[0])
            native_member = bundle.getinfo(native_name)
            if metadata_member.file_size > MAX_METADATA_BYTES:
                raise RuntimeError("SQLCipher wheel METADATA is unexpectedly large")
            if license_member.file_size > MAX_METADATA_BYTES:
                raise RuntimeError("SQLCipher wheel license is unexpectedly large")
            if native_member.file_size > MAX_NATIVE_MEMBER_BYTES:
                raise RuntimeError("SQLCipher wheel native extension is unexpectedly large")

            metadata_bytes = bundle.read(metadata_member)
            license_bytes = bundle.read(license_member)
            native_bytes = bundle.read(native_member)
    except (OSError, zipfile.BadZipFile) as error:
        raise RuntimeError("invalid SQLCipher wheel: %s" % wheel.name) from error

    if hashlib.sha256(metadata_bytes).hexdigest() != expected_metadata_digest:
        raise RuntimeError("SQLCipher wheel METADATA digest mismatch")
    if hashlib.sha256(license_bytes).hexdigest() != expected_license_digest:
        raise RuntimeError("SQLCipher wheel license digest mismatch")

    metadata = BytesParser().parsebytes(metadata_bytes)
    if metadata.get_all("Name", []) != ["sqlcipher3"]:
        raise RuntimeError("SQLCipher wheel has unexpected package metadata")
    if metadata.get_all("Version", []) != ["0.6.2"]:
        raise RuntimeError("SQLCipher wheel has unexpected version metadata")
    if metadata.get_all("License-Expression", []) != ["MIT"]:
        raise RuntimeError("SQLCipher wheel license declaration changed")
    if metadata.get_all("License-File", []) != ["LICENSE"]:
        raise RuntimeError("SQLCipher wheel license-file record changed")
    if metadata.get_all("Project-URL", []) != [
        "Repository, https://github.com/coleifer/sqlcipher3"
    ]:
        raise RuntimeError("SQLCipher wheel source metadata changed")

    missing_markers = [marker.decode("ascii") for marker in native_markers if marker not in native_bytes]
    if missing_markers:
        raise RuntimeError(
            "SQLCipher wheel native component evidence is missing: %s"
            % ", ".join(missing_markers)
        )
    print("SQLCipher wheel component inventory: ok (%s)" % wheel.name)


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


def find_project_wheel(artifacts: Path) -> Path:
    wheels = sorted(path for path in artifacts.iterdir() if path.is_file() and path.suffix == ".whl")
    if len(wheels) != 1:
        raise RuntimeError("expected exactly one project wheel, found %d" % len(wheels))
    wheel = wheels[0]
    version_suffix = "-%s-py3-none-any.whl" % EXPECTED_VERSION
    if not wheel.name.endswith(version_suffix):
        raise RuntimeError("project wheel has an unexpected name or version: %s" % wheel.name)
    filename_distribution = wheel.name[: -len(version_suffix)]
    if normalized_distribution_name(filename_distribution) != EXPECTED_DISTRIBUTION:
        raise RuntimeError("project wheel has an unexpected project name: %s" % wheel.name)

    try:
        with zipfile.ZipFile(str(wheel), mode="r") as bundle:
            metadata_members = [
                member
                for member in bundle.infolist()
                if not member.is_dir()
                and len(PurePosixPath(member.filename).parts) == 2
                and member.filename.endswith(".dist-info/METADATA")
            ]
            if len(metadata_members) != 1:
                raise RuntimeError("project wheel must contain exactly one top-level METADATA")
            member = metadata_members[0]
            if member.file_size > MAX_METADATA_BYTES:
                raise RuntimeError("project wheel METADATA is unexpectedly large")
            metadata = BytesParser().parsebytes(bundle.read(member))
    except (OSError, zipfile.BadZipFile) as error:
        raise RuntimeError("invalid project wheel: %s" % wheel.name) from error

    if metadata.get_all("Name", []) != [EXPECTED_DISTRIBUTION]:
        raise RuntimeError("project wheel metadata has an unexpected project name")
    if metadata.get_all("Version", []) != [EXPECTED_VERSION]:
        raise RuntimeError("project wheel metadata has an unexpected version")
    return wheel


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


def require_wheel_compliance_files(archive: Path, source_root: Path = ROOT) -> None:
    try:
        with zipfile.ZipFile(str(archive), mode="r") as bundle:
            names = [member.filename for member in bundle.infolist() if not member.is_dir()]
    except (OSError, zipfile.BadZipFile) as error:
        raise RuntimeError("invalid project wheel: %s" % archive.name) from error

    metadata_members = [name for name in names if name.endswith(".dist-info/METADATA")]
    if len(metadata_members) != 1:
        raise RuntimeError("project wheel must contain exactly one METADATA")
    dist_info = metadata_members[0][: -len("/METADATA")]
    distribution_stem = dist_info[: -len(".dist-info")]
    required = {
        "%s/licenses/LICENSE" % dist_info,
        "%s/licenses/THIRD_PARTY_NOTICES.md" % dist_info,
        "%s/licenses/third_party_licenses/OpenSSL-3.6.0.txt" % dist_info,
        "%s/licenses/third_party_licenses/SQLCipher-4.12.0.txt" % dist_info,
        "%s/licenses/third_party_licenses/sqlcipher3-0.6.2.txt" % dist_info,
        "%s.data/data/share/continuum-memory/continuum-memory.spdx.json"
        % distribution_stem,
        "%s.data/data/share/continuum-memory/dependency-audit.json"
        % distribution_stem,
    }
    missing = sorted(required - set(names))
    if missing:
        raise RuntimeError("project wheel is missing compliance files: %s" % ", ".join(missing))
    source_files = {
        "%s/licenses/LICENSE" % dist_info: "LICENSE",
        "%s/licenses/THIRD_PARTY_NOTICES.md" % dist_info: "THIRD_PARTY_NOTICES.md",
        "%s/licenses/third_party_licenses/OpenSSL-3.6.0.txt" % dist_info: (
            "third_party_licenses/OpenSSL-3.6.0.txt"
        ),
        "%s/licenses/third_party_licenses/SQLCipher-4.12.0.txt" % dist_info: (
            "third_party_licenses/SQLCipher-4.12.0.txt"
        ),
        "%s/licenses/third_party_licenses/sqlcipher3-0.6.2.txt" % dist_info: (
            "third_party_licenses/sqlcipher3-0.6.2.txt"
        ),
        "%s.data/data/share/continuum-memory/continuum-memory.spdx.json"
        % distribution_stem: "sbom/continuum-memory.spdx.json",
        "%s.data/data/share/continuum-memory/dependency-audit.json"
        % distribution_stem: "security/dependency-audit.json",
    }
    try:
        with zipfile.ZipFile(str(archive), mode="r") as bundle:
            for packaged_path, source_path in source_files.items():
                if bundle.read(packaged_path) != (source_root / source_path).read_bytes():
                    raise RuntimeError(
                        "project wheel compliance file differs from source: %s" % packaged_path
                    )
    except (OSError, KeyError, zipfile.BadZipFile) as error:
        raise RuntimeError("project wheel compliance files could not be verified") from error


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


def normalized_sdist_manifest(archive: Path):
    try:
        with tarfile.open(str(archive), mode="r:gz") as bundle:
            members = bundle.getmembers()
            names = [member.name for member in members]
            if len(names) != len(set(names)):
                raise RuntimeError("source distribution contains duplicate archive members")
            manifest = []
            for member in members:
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts:
                    raise RuntimeError("source distribution contains an unsafe archive path")
                content_digest = None
                if member.isfile():
                    extracted = bundle.extractfile(member)
                    if extracted is None:
                        raise RuntimeError("source distribution member could not be read")
                    content_digest = hashlib.sha256(extracted.read()).hexdigest()
                stable_pax = tuple(
                    sorted(
                        (key, value)
                        for key, value in member.pax_headers.items()
                        if key not in {"atime", "ctime", "mtime"}
                    )
                )
                manifest.append(
                    (
                        member.name,
                        member.type,
                        member.mode,
                        member.uid,
                        member.gid,
                        member.uname,
                        member.gname,
                        member.linkname,
                        member.size,
                        stable_pax,
                        content_digest,
                    )
                )
    except (OSError, tarfile.TarError) as error:
        raise RuntimeError("invalid source distribution: %s" % archive.name) from error
    return manifest


def compare_reproducible_artifacts(
    first_sdist: Path,
    second_sdist: Path,
    first_wheel: Path,
    second_wheel: Path,
) -> None:
    first_wheel_digest = hashlib.sha256(first_wheel.read_bytes()).hexdigest()
    second_wheel_digest = hashlib.sha256(second_wheel.read_bytes()).hexdigest()
    if first_wheel_digest != second_wheel_digest:
        raise RuntimeError("project wheels are not byte-for-byte reproducible")

    first_sdist_digest = hashlib.sha256(first_sdist.read_bytes()).hexdigest()
    second_sdist_digest = hashlib.sha256(second_sdist.read_bytes()).hexdigest()
    if normalized_sdist_manifest(first_sdist) != normalized_sdist_manifest(second_sdist):
        raise RuntimeError("source distributions differ beyond allowed timestamp metadata")

    raw_sdist_status = "byte-identical" if first_sdist_digest == second_sdist_digest else "timestamp-variant"
    print(
        "reproducible build: wheel=%s; sdist=normalized-identical (%s)"
        % (first_wheel_digest, raw_sdist_status)
    )
    print(
        "release payload: sdist=%s; wheel=%s"
        % (first_sdist_digest, first_wheel_digest)
    )


def packaging_smoke() -> None:
    with tempfile.TemporaryDirectory(prefix="continuum-package-", dir=str(ROOT / "work")) as temp:
        build_environment = dict(ENV)
        build_environment["SOURCE_DATE_EPOCH"] = REPRODUCIBLE_BUILD_EPOCH
        artifact_directories = [Path(temp) / "dist-a", Path(temp) / "dist-b"]
        for artifacts in artifact_directories:
            artifacts.mkdir()
            run(
                [
                    sys.executable,
                    "setup.py",
                    "--quiet",
                    "sdist",
                    "--dist-dir",
                    str(artifacts),
                ],
                build_environment,
            )
            run(
                [
                    sys.executable,
                    "setup.py",
                    "--quiet",
                    "bdist_wheel",
                    "--dist-dir",
                    str(artifacts),
                ],
                build_environment,
            )
        archive = find_sdist(artifact_directories[0])
        comparison_archive = find_sdist(artifact_directories[1])
        require_sdist_files(archive)
        project_wheel = find_project_wheel(artifact_directories[0])
        comparison_wheel = find_project_wheel(artifact_directories[1])
        require_wheel_compliance_files(project_wheel)
        compare_reproducible_artifacts(
            archive,
            comparison_archive,
            project_wheel,
            comparison_wheel,
        )
        dependency = find_sqlcipher_wheel(ROOT / "work" / "dependencies")
        inspect_sqlcipher_wheel(dependency)
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
    third_party_manifest_check()
    run([sys.executable, "-m", "compileall", "-q", "src", "fixtures", "tests", "scripts"])
    run([sys.executable, "-W", "error::ResourceWarning", "-m", "unittest", "discover", "-s", "tests", "-v"])
    run([sys.executable, "-m", "fixtures.demo"])
    packaging_smoke()
    run(["git", "diff", "--check"])
    print("verification: PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
