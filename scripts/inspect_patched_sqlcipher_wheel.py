#!/usr/bin/env python3
"""Compare and deeply inspect two reproducible patched SQLCipher wheels."""

import argparse
import base64
import csv
import filecmp
import hashlib
import io
import json
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
# Isolated mode intentionally removes the checkout and script directory from
# sys.path. Add only this script's resolved repository root so it can import
# the separately hash-reviewed source-verification helper.
sys.path.insert(0, str(ROOT))

from scripts.fetch_patched_sqlcipher_sources import (  # noqa: E402
    DEFAULT_MANIFEST,
    artifact_target,
    is_single_regular_file,
    iter_downloads,
    load_json_strict,
    publish_bytes_exclusive,
    require_real_directory,
    sha256,
    validate_manifest,
)


DIST_INFO = "continuum_sqlcipher3-0.6.2.post1.dist-info"
REPOSITORY_ROOT = DEFAULT_MANIFEST.parents[2]
MAX_WHEEL_BYTES = 64 * 1024 * 1024
MAX_WHEEL_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_WHEEL_MEMBERS = 32
EXPECTED_NATIVE_MARKERS = (
    b"4.18.0",
    b"3.53.4",
    b"OpenSSL 3.5.8 25 Aug 2026",
)
EXPECTED_PYTHON_HASHES = {
    "sqlcipher3/__init__.py": "3e9fb2097abc3d7802d06a03faba070eeef8274412fed70293aa3b421bbb6a8e",
    "sqlcipher3/dbapi2.py": "8fa5c6ae7b32600a601c164c75e2a14bed13ea9d9240e4791c4dcca508262394",
}
EXPECTED_METADATA_SHA256 = "9245a656987a353c5eedc96d36c513eec365cdf650111a2e4ff1dd1dd92f0063"
EXPECTED_LICENSE_HASHES = {
    "LICENSE": "fa23cf250126548e90008fe92de4ee76d485bfbb3592f5be8aa731775892a960",
    "OpenSSL-Apache-2.0.txt": (
        "7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a"
    ),
    "SQLCipher-BSD-3-Clause.txt": (
        "2a2826f6acf46fa650730cf42cbb22a642be33a7ef119c9c4f4bf6daf3bef48e"
    ),
    "SQLite-Public-Domain.txt": (
        "595e823c2ada6c839679e693bee1f4d7f88e2d34ac99a913ae41e3d43fb10c7d"
    ),
}
ALLOWED_NEEDED = {
    "ld-linux-x86-64.so.2",
    "libc.so.6",
    "libdl.so.2",
    "libm.so.6",
    "libpthread.so.0",
}
GLIBC_CEILING = (2, 28)
READ_ELF = "/opt/rh/gcc-toolset-14/root/usr/bin/readelf"
NM = "/opt/rh/gcc-toolset-14/root/usr/bin/nm"
AUDITWHEEL = "/opt/_internal/pipx/venvs/auditwheel/bin/auditwheel"


def one_wheel(directory: Path) -> Path:
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError("wheel directory must be a real directory: %s" % directory)
    candidates = sorted(directory.glob("*.whl"))
    if len(candidates) != 1:
        raise RuntimeError("expected exactly one wheel in %s, found %d" % (directory, len(candidates)))
    wheel = candidates[0]
    if not is_single_regular_file(wheel) or wheel.stat().st_size > MAX_WHEEL_BYTES:
        raise RuntimeError("wheel must be one unlinked regular file within the size limit")
    return wheel


def safe_wheel_path(name: str) -> None:
    if not isinstance(name, str) or not name or "\0" in name or "\\" in name:
        raise RuntimeError("wheel contains an unsafe path: %s" % name)
    path = PurePosixPath(name)
    comparable = name[:-1] if name.endswith("/") else name
    if path.is_absolute() or ".." in path.parts or not path.parts or comparable != str(path):
        raise RuntimeError("wheel contains an unsafe path: %s" % name)


def native_member_name(target: dict) -> str:
    python_digits = target["pythonAbi"].split("-", 1)[0][2:]
    return "sqlcipher3/_sqlite3.cpython-%s-x86_64-linux-gnu.so" % python_digits


def expected_wheel_members(target: dict) -> set[str]:
    return {
        "sqlcipher3/",
        "sqlcipher3/__init__.py",
        native_member_name(target),
        "sqlcipher3/dbapi2.py",
        "%s/" % DIST_INFO,
        "%s/METADATA" % DIST_INFO,
        "%s/WHEEL" % DIST_INFO,
        "%s/top_level.txt" % DIST_INFO,
        "%s/RECORD" % DIST_INFO,
        "%s/licenses/" % DIST_INFO,
        "%s/licenses/LICENSE" % DIST_INFO,
        "%s/licenses/THIRD_PARTY_LICENSES/" % DIST_INFO,
        "%s/licenses/THIRD_PARTY_LICENSES/OpenSSL-Apache-2.0.txt" % DIST_INFO,
        "%s/licenses/THIRD_PARTY_LICENSES/SQLCipher-BSD-3-Clause.txt" % DIST_INFO,
        "%s/licenses/THIRD_PARTY_LICENSES/SQLite-Public-Domain.txt" % DIST_INFO,
    }


def validate_wheel_member(member: zipfile.ZipInfo) -> None:
    safe_wheel_path(member.filename)
    if member.flag_bits & 0x1:
        raise RuntimeError("wheel contains an encrypted member")
    file_type = stat.S_IFMT((member.external_attr >> 16) & 0xFFFF)
    if member.is_dir():
        if file_type not in (0, stat.S_IFDIR):
            raise RuntimeError("wheel contains a special directory member")
    elif file_type not in (0, stat.S_IFREG):
        raise RuntimeError("wheel contains a link or special member")


def validate_wheel_member_inventory(names: list[str], target: dict) -> None:
    normalized = [name[:-1] if name.endswith("/") else name for name in names]
    if len(normalized) != len(set(normalized)):
        raise RuntimeError("wheel contains duplicate members")
    if set(names) != expected_wheel_members(target) or len(names) != len(set(names)):
        raise RuntimeError("wheel member inventory changed")


def validate_wheel_metadata(payload: bytes, target: dict) -> str:
    wheel_metadata = BytesParser().parsebytes(payload)
    expected_tag = "%s-manylinux_2_28_x86_64" % target["pythonAbi"]
    if (
        wheel_metadata.get_all("Wheel-Version", []) != ["1.0"]
        or wheel_metadata.get_all("Generator", []) != ["setuptools (80.9.0)"]
        or wheel_metadata.get_all("Root-Is-Purelib", []) != ["false"]
        or wheel_metadata.get_all("Tag", []) != [expected_tag]
    ):
        raise RuntimeError("wheel build metadata or platform tag changed")
    return expected_tag


def validate_record(record_payload: bytes, payloads: dict[str, bytes]) -> None:
    try:
        rows = list(csv.reader(io.StringIO(record_payload.decode("utf-8"), newline="")))
    except (UnicodeDecodeError, csv.Error) as error:
        raise RuntimeError("wheel RECORD is malformed") from error
    seen = set()
    for row in rows:
        if len(row) != 3:
            raise RuntimeError("wheel RECORD row must have exactly three fields")
        name, encoded_hash, encoded_size = row
        safe_wheel_path(name)
        if name in seen or name not in payloads:
            raise RuntimeError("wheel RECORD contains a duplicate or unexpected member")
        seen.add(name)
        if name == "%s/RECORD" % DIST_INFO:
            if encoded_hash or encoded_size:
                raise RuntimeError("wheel RECORD self-entry must omit hash and size")
            continue
        payload = payloads[name]
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")
        if encoded_hash != "sha256=%s" % digest or encoded_size != str(len(payload)):
            raise RuntimeError("wheel RECORD hash or size mismatch: %s" % name)
    if seen != set(payloads):
        raise RuntimeError("wheel RECORD does not inventory every regular member")


def inspect_wheel_archive(wheel: Path, manifest: dict, artifact_key: str) -> dict:
    target = artifact_target(manifest, artifact_key)
    if wheel.name != target["filename"]:
        raise RuntimeError("unexpected patched wheel filename: %s" % wheel.name)
    try:
        with zipfile.ZipFile(wheel) as archive:
            members = archive.infolist()
            if len(members) > MAX_WHEEL_MEMBERS:
                raise RuntimeError("wheel contains too many members")
            if sum(member.file_size for member in members) > MAX_WHEEL_EXPANDED_BYTES:
                raise RuntimeError("wheel expands beyond the reviewed size limit")
            names = []
            normalized_names = set()
            payloads = {}
            for member in members:
                validate_wheel_member(member)
                normalized = member.filename[:-1] if member.filename.endswith("/") else member.filename
                if normalized in normalized_names:
                    raise RuntimeError("wheel contains duplicate members")
                normalized_names.add(normalized)
                if not member.is_dir():
                    payloads[member.filename] = archive.read(member)
                names.append(member.filename)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise RuntimeError("patched wheel is not a valid bounded ZIP archive") from error

    validate_wheel_member_inventory(names, target)
    metadata_name = "%s/METADATA" % DIST_INFO
    metadata_payload = payloads[metadata_name]
    if hashlib.sha256(metadata_payload).hexdigest() != EXPECTED_METADATA_SHA256:
        raise RuntimeError("wheel metadata payload changed")
    metadata = BytesParser().parsebytes(metadata_payload)
    if metadata.get_all("Metadata-Version", []) != ["2.4"]:
        raise RuntimeError("wheel metadata standard changed")
    if metadata.get_all("Name", []) != ["continuum-sqlcipher3"]:
        raise RuntimeError("wheel distribution name changed")
    if metadata.get_all("Version", []) != ["0.6.2.post1"]:
        raise RuntimeError("wheel version changed")
    if metadata.get_all("Requires-Python", []) != [">=3.11,<3.15"]:
        raise RuntimeError("wheel Python range changed")
    if metadata.get_all("License-Expression", []):
        raise RuntimeError("wheel must not overstate the unresolved binding license")
    if metadata.get_all("License-File", []) != [
        "LICENSE",
        "THIRD_PARTY_LICENSES/OpenSSL-Apache-2.0.txt",
        "THIRD_PARTY_LICENSES/SQLCipher-BSD-3-Clause.txt",
        "THIRD_PARTY_LICENSES/SQLite-Public-Domain.txt",
    ]:
        raise RuntimeError("wheel license metadata changed")

    expected_tag = validate_wheel_metadata(payloads["%s/WHEEL" % DIST_INFO], target)
    if payloads["%s/top_level.txt" % DIST_INFO] != b"sqlcipher3\n":
        raise RuntimeError("wheel top-level package declaration changed")
    for name, expected_hash in EXPECTED_PYTHON_HASHES.items():
        if hashlib.sha256(payloads[name]).hexdigest() != expected_hash:
            raise RuntimeError("wheel Python payload changed: %s" % name)
    validate_record(payloads["%s/RECORD" % DIST_INFO], payloads)

    native_name = native_member_name(target)
    native_payload = payloads[native_name]
    for marker in EXPECTED_NATIVE_MARKERS:
        if marker not in native_payload:
            raise RuntimeError("wheel native payload is missing marker: %r" % marker)
    license_members = {
        PurePosixPath(name).name: payload
        for name, payload in payloads.items()
        if "/licenses/" in name
    }
    if set(license_members) != set(EXPECTED_LICENSE_HASHES):
        raise RuntimeError("wheel license payload changed")
    for name, expected_hash in EXPECTED_LICENSE_HASHES.items():
        if hashlib.sha256(license_members[name]).hexdigest() != expected_hash:
            raise RuntimeError("wheel license digest mismatch: %s" % name)

    return {
        "_nativePayload": native_payload,
        "_sqliteLicenseText": license_members["SQLite-Public-Domain.txt"].decode("utf-8"),
        "artifactKey": artifact_key,
        "filename": wheel.name,
        "licenseSha256": {
            name: hashlib.sha256(payload).hexdigest() for name, payload in license_members.items()
        },
        "memberCount": len(names),
        "metadataSha256": hashlib.sha256(metadata_payload).hexdigest(),
        "nativeMember": native_name,
        "nativeSha256": hashlib.sha256(native_payload).hexdigest(),
        "pythonAbi": target["pythonAbi"],
        "sha256": sha256(wheel),
        "wheelTag": expected_tag,
    }


def command_output(command: list[str]) -> str:
    if not Path(command[0]).is_absolute() or not Path(command[0]).is_file():
        raise RuntimeError("native inspection tool is missing: %s" % command[0])
    return subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout


def validate_native_dependencies(needed: set[str]) -> None:
    if needed != ALLOWED_NEEDED:
        raise RuntimeError("wheel native dependency set changed: %s" % sorted(needed))
    if any("crypto" in item.lower() or "ssl" in item.lower() for item in needed):
        raise RuntimeError("OpenSSL must be statically linked")


def validate_elf_outputs(
    header: str,
    dynamic: str,
    program_headers: str,
    versions: str,
    symbols: str,
    undefined_symbols: str,
) -> dict:
    required_header = {
        "Class": "ELF64",
        "Data": "2's complement, little endian",
        "Type": "DYN (Shared object file)",
        "Machine": "Advanced Micro Devices X86-64",
    }
    for label, expected in required_header.items():
        if re.search(r"^\s*%s:\s*%s\s*$" % (re.escape(label), re.escape(expected)), header, re.M) is None:
            raise RuntimeError("native ELF %s changed" % label.lower())
    needed = set(re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic))
    validate_native_dependencies(needed)
    for tag in ("RPATH", "RUNPATH", "TEXTREL"):
        if "(%s)" % tag in dynamic:
            raise RuntimeError("native ELF contains forbidden %s" % tag)
    if "BIND_NOW" not in dynamic and re.search(r"\(FLAGS_1\).*\bNOW\b", dynamic) is None:
        raise RuntimeError("native ELF does not enable immediate binding")
    if "GNU_RELRO" not in program_headers:
        raise RuntimeError("native ELF does not contain GNU_RELRO")
    stack_line = next(
        (line for line in program_headers.splitlines() if "GNU_STACK" in line), None
    )
    stack_flags = [] if stack_line is None else [
        token for token in stack_line.split() if re.fullmatch(r"[RWE]+", token)
    ]
    if stack_flags != ["RW"]:
        raise RuntimeError("native ELF stack is executable or malformed")

    version_names = set(re.findall(r"\bName:\s*([A-Za-z0-9_.-]+)", versions))
    glibc_versions = set()
    for name in version_names:
        match = re.fullmatch(r"GLIBC_(\d+)\.(\d+)(?:\.(\d+))?", name)
        if match is None:
            raise RuntimeError("native ELF references an unreviewed symbol namespace: %s" % name)
        parsed = tuple(int(value or 0) for value in match.groups())
        if parsed[:2] > GLIBC_CEILING:
            raise RuntimeError("native ELF exceeds the GLIBC 2.28 ceiling: %s" % name)
        glibc_versions.add(name)
    if not glibc_versions:
        raise RuntimeError("native ELF has no reviewed GLIBC version references")

    exported = {
        line.split()[-1]
        for line in symbols.splitlines()
        if line.split() and not line.split()[-1].startswith("_ITM_")
    }
    if exported != {"PyInit__sqlite3"}:
        raise RuntimeError("wheel exports an unexpected native symbol set: %s" % sorted(exported))
    if re.search(r"\b__stack_chk_fail(?:@\S+)?", undefined_symbols) is None:
        raise RuntimeError("native ELF does not contain stack-protector references")
    return {
        "elfClass": "ELF64",
        "elfMachine": "x86-64",
        "glibcVersions": sorted(
            glibc_versions,
            key=lambda value: tuple(int(part) for part in value.removeprefix("GLIBC_").split(".")),
        ),
        "nativeNeeded": sorted(needed),
        "nativeSecurity": ["bind-now", "non-executable-stack", "relro", "stack-protector"],
    }


def inspect_wheel(wheel: Path, manifest: dict, artifact_key: str) -> dict:
    inspection = inspect_wheel_archive(wheel, manifest, artifact_key)
    native_payload = inspection.pop("_nativePayload")
    with tempfile.TemporaryDirectory(prefix="continuum-wheel-native-") as temporary:
        native_path = Path(temporary) / PurePosixPath(inspection["nativeMember"]).name
        native_path.write_bytes(native_payload)
        elf = validate_elf_outputs(
            command_output([READ_ELF, "-hW", str(native_path)]),
            command_output([READ_ELF, "-dW", str(native_path)]),
            command_output([READ_ELF, "-lW", str(native_path)]),
            command_output([READ_ELF, "--version-info", "--wide", str(native_path)]),
            command_output([NM, "-D", "--defined-only", str(native_path)]),
            command_output([NM, "-D", "--undefined-only", str(native_path)]),
        )
    auditwheel = command_output([AUDITWHEEL, "show", str(wheel)])
    if "manylinux_2_28_x86_64" not in auditwheel or re.search(
        r"\blib(?:crypto|ssl|z)\.so", auditwheel, re.I
    ):
        raise RuntimeError("auditwheel reported an unexpected platform or dependency")
    inspection.update(elf)
    inspection["_auditwheelText"] = auditwheel
    return inspection


def validate_source_evidence(path: Path, manifest: dict, manifest_path: Path) -> dict:
    if not is_single_regular_file(path):
        raise RuntimeError("source verification evidence is missing, linked, or not regular")
    evidence = load_json_strict(path)
    expected_downloads = {
        label: {"filename": record["filename"], "sha256": record["sha256"]}
        for label, record in iter_downloads(manifest)
    }
    expected_signatures = {
        label: {
            "primaryFingerprint": manifest["sources"][label]["signingKey"]["primaryFingerprint"],
            "signatureVerified": True,
        }
        for label in ("SQLCipher", "OpenSSL")
    }
    if evidence != {
        "downloads": expected_downloads,
        "manifestSha256": sha256(manifest_path),
        "signatures": expected_signatures,
        "status": "VERIFIED",
    }:
        raise RuntimeError("source verification evidence does not bind every reviewed input")
    return evidence


def validate_workflow_context(context: dict) -> dict:
    commit = context.get("repositoryCommit")
    run_id = context.get("runId")
    run_attempt = context.get("runAttempt")
    event = context.get("event")
    ref = context.get("ref")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise RuntimeError("repository commit provenance is invalid")
    if not isinstance(run_id, str) or re.fullmatch(r"[1-9][0-9]*", run_id) is None:
        raise RuntimeError("workflow run provenance is invalid")
    if not isinstance(run_attempt, str) or re.fullmatch(r"[1-9][0-9]*", run_attempt) is None:
        raise RuntimeError("workflow attempt provenance is invalid")
    if event not in ("pull_request", "push", "workflow_dispatch"):
        raise RuntimeError("workflow event provenance is invalid")
    if (
        not isinstance(ref, str)
        or not ref.startswith("refs/")
        or len(ref) > 512
        or any(ord(character) < 0x20 for character in ref)
    ):
        raise RuntimeError("workflow ref provenance is invalid")
    return context


def source_packages(manifest: dict) -> list[dict]:
    sources = manifest["sources"]
    return [
        {
            "SPDXID": "SPDXRef-Package-sqlcipher3",
            "checksums": [
                {"algorithm": "SHA256", "checksumValue": sources["sqlcipher3"]["sha256"]}
            ],
            "copyrightText": "NOASSERTION",
            "downloadLocation": sources["sqlcipher3"]["url"],
            "filesAnalyzed": False,
            "licenseComments": (
                "Upstream metadata declares MIT, but the shipped LICENSE has SHA-256 "
                "%s and contains different Gerhard Haring terms; legal reconciliation is pending."
                % sources["sqlcipher3"]["licenseSha256"]
            ),
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "MIT",
            "name": "sqlcipher3 binding source",
            "versionInfo": sources["sqlcipher3"]["version"],
        },
        {
            "SPDXID": "SPDXRef-Package-SQLCipher",
            "checksums": [
                {"algorithm": "SHA256", "checksumValue": sources["SQLCipher"]["sha256"]}
            ],
            "copyrightText": "NOASSERTION",
            "downloadLocation": sources["SQLCipher"]["url"],
            "filesAnalyzed": False,
            "licenseConcluded": "BSD-3-Clause",
            "licenseDeclared": "BSD-3-Clause",
            "name": "SQLCipher Community Edition",
            "versionInfo": sources["SQLCipher"]["version"],
        },
        {
            "SPDXID": "SPDXRef-Package-SQLite",
            "comment": "Contained in the exact signed SQLCipher source archive; no separate archive is used.",
            "copyrightText": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "LicenseRef-SQLite-Public-Domain",
            "licenseDeclared": "LicenseRef-SQLite-Public-Domain",
            "name": "SQLite",
            "versionInfo": sources["SQLite"]["version"],
        },
        {
            "SPDXID": "SPDXRef-Package-OpenSSL",
            "checksums": [
                {"algorithm": "SHA256", "checksumValue": sources["OpenSSL"]["sha256"]}
            ],
            "copyrightText": "NOASSERTION",
            "downloadLocation": sources["OpenSSL"]["url"],
            "filesAnalyzed": False,
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "name": "OpenSSL",
            "versionInfo": sources["OpenSSL"]["version"],
        },
    ]


def build_and_runtime_packages(manifest: dict, target: dict, context: dict) -> list[dict]:
    dependencies = manifest["buildDependencies"]
    image_digest = manifest["builder"]["image"].rsplit("@sha256:", 1)[1]
    return [
        {
            "SPDXID": "SPDXRef-Build-manylinux",
            "checksums": [{"algorithm": "SHA256", "checksumValue": image_digest}],
            "copyrightText": "NOASSERTION",
            "downloadLocation": "https://quay.io/repository/pypa/manylinux_2_28_x86_64",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "name": "pypa manylinux_2_28_x86_64 builder image",
            "versionInfo": manifest["builder"]["imageTag"],
        },
        *[
            {
                "SPDXID": "SPDXRef-Build-%s" % name,
                "checksums": [{"algorithm": "SHA256", "checksumValue": record["sha256"]}],
                "copyrightText": "NOASSERTION",
                "downloadLocation": record["url"],
                "filesAnalyzed": False,
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "name": "%s build dependency" % name,
                "versionInfo": record["version"],
            }
            for name, record in dependencies.items()
        ],
        {
            "SPDXID": "SPDXRef-Build-continuum-recipe",
            "checksums": [{"algorithm": "SHA1", "checksumValue": context["repositoryCommit"]}],
            "copyrightText": "NOASSERTION",
            "downloadLocation": (
                "https://github.com/Oussamoux1234/continuum-memory/commit/%s"
                % context["repositoryCommit"]
            ),
            "filesAnalyzed": False,
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "name": "Continuum Memory patched-wheel recipe",
            "versionInfo": context["repositoryCommit"],
        },
        {
            "SPDXID": "SPDXRef-Runtime-CPython",
            "comment": "External interpreter ABI required to load the wheel; not bundled.",
            "copyrightText": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "name": "CPython %s ABI" % target["pythonAbi"],
            "versionInfo": target["pythonMinor"],
        },
        {
            "SPDXID": "SPDXRef-Runtime-glibc",
            "comment": "External runtime ABI, not bundled; inspected symbol ceiling is GLIBC_2.28.",
            "copyrightText": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "name": "GNU C Library runtime ABI",
            "versionInfo": "2.28 ceiling",
        },
    ]


def write_evidence(
    evidence_dir: Path,
    inspection: dict,
    manifest: dict,
    *,
    context: dict,
    manifest_sha256: str,
    source_evidence: dict,
    source_evidence_sha256: str,
) -> None:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    require_real_directory(evidence_dir, "artifact evidence")
    if evidence_dir.is_symlink() or not evidence_dir.is_dir():
        raise RuntimeError("evidence destination must be a real directory")
    context = validate_workflow_context(context)
    sqlite_license_text = inspection.get("_sqliteLicenseText")
    auditwheel_text = inspection.get("_auditwheelText")
    if not isinstance(sqlite_license_text, str) or not sqlite_license_text:
        raise RuntimeError("SQLite extracted license text is missing")
    if not isinstance(auditwheel_text, str) or not auditwheel_text:
        raise RuntimeError("auditwheel evidence is missing")
    public_inspection = {
        key: value for key, value in inspection.items() if not key.startswith("_")
    }
    provenance = {
        "artifact": public_inspection,
        "artifactSigningStatus": manifest["signing"]["artifactSigningStatus"],
        "attestationStatus": "UNSIGNED_PROJECT_EVIDENCE_ONLY",
        "buildComparison": {
            "buildA": inspection["sha256"],
            "buildB": inspection["sha256"],
            "result": "byte-for-byte-identical",
            "scope": "two clean network-disabled containers using the same immutable recipe",
        },
        "builder": manifest["builder"],
        "canonicalSourceManifestSha256": hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "rawSourceManifestSha256": manifest_sha256,
        "repository": {"commit": context["repositoryCommit"], "ref": context["ref"]},
        "sourceVerification": {
            "evidenceSha256": source_evidence_sha256,
            "signatures": source_evidence["signatures"],
            "status": source_evidence["status"],
        },
        "status": "EPHEMERAL_CI_TEST_ARTIFACT_NOT_RELEASED",
        "workflow": {
            "event": context["event"],
            "runAttempt": context["runAttempt"],
            "runId": context["runId"],
            "runUrl": (
                "https://github.com/Oussamoux1234/continuum-memory/actions/runs/%s"
                % context["runId"]
            ),
        },
    }
    publish_bytes_exclusive(
        evidence_dir / "artifact-provenance.json",
        (json.dumps(provenance, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )

    wheel_package = {
        "SPDXID": "SPDXRef-Package-continuum-sqlcipher3-wheel",
        "checksums": [{"algorithm": "SHA256", "checksumValue": inspection["sha256"]}],
        "copyrightText": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseComments": (
            "The sqlcipher3 binding license discrepancy is unresolved; exact license texts are "
            "retained and NOASSERTION is intentional."
        ),
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "name": inspection["filename"],
        "versionInfo": manifest["artifact"]["version"],
    }
    target = artifact_target(manifest, inspection["artifactKey"])
    material_packages = build_and_runtime_packages(manifest, target, context)
    shim_files = [
        {
            "SPDXID": "SPDXRef-File-IPC-Cmd-shim",
            "checksums": [
                {
                    "algorithm": "SHA1",
                    "checksumValue": hashlib.sha1(
                        (REPOSITORY_ROOT / "packaging/sqlcipher/perl/IPC/Cmd.pm").read_bytes(),
                        usedforsecurity=False,
                    ).hexdigest(),
                },
                {
                    "algorithm": "SHA256",
                    "checksumValue": manifest["builder"]["reviewedProjectFiles"][
                        "packaging/sqlcipher/perl/IPC/Cmd.pm"
                    ],
                }
            ],
            "copyrightText": "NOASSERTION",
            "fileName": "./packaging/sqlcipher/perl/IPC/Cmd.pm",
            "licenseConcluded": "Apache-2.0",
            "licenseInfoInFiles": ["Apache-2.0"],
        },
        {
            "SPDXID": "SPDXRef-File-Time-Piece-shim",
            "checksums": [
                {
                    "algorithm": "SHA1",
                    "checksumValue": hashlib.sha1(
                        (REPOSITORY_ROOT / "packaging/sqlcipher/perl/Time/Piece.pm").read_bytes(),
                        usedforsecurity=False,
                    ).hexdigest(),
                },
                {
                    "algorithm": "SHA256",
                    "checksumValue": manifest["builder"]["reviewedProjectFiles"][
                        "packaging/sqlcipher/perl/Time/Piece.pm"
                    ],
                }
            ],
            "copyrightText": "NOASSERTION",
            "fileName": "./packaging/sqlcipher/perl/Time/Piece.pm",
            "licenseConcluded": "Apache-2.0",
            "licenseInfoInFiles": ["Apache-2.0"],
        },
    ]
    build_dependency_ids = [
        package["SPDXID"]
        for package in material_packages
        if package["SPDXID"].startswith("SPDXRef-Build-")
    ]
    relationships = [
        {"relatedSpdxElement": "SPDXRef-Package-sqlcipher3", "relationshipType": "GENERATED_FROM", "spdxElementId": wheel_package["SPDXID"]},
        {"relatedSpdxElement": "SPDXRef-Package-SQLCipher", "relationshipType": "STATIC_LINK", "spdxElementId": wheel_package["SPDXID"]},
        {"relatedSpdxElement": "SPDXRef-Package-OpenSSL", "relationshipType": "STATIC_LINK", "spdxElementId": wheel_package["SPDXID"]},
        {"relatedSpdxElement": "SPDXRef-Package-SQLite", "relationshipType": "CONTAINS", "spdxElementId": "SPDXRef-Package-SQLCipher"},
        {"relatedSpdxElement": wheel_package["SPDXID"], "relationshipType": "RUNTIME_DEPENDENCY_OF", "spdxElementId": "SPDXRef-Runtime-CPython"},
        {"relatedSpdxElement": wheel_package["SPDXID"], "relationshipType": "RUNTIME_DEPENDENCY_OF", "spdxElementId": "SPDXRef-Runtime-glibc"},
        *[
            {"relatedSpdxElement": wheel_package["SPDXID"], "relationshipType": "BUILD_DEPENDENCY_OF", "spdxElementId": identifier}
            for identifier in build_dependency_ids
        ],
        *[
            {"relatedSpdxElement": wheel_package["SPDXID"], "relationshipType": "BUILD_DEPENDENCY_OF", "spdxElementId": item["SPDXID"]}
            for item in shim_files
        ],
    ]
    sbom = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {"created": "2026-09-07T00:00:00Z", "creators": ["Organization: Continuum Memory project"]},
        "dataLicense": "CC0-1.0",
        "documentDescribes": [wheel_package["SPDXID"]],
        "documentNamespace": "https://github.com/Oussamoux1234/continuum-memory/spdx/patched-wheel/%s" % inspection["sha256"],
        "files": shim_files,
        "hasExtractedLicensingInfos": [
            {"extractedText": sqlite_license_text, "licenseId": "LicenseRef-SQLite-Public-Domain", "name": "SQLite public-domain statement"}
        ],
        "name": "Continuum SQLCipher patched wheel SBOM",
        "packages": [wheel_package, *source_packages(manifest), *material_packages],
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }
    publish_bytes_exclusive(
        evidence_dir / "patched-wheel.spdx.json",
        (json.dumps(sbom, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    publish_bytes_exclusive(
        evidence_dir / "wheel.sha256",
        ("%s  %s\n" % (inspection["sha256"], inspection["filename"])).encode("ascii"),
    )
    publish_bytes_exclusive(
        evidence_dir / "auditwheel.txt", auditwheel_text.encode("utf-8")
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-key", required=True)
    parser.add_argument("--allow-unlocked-bootstrap", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--build-a", type=Path, required=True)
    parser.add_argument("--build-b", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--repository-commit", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-evidence", type=Path, required=True)
    arguments = parser.parse_args()
    manifest_path = arguments.manifest.absolute()
    if not is_single_regular_file(manifest_path):
        raise RuntimeError("patched-wheel manifest must be one unlinked regular file")
    manifest = validate_manifest(load_json_strict(manifest_path))
    artifact_target(manifest, arguments.artifact_key)
    wheel_a = one_wheel(arguments.build_a)
    wheel_b = one_wheel(arguments.build_b)
    if wheel_a.name != wheel_b.name or not filecmp.cmp(wheel_a, wheel_b, shallow=False):
        raise RuntimeError("independent patched wheel builds are not byte-for-byte identical")
    inspection = inspect_wheel(wheel_a, manifest, arguments.artifact_key)
    expected_hash = artifact_target(manifest, arguments.artifact_key)["sha256"]
    bootstrap_hash = "0" * 64
    if inspection["sha256"] != expected_hash and not (
        arguments.allow_unlocked_bootstrap and expected_hash == bootstrap_hash
    ):
        raise RuntimeError("patched wheel SHA-256 does not match the locked artifact")
    source_evidence_path = arguments.source_evidence.absolute()
    source_evidence = validate_source_evidence(source_evidence_path, manifest, manifest_path)
    context = validate_workflow_context(
        {
            "event": arguments.event,
            "ref": arguments.ref,
            "repositoryCommit": arguments.repository_commit,
            "runAttempt": arguments.run_attempt,
            "runId": arguments.run_id,
        }
    )
    write_evidence(
        arguments.evidence_dir,
        inspection,
        manifest,
        context=context,
        manifest_sha256=sha256(manifest_path),
        source_evidence=source_evidence,
        source_evidence_sha256=sha256(source_evidence_path),
    )
    print(json.dumps({key: value for key, value in inspection.items() if not key.startswith("_")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
