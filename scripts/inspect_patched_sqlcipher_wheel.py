#!/usr/bin/env python3
"""Compare and inspect two independently built patched SQLCipher wheels."""

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

try:
    from scripts.fetch_patched_sqlcipher_sources import (
        DEFAULT_MANIFEST,
        load_json_strict,
        sha256,
        validate_manifest,
    )
except ModuleNotFoundError:  # Direct script execution places scripts/ on sys.path.
    from fetch_patched_sqlcipher_sources import (
        DEFAULT_MANIFEST,
        load_json_strict,
        sha256,
        validate_manifest,
    )


EXPECTED_NATIVE_MARKERS = (
    b"4.18.0",
    b"3.53.4",
    b"OpenSSL 3.5.8 25 Aug 2026",
)
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
ALLOWED_NEEDED = {"libc.so.6", "libdl.so.2", "libm.so.6", "libpthread.so.0"}


def one_wheel(directory: Path) -> Path:
    candidates = sorted(directory.glob("*.whl"))
    if len(candidates) != 1:
        raise RuntimeError("expected exactly one wheel in %s, found %d" % (directory, len(candidates)))
    return candidates[0]


def safe_wheel_path(name: str) -> None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise RuntimeError("wheel contains an unsafe path: %s" % name)


def command_output(command: list[str]) -> str:
    return subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout


def inspect_wheel(wheel: Path, manifest: dict) -> dict:
    expected_name = manifest["expectedArtifacts"]["linuxCp314"]["filename"]
    if wheel.name != expected_name:
        raise RuntimeError("unexpected patched wheel filename: %s" % wheel.name)
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise RuntimeError("wheel contains duplicate members")
        for name in names:
            safe_wheel_path(name)
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        native_names = [name for name in names if name.endswith((".so", ".dylib", ".dll", ".pyd"))]
        if len(metadata_names) != 1 or len(native_names) != 1:
            raise RuntimeError("wheel must contain exactly one metadata and one native member")
        metadata_payload = archive.read(metadata_names[0])
        metadata = BytesParser().parsebytes(metadata_payload)
        if metadata.get_all("Name", []) != ["continuum-sqlcipher3"]:
            raise RuntimeError("wheel distribution name changed")
        if metadata.get_all("Version", []) != ["0.6.2.post1"]:
            raise RuntimeError("wheel version changed")
        if metadata.get_all("Requires-Python", []) != [">=3.11,<3.15"]:
            raise RuntimeError("wheel Python range changed")
        if metadata.get_all("License-Expression", []):
            raise RuntimeError("wheel must not overstate the unresolved binding license")
        native_payload = archive.read(native_names[0])
        for marker in EXPECTED_NATIVE_MARKERS:
            if marker not in native_payload:
                raise RuntimeError("wheel native payload is missing marker: %r" % marker)
        license_members = {
            PurePosixPath(name).name: archive.read(name)
            for name in names
            if ".dist-info/licenses/" in name and not name.endswith("/")
        }
        if set(license_members) != set(EXPECTED_LICENSE_HASHES):
            raise RuntimeError("wheel license payload changed")
        for name, expected_hash in EXPECTED_LICENSE_HASHES.items():
            if hashlib.sha256(license_members[name]).hexdigest() != expected_hash:
                raise RuntimeError("wheel license digest mismatch: %s" % name)

    with tempfile.TemporaryDirectory(prefix="continuum-wheel-native-") as temporary:
        native_path = Path(temporary) / PurePosixPath(native_names[0]).name
        native_path.write_bytes(native_payload)
        dynamic = command_output(["readelf", "-d", str(native_path)])
        needed = set(re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic))
        if not needed.issubset(ALLOWED_NEEDED):
            raise RuntimeError("wheel has an unreviewed native dependency: %s" % sorted(needed))
        if any("crypto" in item.lower() or "ssl" in item.lower() for item in needed):
            raise RuntimeError("OpenSSL must be statically linked")
        symbols = command_output(["nm", "-D", "--defined-only", str(native_path)])
        exported = {
            line.split()[-1]
            for line in symbols.splitlines()
            if line.split() and not line.split()[-1].startswith("_ITM_")
        }
        if exported != {"PyInit__sqlite3"}:
            raise RuntimeError("wheel exports an unexpected native symbol set: %s" % sorted(exported))

    return {
        "_sqliteLicenseText": license_members["SQLite-Public-Domain.txt"].decode("utf-8"),
        "filename": wheel.name,
        "licenseSha256": {
            name: hashlib.sha256(payload).hexdigest() for name, payload in license_members.items()
        },
        "metadataSha256": hashlib.sha256(metadata_payload).hexdigest(),
        "nativeMember": native_names[0],
        "nativeNeeded": sorted(needed),
        "nativeSha256": hashlib.sha256(native_payload).hexdigest(),
        "sha256": sha256(wheel),
    }


def source_packages(manifest: dict) -> list[dict]:
    sources = manifest["sources"]
    return [
        {
            "SPDXID": "SPDXRef-Package-sqlcipher3",
            "checksums": [
                {"algorithm": "SHA256", "checksumValue": sources["sqlcipher3"]["sha256"]}
            ],
            "downloadLocation": sources["sqlcipher3"]["url"],
            "filesAnalyzed": False,
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
            "downloadLocation": sources["SQLCipher"]["url"],
            "filesAnalyzed": False,
            "licenseConcluded": "BSD-3-Clause",
            "licenseDeclared": "BSD-3-Clause",
            "name": "SQLCipher Community Edition",
            "versionInfo": sources["SQLCipher"]["version"],
        },
        {
            "SPDXID": "SPDXRef-Package-SQLite",
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
            "downloadLocation": sources["OpenSSL"]["url"],
            "filesAnalyzed": False,
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "name": "OpenSSL",
            "versionInfo": sources["OpenSSL"]["version"],
        },
    ]


def write_evidence(evidence_dir: Path, inspection: dict, manifest: dict) -> None:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    sqlite_license_text = inspection.get("_sqliteLicenseText")
    if not isinstance(sqlite_license_text, str) or not sqlite_license_text:
        raise RuntimeError("SQLite extracted license text is missing")
    public_inspection = {
        key: value for key, value in inspection.items() if not key.startswith("_")
    }
    provenance = {
        "artifact": public_inspection,
        "buildComparison": "byte-for-byte-identical",
        "builder": manifest["builder"],
        "canonicalSourceManifestSha256": hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "sourceSignatures": "verified-before-build",
        "status": "CI_TEST_ARTIFACT_NOT_PUBLISHED",
    }
    (evidence_dir / "artifact-provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    wheel_package = {
        "SPDXID": "SPDXRef-Package-continuum-sqlcipher3-wheel",
        "checksums": [{"algorithm": "SHA256", "checksumValue": inspection["sha256"]}],
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "name": inspection["filename"],
        "versionInfo": manifest["artifact"]["version"],
    }
    sbom = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": "2026-09-05T00:00:00Z",
            "creators": ["Organization: Continuum Memory project"],
        },
        "dataLicense": "CC0-1.0",
        "documentDescribes": [wheel_package["SPDXID"]],
        "documentNamespace": "https://github.com/Oussamoux1234/continuum-memory/spdx/patched-wheel/%s"
        % inspection["sha256"],
        "name": "Continuum SQLCipher patched wheel SBOM",
        "hasExtractedLicensingInfos": [
            {
                "extractedText": sqlite_license_text,
                "licenseId": "LicenseRef-SQLite-Public-Domain",
                "name": "SQLite public-domain statement",
            }
        ],
        "packages": [wheel_package, *source_packages(manifest)],
        "relationships": [
            {
                "relatedSpdxElement": "SPDXRef-Package-sqlcipher3",
                "relationshipType": "CONTAINS",
                "spdxElementId": wheel_package["SPDXID"],
            },
            {
                "relatedSpdxElement": "SPDXRef-Package-SQLCipher",
                "relationshipType": "STATIC_LINK",
                "spdxElementId": wheel_package["SPDXID"],
            },
            {
                "relatedSpdxElement": "SPDXRef-Package-OpenSSL",
                "relationshipType": "STATIC_LINK",
                "spdxElementId": wheel_package["SPDXID"],
            },
            {
                "relatedSpdxElement": "SPDXRef-Package-SQLite",
                "relationshipType": "CONTAINS",
                "spdxElementId": "SPDXRef-Package-SQLCipher",
            },
        ],
        "spdxVersion": "SPDX-2.3",
    }
    (evidence_dir / "patched-wheel.spdx.json").write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (evidence_dir / "wheel.sha256").write_text(
        "%s  %s\n" % (inspection["sha256"], inspection["filename"]), encoding="ascii"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-a", type=Path, required=True)
    parser.add_argument("--build-b", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--bootstrap-unlocked-hash", action="store_true")
    arguments = parser.parse_args()
    manifest = validate_manifest(load_json_strict(arguments.manifest))
    wheel_a = one_wheel(arguments.build_a)
    wheel_b = one_wheel(arguments.build_b)
    if wheel_a.name != wheel_b.name or wheel_a.read_bytes() != wheel_b.read_bytes():
        raise RuntimeError("independent patched wheel builds are not byte-for-byte identical")
    inspection = inspect_wheel(wheel_a, manifest)
    expected_hash = manifest["expectedArtifacts"]["linuxCp314"]["sha256"]
    if expected_hash is None and not arguments.bootstrap_unlocked_hash:
        raise RuntimeError("patched wheel SHA-256 is not locked in the manifest")
    if expected_hash is not None and inspection["sha256"] != expected_hash:
        raise RuntimeError("patched wheel SHA-256 does not match the locked artifact")
    write_evidence(arguments.evidence_dir, inspection, manifest)
    print(json.dumps({key: value for key, value in inspection.items() if not key.startswith("_")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
