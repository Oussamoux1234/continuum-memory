#!/usr/bin/env python3
"""Acquire and verify every pinned input for the patched SQLCipher wheel build."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "packaging" / "sqlcipher" / "manifest.json"
MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
HEX_64 = re.compile(r"[0-9a-f]{64}")
FINGERPRINT = re.compile(r"[0-9A-F]{40}")


def load_json_strict(path: Path):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key: %s" % key)
            result[key] = value
        return result

    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle, object_pairs_hook=reject_duplicates)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checked_filename(value: object) -> str:
    if not isinstance(value, str) or not value or Path(value).name != value:
        raise RuntimeError("download filename must be a single safe path component")
    return value


def validate_download(record: object, label: str) -> None:
    if not isinstance(record, dict):
        raise RuntimeError("%s download record must be an object" % label)
    checked_filename(record.get("filename"))
    url = record.get("url")
    if not isinstance(url, str) or not url.startswith("https://"):
        raise RuntimeError("%s download URL must use HTTPS" % label)
    expected_hash = record.get("sha256")
    if not isinstance(expected_hash, str) or HEX_64.fullmatch(expected_hash) is None:
        raise RuntimeError("%s download must have one SHA-256 digest" % label)


def validate_manifest(manifest: object) -> dict:
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1:
        raise RuntimeError("unsupported patched-wheel manifest schema")
    if manifest.get("evidenceDate") != "2026-09-05":
        raise RuntimeError("patched-wheel manifest evidence is stale")
    builder = manifest.get("builder")
    if not isinstance(builder, dict) or not str(builder.get("image", "")).endswith(
        "@sha256:53390351aeb4688114b02c36a23b3e6ce1166ee9b7afc5df1a4f776354fc764c"
    ):
        raise RuntimeError("builder image must be immutable and reviewed")
    if builder.get("opensslPerlShims") != {
        "packaging/sqlcipher/perl/IPC/Cmd.pm": (
            "899f6a63fef81455c23e9b7c2c5b59568e321a02faf9685d9f63e6416837ba82"
        ),
        "packaging/sqlcipher/perl/Time/Piece.pm": (
            "91854216b72683d724e76a1ed26e8f90dee87e136dee3db5ac509ce400585f3f"
        ),
    }:
        raise RuntimeError("OpenSSL Perl shims must be exact and reviewed")
    sources = manifest.get("sources")
    dependencies = manifest.get("buildDependencies")
    if not isinstance(sources, dict) or not isinstance(dependencies, dict):
        raise RuntimeError("manifest sources and build dependencies must be objects")
    for label in ("sqlcipher3", "SQLCipher", "OpenSSL"):
        validate_download(sources.get(label), label)
    for label in ("setuptools", "wheel"):
        validate_download(dependencies.get(label), label)
    for label in ("SQLCipher", "OpenSSL"):
        source = sources[label]
        for nested in ("signature", "signingKey"):
            validate_download(source.get(nested), "%s %s" % (label, nested))
        fingerprint = source["signingKey"].get("primaryFingerprint")
        if not isinstance(fingerprint, str) or FINGERPRINT.fullmatch(fingerprint) is None:
            raise RuntimeError("%s signing fingerprint is invalid" % label)
    if sources["SQLCipher"].get("embeddedSQLiteVersion") != "3.53.4":
        raise RuntimeError("unexpected SQLCipher SQLite baseline")
    if sources["OpenSSL"].get("releaseSeries") != "3.5 LTS":
        raise RuntimeError("OpenSSL must remain on the reviewed LTS series")
    artifact = manifest.get("artifact")
    if artifact != {
        "distribution": "continuum-sqlcipher3",
        "module": "sqlcipher3",
        "version": "0.6.2.post1",
    }:
        raise RuntimeError("patched-wheel artifact identity changed")
    return manifest


def iter_downloads(manifest: dict):
    for label in ("sqlcipher3", "SQLCipher", "OpenSSL"):
        source = manifest["sources"][label]
        yield label, source
        if label in ("SQLCipher", "OpenSSL"):
            yield "%s-signature" % label, source["signature"]
            yield "%s-signing-key" % label, source["signingKey"]
    for label in ("setuptools", "wheel"):
        yield label, manifest["buildDependencies"][label]


def download(record: dict, destination: Path) -> Path:
    filename = checked_filename(record["filename"])
    target = destination / filename
    if target.is_file() and sha256(target) == record["sha256"]:
        return target
    temporary = destination / (filename + ".partial")
    if temporary.exists():
        temporary.unlink()
    request = urllib.request.Request(record["url"], headers={"User-Agent": "continuum-memory/0.1"})
    total = 0
    try:
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open("xb") as output:
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > MAX_DOWNLOAD_BYTES:
                raise RuntimeError("download exceeds size limit: %s" % filename)
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise RuntimeError("download exceeds size limit: %s" % filename)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if sha256(temporary) != record["sha256"]:
            raise RuntimeError("download SHA-256 mismatch: %s" % filename)
        temporary.replace(target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


def safe_archive_path(name: str, expected_root: str) -> None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != expected_root:
        raise RuntimeError("archive contains an unsafe or unexpected path: %s" % name)


def inspect_sqlcipher_source(path: Path, source: dict) -> None:
    root = "sqlcipher-%s" % source["version"]
    with zipfile.ZipFile(path) as archive:
        if archive.comment.decode("ascii") != source["commit"]:
            raise RuntimeError("SQLCipher archive commit comment mismatch")
        for name in archive.namelist():
            safe_archive_path(name, root)
        manifest_uuid = archive.read("%s/manifest.uuid" % root).decode("ascii").strip()
        version = archive.read("%s/VERSION" % root).decode("ascii").strip()
        license_hash = hashlib.sha256(archive.read("%s/LICENSE.txt" % root)).hexdigest()
        sqlite_license_hash = hashlib.sha256(
            archive.read("%s/SQLITE_LICENSE.md" % root)
        ).hexdigest()
    if manifest_uuid != source["manifestUuid"]:
        raise RuntimeError("SQLCipher manifest UUID mismatch")
    if version != source["embeddedSQLiteVersion"]:
        raise RuntimeError("SQLCipher embedded SQLite version mismatch")
    if license_hash != source["licenseSha256"]:
        raise RuntimeError("SQLCipher license mismatch")
    if sqlite_license_hash != "595e823c2ada6c839679e693bee1f4d7f88e2d34ac99a913ae41e3d43fb10c7d":
        raise RuntimeError("SQLite license record mismatch")


def inspect_tar_source(path: Path, root: str, required: tuple[str, ...]) -> None:
    with tarfile.open(path, "r:gz") as archive:
        names = set()
        for member in archive.getmembers():
            safe_archive_path(member.name, root)
            names.add(member.name)
        missing = ["%s/%s" % (root, item) for item in required if "%s/%s" % (root, item) not in names]
        if missing:
            raise RuntimeError("source archive is missing: %s" % ", ".join(missing))


def inspect_sources(directory: Path, manifest: dict) -> None:
    sources = manifest["sources"]
    inspect_sqlcipher_source(directory / sources["SQLCipher"]["filename"], sources["SQLCipher"])
    inspect_tar_source(
        directory / sources["OpenSSL"]["filename"],
        "openssl-%s" % sources["OpenSSL"]["version"],
        ("LICENSE.txt", "VERSION.dat", "Configure"),
    )
    inspect_tar_source(
        directory / sources["sqlcipher3"]["filename"],
        "sqlcipher3-%s" % sources["sqlcipher3"]["version"],
        ("LICENSE", "PKG-INFO", "setup.py", "src/module.c", "vendor/sqlite3.c"),
    )


def inspect_project_inputs(repository_root: Path, manifest: dict) -> None:
    for relative, expected_hash in manifest["builder"]["opensslPerlShims"].items():
        path = repository_root / relative
        if path.is_symlink() or not path.is_file() or sha256(path) != expected_hash:
            raise RuntimeError("OpenSSL Perl shim is missing, linked, or modified: %s" % relative)


def gpg_fingerprints(gpg: str, key_file: Path) -> set[str]:
    result = subprocess.run(
        [gpg, "--batch", "--with-colons", "--show-keys", "--fingerprint", str(key_file)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return {
        fields[9]
        for line in result.stdout.splitlines()
        if (fields := line.split(":"))[0] == "fpr" and len(fields) > 9
    }


def valid_signature_fingerprints(status: bytes) -> tuple[str, str]:
    """Return the signing and primary fingerprints from one GnuPG VALIDSIG.

    Other status records may contain an unescaped, non-UTF-8 user ID.  Keep the
    stream binary and decode only the VALIDSIG record, whose fields are ASCII.
    """
    prefix = b"[GNUPG:] VALIDSIG "
    records = [line for line in status.splitlines() if line.startswith(prefix)]
    if len(records) != 1:
        raise RuntimeError("GnuPG must emit exactly one VALIDSIG record")
    try:
        fields = records[0].decode("ascii").split()
    except UnicodeDecodeError as error:
        raise RuntimeError("GnuPG VALIDSIG record is not ASCII") from error
    if len(fields) not in (11, 12) or fields[:2] != ["[GNUPG:]", "VALIDSIG"]:
        raise RuntimeError("GnuPG emitted a malformed VALIDSIG record")
    signing_fingerprint = fields[2]
    primary_fingerprint = fields[11] if len(fields) == 12 else signing_fingerprint
    if (
        FINGERPRINT.fullmatch(signing_fingerprint) is None
        or FINGERPRINT.fullmatch(primary_fingerprint) is None
    ):
        raise RuntimeError("GnuPG VALIDSIG fingerprints are malformed")
    return signing_fingerprint, primary_fingerprint


def verify_signature(directory: Path, label: str, source: dict) -> dict:
    gpg = shutil.which("gpg")
    if gpg is None:
        raise RuntimeError("gpg is required to verify signed sources")
    key_file = directory / source["signingKey"]["filename"]
    expected = source["signingKey"]["primaryFingerprint"]
    if expected not in gpg_fingerprints(gpg, key_file):
        raise RuntimeError("%s signing key fingerprint mismatch" % label)
    home = directory / (".%s-gnupg" % label.lower())
    home.mkdir(mode=0o700)
    subprocess.run(
        [gpg, "--batch", "--homedir", str(home), "--import", str(key_file)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    result = subprocess.run(
        [
            gpg,
            "--batch",
            "--no-tty",
            "--homedir",
            str(home),
            "--status-fd=1",
            "--verify",
            str(directory / source["signature"]["filename"]),
            str(directory / source["filename"]),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _signing, primary = valid_signature_fingerprints(result.stdout)
    if primary != expected:
        raise RuntimeError("%s signature is not bound to the reviewed primary key" % label)
    return {"primaryFingerprint": expected, "signatureVerified": True}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    arguments = parser.parse_args()
    manifest = validate_manifest(load_json_strict(arguments.manifest))
    inspect_project_inputs(ROOT, manifest)
    destination = arguments.destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    downloads = {}
    for label, record in iter_downloads(manifest):
        path = download(record, destination)
        downloads[label] = {"filename": path.name, "sha256": sha256(path)}
    inspect_sources(destination, manifest)
    signatures = {
        label: verify_signature(destination, label, manifest["sources"][label])
        for label in ("SQLCipher", "OpenSSL")
    }
    evidence = {
        "downloads": downloads,
        "manifestSha256": sha256(arguments.manifest),
        "signatures": signatures,
        "status": "VERIFIED",
    }
    evidence_path = destination / "source-verification.json"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(str(evidence_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
