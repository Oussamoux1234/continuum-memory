#!/usr/bin/env python3
"""Acquire and verify every pinned input for the patched SQLCipher wheel build."""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "packaging" / "sqlcipher" / "manifest.json"
MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_EXPANDED_ARCHIVE_BYTES = 512 * 1024 * 1024
HEX_64 = re.compile(r"[0-9a-f]{64}")
FINGERPRINT = re.compile(r"[0-9A-F]{40}")
REVIEWED_DOWNLOAD_HOSTS = {
    "files.pythonhosted.org": {"files.pythonhosted.org"},
    "github.com": {"github.com", "release-assets.githubusercontent.com"},
    "mirror.openssl-library.org": {"mirror.openssl-library.org"},
    "www.zetetic.net": {"www.zetetic.net"},
}
REVIEWED_FINAL_HOSTS = set().union(*REVIEWED_DOWNLOAD_HOSTS.values())
REVIEWED_BUILDER = {
    "image": (
        "quay.io/pypa/manylinux_2_28_x86_64"
        "@sha256:53390351aeb4688114b02c36a23b3e6ce1166ee9b7afc5df1a4f776354fc764c"
    ),
    "imageTag": "2026.09.05-1",
    "platform": "linux-x86_64",
    "sourceDateEpoch": 1788285600,
}
REVIEWED_BUILD_DEPENDENCIES = {
    "setuptools": {
        "filename": "setuptools-80.9.0-py3-none-any.whl",
        "sha256": "062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922",
        "url": (
            "https://files.pythonhosted.org/packages/a3/dc/17031897dae0efacfea57dfd3a82fdd2a2aeb58e0ff71b77b87e44edc772/"
            "setuptools-80.9.0-py3-none-any.whl"
        ),
        "version": "80.9.0",
    },
    "wheel": {
        "filename": "wheel-0.45.1-py3-none-any.whl",
        "sha256": "708e7481cc80179af0e556bbf0cc00b8444c7321e2700b8d8580231d13017248",
        "url": (
            "https://files.pythonhosted.org/packages/0b/2c/87f3254fd8ffd29e4c02732eee68a83a1d3c346ae39bc6822dcbcb697f2b/"
            "wheel-0.45.1-py3-none-any.whl"
        ),
        "version": "0.45.1",
    },
}
REVIEWED_SOURCES = {
    "OpenSSL": {
        "commit": "f4dc4d58b48d346a8270183f89acf826d459b0ca",
        "endOfLife": "2030-04-08",
        "filename": "openssl-3.5.8.tar.gz",
        "license": "Apache-2.0",
        "licenseSha256": "7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a",
        "releaseSeries": "3.5 LTS",
        "sha256": "a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2",
        "signature": {
            "filename": "openssl-3.5.8.tar.gz.asc",
            "sha256": "f4bfa84a290dfd5ad102a54ebc0f93f9b35359cb36c383769b5c7bc6034f1f65",
            "url": (
                "https://github.com/openssl/openssl/releases/download/openssl-3.5.8/"
                "openssl-3.5.8.tar.gz.asc"
            ),
        },
        "signingKey": {
            "filename": "openssl-pubkeys.asc",
            "primaryFingerprint": "B146647E45A7B33947AB226B2A2C87D161692D40",
            "sha256": "56e106cd1c44bdb117aec24795f6dfbecaa9bfa0a2901b85331f0059aad16d53",
            "url": "https://mirror.openssl-library.org/source/pubkeys.asc",
        },
        "tag": "openssl-3.5.8",
        "tagObject": "090eec6d3628aa0520bdf2cf97b063fafc34e7be",
        "url": (
            "https://github.com/openssl/openssl/releases/download/openssl-3.5.8/"
            "openssl-3.5.8.tar.gz"
        ),
        "version": "3.5.8",
    },
    "SQLCipher": {
        "commit": "c4b275a47932888216bade83aff2bbc73df0ff85",
        "embeddedSQLiteVersion": "3.53.4",
        "filename": "sqlcipher-4.19.0.zip",
        "license": "BSD-3-Clause",
        "licenseSha256": "2a2826f6acf46fa650730cf42cbb22a642be33a7ef119c9c4f4bf6daf3bef48e",
        "manifestUuid": "bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc",
        "sha256": "268d603ff040fa669556fe8be2e8ae8f353d86d799279e3a86e683eb5fb25c95",
        "signature": {
            "filename": "sqlcipher-4.19.0.zip.sig",
            "sha256": "f5adf1c55a52af2a362dc76a63e10af0df76a0f811b6ebd355e852ff58acec33",
            "url": (
                "https://www.zetetic.net/downloads/sqlcipher/verify/4.19.0/"
                "sqlcipher-4.19.0.zip.sig"
            ),
        },
        "signingKey": {
            "filename": "zetetic-public-key.gpg",
            "primaryFingerprint": "D83F5F9EB811D6E6B4A0D9C5D1FA3A2A97ED25C2",
            "sha256": "b5fa10e62b50478db1236f3a8c7157074d71450a1f6a245eb77a71802202eefd",
            "url": "https://www.zetetic.net/security/support_zetetic_net_public_key.gpg",
        },
        "tag": "v4.19.0",
        "tagObject": "58beb4a302f0e3c37341d2312cef521f858b1273",
        "url": (
            "https://www.zetetic.net/downloads/sqlcipher/verify/4.19.0/"
            "sqlcipher-4.19.0.zip"
        ),
        "version": "4.19.0",
    },
    "SQLite": {
        "license": "LicenseRef-SQLite-Public-Domain",
        "licenseSha256": "595e823c2ada6c839679e693bee1f4d7f88e2d34ac99a913ae41e3d43fb10c7d",
        "version": "3.53.4",
    },
    "sqlcipher3": {
        "commit": "14fc2632676b20011e0bba64fdda49763a2dd2ec",
        "filename": "sqlcipher3-0.6.2.tar.gz",
        "licenseConcluded": "NOASSERTION",
        "licenseSha256": "fa23cf250126548e90008fe92de4ee76d485bfbb3592f5be8aa731775892a960",
        "sha256": "a2b675289ba8889f389625a21f3a01f1ff159a551b5b88fba8fd92da0e02380a",
        "tag": "0.6.2",
        "url": (
            "https://files.pythonhosted.org/packages/ae/c1/414003d77549c444bafd636149ab3ace6f4e2cb4666c9955d54ad62096cb/"
            "sqlcipher3-0.6.2.tar.gz"
        ),
        "version": "0.6.2",
    },
}
REVIEWED_TARGETS = {
    "linuxCp311": {
        "filename": "continuum_sqlcipher3-0.6.2.post2-cp311-cp311-manylinux_2_28_x86_64.whl",
        "pythonAbi": "cp311-cp311",
        "pythonMinor": "3.11",
    },
    "linuxCp312": {
        "filename": "continuum_sqlcipher3-0.6.2.post2-cp312-cp312-manylinux_2_28_x86_64.whl",
        "pythonAbi": "cp312-cp312",
        "pythonMinor": "3.12",
    },
    "linuxCp313": {
        "filename": "continuum_sqlcipher3-0.6.2.post2-cp313-cp313-manylinux_2_28_x86_64.whl",
        "pythonAbi": "cp313-cp313",
        "pythonMinor": "3.13",
    },
    "linuxCp314": {
        "filename": "continuum_sqlcipher3-0.6.2.post2-cp314-cp314-manylinux_2_28_x86_64.whl",
        "pythonAbi": "cp314-cp314",
        "pythonMinor": "3.14",
    },
}


REVIEWED_SECURITY_EVIDENCE = {'endpoint': 'https://api.osv.dev/v1/query',
 'evidenceDate': '2026-09-23',
 'qualification': 'Empty exact-commit query responses mean no known OSV findings at query time; '
                  'they are not proof of safety. SQLCipher 4.19.0 is the upstream remediation for '
                  'two issues disclosed 2026-09-08 affecting 4.18.0 and earlier.',
 'queriedAt': '2026-09-23T13:23:10.882825+00:00',
 'queries': [{'component': 'OpenSSL',
              'request': {'commit': 'f4dc4d58b48d346a8270183f89acf826d459b0ca'},
              'response': {}},
             {'component': 'sqlcipher3',
              'request': {'commit': '14fc2632676b20011e0bba64fdda49763a2dd2ec'},
              'response': {}},
             {'component': 'SQLCipher',
              'request': {'commit': 'c4b275a47932888216bade83aff2bbc73df0ff85'},
              'response': {}}],
 'requestContentType': 'application/json',
 'schemaVersion': 1,
 'vendorAdvisories': [{'affectedVersions': '4.18.0 and earlier',
                       'component': 'SQLCipher',
                       'fixedVersion': '4.19.0',
                       'issues': [{'conditions': 'Attacker-controlled attached database aliases '
                                                 'must reach sqlcipher_export through SQL '
                                                 'injection or unrestricted SQL access.',
                                   'effect': 'Aliases can alter generated SQL statements; upstream '
                                             'says encryption and per-page integrity remain intact '
                                             'and this issue does not leak data.',
                                   'name': 'Unquoted schema aliases in sqlcipher_export'},
                                  {'conditions': 'A new database is opened with the optional '
                                                 'hexkey URI parameter containing no valid key '
                                                 'material.',
                                   'effect': 'Affected versions can create a plaintext SQLite '
                                             'database without reporting an error; 4.19.0 reports '
                                             'an error.',
                                   'name': 'Invalid nonempty URI hexkey'}],
                       'observedDate': '2026-09-23',
                       'publishedDate': '2026-09-08',
                       'qualification': 'Upstream rates both issues Low. The export issue and '
                                        'plaintext-creation issue have different effects. These '
                                        'vendor findings invalidate an unqualified security '
                                        'clearance for 4.18.0 even when its OSV response is empty; '
                                        'the 4.19.0 candidate still requires signature, build, '
                                        'runtime, and independent acceptance checks.',
                       'url': 'https://www.zetetic.net/blog/2026/09/08/sqlcipher-4.19.0-release/'}]}

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


def publish_bytes_exclusive(path: Path, payload: bytes) -> None:
    """Atomically publish one new regular file without following or replacing links."""
    require_real_directory(path.parent, "evidence parent")
    if path.exists() or path.is_symlink():
        raise RuntimeError("evidence output already exists or is linked: %s" % path.name)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=".%s." % path.name, suffix=".partial"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as error:
            raise RuntimeError("evidence output appeared during publication: %s" % path.name) from error
        temporary.unlink()
        directory_descriptor = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()
    if not is_single_regular_file(path):
        raise RuntimeError("evidence output is linked or not regular: %s" % path.name)


def checked_filename(value: object) -> str:
    if not isinstance(value, str) or not value or Path(value).name != value:
        raise RuntimeError("download filename must be a single safe path component")
    return value


def validated_https_url(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise RuntimeError("%s URL must use HTTPS" % label)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise RuntimeError("%s URL is malformed" % label) from error
    if (
        parsed.scheme != "https"
        or parsed.hostname not in REVIEWED_FINAL_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise RuntimeError("%s URL must use a reviewed HTTPS origin" % label)
    return parsed.hostname


def validate_download(record: object, label: str) -> None:
    if not isinstance(record, dict):
        raise RuntimeError("%s download record must be an object" % label)
    checked_filename(record.get("filename"))
    host = validated_https_url(record.get("url"), "%s download" % label)
    if host not in REVIEWED_DOWNLOAD_HOSTS:
        raise RuntimeError("%s download URL is not a reviewed origin" % label)
    expected_hash = record.get("sha256")
    if not isinstance(expected_hash, str) or HEX_64.fullmatch(expected_hash) is None:
        raise RuntimeError("%s download must have one SHA-256 digest" % label)


def validate_manifest(manifest: object) -> dict:
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1:
        raise RuntimeError("unsupported patched-wheel manifest schema")
    if manifest.get("evidenceDate") != "2026-09-23":
        raise RuntimeError("patched-wheel manifest evidence is stale")
    builder = manifest.get("builder")
    if (
        not isinstance(builder, dict)
        or set(builder) != set(REVIEWED_BUILDER) | {"reviewedProjectFiles"}
        or any(builder.get(key) != value for key, value in REVIEWED_BUILDER.items())
    ):
        raise RuntimeError("builder identity must be immutable and reviewed")
    reviewed_project_files = builder.get("reviewedProjectFiles")
    expected_project_files = {
        ".github/workflows/patched-sqlcipher-wheel.yml",
        "packaging/sqlcipher/perl/IPC/Cmd.pm",
        "packaging/sqlcipher/perl/Time/Piece.pm",
        "packaging/sqlcipher/security-evidence-2026-09-23.json",
        "packaging/sqlcipher/SOURCE_REVIEW_2026-09-23.md",
        "packaging/sqlcipher/pyproject.toml",
        "packaging/sqlcipher/setup_continuum.py",
        "scripts/build_patched_sqlcipher_wheel.sh",
        "scripts/fetch_patched_sqlcipher_sources.py",
        "scripts/inspect_patched_sqlcipher_wheel.py",
        "scripts/test_patched_sqlcipher_install.py",
        "scripts/test_patched_sqlcipher_runtime.py",
        "scripts/verify_patched_sqlcipher_inputs.py",
    }
    if (
        not isinstance(reviewed_project_files, dict)
        or set(reviewed_project_files) != expected_project_files
        or any(
            not isinstance(value, str) or HEX_64.fullmatch(value) is None
            for value in reviewed_project_files.values()
        )
    ):
        raise RuntimeError("reviewed project build inputs must be exact and locked")
    sources = manifest.get("sources")
    dependencies = manifest.get("buildDependencies")
    if sources != REVIEWED_SOURCES or dependencies != REVIEWED_BUILD_DEPENDENCIES:
        raise RuntimeError("reviewed sources or build dependencies changed")
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
    artifact = manifest.get("artifact")
    if artifact != {
        "distribution": "continuum-sqlcipher3",
        "module": "sqlcipher3",
        "version": "0.6.2.post2",
    }:
        raise RuntimeError("patched-wheel artifact identity changed")
    expected_artifacts = manifest.get("expectedArtifacts")
    if not isinstance(expected_artifacts, dict) or set(expected_artifacts) != set(
        REVIEWED_TARGETS
    ):
        raise RuntimeError("patched-wheel expected artifacts must be an object")
    for key, target in REVIEWED_TARGETS.items():
        expected_artifact = expected_artifacts.get(key)
        if not isinstance(expected_artifact, dict) or {
            name: expected_artifact.get(name) for name in target
        } != target:
            raise RuntimeError("patched-wheel target identity is not exact: %s" % key)
        if set(expected_artifact) != set(target) | {"sha256"}:
            raise RuntimeError("patched-wheel target fields changed: %s" % key)
        expected_artifact_hash = expected_artifact.get("sha256")
        if (
            not isinstance(expected_artifact_hash, str)
            or HEX_64.fullmatch(expected_artifact_hash) is None
            or expected_artifact_hash == "0" * 64
        ):
            raise RuntimeError("patched-wheel SHA-256 must be locked: %s" % key)
    if manifest.get("signing") != {
        "artifactSigningStatus": "BLOCKED_IDENTITY_NOT_SELECTED",
        "requiredDecision": (
            "Select and approve the artifact signing identity, trust root, transparency policy, "
            "verification procedure, and revocation procedure before permanent distribution."
        ),
    }:
        raise RuntimeError("artifact signing status changed without review")
    if manifest.get("supportedSlice") != {
        "built": [
            "linux-x86_64/cp311",
            "linux-x86_64/cp312",
            "linux-x86_64/cp313",
            "linux-x86_64/cp314",
        ],
        "planned": [
            "macos-arm64/cp311",
            "macos-arm64/cp312",
            "macos-arm64/cp313",
            "macos-arm64/cp314",
        ],
        "windowsSupported": False,
    }:
        raise RuntimeError("supported platform status changed without evidence")
    if manifest.get("vulnerabilityEvidence") != {
        "evidenceFile": "packaging/sqlcipher/security-evidence-2026-09-23.json",
        "evidenceSha256": "90b2e18631cc8eca526e7b66f94d96bcd0ce306429ab68334b0864befdba5d7d",
        "findingCounts": {"OpenSSL": 0, "SQLCipher": 0, "sqlcipher3": 0},
        "method": "Retained exact-commit OSV responses and upstream SQLCipher advisory",
        "qualification": (
            "Zero OSV findings for the pinned commits; the vendor advisory fixes "
            "require separate runtime testing. Not proof of safety."
        ),
    }:
        raise RuntimeError("vulnerability evidence changed without review")
    return manifest


def artifact_target(manifest: dict, key: str) -> dict:
    if key not in REVIEWED_TARGETS:
        raise RuntimeError("unknown patched-wheel target: %s" % key)
    return manifest["expectedArtifacts"][key]


def iter_downloads(manifest: dict):
    for label in ("sqlcipher3", "SQLCipher", "OpenSSL"):
        source = manifest["sources"][label]
        yield label, source
        if label in ("SQLCipher", "OpenSSL"):
            yield "%s-signature" % label, source["signature"]
            yield "%s-signing-key" % label, source["signingKey"]
    for label in ("setuptools", "wheel"):
        yield label, manifest["buildDependencies"][label]


def is_single_regular_file(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1


def require_real_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise RuntimeError("%s directory is missing" % label) from error
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise RuntimeError("%s must be a real directory" % label)


def validate_download_response(configured_url: str, response) -> None:
    configured_host = validated_https_url(configured_url, "configured download")
    final_host = validated_https_url(response.geturl(), "final download")
    if final_host not in REVIEWED_DOWNLOAD_HOSTS[configured_host]:
        raise RuntimeError("download redirected to an unreviewed host")
    if getattr(response, "status", 200) != 200:
        raise RuntimeError("download did not return HTTP 200")
    content_encoding = response.headers.get("Content-Encoding")
    if content_encoding not in (None, "identity"):
        raise RuntimeError("download returned an unexpected content encoding")


def download(record: dict, destination: Path) -> Path:
    require_real_directory(destination, "download destination")
    filename = checked_filename(record["filename"])
    target = destination / filename
    if target.exists() or target.is_symlink():
        if not is_single_regular_file(target):
            raise RuntimeError("download target is linked or not a regular file: %s" % filename)
        if sha256(target) != record["sha256"]:
            raise RuntimeError("existing download SHA-256 mismatch: %s" % filename)
        return target
    descriptor, temporary_name = tempfile.mkstemp(
        dir=str(destination), prefix=".%s." % filename, suffix=".partial"
    )
    temporary = Path(temporary_name)
    request = urllib.request.Request(record["url"], headers={"User-Agent": "continuum-memory/0.1"})
    total = 0
    try:
        with urllib.request.urlopen(request, timeout=60) as response, os.fdopen(
            descriptor, "wb"
        ) as output:
            descriptor = -1
            validate_download_response(record["url"], response)
            length = response.headers.get("Content-Length")
            if length is not None:
                try:
                    declared_length = int(length)
                except ValueError as error:
                    raise RuntimeError("download has an invalid size: %s" % filename) from error
                if declared_length < 0 or declared_length > MAX_DOWNLOAD_BYTES:
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
        os.chmod(temporary, 0o644)
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError as error:
            raise RuntimeError("download target appeared during acquisition: %s" % filename) from error
        temporary.unlink()
        directory_descriptor = os.open(str(destination), os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()
    if not is_single_regular_file(target):
        raise RuntimeError("download target is linked or not a regular file: %s" % filename)
    return target


def safe_archive_path(name: str, expected_root: str) -> None:
    if not isinstance(name, str) or not name or "\0" in name or "\\" in name:
        raise RuntimeError("archive contains an unsafe or unexpected path: %s" % name)
    path = PurePosixPath(name)
    comparable = name[:-1] if name.endswith("/") else name
    if (
        path.is_absolute()
        or ".." in path.parts
        or not path.parts
        or path.parts[0] != expected_root
        or comparable != str(path)
    ):
        raise RuntimeError("archive contains an unsafe or unexpected path: %s" % name)


def inspect_zip_members(archive: zipfile.ZipFile, expected_root: str) -> dict[str, zipfile.ZipInfo]:
    members = archive.infolist()
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise RuntimeError("source archive contains too many members")
    if sum(member.file_size for member in members) > MAX_EXPANDED_ARCHIVE_BYTES:
        raise RuntimeError("source archive expands beyond the size limit")
    result = {}
    for member in members:
        safe_archive_path(member.filename, expected_root)
        normalized_name = member.filename[:-1] if member.filename.endswith("/") else member.filename
        if normalized_name in result:
            raise RuntimeError("source archive contains duplicate members")
        if member.flag_bits & 0x1:
            raise RuntimeError("source archive contains an encrypted member")
        mode = (member.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if member.is_dir():
            if file_type not in (0, stat.S_IFDIR):
                raise RuntimeError("source archive contains a special member")
        elif file_type not in (0, stat.S_IFREG):
            raise RuntimeError("source archive contains a link or special member")
        result[normalized_name] = member
    return result


def inspect_sqlcipher_source(path: Path, source: dict) -> None:
    root = "sqlcipher-%s" % source["version"]
    with zipfile.ZipFile(path) as archive:
        if archive.comment.decode("ascii") != source["commit"]:
            raise RuntimeError("SQLCipher archive commit comment mismatch")
        members = inspect_zip_members(archive, root)
        required = ("manifest.uuid", "VERSION", "LICENSE.txt", "SQLITE_LICENSE.md")
        for relative in required:
            member = members.get("%s/%s" % (root, relative))
            if member is None or member.is_dir():
                raise RuntimeError("SQLCipher archive is missing a required regular file")
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
        members = archive.getmembers()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise RuntimeError("source archive contains too many members")
        if sum(member.size for member in members) > MAX_EXPANDED_ARCHIVE_BYTES:
            raise RuntimeError("source archive expands beyond the size limit")
        names = {}
        for member in members:
            safe_archive_path(member.name, root)
            normalized_name = member.name[:-1] if member.name.endswith("/") else member.name
            if normalized_name in names:
                raise RuntimeError("source archive contains duplicate members")
            if not (member.isfile() or member.isdir()):
                raise RuntimeError("source archive contains a link or special member")
            names[normalized_name] = member
        missing = [
            "%s/%s" % (root, item)
            for item in required
            if "%s/%s" % (root, item) not in names
            or not names["%s/%s" % (root, item)].isfile()
        ]
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
    for relative, expected_hash in manifest["builder"]["reviewedProjectFiles"].items():
        path = repository_root / relative
        if not is_single_regular_file(path) or sha256(path) != expected_hash:
            raise RuntimeError("reviewed project input is missing, linked, or modified: %s" % relative)
    evidence_path = repository_root / manifest["vulnerabilityEvidence"]["evidenceFile"]
    evidence = load_json_strict(evidence_path)
    if evidence != REVIEWED_SECURITY_EVIDENCE:
        raise RuntimeError("retained security evidence changed or is malformed")


def gpg_fingerprints(gpg: str, key_file: Path) -> set[str]:
    with tempfile.TemporaryDirectory(
        dir=str(key_file.parent), prefix=".continuum-gpg-show-"
    ) as home:
        os.chmod(home, 0o700)
        result = subprocess.run(
            [
                gpg,
                "--batch",
                "--no-options",
                "--homedir",
                home,
                "--with-colons",
                "--show-keys",
                "--fingerprint",
                str(key_file),
            ],
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
    adverse_records = (
        b"[GNUPG:] BADSIG ",
        b"[GNUPG:] ERRSIG ",
        b"[GNUPG:] EXPSIG ",
        b"[GNUPG:] EXPKEYSIG ",
        b"[GNUPG:] REVKEYSIG ",
        b"[GNUPG:] KEYREVOKED",
        b"[GNUPG:] KEYEXPIRED ",
        b"[GNUPG:] SIGEXPIRED ",
        b"[GNUPG:] NO_PUBKEY ",
        b"[GNUPG:] NODATA ",
        b"[GNUPG:] FAILURE ",
    )
    if any(
        line.startswith(adverse)
        for line in status.splitlines()
        for adverse in adverse_records
    ):
        raise RuntimeError("GnuPG emitted an adverse signature status")
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
    with tempfile.TemporaryDirectory(
        dir=str(directory), prefix=".%s-gnupg-" % label.lower()
    ) as home:
        os.chmod(home, 0o700)
        subprocess.run(
            [gpg, "--batch", "--no-options", "--homedir", home, "--import", str(key_file)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        result = subprocess.run(
            [
                gpg,
                "--batch",
                "--no-options",
                "--no-tty",
                "--homedir",
                home,
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
    destination = arguments.destination.absolute()
    destination.mkdir(parents=True, exist_ok=True)
    require_real_directory(destination, "download destination")
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
    publish_bytes_exclusive(
        evidence_path,
        (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    print(str(evidence_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
