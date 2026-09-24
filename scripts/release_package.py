#!/usr/bin/env python3
"""Build and verify unsigned experimental distributions without network access."""

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from email.parser import BytesParser
from importlib import metadata
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
NAME = "continuum-memory"
VERSION = "0.1.0.dev0"
ENTRY_POINTS = {
    "continuum": "--version",
    "memoryd": "--help",
    "continuum-mcp": "--help",
    "continuum-polkit-helper": "--help",
}
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
WINDOWS_DEVICE = re.compile(r"^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", re.IGNORECASE)


def portable_member(name):
    """One canonical path on both Unix and Windows, never a drive/ADS alias."""
    path = PurePosixPath(name)
    if (not path.parts or path.is_absolute() or str(path) != name or ".." in path.parts
            or any(char in name for char in '\\:<>"|?*')
            or any(ord(char) < 32 for char in name)
            or any(part.endswith((".", " ")) or WINDOWS_DEVICE.match(part) for part in path.parts)):
        raise ValueError("unsafe or duplicate archive member")
    return path


def sha256(payload):
    return hashlib.sha256(payload).hexdigest()


def run(arguments, *, cwd, env):
    print("+ " + " ".join(map(str, arguments)), flush=True)
    subprocess.run(list(map(str, arguments)), cwd=str(cwd), env=env, check=True)


def offline_environment(epoch):
    environment = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS"):
        environment.pop(name, None)
    environment.update({
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_NO_INDEX": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_CACHE_DIR": "1",
        "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": str(epoch),
        "TZ": "UTC",
    })
    return environment


def archive_members(archive):
    """Read bounded regular-file payloads only; never extract supplied archives."""
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("archive exceeds size limit")
    result = {}
    portable_names = set()
    total = 0

    def add(name, size, read):
        nonlocal total
        portable_member(name)
        if name.casefold() in portable_names:
            raise ValueError("unsafe or duplicate archive member")
        if size > MAX_MEMBER_BYTES or total + size > MAX_ARCHIVE_BYTES:
            raise ValueError("expanded archive exceeds size limit")
        payload = read()
        if len(payload) != size:
            raise ValueError("archive member size mismatch")
        total += size
        result[name] = payload
        portable_names.add(name.casefold())

    if archive.name.endswith(".whl"):
        with zipfile.ZipFile(archive) as bundle:
            for entry in bundle.infolist():
                if entry.is_dir():
                    continue
                mode = entry.external_attr >> 16
                if mode & 0o170000 not in (0, 0o100000):
                    raise ValueError("non-regular wheel member")
                add(entry.filename, entry.file_size, lambda entry=entry: bundle.read(entry))
    else:
        with tarfile.open(archive, "r:gz") as bundle:
            for entry in bundle.getmembers():
                if entry.isdir():
                    continue
                if not entry.isfile():
                    raise ValueError("non-regular source member")
                def read(entry=entry):
                    with bundle.extractfile(entry) as handle:
                        return handle.read()
                add(entry.name, entry.size, read)
    return result


def validate_metadata(archive):
    members = archive_members(archive)
    if archive.name.endswith(".whl"):
        expected = "continuum_memory-%s-py3-none-any.whl" % VERSION
        candidates = [name for name in members if name.count("/") == 1 and name.endswith(".dist-info/METADATA")]
    else:
        expected = "continuum_memory-%s.tar.gz" % VERSION
        candidates = [name for name in members if name.count("/") == 1 and name.endswith("/PKG-INFO")]
    if archive.name != expected or len(candidates) != 1:
        raise ValueError("unexpected distribution filename or metadata")
    fields = BytesParser().parsebytes(members[candidates[0]])
    for field, value in (("Name", NAME), ("Version", VERSION), ("License-Expression", "Apache-2.0")):
        if fields.get_all(field) != [value]:
            raise ValueError("unexpected distribution %s" % field)
    if fields.get_all("Requires-Dist"):
        raise ValueError("runtime dependencies changed: update release verification and SBOM first")
    if fields.get("Author-email") != "Oussama Essalmani <98963291+Oussamoux1234@users.noreply.github.com>":
        raise ValueError("unexpected author metadata")
    return members


def normalize_sdist(archive, epoch):
    """Canonical tar/gzip metadata; file bytes are preserved exactly."""
    members = archive_members(archive)
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, filename="", mode="wb", mtime=epoch, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as bundle:
            for name, payload in sorted(members.items()):
                entry = tarfile.TarInfo(name)
                entry.size = len(payload)
                entry.mtime = epoch
                entry.mode = 0o755 if name.endswith((".sh", "/approval-helper")) else 0o644
                bundle.addfile(entry, io.BytesIO(payload))
    archive.write_bytes(raw.getvalue())


def build_once(source, output, epoch):
    environment = offline_environment(epoch)
    run([sys.executable, "-m", "build", "--no-isolation", "--sdist", "--outdir", output, source], cwd=source, env=environment)
    sdists = list(output.glob("*.tar.gz"))
    if len(sdists) != 1:
        raise ValueError("expected exactly one sdist")
    archive = sdists[0]
    normalize_sdist(archive, epoch)
    unpacked = output / "source"
    unpacked.mkdir()
    for name, payload in archive_members(archive).items():
        destination = unpacked / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    roots = list(unpacked.iterdir())
    if len(roots) != 1 or not roots[0].is_dir():
        raise ValueError("source distribution must contain one root")
    run([sys.executable, "-m", "build", "--no-isolation", "--wheel", "--outdir", output, roots[0]], cwd=roots[0], env=environment)
    wheels = list(output.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("expected exactly one wheel")
    for artifact in (archive, wheels[0]):
        validate_metadata(artifact)
    return [archive, wheels[0]]


def make_sbom(artifacts, epoch):
    packages, files, relationships = [], [], []
    subjects = []
    for artifact in sorted(artifacts):
        kind = "wheel" if artifact.name.endswith(".whl") else "sdist"
        package_id = "SPDXRef-Package-" + kind
        members = validate_metadata(artifact)
        digests = []
        for name, payload in sorted(members.items()):
            file_id = "SPDXRef-File-" + sha256((kind + "/" + name).encode())
            digest = hashlib.sha1(payload).hexdigest()
            digests.append(digest)
            files.append({
                "SPDXID": file_id, "fileName": "./" + kind + "/" + name,
                "checksums": [{"algorithm": "SHA1", "checksumValue": digest},
                              {"algorithm": "SHA256", "checksumValue": sha256(payload)}],
                "licenseConcluded": "NOASSERTION", "licenseInfoInFiles": ["NOASSERTION"],
                "copyrightText": "NOASSERTION",
            })
            relationships.append({"spdxElementId": package_id, "relationshipType": "CONTAINS", "relatedSpdxElement": file_id})
        artifact_digest = sha256(artifact.read_bytes())
        subjects.append(artifact_digest)
        packages.append({
            "SPDXID": package_id, "name": NAME, "versionInfo": VERSION,
            "packageFileName": artifact.name, "downloadLocation": "NOASSERTION",
            "filesAnalyzed": True,
            "checksums": [{"algorithm": "SHA256", "checksumValue": artifact_digest}],
            "packageVerificationCode": {"packageVerificationCodeValue": hashlib.sha1("".join(sorted(digests)).encode()).hexdigest()},
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "Apache-2.0",
            "licenseInfoFromFiles": ["NOASSERTION"], "copyrightText": "NOASSERTION",
            "comment": "Experimental unsigned application payload. Host Python/SQLite/OpenSSL and build tools are not bundled or inventoried by this payload SBOM.",
        })
        relationships.append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": package_id})
    identity = sha256((str(epoch) + ":" + ":".join(subjects)).encode())
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": NAME + "-" + VERSION + "-payload",
        "documentNamespace": "https://github.com/Oussamoux1234/continuum-memory/sbom/" + identity,
        "creationInfo": {"created": datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "creators": ["Tool: continuum-release-package-1"]},
        "packages": packages, "files": files, "relationships": relationships,
    }


def validate_sbom(path, artifacts, epoch):
    if json.loads(path.read_text()) != make_sbom(artifacts, epoch):
        raise ValueError("SBOM does not match exact archive bytes and complete file inventory")
    from spdx_tools.spdx.parser.parse_anything import parse_file
    from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
    messages = validate_full_spdx_document(parse_file(str(path)))
    if messages:
        raise ValueError("SPDX validation failed: %s" % messages)


def install_smoke(artifact, directory, wheelhouse, epoch):
    environment = offline_environment(epoch)
    run([sys.executable, "-m", "venv", directory], cwd=ROOT, env=environment)
    bin_dir = directory / ("Scripts" if os.name == "nt" else "bin")
    python = bin_dir / ("python.exe" if os.name == "nt" else "python")
    if artifact.name.endswith(".tar.gz"):
        run([python, "-m", "pip", "install", "--no-index", "--no-deps", "--require-hashes", "--find-links", wheelhouse,
             "-r", ROOT / "packaging" / "backend-requirements.txt"], cwd=directory, env=environment)
    run([python, "-m", "pip", "install", "--no-index", "--no-deps", "--no-build-isolation", artifact], cwd=directory, env=environment)
    for entry, flag in ENTRY_POINTS.items():
        executable = bin_dir / (entry + (".exe" if os.name == "nt" else ""))
        run([executable, flag], cwd=directory, env=environment)
    # Exercise the installed launcher, not checkout imports, with a real normal
    # bootstrap. No approval provider is injected and no existing vault is used.
    project = "Décision — 東京 — مرحبا — 🧠"
    for compact in (False, True):
        vault = directory / ("unicode-compact-vault" if compact else "unicode-pretty-vault")
        command = [bin_dir / ("continuum.exe" if os.name == "nt" else "continuum"), "--data-dir", vault]
        if compact:
            command.append("--json")
        command.extend(["init", "--project-name", project, "--project-path", directory])
        result = subprocess.run(list(map(str, command)), cwd=directory,
            env=dict(environment, PYTHONIOENCODING="cp1252", PYTHONUTF8="0"),
            capture_output=True, timeout=15, check=True)
        output = result.stdout.decode("utf-8")
        if (result.stderr or project not in output or json.loads(output)["projects"][0]["name"] != project
                or (len(output.splitlines()) == 1) != compact):
            raise ValueError("installed CLI UTF-8 bootstrap verification failed")
    # The fresh environment must import its installed payload, not this checkout.
    run([python, "-I", "-c", "import continuum_memory; print(continuum_memory.__file__)"], cwd=directory, env=environment)
    if artifact.name.endswith(".whl"):
        # The privileged installer activates its staged venv with a rename. Its
        # fixed wrapper must use the relocated interpreter, not stale shebangs.
        relocated = directory.with_name(directory.name + "-activated")
        directory.rename(relocated)
        if directory.exists():
            raise ValueError("old approval runtime staging path still exists")
        relocated_python = relocated / bin_dir.name / python.name
        run([relocated_python, "-I", "-m", "continuum_memory.polkit_helper", "--help"], cwd=relocated.parent, env=environment)


def build_release(output, wheelhouse):
    if sys.version_info < (3, 11):
        raise RuntimeError("release verification tools require Python 3.11+; runtime compatibility is separate")
    if metadata.version("setuptools") != "80.9.0" or metadata.version("wheel") != "0.45.1":
        raise RuntimeError("install the pinned build requirements before verification")
    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory must be empty; refusing to overwrite artifacts")
    output.mkdir(parents=True, exist_ok=True)
    if not wheelhouse.is_dir():
        raise ValueError("offline build wheelhouse is missing; see docs/LINUX_RELEASE.md")
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=ROOT, text=True).strip())
    if epoch < 315532800 or epoch > 0xFFFFFFFF:
        raise ValueError("SOURCE_DATE_EPOCH must fit the reproducible tar/zip timestamp range")
    tracked = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT).decode().split("\0")
    source_digest = hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix="continuum-release-") as temporary:
        temporary = Path(temporary)
        builds = []
        for attempt in ("one", "two"):
            source = temporary / attempt
            source.mkdir()
            for name in sorted(set(tracked) - {""}):
                portable_member(name)
                path = ROOT / name
                if path.is_symlink() or not path.is_file():
                    raise ValueError("release source must contain only regular tracked files")
                destination = source / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
                if attempt == "one":
                    source_digest.update(name.encode() + b"\0" + bytes.fromhex(sha256(path.read_bytes())))
            distribution = temporary / (attempt + "-dist")
            distribution.mkdir()
            builds.append(build_once(source, distribution, epoch))
        first = {path.name: sha256(path.read_bytes()) for path in builds[0]}
        second = {path.name: sha256(path.read_bytes()) for path in builds[1]}
        if first != second:
            raise ValueError("independent clean builds are not byte-for-byte reproducible")
        artifacts = []
        for artifact in builds[0]:
            destination = output / artifact.name
            shutil.copyfile(artifact, destination)
            artifacts.append(destination)
            install_smoke(destination, temporary / ("install-" + artifact.suffix), wheelhouse, epoch)
    sbom_path = output / "sbom.spdx.json"
    sbom_path.write_text(json.dumps(make_sbom(artifacts, epoch), sort_keys=True, indent=2) + "\n")
    validate_sbom(sbom_path, artifacts, epoch)
    evidence = {
        "schema_version": 1, "status": "unsigned-local-build-evidence-not-an-attestation",
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
        "source_inputs_sha256": source_digest.hexdigest(), "source_date_epoch": epoch,
        "python": sys.version, "sqlite": sqlite3.sqlite_version,
        "build_tools": {name: metadata.version(name) for name in ("setuptools", "wheel", "build", "spdx-tools")},
        "reproducible_builds": 2, "offline_installs": [artifact.name for artifact in artifacts],
        "entrypoints_per_artifact": sorted(ENTRY_POINTS),
        "utf8_cli_init_per_artifact": ["compact", "pretty"],
        "relocated_wheel_helper_module_smoke": True,
        "subjects": {path.name: sha256(path.read_bytes()) for path in artifacts + [sbom_path]},
    }
    (output / "build-evidence.json").write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    print(json.dumps(evidence, sort_keys=True, indent=2))
    print("reproducible artifacts, offline installs, and SPDX validation: PASSED")
    return artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, default=ROOT / "work" / "build-wheels")
    arguments = parser.parse_args()
    build_release(arguments.output.resolve(), arguments.wheelhouse.resolve())


if __name__ == "__main__":
    main()
