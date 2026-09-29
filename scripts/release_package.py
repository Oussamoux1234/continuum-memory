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
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from scripts.application_inputs import (  # noqa: E402
    DEFAULT_MANIFEST, NATIVE_REQUIREMENT, PYTHON_REQUIREMENT,
    application_manifest, application_verification_wheels,
)

NAME = "continuum-memory"
VERSION = "0.1.0.dev0"
RUNTIME_PACKAGE_ID = "SPDXRef-Runtime-continuum-sqlcipher3"
SOURCE_SBOM = ROOT / "sbom" / "patched-sqlcipher-sources.spdx.json"
BUILD_REQUIREMENTS = ROOT / "packaging" / "build-requirements.txt"
ENTRY_POINTS = {
    "continuum": "--version",
    "memoryd": "--help",
    "continuum-mcp": "--help",
    "continuum-polkit-helper": "--help",
}
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
INSTALLED_RUNTIME_CHECK = """
import json
import sys
from importlib import metadata
from pathlib import Path
import continuum_memory
from continuum_memory import storage
from sqlcipher3 import _sqlite3, dbapi2

prefix = Path(sys.prefix).resolve()
modules = {}
for module in (continuum_memory, storage, dbapi2, _sqlite3):
    path = Path(module.__file__).resolve()
    path.relative_to(prefix)
    modules[module.__name__] = str(path)
if metadata.version('continuum-memory') != '0.1.0.dev0':
    raise RuntimeError('unexpected installed application version')
storage._require_sqlcipher_runtime()
connection = dbapi2.connect(':memory:')
try:
    cipher = connection.execute('PRAGMA cipher_version').fetchone()[0]
finally:
    connection.close()
print(json.dumps({'applicationVersion': metadata.version('continuum-memory'),
                  'nativeDistribution': 'continuum-sqlcipher3',
                  'nativeVersion': metadata.version('continuum-sqlcipher3'),
                  'cipherVersion': cipher, 'sqliteVersion': dbapi2.sqlite_version,
                  'modulePaths': modules}, sort_keys=True))
"""


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
    for name in list(environment):
        if name.startswith("PIP_") or name.startswith("PYTHON"):
            environment.pop(name)
    environment.update({
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_NO_INDEX": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_CACHE_DIR": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": str(epoch),
        "TZ": "UTC",
    })
    return environment


def require_build_tools(wheelhouse):
    """Check installed versions and available locked wheels, without installing.

    Installed byte provenance still depends on the reviewed environment setup.
    """
    if not wheelhouse.is_dir():
        raise ValueError("offline build wheelhouse is missing; see docs/LINUX_RELEASE.md")
    pins = {}
    for raw_line in BUILD_REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "--hash=")):
            continue
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\]+)(?:\s+\\)?", line)
        if match is None:
            raise ValueError("build requirements must contain exact version pins")
        name, version = match.groups()
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        if normalized in pins:
            raise ValueError("build requirements contain a duplicate distribution")
        pins[normalized] = version
    if not pins:
        raise ValueError("build requirements must not be empty")
    for name, expected in pins.items():
        try:
            installed = metadata.version(name)
        except metadata.PackageNotFoundError:
            installed = None
        if installed != expected:
            raise RuntimeError("install the pinned build requirements before verification: " + name)
    run([sys.executable, "-I", "-m", "pip", "--isolated", "install", "--dry-run",
         "--ignore-installed", "--no-index", "--no-cache-dir", "--find-links", wheelhouse,
         "--only-binary=:all:", "--require-hashes", "-r", BUILD_REQUIREMENTS],
        cwd=ROOT, env=offline_environment(315532800))


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
    if fields.get_all("Requires-Dist") != [NATIVE_REQUIREMENT]:
        raise ValueError("application must require exactly the reviewed encrypted runtime")
    from packaging.specifiers import SpecifierSet
    python_requirements = fields.get_all("Requires-Python", [])
    if (len(python_requirements) != 1
            or SpecifierSet(python_requirements[0]) != SpecifierSet(PYTHON_REQUIREMENT)):
        raise ValueError("application Python support must match the reviewed native ABI range")
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
            "comment": "Experimental unsigned application payload. The required native runtime is a separate package, not bundled in this archive. Host Python and build tools are not inventoried by this payload SBOM.",
        })
        relationships.append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": package_id})
        relationships.append({"spdxElementId": package_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": RUNTIME_PACKAGE_ID})
    manifest = application_manifest()
    runtime = {
        "SPDXID": RUNTIME_PACKAGE_ID,
        "name": manifest["artifact"]["distribution"], "versionInfo": manifest["artifact"]["version"],
        "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "comment": "Required external native runtime; no native wheel payload is bundled or file-inventoried here. Binding and aggregate license reconciliation remains open.",
        "sourceInfo": (
            "ABI wheel identities and hashes: packaging/sqlcipher/manifest.json (SHA-256 "
            + sha256(DEFAULT_MANIFEST.read_bytes())
            + "). Native source/license inventory: sbom/patched-sqlcipher-sources.spdx.json (SHA-256 "
            + sha256(SOURCE_SBOM.read_bytes()) + ")."
        ),
    }
    packages.append(runtime)
    identity = sha256((str(epoch) + ":" + ":".join(subjects) + ":" + json.dumps(runtime, sort_keys=True)).encode())
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


def install_smoke(artifact, directory, epoch):
    environment = offline_environment(epoch)
    locked_wheels = application_verification_wheels()
    manifest = application_manifest()
    target = manifest["expectedArtifacts"]["linuxCp%d%d" % sys.version_info[:2]]
    locks = {record["filename"]: record["sha256"] for record in
             [target] + list(manifest["buildDependencies"].values())}
    run([sys.executable, "-m", "venv", directory], cwd=ROOT, env=environment)
    bin_dir = directory / ("Scripts" if os.name == "nt" else "bin")
    python = bin_dir / ("python.exe" if os.name == "nt" else "python")
    requirements = directory / "reviewed-native-inputs.txt"
    requirements.write_text("".join(
        "%s --hash=sha256:%s\n" % (path.as_uri(), locks[path.name]) for path in locked_wheels
    ), encoding="utf-8")
    run([python, "-I", "-m", "pip", "--isolated", "install", "--no-index", "--no-deps",
         "--no-cache-dir", "--no-compile", "--no-build-isolation", "--only-binary=:all:",
         "--require-hashes", "--force-reinstall", "-r", requirements], cwd=directory, env=environment)
    run([python, "-I", "-m", "pip", "--isolated", "install", "--no-index", "--no-deps",
         "--no-cache-dir", "--no-compile", "--no-build-isolation", artifact], cwd=directory, env=environment)
    for entry, flag in ENTRY_POINTS.items():
        executable = bin_dir / (entry + (".exe" if os.name == "nt" else ""))
        run([executable, flag], cwd=directory, env=environment)
    # Both archives must admit the installed native runtime from the fresh venv.
    checked = subprocess.check_output([str(python), "-I", "-c", INSTALLED_RUNTIME_CHECK],
                                      cwd=str(directory), env=environment, text=True)
    runtime_evidence = json.loads(checked)
    print("installed application runtime: " + json.dumps(runtime_evidence, sort_keys=True), flush=True)


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
    return runtime_evidence


def build_release(output, wheelhouse):
    if sys.version_info < (3, 11):
        raise RuntimeError("release verification tools require Python 3.11+; runtime compatibility is separate")
    require_build_tools(wheelhouse)
    native_wheel = application_verification_wheels()[0]
    manifest = application_manifest()
    artifact_key = "linuxCp%d%d" % sys.version_info[:2]
    native_target = manifest["expectedArtifacts"][artifact_key]
    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory must be empty; refusing to overwrite artifacts")
    output.mkdir(parents=True, exist_ok=True)
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
        installed_runtimes = {}
        for artifact in builds[0]:
            destination = output / artifact.name
            shutil.copyfile(artifact, destination)
            artifacts.append(destination)
            installed_runtimes[artifact.name] = install_smoke(destination, temporary / ("install-" + artifact.suffix), epoch)
    sbom_path = output / "sbom.spdx.json"
    sbom_path.write_text(json.dumps(make_sbom(artifacts, epoch), sort_keys=True, indent=2) + "\n")
    validate_sbom(sbom_path, artifacts, epoch)
    evidence = {
        "schema_version": 1, "status": "unsigned-local-build-evidence-not-an-attestation",
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
        "source_inputs_sha256": source_digest.hexdigest(), "source_date_epoch": epoch,
        "python": sys.version,
        "native_runtime": {
            "distribution": manifest["artifact"]["distribution"], "version": manifest["artifact"]["version"],
            "artifact_key": artifact_key, "wheel_filename": native_wheel.name,
            "wheel_sha256": native_target["sha256"],
            "manifest_sha256": sha256(DEFAULT_MANIFEST.read_bytes()),
            "source_sbom_sha256": sha256(SOURCE_SBOM.read_bytes()),
            "bundled_in_application": False, "license_concluded": "NOASSERTION",
            "installed_runtime_checks": installed_runtimes,
        },
        "build_tools": {name: metadata.version(name) for name in ("setuptools", "wheel", "build", "spdx-tools")},
        "reproducible_builds": 2, "offline_installs": [artifact.name for artifact in artifacts],
        "entrypoints_per_artifact": sorted(ENTRY_POINTS),
        "utf8_cli_init_per_artifact": ["compact", "pretty"],
        "relocated_wheel_helper_module_smoke": True,
        "privileged_installer_compatible": False,
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
