import base64
import copy
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from scripts.fetch_patched_sqlcipher_sources import (
    DEFAULT_MANIFEST,
    REVIEWED_BUILD_DEPENDENCIES,
    REVIEWED_BUILDER,
    REVIEWED_SOURCES,
    REVIEWED_TARGETS,
    artifact_target,
    download,
    gpg_fingerprints,
    inspect_project_inputs,
    inspect_tar_source,
    inspect_zip_members,
    load_json_strict,
    publish_bytes_exclusive,
    safe_archive_path,
    sha256,
    valid_signature_fingerprints,
    validate_download_response,
    validate_manifest,
)
from scripts.inspect_patched_sqlcipher_wheel import (
    ALLOWED_NEEDED,
    DIST_INFO,
    expected_wheel_members,
    native_member_name,
    one_wheel,
    validate_elf_outputs,
    validate_native_dependencies,
    validate_record,
    validate_wheel_member,
    validate_wheel_member_inventory,
    validate_wheel_metadata,
    validate_workflow_context,
    write_evidence,
)
from scripts.test_patched_sqlcipher_install import (
    require_regular_wheel,
    sanitized_environment,
)
from scripts.test_patched_sqlcipher_runtime import require_active_cipher


ROOT = Path(__file__).resolve().parents[1]


def changed_leaf(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        return value + "-drift"
    if isinstance(value, list):
        return [*value, "unexpected"]
    raise AssertionError("unsupported manifest leaf: %r" % (value,))


def leaf_paths(value, prefix=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from leaf_paths(child, (*prefix, key))
    else:
        yield prefix


def mutate_path(value, path):
    target = value
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = changed_leaf(target[path[-1]])


class FakeResponse:
    def __init__(self, url, *, status=200, headers=None):
        self._url = url
        self.status = status
        self.headers = {} if headers is None else headers

    def geturl(self):
        return self._url


class PatchedSqlcipherManifestTest(unittest.TestCase):
    def setUp(self):
        self.manifest = load_json_strict(DEFAULT_MANIFEST)

    def test_reviewed_manifest_project_inputs_and_source_sbom_are_consistent(self):
        manifest = validate_manifest(self.manifest)
        self.assertEqual(manifest["sources"], REVIEWED_SOURCES)
        self.assertEqual(manifest["buildDependencies"], REVIEWED_BUILD_DEPENDENCIES)
        for key, expected in REVIEWED_BUILDER.items():
            self.assertEqual(manifest["builder"][key], expected)
        self.assertEqual(set(manifest["expectedArtifacts"]), set(REVIEWED_TARGETS))
        for key, target in REVIEWED_TARGETS.items():
            self.assertEqual(
                {name: manifest["expectedArtifacts"][key][name] for name in target},
                target,
            )
        inspect_project_inputs(ROOT, manifest)

        sbom = load_json_strict(ROOT / "sbom" / "patched-sqlcipher-sources.spdx.json")
        packages = {item["SPDXID"]: item for item in sbom["packages"]}
        self.assertTrue(all(item.get("copyrightText") for item in packages.values()))
        self.assertEqual(
            packages["SPDXRef-Source-sqlcipher3"]["licenseConcluded"], "NOASSERTION"
        )
        self.assertIn("legal reconciliation is pending", packages["SPDXRef-Source-sqlcipher3"]["licenseComments"])
        self.assertEqual(
            packages["SPDXRef-Source-OpenSSL"]["checksums"][0]["checksumValue"],
            manifest["sources"]["OpenSSL"]["sha256"],
        )
        self.assertEqual(
            packages["SPDXRef-Builder-manylinux"]["checksums"][0]["checksumValue"],
            manifest["builder"]["image"].rsplit(":", 1)[1],
        )
        files = {item["fileName"]: item for item in sbom["files"]}
        for relative in (
            "packaging/sqlcipher/perl/IPC/Cmd.pm",
            "packaging/sqlcipher/perl/Time/Piece.pm",
        ):
            item = files["./%s" % relative]
            self.assertEqual(item["licenseConcluded"], "Apache-2.0")
            checksums = {
                checksum["algorithm"]: checksum["checksumValue"]
                for checksum in item["checksums"]
            }
            self.assertEqual(
                checksums["SHA256"],
                manifest["builder"]["reviewedProjectFiles"][relative],
            )
            self.assertEqual(
                checksums["SHA1"],
                hashlib.sha1((ROOT / relative).read_bytes(), usedforsecurity=False).hexdigest(),
            )

    def test_every_locked_security_and_provenance_leaf_fails_closed_on_drift(self):
        for section in (
            "artifact",
            "buildDependencies",
            "signing",
            "sources",
            "supportedSlice",
            "vulnerabilityEvidence",
        ):
            for relative_path in leaf_paths(self.manifest[section]):
                with self.subTest(section=section, path=relative_path):
                    changed = copy.deepcopy(self.manifest)
                    mutate_path(changed[section], relative_path)
                    with self.assertRaises(RuntimeError):
                        validate_manifest(changed)
        for key in REVIEWED_BUILDER:
            with self.subTest(builder=key):
                changed = copy.deepcopy(self.manifest)
                changed["builder"][key] = changed_leaf(changed["builder"][key])
                with self.assertRaises(RuntimeError):
                    validate_manifest(changed)

    def test_project_file_hashes_and_artifact_targets_fail_closed(self):
        changed = copy.deepcopy(self.manifest)
        path = "scripts/build_patched_sqlcipher_wheel.sh"
        changed["builder"]["reviewedProjectFiles"][path] = "f" * 64
        validate_manifest(changed)
        with self.assertRaisesRegex(RuntimeError, "reviewed project input"):
            inspect_project_inputs(ROOT, changed)

        cases = []
        missing = copy.deepcopy(self.manifest)
        missing["expectedArtifacts"].pop("linuxCp311")
        cases.append(missing)
        extra = copy.deepcopy(self.manifest)
        extra["expectedArtifacts"]["other"] = copy.deepcopy(extra["expectedArtifacts"]["linuxCp311"])
        cases.append(extra)
        bad_hash = copy.deepcopy(self.manifest)
        bad_hash["expectedArtifacts"]["linuxCp312"]["sha256"] = "not-a-hash"
        cases.append(bad_hash)
        zero_hash = copy.deepcopy(self.manifest)
        zero_hash["expectedArtifacts"]["linuxCp312"]["sha256"] = "0" * 64
        cases.append(zero_hash)
        bad_abi = copy.deepcopy(self.manifest)
        bad_abi["expectedArtifacts"]["linuxCp313"]["pythonAbi"] = "cp314-cp314"
        cases.append(bad_abi)
        for changed in cases:
            with self.subTest(keys=sorted(changed["expectedArtifacts"])):
                with self.assertRaises(RuntimeError):
                    validate_manifest(changed)
        with self.assertRaisesRegex(RuntimeError, "unknown patched-wheel target"):
            artifact_target(validate_manifest(self.manifest), "unknown")

    def test_rejects_duplicate_manifest_keys(self):
        text = DEFAULT_MANIFEST.read_text(encoding="utf-8")
        text = text.replace('"schemaVersion": 1', '"schemaVersion": 1, "schemaVersion": 1')
        with tempfile.TemporaryDirectory(prefix="continuum-manifest-") as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate key"):
                load_json_strict(path)

    def test_gpg_status_requires_one_validsig_and_rejects_adverse_status(self):
        signing = "A" * 40
        primary = "B" * 40
        validsig = (
            "[GNUPG:] VALIDSIG %s 2026-09-05 1788645539 0 4 0 1 10 00 %s\n"
            % (signing, primary)
        ).encode("ascii")
        status = b"[GNUPG:] GOODSIG DEADBEEF name-\xcc\n" + validsig
        self.assertEqual(valid_signature_fingerprints(status), (signing, primary))
        for rejected in (
            b"[GNUPG:] GOODSIG only\n",
            validsig + validsig,
            b"[GNUPG:] VALIDSIG \xcc\n",
            b"[GNUPG:] VALIDSIG " + (b"A" * 40) + b" too-short\n",
            b"[GNUPG:] REVKEYSIG dead revoked\n" + validsig,
            b"[GNUPG:] EXPKEYSIG dead expired\n" + validsig,
            b"[GNUPG:] BADSIG dead bad\n" + validsig,
            b"[GNUPG:] KEYEXPIRED 1788645539\n" + validsig,
            b"[GNUPG:] SIGEXPIRED deprecated\n" + validsig,
            b"[GNUPG:] NODATA 1\n" + validsig,
            b"[GNUPG:] FAILURE verify 1\n" + validsig,
        ):
            with self.subTest(status=rejected):
                with self.assertRaises(RuntimeError):
                    valid_signature_fingerprints(rejected)

    def test_gpg_fingerprint_lookup_uses_explicit_temporary_home(self):
        fingerprint = "A" * 40
        with tempfile.TemporaryDirectory(prefix="continuum-gpg-home-") as temporary:
            directory = Path(temporary)
            key = directory / "reviewed-key.gpg"
            key.write_bytes(b"key")
            result = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="fpr:::::::::%s:\n" % fingerprint
            )
            with mock.patch(
                "scripts.fetch_patched_sqlcipher_sources.subprocess.run",
                return_value=result,
            ) as run:
                self.assertEqual(gpg_fingerprints("/usr/bin/gpg", key), {fingerprint})
            command = run.call_args.args[0]
            self.assertIn("--homedir", command)
            home = Path(command[command.index("--homedir") + 1])
            self.assertEqual(home.parent, directory)
            self.assertFalse(home.exists())

    def test_download_redirect_policy_and_linked_cache_fail_closed(self):
        configured = REVIEWED_SOURCES["OpenSSL"]["url"]
        validate_download_response(
            configured,
            FakeResponse("https://release-assets.githubusercontent.com/object?token=ephemeral"),
        )
        for response in (
            FakeResponse("http://release-assets.githubusercontent.com/object"),
            FakeResponse("https://example.invalid/object"),
            FakeResponse("https://release-assets.githubusercontent.com/object", status=206),
            FakeResponse(
                "https://release-assets.githubusercontent.com/object",
                headers={"Content-Encoding": "gzip"},
            ),
        ):
            with self.subTest(url=response.geturl()):
                with self.assertRaises(RuntimeError):
                    validate_download_response(configured, response)

        with tempfile.TemporaryDirectory(prefix="continuum-linked-download-") as temporary:
            directory = Path(temporary)
            payload = directory / "payload"
            payload.write_bytes(b"reviewed")
            target = directory / "input.whl"
            target.symlink_to(payload)
            record = {
                "filename": target.name,
                "sha256": hashlib.sha256(b"reviewed").hexdigest(),
                "url": REVIEWED_BUILD_DEPENDENCIES["wheel"]["url"],
            }
            with self.assertRaisesRegex(RuntimeError, "linked"):
                download(record, directory)

    def test_evidence_publication_is_exclusive_and_rejects_links(self):
        with tempfile.TemporaryDirectory(prefix="continuum-evidence-output-") as temporary:
            directory = Path(temporary)
            victim = directory / "victim"
            victim.write_bytes(b"unchanged")
            linked = directory / "evidence.json"
            linked.symlink_to(victim)
            with self.assertRaisesRegex(RuntimeError, "exists or is linked"):
                publish_bytes_exclusive(linked, b"replacement")
            self.assertEqual(victim.read_bytes(), b"unchanged")
            linked.unlink()
            publish_bytes_exclusive(linked, b"evidence")
            self.assertEqual(linked.read_bytes(), b"evidence")
            self.assertEqual(linked.stat().st_nlink, 1)
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                publish_bytes_exclusive(linked, b"replacement")

    def test_source_archives_reject_unsafe_paths_duplicates_links_and_special_types(self):
        safe_archive_path("sqlcipher-4.18.0/src/sqliteInt.h", "sqlcipher-4.18.0")
        for path in (
            "/absolute",
            "sqlcipher-4.18.0/../escape",
            "sqlcipher-4.18.0//double",
            "sqlcipher-4.18.0\\windows",
            "other/file",
        ):
            with self.subTest(path=path):
                with self.assertRaisesRegex(RuntimeError, "unsafe or unexpected"):
                    safe_archive_path(path, "sqlcipher-4.18.0")

        with tempfile.TemporaryDirectory(prefix="continuum-malicious-archive-") as temporary:
            directory = Path(temporary)
            archive_path = directory / "source.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                payload = b"ok"
                regular = tarfile.TarInfo("source/required")
                regular.size = len(payload)
                archive.addfile(regular, io.BytesIO(payload))
                link = tarfile.TarInfo("source/link")
                link.type = tarfile.SYMTYPE
                link.linkname = "required"
                archive.addfile(link)
            with self.assertRaisesRegex(RuntimeError, "link or special"):
                inspect_tar_source(archive_path, "source", ("required",))

            zip_path = directory / "source.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                linked = zipfile.ZipInfo("source/link")
                linked.create_system = 3
                linked.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(linked, "target")
            with zipfile.ZipFile(zip_path) as archive:
                with self.assertRaisesRegex(RuntimeError, "link or special"):
                    inspect_zip_members(archive, "source")


class PatchedSqlcipherArtifactTest(unittest.TestCase):
    def setUp(self):
        self.manifest = validate_manifest(load_json_strict(DEFAULT_MANIFEST))

    @unittest.skipIf(os.name == "nt", "the reviewed native wheel slice is Linux-only")
    def test_project_openssl_can_run_shim_rejects_every_relative_path_entry(self):
        perl = shutil.which("perl")
        if perl is None:
            self.skipTest("Perl is not installed on this host")
        shim_root = ROOT / "packaging" / "sqlcipher" / "perl"
        with tempfile.TemporaryDirectory(prefix="continuum-can-run-") as temporary:
            directory = Path(temporary)
            executable = directory / "reviewed-tool"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            executable.chmod(0o755)
            environment = dict(os.environ)
            environment["PATH"] = str(directory)
            found = subprocess.run(
                [perl, "-I%s" % shim_root, "-MIPC::Cmd", "-e", 'print IPC::Cmd::can_run("reviewed-tool") // q{}'],
                check=True,
                cwd=str(ROOT),
                env=environment,
                stdout=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(found.stdout, str(executable))
            for relative_path in ("", ".", "./bin", "relative/bin"):
                environment["PATH"] = relative_path
                result = subprocess.run(
                    [perl, "-I%s" % shim_root, "-MIPC::Cmd", "-e", 'exit defined IPC::Cmd::can_run("reviewed-tool") ? 1 : 0'],
                    cwd=str(directory),
                    env=environment,
                )
                self.assertEqual(result.returncode, 0, relative_path)

    @unittest.skipIf(os.name == "nt", "the reviewed native wheel slice is Linux-only")
    def test_project_openssl_time_shim_is_strict(self):
        perl = shutil.which("perl")
        if perl is None:
            self.skipTest("Perl is not installed on this host")
        shim_root = ROOT / "packaging" / "sqlcipher" / "perl"
        valid = subprocess.run(
            [perl, "-I%s" % shim_root, "-MTime::Piece", "-e", 'my $date = Time::Piece->strptime("25 Aug 2026", "%d %b %Y"); print $date->strftime("%Y-%m-%d")'],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(valid.stdout, "2026-08-25")
        for value, date_format in (("31 Feb 2026", "%d %b %Y"), ("25 Aug 2026", "%F")):
            result = subprocess.run(
                [perl, "-I%s" % shim_root, "-MTime::Piece", "-e", "Time::Piece->strptime($ARGV[0], $ARGV[1])", value, date_format],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_ambiguous_or_linked_wheel_discovery_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="continuum-wheel-count-") as temporary:
            directory = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "found 0"):
                one_wheel(directory)
            first = directory / "one.whl"
            first.write_bytes(b"one")
            self.assertEqual(one_wheel(directory), first)
            (directory / "two.whl").write_bytes(b"two")
            with self.assertRaisesRegex(RuntimeError, "found 2"):
                one_wheel(directory)

    def test_every_target_has_exact_inventory_native_suffix_and_wheel_tag(self):
        for key in REVIEWED_TARGETS:
            target = artifact_target(self.manifest, key)
            members = expected_wheel_members(target)
            self.assertEqual(len(members), 15)
            self.assertIn(native_member_name(target), members)
            validate_wheel_member_inventory(sorted(members), target)
            for changed in (members | {"evil.pth"}, members - {"sqlcipher3/dbapi2.py"}):
                with self.assertRaises(RuntimeError):
                    validate_wheel_member_inventory(sorted(changed), target)
            wheel_payload = (
                "Wheel-Version: 1.0\n"
                "Generator: setuptools (80.9.0)\n"
                "Root-Is-Purelib: false\n"
                "Tag: %s-manylinux_2_28_x86_64\n\n" % target["pythonAbi"]
            ).encode("ascii")
            self.assertEqual(
                validate_wheel_metadata(wheel_payload, target),
                "%s-manylinux_2_28_x86_64" % target["pythonAbi"],
            )
            with self.assertRaisesRegex(RuntimeError, "platform tag"):
                validate_wheel_metadata(wheel_payload.replace(b"x86_64", b"aarch64"), target)

    def test_wheel_member_types_and_record_hashes_fail_closed(self):
        linked = zipfile.ZipInfo("sqlcipher3/linked.py")
        linked.create_system = 3
        linked.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaisesRegex(RuntimeError, "link or special"):
            validate_wheel_member(linked)

        record_name = "%s/RECORD" % DIST_INFO
        payloads = {"sqlcipher3/__init__.py": b"payload", record_name: b""}
        digest = base64.urlsafe_b64encode(hashlib.sha256(b"payload").digest()).rstrip(b"=").decode()
        record = (
            "sqlcipher3/__init__.py,sha256=%s,7\r\n%s,,\r\n" % (digest, record_name)
        ).encode("ascii")
        payloads[record_name] = record
        validate_record(record, payloads)
        with self.assertRaisesRegex(RuntimeError, "hash or size"):
            validate_record(record.replace(b",7", b",8"), payloads)
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            validate_record(record + record.splitlines(keepends=True)[0], payloads)

    def test_native_linkage_architecture_glibc_and_hardening_fail_closed(self):
        header = """
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
"""
        dynamic = "\n".join(
            [" (NEEDED) Shared library: [%s]" % item for item in sorted(ALLOWED_NEEDED)]
        ) + "\n (FLAGS) BIND_NOW\n"
        program = "GNU_RELRO 0x0\nGNU_STACK 0x0 0x0 0x0 0x0 0x0 RW 0x10\n"
        versions = "Name: GLIBC_2.2.5\nName: GLIBC_2.28\n"
        symbols = "000000 T PyInit__sqlite3\n"
        undefined = "         U __stack_chk_fail@GLIBC_2.4\n"
        evidence = validate_elf_outputs(header, dynamic, program, versions, symbols, undefined)
        self.assertEqual(set(evidence["nativeNeeded"]), ALLOWED_NEEDED)
        cases = (
            (header.replace("ELF64", "ELF32"), dynamic, program, versions, symbols, undefined),
            (header, dynamic + " (RUNPATH) Library runpath: [/tmp]\n", program, versions, symbols, undefined),
            (header, dynamic, program.replace(" RW ", " RWE "), versions, symbols, undefined),
            (header, dynamic, program, versions + "Name: GLIBC_2.29\n", symbols, undefined),
            (header, dynamic, program, versions, symbols, ""),
        )
        for values in cases:
            with self.assertRaises(RuntimeError):
                validate_elf_outputs(*values)
        validate_native_dependencies(ALLOWED_NEEDED)
        for changed in (ALLOWED_NEEDED - {"libm.so.6"}, ALLOWED_NEEDED | {"libcrypto.so.3"}):
            with self.assertRaises(RuntimeError):
                validate_native_dependencies(changed)

    def test_runtime_and_offline_install_helpers_fail_closed(self):
        require_active_cipher("1")
        for status in (1, True, "0", 0, None):
            with self.assertRaisesRegex(AssertionError, "not active"):
                require_active_cipher(status)
        environment = sanitized_environment()
        self.assertEqual(environment["PIP_NO_INDEX"], "1")
        self.assertEqual(environment["PYTHONNOUSERSITE"], "1")
        self.assertNotIn("PYTHONPATH", environment)
        with tempfile.TemporaryDirectory(prefix="continuum-install-wheel-") as temporary:
            directory = Path(temporary)
            payload = b"locked-wheel"
            target = copy.deepcopy(artifact_target(self.manifest, "linuxCp311"))
            target["filename"] = "test.whl"
            target["sha256"] = hashlib.sha256(payload).hexdigest()
            wheel = directory / target["filename"]
            wheel.write_bytes(payload)
            self.assertEqual(require_regular_wheel(directory, target), wheel)
            target["sha256"] = "0" * 64
            with self.assertRaisesRegex(RuntimeError, "SHA-256"):
                require_regular_wheel(directory, target)

    def test_reviewed_drivers_start_under_isolated_python(self):
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        for relative in (
            "scripts/inspect_patched_sqlcipher_wheel.py",
            "scripts/test_patched_sqlcipher_install.py",
        ):
            result = subprocess.run(
                [sys.executable, "-I", str(ROOT / relative), "--help"],
                cwd=tempfile.gettempdir(),
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_workflow_context_and_generated_evidence_bind_exact_inputs(self):
        context = {
            "event": "pull_request",
            "ref": "refs/pull/14/merge",
            "repositoryCommit": "a" * 40,
            "runAttempt": "1",
            "runId": "12345",
        }
        validate_workflow_context(context)
        for key, value in (
            ("repositoryCommit", "short"),
            ("runId", "0"),
            ("runAttempt", "-1"),
            ("event", "schedule"),
            ("ref", "main\nforged"),
        ):
            changed = dict(context)
            changed[key] = value
            with self.assertRaises(RuntimeError):
                validate_workflow_context(changed)

        source_evidence = {"status": "VERIFIED", "signatures": {"SQLCipher": {}, "OpenSSL": {}}}
        inspection = {
            "_auditwheelText": "manylinux_2_28_x86_64",
            "_sqliteLicenseText": "Synthetic SQLite public-domain statement.",
            "artifactKey": "linuxCp311",
            "filename": artifact_target(self.manifest, "linuxCp311")["filename"],
            "licenseSha256": {},
            "memberCount": 15,
            "metadataSha256": "1" * 64,
            "nativeMember": native_member_name(artifact_target(self.manifest, "linuxCp311")),
            "nativeNeeded": sorted(ALLOWED_NEEDED),
            "nativeSha256": "2" * 64,
            "pythonAbi": "cp311-cp311",
            "sha256": "3" * 64,
            "wheelTag": "cp311-cp311-manylinux_2_28_x86_64",
        }
        with tempfile.TemporaryDirectory(prefix="continuum-wheel-evidence-") as temporary:
            directory = Path(temporary)
            write_evidence(
                directory,
                inspection,
                self.manifest,
                context=context,
                manifest_sha256="4" * 64,
                source_evidence=source_evidence,
                source_evidence_sha256="5" * 64,
            )
            provenance = load_json_strict(directory / "artifact-provenance.json")
            sbom = load_json_strict(directory / "patched-wheel.spdx.json")
            self.assertEqual(provenance["repository"]["commit"], "a" * 40)
            self.assertEqual(provenance["sourceVerification"]["evidenceSha256"], "5" * 64)
            self.assertEqual(provenance["status"], "EPHEMERAL_CI_TEST_ARTIFACT_NOT_RELEASED")
            packages = {item["SPDXID"]: item for item in sbom["packages"]}
            self.assertTrue(all(item.get("copyrightText") for item in packages.values()))
            self.assertEqual(
                packages["SPDXRef-Package-continuum-sqlcipher3-wheel"]["licenseConcluded"],
                "NOASSERTION",
            )
            self.assertIn("SPDXRef-Runtime-CPython", packages)
            self.assertIn("SPDXRef-Runtime-glibc", packages)
            self.assertIn("SPDXRef-Build-manylinux", packages)
            relationships = {item["relationshipType"] for item in sbom["relationships"]}
            self.assertIn("GENERATED_FROM", relationships)
            self.assertIn("BUILD_DEPENDENCY_OF", relationships)

    def test_workflow_and_build_recipe_enforce_isolation_and_success_only_retention(self):
        workflow = (ROOT / ".github/workflows/patched-sqlcipher-wheel.yml").read_text(encoding="utf-8")
        build_script = (ROOT / "scripts/build_patched_sqlcipher_wheel.sh").read_text(encoding="utf-8")
        setup_text = (ROOT / "packaging/sqlcipher/setup_continuum.py").read_text(encoding="utf-8")
        for key in REVIEWED_TARGETS:
            self.assertIn("artifact_key: %s" % key, workflow)
            self.assertIn("%s)" % key, build_script)
        self.assertEqual(workflow.count("docker run"), 6)
        self.assertEqual(workflow.count("--pull=never"), 6)
        self.assertEqual(workflow.count("--network=none"), 5)
        self.assertGreaterEqual(workflow.count("--read-only"), 6)
        self.assertEqual(workflow.count('--user "$(id -u):$(id -g)"'), 6)
        self.assertEqual(workflow.count("--env HOME=/tmp"), 6)
        self.assertIn("persist-credentials: false", workflow)
        self.assertNotIn("if: always()", workflow)
        self.assertNotIn("actions/cache", workflow)
        self.assertNotIn("allow-unlocked-bootstrap", workflow)
        self.assertNotIn("Report bootstrap digest", workflow)
        inspector = (ROOT / "scripts/inspect_patched_sqlcipher_wheel.py").read_text(
            encoding="utf-8"
        )
        installer = (ROOT / "scripts/test_patched_sqlcipher_install.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("allow-unlocked-bootstrap", inspector)
        self.assertNotIn("allow-unlocked-bootstrap", installer)
        self.assertGreater(
            workflow.index("Retain only fully validated"),
            workflow.index("Test offline installation"),
        )
        self.assertIn("-w /tmp", workflow)
        self.assertIn("test_patched_sqlcipher_install.py", workflow)
        self.assertIn("no-autoload-config", build_script)
        self.assertIn("-fstack-protector-strong", build_script)
        self.assertIn('export CC="${DEVTOOLSET_ROOT}/usr/bin/gcc"', build_script)
        self.assertIn('readonly DEVTOOLSET_ROOT="/opt/rh/gcc-toolset-14/root"', build_script)
        self.assertIn("command -v gcc", workflow)
        self.assertIn("-Wl,-z,now", setup_text)
        self.assertIn("extra_objects=[libcrypto]", setup_text)
        self.assertNotIn("conan", setup_text.lower())


if __name__ == "__main__":
    unittest.main()
