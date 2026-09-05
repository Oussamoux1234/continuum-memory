import copy
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.fetch_patched_sqlcipher_sources import (
    DEFAULT_MANIFEST,
    load_json_strict,
    safe_archive_path,
    sha256,
    valid_signature_fingerprints,
    validate_manifest,
)
from scripts.inspect_patched_sqlcipher_wheel import one_wheel, write_evidence


ROOT = Path(__file__).resolve().parents[1]


class PatchedSqlcipherManifestTest(unittest.TestCase):
    def setUp(self):
        self.manifest = load_json_strict(DEFAULT_MANIFEST)

    def test_reviewed_manifest_and_source_sbom_are_consistent(self):
        manifest = validate_manifest(self.manifest)
        self.assertEqual(manifest["sources"]["SQLCipher"]["version"], "4.18.0")
        self.assertEqual(manifest["sources"]["SQLCipher"]["embeddedSQLiteVersion"], "3.53.4")
        self.assertEqual(manifest["sources"]["OpenSSL"]["version"], "3.5.8")
        self.assertEqual(manifest["sources"]["OpenSSL"]["endOfLife"], "2030-04-08")
        self.assertEqual(manifest["sources"]["sqlcipher3"]["licenseConcluded"], "NOASSERTION")
        for relative, expected_hash in manifest["builder"]["opensslPerlShims"].items():
            self.assertEqual(sha256(ROOT / relative), expected_hash)
        self.assertFalse(manifest["supportedSlice"]["windowsSupported"])

        sbom = load_json_strict(ROOT / "sbom" / "patched-sqlcipher-sources.spdx.json")
        packages = {item["SPDXID"]: item for item in sbom["packages"]}
        self.assertEqual(
            packages["SPDXRef-Source-sqlcipher3"]["licenseConcluded"], "NOASSERTION"
        )
        self.assertEqual(
            packages["SPDXRef-Source-OpenSSL"]["checksums"][0]["checksumValue"],
            manifest["sources"]["OpenSSL"]["sha256"],
        )
        self.assertEqual(
            packages["SPDXRef-Builder-manylinux"]["checksums"][0]["checksumValue"],
            manifest["builder"]["image"].rsplit(":", 1)[1],
        )

    def test_rejects_mutable_or_drifted_inputs_and_claims(self):
        cases = (
            (
                lambda value: value["builder"].update(
                    {"image": "quay.io/pypa/manylinux_2_28_x86_64:latest"}
                ),
                "immutable",
            ),
            (lambda value: value.update({"evidenceDate": "2026-01-01"}), "stale"),
            (
                lambda value: value["sources"]["SQLCipher"].update({"sha256": "invalid"}),
                "SHA-256",
            ),
            (
                lambda value: value["sources"]["SQLCipher"].update(
                    {"embeddedSQLiteVersion": "3.51.1"}
                ),
                "SQLite baseline",
            ),
            (
                lambda value: value["sources"]["OpenSSL"].update(
                    {"releaseSeries": "3.6"}
                ),
                "LTS",
            ),
            (
                lambda value: value["sources"]["SQLCipher"]["signingKey"].update(
                    {"primaryFingerprint": "short"}
                ),
                "fingerprint",
            ),
            (
                lambda value: value["sources"]["OpenSSL"].update(
                    {"filename": "../openssl.tar.gz"}
                ),
                "safe path",
            ),
            (
                lambda value: value["builder"]["opensslPerlShims"].update(
                    {"packaging/sqlcipher/perl/IPC/Cmd.pm": "0" * 64}
                ),
                "shims",
            ),
            (
                lambda value: value["artifact"].update({"distribution": "sqlcipher3"}),
                "artifact identity",
            ),
        )
        for mutation, expected_error in cases:
            with self.subTest(error=expected_error):
                changed = copy.deepcopy(self.manifest)
                mutation(changed)
                with self.assertRaisesRegex(RuntimeError, expected_error):
                    validate_manifest(changed)

    def test_rejects_duplicate_manifest_keys(self):
        text = DEFAULT_MANIFEST.read_text(encoding="utf-8")
        text = text.replace('"schemaVersion": 1', '"schemaVersion": 1, "schemaVersion": 1')
        with tempfile.TemporaryDirectory(prefix="continuum-manifest-") as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate key"):
                load_json_strict(path)

    def test_gpg_status_tolerates_non_utf8_user_ids_but_requires_one_validsig(self):
        signing = "A" * 40
        primary = "B" * 40
        validsig = (
            "[GNUPG:] VALIDSIG %s 2026-09-05 1788645539 0 4 0 1 10 00 %s\n"
            % (signing, primary)
        ).encode("ascii")
        status = b"[GNUPG:] GOODSIG DEADBEEF name-\xcc\n" + validsig
        self.assertEqual(
            valid_signature_fingerprints(status),
            (signing, primary),
        )

        for rejected in (
            b"[GNUPG:] GOODSIG only\n",
            validsig + validsig,
            b"[GNUPG:] VALIDSIG \xcc\n",
            b"[GNUPG:] VALIDSIG " + (b"A" * 40) + b" too-short\n",
        ):
            with self.subTest(status=rejected):
                with self.assertRaisesRegex(RuntimeError, "VALIDSIG"):
                    valid_signature_fingerprints(rejected)


class PatchedSqlcipherArtifactTest(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "the first native wheel slice is Linux-only")
    def test_project_openssl_can_run_shim_rejects_current_directory_path_entry(self):
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
            environment["PATH"] = ":%s" % directory
            found = subprocess.run(
                [
                    perl,
                    "-I%s" % shim_root,
                    "-MIPC::Cmd",
                    "-e",
                    'print IPC::Cmd::can_run("reviewed-tool") // q{}',
                ],
                check=True,
                cwd=str(ROOT),
                env=environment,
                stdout=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(found.stdout, str(executable))

            environment["PATH"] = ":"
            subprocess.run(
                [
                    perl,
                    "-I%s" % shim_root,
                    "-MIPC::Cmd",
                    "-e",
                    'exit defined IPC::Cmd::can_run("reviewed-tool") ? 1 : 0',
                ],
                check=True,
                cwd=str(directory),
                env=environment,
            )

    @unittest.skipIf(os.name == "nt", "the first native wheel slice is Linux-only")
    def test_project_openssl_time_shim_is_strict(self):
        perl = shutil.which("perl")
        if perl is None:
            self.skipTest("Perl is not installed on this host")
        shim_root = ROOT / "packaging" / "sqlcipher" / "perl"
        valid = subprocess.run(
            [
                perl,
                "-I%s" % shim_root,
                "-MTime::Piece",
                "-e",
                'my $date = Time::Piece->strptime("25 Aug 2026", "%d %b %Y"); print $date->strftime("%Y-%m-%d")',
            ],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(valid.stdout, "2026-08-25")
        for value, date_format in (("31 Feb 2026", "%d %b %Y"), ("25 Aug 2026", "%F")):
            with self.subTest(value=value, date_format=date_format):
                result = subprocess.run(
                    [
                        perl,
                        "-I%s" % shim_root,
                        "-MTime::Piece",
                        "-e",
                        "Time::Piece->strptime($ARGV[0], $ARGV[1])",
                        value,
                        date_format,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertNotEqual(result.returncode, 0)

    def test_rejects_unsafe_source_paths_and_ambiguous_wheels(self):
        safe_archive_path("sqlcipher-4.18.0/src/sqliteInt.h", "sqlcipher-4.18.0")
        for path in ("/absolute", "sqlcipher-4.18.0/../escape", "other/file"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(RuntimeError, "unsafe or unexpected"):
                    safe_archive_path(path, "sqlcipher-4.18.0")

        with tempfile.TemporaryDirectory(prefix="continuum-wheel-count-") as temporary:
            directory = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "found 0"):
                one_wheel(directory)
            (directory / "one.whl").write_bytes(b"one")
            self.assertEqual(one_wheel(directory).name, "one.whl")
            (directory / "two.whl").write_bytes(b"two")
            with self.assertRaisesRegex(RuntimeError, "found 2"):
                one_wheel(directory)

    def test_generated_provenance_and_sbom_bind_exact_wheel_hash(self):
        manifest = validate_manifest(load_json_strict(DEFAULT_MANIFEST))
        inspection = {
            "_sqliteLicenseText": "Synthetic SQLite public-domain statement for this unit test.",
            "filename": manifest["expectedArtifacts"]["linuxCp314"]["filename"],
            "licenseSha256": {},
            "metadataSha256": "1" * 64,
            "nativeMember": "sqlcipher3/_sqlite3.so",
            "nativeNeeded": ["libc.so.6"],
            "nativeSha256": "2" * 64,
            "sha256": "3" * 64,
        }
        with tempfile.TemporaryDirectory(prefix="continuum-wheel-evidence-") as temporary:
            directory = Path(temporary)
            write_evidence(directory, inspection, manifest)
            provenance = load_json_strict(directory / "artifact-provenance.json")
            sbom = load_json_strict(directory / "patched-wheel.spdx.json")
            self.assertEqual(provenance["artifact"]["sha256"], "3" * 64)
            wheel = next(
                item
                for item in sbom["packages"]
                if item["SPDXID"] == "SPDXRef-Package-continuum-sqlcipher3-wheel"
            )
            self.assertEqual(wheel["checksums"][0]["checksumValue"], "3" * 64)
            self.assertEqual(wheel["licenseConcluded"], "NOASSERTION")

    def test_build_definition_has_no_conan_or_dynamic_network_path(self):
        setup_text = (ROOT / "packaging/sqlcipher/setup_continuum.py").read_text(
            encoding="utf-8"
        )
        workflow = (
            ROOT / ".github/workflows/patched-sqlcipher-wheel.yml"
        ).read_text(encoding="utf-8")
        build_script = (ROOT / "scripts/build_patched_sqlcipher_wheel.sh").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("conan", setup_text.lower())
        self.assertIn("extra_objects=[libcrypto]", setup_text)
        self.assertIn('exit($date->strftime', build_script)
        self.assertIn("export SOURCE_DATE_EPOCH", build_script)
        self.assertEqual(build_script.count("SOURCE_DATE_EPOCH"), 2)
        self.assertIn("make sourcetest", build_script)
        self.assertNotIn("make verify-source", build_script)
        self.assertGreaterEqual(workflow.count("--network=none"), 5)
        self.assertNotIn("docker.io", workflow)
        self.assertIn("@sha256:53390351", workflow)
        self.assertNotIn("release", workflow.lower().replace("source release", ""))


if __name__ == "__main__":
    unittest.main()
