import copy
import importlib.util
import io
import json
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.release_package import (
    ROOT, archive_members, make_sbom, normalize_sdist, offline_environment,
    validate_metadata, validate_sbom,
)


spec = importlib.util.spec_from_file_location("stage_polkit_wheel", ROOT / "packaging/linux/stage-polkit-wheel.py")
staging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(staging)

METADATA = (
    "Metadata-Version: 2.4\nName: continuum-memory\nVersion: 0.1.0.dev0\n"
    "License-Expression: Apache-2.0\n"
    "Author-email: Oussama Essalmani <98963291+Oussamoux1234@users.noreply.github.com>\n\n"
).encode()
INFO = "continuum_memory-0.1.0.dev0.dist-info/"
EPOCH = 1700000000


def wheel(directory, fields=METADATA, entry="continuum_memory.polkit_helper:main"):
    path = directory / staging.WHEEL_NAME
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr(INFO + "METADATA", fields)
        bundle.writestr(INFO + "entry_points.txt", "[console_scripts]\ncontinuum-polkit-helper = " + entry + "\n")
        bundle.writestr("continuum_memory/polkit_helper.py", "# synthetic wheel fixture\n")
    return path


def sdist(directory, name="continuum_memory-0.1.0.dev0/PKG-INFO", payload=METADATA):
    path = directory / "continuum_memory-0.1.0.dev0.tar.gz"
    with tarfile.open(path, "w:gz") as bundle:
        entry = tarfile.TarInfo(name)
        entry.size = len(payload)
        bundle.addfile(entry, io.BytesIO(payload))
    return path


class ReleasePackageTest(unittest.TestCase):
    def test_exact_metadata_and_payload_are_verified_for_both_artifact_types(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            self.assertIn(INFO + "METADATA", validate_metadata(wheel(directory)))
            self.assertEqual(list(validate_metadata(sdist(directory))), ["continuum_memory-0.1.0.dev0/PKG-INFO"])

    def test_runtime_dependency_or_wrong_author_requires_explicit_sbom_update(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            for content in (METADATA.replace(b"\n\n", b"\nRequires-Dist: example\n\n"), METADATA.replace(b"Oussama Essalmani", b"Someone Else")):
                with self.subTest(content=content):
                    with self.assertRaises(ValueError):
                        validate_metadata(wheel(directory, content))

    def test_canonical_sdist_is_deterministic_without_changing_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = sdist(Path(directory))
            original = archive_members(archive)
            normalize_sdist(archive, EPOCH)
            first = archive.read_bytes()
            normalize_sdist(archive, EPOCH)
            self.assertEqual(first, archive.read_bytes())
            self.assertEqual(original, archive_members(archive))
            with tarfile.open(archive) as bundle:
                self.assertEqual(bundle.getmembers()[0].mtime, EPOCH)
                self.assertEqual(bundle.getmembers()[0].uid, 0)

    def test_rejects_traversal_and_absolute_members_without_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ("../escape", "/escape", "prefix\\escape", "a//b", "a/./b"):
                with self.subTest(name=name):
                    with self.assertRaisesRegex(ValueError, "unsafe"):
                        archive_members(sdist(Path(directory), name))

    def test_rejects_archive_links(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsafe.tar.gz"
            with tarfile.open(path, "w:gz") as bundle:
                entry = tarfile.TarInfo("source/link")
                entry.type = tarfile.SYMTYPE
                entry.linkname = "/tmp/example"
                bundle.addfile(entry)
            with self.assertRaisesRegex(ValueError, "non-regular"):
                archive_members(path)

    def test_spdx_validator_accepts_complete_payload_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            artifacts = [sdist(directory), wheel(directory)]
            document = make_sbom(artifacts, EPOCH)
            path = directory / "sbom.spdx.json"
            path.write_text(json.dumps(document))
            validate_sbom(path, artifacts, EPOCH)
            self.assertEqual(len(document["files"]), 4)
            self.assertEqual({package["licenseConcluded"] for package in document["packages"]}, {"NOASSERTION"})

    def test_sbom_missing_files_modified_hash_or_invented_license_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            artifacts = [sdist(directory), wheel(directory)]
            document = make_sbom(artifacts, EPOCH)
            path = directory / "sbom.spdx.json"
            mutations = []
            missing = copy.deepcopy(document)
            missing["files"].pop()
            mutations.append(missing)
            changed = copy.deepcopy(document)
            changed["packages"][0]["checksums"][0]["checksumValue"] = "0" * 64
            mutations.append(changed)
            invented = copy.deepcopy(document)
            invented["packages"][0]["licenseConcluded"] = "Apache-2.0"
            mutations.append(invented)
            for mutation in mutations:
                path.write_text(json.dumps(mutation))
                with self.assertRaisesRegex(ValueError, "SBOM does not match"):
                    validate_sbom(path, artifacts, EPOCH)

    def test_tampered_archive_invalidates_previously_generated_sbom(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            artifacts = [sdist(directory), wheel(directory)]
            path = directory / "sbom.spdx.json"
            path.write_text(json.dumps(make_sbom(artifacts, EPOCH)))
            with zipfile.ZipFile(artifacts[1], "a") as bundle:
                bundle.writestr("continuum_memory/extra.py", "# altered\n")
            with self.assertRaisesRegex(ValueError, "SBOM does not match"):
                validate_sbom(path, artifacts, EPOCH)

    def test_offline_environment_disables_indexes_and_checkout_imports(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"PYTHONPATH": "/unexpected", "PIP_INDEX_URL": "https://invalid", "PIP_FIND_LINKS": "https://invalid"}):
            environment = offline_environment(EPOCH)
        self.assertEqual(environment["PIP_NO_INDEX"], "1")
        self.assertEqual(environment["PIP_CONFIG_FILE"], os.devnull)
        self.assertNotIn("PYTHONPATH", environment)
        self.assertNotIn("PIP_FIND_LINKS", environment)


class PolkitWheelStagingTest(unittest.TestCase):
    def test_stages_exact_wheel_in_new_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            artifact = wheel(directory)
            destination = directory / "staged.whl"
            staging.stage_wheel(artifact, destination)
            self.assertEqual(artifact.read_bytes(), destination.read_bytes())
            with self.assertRaises(FileExistsError):
                staging.stage_wheel(artifact, destination)

    def test_rejects_relative_missing_symlink_hardlink_and_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            artifact = wheel(directory)
            alias = directory / "alias"
            alias.symlink_to(directory, target_is_directory=True)
            for source in (Path(staging.WHEEL_NAME), directory / "missing.whl", alias / artifact.name, directory):
                with self.subTest(source=source):
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        staging.stage_wheel(source, directory / "staged.whl")
            os.link(artifact, directory / "hardlink")
            with self.assertRaisesRegex(ValueError, "one link"):
                staging.stage_wheel(artifact, directory / "staged.whl")

    def test_rejects_wrong_metadata_or_redirected_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            for index, (fields, entry) in enumerate(((METADATA.replace(b"Version: 0.1.0.dev0", b"Version: 9.0"), "continuum_memory.polkit_helper:main"), (METADATA, "unexpected:main"))):
                artifact = wheel(directory, fields, entry)
                with self.assertRaises(ValueError):
                    staging.stage_wheel(artifact, directory / ("staged-%s.whl" % index))

    def test_rejects_fifo_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            source = directory / staging.WHEEL_NAME
            os.mkfifo(source)
            with self.assertRaisesRegex(ValueError, "regular file"):
                staging.stage_wheel(source, directory / "staged.whl")

    def test_rejects_unsafe_wheel_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            artifact = wheel(directory)
            with zipfile.ZipFile(artifact, "a") as bundle:
                bundle.writestr("../escape", "unsafe")
            with self.assertRaisesRegex(ValueError, "unsafe wheel member"):
                staging.stage_wheel(artifact, directory / "staged.whl")

    def test_rejects_compressed_oversized_metadata_before_reading_it(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            artifact = directory / staging.WHEEL_NAME
            with zipfile.ZipFile(artifact, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                bundle.writestr(INFO + "METADATA", b"x" * (1024 * 1024 + 1))
            self.assertLess(artifact.stat().st_size, 10000)
            with self.assertRaisesRegex(ValueError, "metadata is too large"):
                staging.stage_wheel(artifact, directory / "staged.whl")

    def test_installer_requires_staged_wheel_without_source_build_fallback(self):
        installer = (ROOT / "packaging/linux/install-polkit.sh").read_text()
        self.assertIn('[ "$#" -ne 1 ]', installer)
        self.assertIn('"$SCRIPT_DIRECTORY/stage-polkit-wheel.py"', installer)
        self.assertIn('--no-index --force-reinstall "$BUILD_DIRECTORY/continuum_memory-0.1.0.dev0-py3-none-any.whl"', installer)
        self.assertNotIn('"$SOURCE_DIRECTORY"', installer)


if __name__ == "__main__":
    unittest.main()
