import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.release_package import (
    ROOT, RUNTIME_PACKAGE_ID, archive_members, build_release, install_smoke, make_sbom,
    normalize_sdist, offline_environment, validate_metadata, validate_sbom,
)


spec = importlib.util.spec_from_file_location("stage_polkit_wheel", ROOT / "packaging/linux/stage-polkit-wheel.py")
staging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(staging)

HELPER_METADATA = (
    "Metadata-Version: 2.4\nName: continuum-memory\nVersion: 0.1.0.dev0\n"
    "License-Expression: Apache-2.0\n"
    "Author-email: Oussama Essalmani <98963291+Oussamoux1234@users.noreply.github.com>\n\n"
).encode()
METADATA = HELPER_METADATA.replace(
    b"\n\n", b"\nRequires-Python: >=3.11,<3.15\nRequires-Dist: continuum-sqlcipher3==0.6.2.post2\n\n"
)
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


def helper_wheel(directory, fields=HELPER_METADATA, entry="continuum_memory.polkit_helper:main"):
    """Legacy dependency-free staging fixture, not the encrypted application."""
    return wheel(directory, fields, entry)


class ReleasePackageTest(unittest.TestCase):
    def test_exact_metadata_and_payload_are_verified_for_both_artifact_types(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            self.assertIn(INFO + "METADATA", validate_metadata(wheel(directory)))
            self.assertEqual(list(validate_metadata(sdist(directory))), ["continuum_memory-0.1.0.dev0/PKG-INFO"])

    def test_runtime_dependency_and_python_range_must_be_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            dependency = b"Requires-Dist: continuum-sqlcipher3==0.6.2.post2\n"
            python = b"Requires-Python: >=3.11,<3.15\n"
            invalid = (
                METADATA.replace(dependency, b""),
                METADATA.replace(dependency, dependency + dependency),
                METADATA.replace(dependency, dependency + b"Requires-Dist: example\n"),
                METADATA.replace(b"==0.6.2.post2", b"==0.6.2.post1"),
                METADATA.replace(b"==0.6.2.post2", b">=0.6.2.post2"),
                METADATA.replace(dependency, dependency.rstrip(b"\n") + b'; sys_platform == "linux"\n'),
                METADATA.replace(python, b""),
                METADATA.replace(python, python + python),
                METADATA.replace(python, b"Requires-Python: >=3.9\n"),
                METADATA.replace(python, b"Requires-Python: >=3.11\n"),
                METADATA.replace(b"Oussama Essalmani", b"Someone Else"),
            )
            for content in invalid:
                with self.subTest(content=content):
                    for artifact in (wheel(directory, content), sdist(directory, payload=content)):
                        with self.assertRaises(ValueError):
                            validate_metadata(artifact)
            reordered = METADATA.replace(python, b"Requires-Python: <3.15,>=3.11\n")
            validate_metadata(wheel(directory, reordered))

    def test_installed_runtime_gate_requires_reviewed_inputs_before_creating_venv(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            artifact = wheel(directory)
            destination = directory / "fresh-environment"
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(RuntimeError, "reviewed offline wheelhouse"):
                    install_smoke(artifact, destination, EPOCH)
            self.assertFalse(destination.exists())

    def test_empty_build_wheelhouse_fails_real_offline_hash_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "release"
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                build_release(output, Path(directory))
            self.assertNotEqual(caught.exception.returncode, 0)
            self.assertIn("--dry-run", caught.exception.cmd)
            self.assertIn("--ignore-installed", caught.exception.cmd)
            self.assertIn("--require-hashes", caught.exception.cmd)
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_wrong_installed_build_tool_version_fails_before_resolving_inputs(self):
        from unittest.mock import patch
        from scripts import release_package
        real_version = release_package.metadata.version

        def wrong_version(name):
            return "0.0.synthetic" if name == "build" else real_version(name)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "release"
            with patch.object(release_package.metadata, "version", side_effect=wrong_version):
                with patch.object(release_package, "run") as resolver:
                    with self.assertRaisesRegex(RuntimeError, "pinned build requirements.*build"):
                        build_release(output, Path(directory))
                    resolver.assert_not_called()
            self.assertFalse(output.exists())

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
            for name in ("../escape", "/escape", "prefix\\escape", "a//b", "a/./b",
                         "C:/escape", "C:relative", "source/a:stream", "source/NUL",
                         "source/COM1.txt", "source/lpt².log", "source/path.", "source/path ",
                         "source/a\x01b", "source/a?b"):
                with self.subTest(name=name):
                    with self.assertRaisesRegex(ValueError, "unsafe"):
                        archive_members(sdist(Path(directory), name))

    def test_rejects_case_aliases_before_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = wheel(Path(directory))
            with zipfile.ZipFile(archive, "a") as bundle:
                bundle.writestr("continuum_memory/POLKIT_HELPER.py", b"alias")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                archive_members(archive)

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
            packages = {package["SPDXID"]: package for package in document["packages"]}
            runtime = packages[RUNTIME_PACKAGE_ID]
            self.assertEqual(runtime["name"], "continuum-sqlcipher3")
            self.assertEqual(runtime["versionInfo"], "0.6.2.post2")
            self.assertEqual(runtime["licenseDeclared"], "NOASSERTION")
            self.assertFalse(runtime["filesAnalyzed"])
            self.assertNotIn("packageFileName", runtime)
            self.assertNotIn("packageVerificationCode", runtime)
            for name in ("packaging/sqlcipher/manifest.json", "sbom/patched-sqlcipher-sources.spdx.json"):
                digest = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                self.assertIn(name + " (SHA-256 " + digest + ")", runtime["sourceInfo"])
            dependencies = {row["spdxElementId"] for row in document["relationships"]
                            if row["relationshipType"] == "DEPENDS_ON" and row["relatedSpdxElement"] == RUNTIME_PACKAGE_ID}
            self.assertEqual(dependencies, {"SPDXRef-Package-wheel", "SPDXRef-Package-sdist"})
            self.assertFalse(any(row["spdxElementId"] == RUNTIME_PACKAGE_ID
                                 and row["relationshipType"] == "CONTAINS" for row in document["relationships"]))

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
            omitted_dependency = copy.deepcopy(document)
            omitted_dependency["relationships"] = [row for row in omitted_dependency["relationships"]
                                                    if row["relationshipType"] != "DEPENDS_ON"]
            mutations.append(omitted_dependency)
            wrong_runtime = copy.deepcopy(document)
            next(package for package in wrong_runtime["packages"]
                 if package["SPDXID"] == RUNTIME_PACKAGE_ID)["versionInfo"] = "0.6.2.post1"
            mutations.append(wrong_runtime)
            invented_runtime_license = copy.deepcopy(document)
            next(package for package in invented_runtime_license["packages"]
                 if package["SPDXID"] == RUNTIME_PACKAGE_ID)["licenseDeclared"] = "Apache-2.0"
            mutations.append(invented_runtime_license)
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


@unittest.skipUnless(os.name == "posix", "Linux installer staging uses POSIX no-follow descriptors")
class PolkitWheelStagingTest(unittest.TestCase):
    def test_stages_exact_wheel_in_new_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            artifact = helper_wheel(directory)
            destination = directory / "staged.whl"
            staging.stage_wheel(artifact, destination)
            self.assertEqual(artifact.read_bytes(), destination.read_bytes())
            with self.assertRaises(FileExistsError):
                staging.stage_wheel(artifact, destination)

    def test_rejects_relative_missing_symlink_hardlink_and_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            artifact = helper_wheel(directory)
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
            for index, (fields, entry) in enumerate(((HELPER_METADATA.replace(b"Version: 0.1.0.dev0", b"Version: 9.0"), "continuum_memory.polkit_helper:main"), (HELPER_METADATA, "unexpected:main"))):
                artifact = helper_wheel(directory, fields, entry)
                with self.assertRaises(ValueError):
                    staging.stage_wheel(artifact, directory / ("staged-%s.whl" % index))

    def test_encrypted_application_wheel_is_refused_by_legacy_privileged_stager(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            artifact = wheel(directory)
            with self.assertRaisesRegex(ValueError, "no runtime dependencies"):
                staging.stage_wheel(artifact, directory / "staged.whl")

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
            artifact = helper_wheel(directory)
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
