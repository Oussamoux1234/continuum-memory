import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.verify import (
    EXPECTED_DISTRIBUTION,
    EXPECTED_VERSION,
    find_sdist,
    require_sdist_files,
)


class SourceDistributionDiscoveryTest(unittest.TestCase):
    def make_sdist(
        self,
        directory: Path,
        filename: str,
        metadata_name: str = EXPECTED_DISTRIBUTION,
        metadata_version: str = EXPECTED_VERSION,
        files: tuple[str, ...] = (),
    ) -> Path:
        archive = directory / filename
        payload = ("Name: %s\nVersion: %s\n\n" % (metadata_name, metadata_version)).encode("utf-8")
        root = filename[: -len(".tar.gz")]
        member = tarfile.TarInfo("%s/PKG-INFO" % root)
        member.size = len(payload)
        with tarfile.open(str(archive), mode="w:gz") as bundle:
            bundle.addfile(member, io.BytesIO(payload))
            for relative_path in files:
                extra = tarfile.TarInfo("%s/%s" % (root, relative_path))
                extra.size = 0
                bundle.addfile(extra, io.BytesIO())
        return archive

    def test_accepts_hyphenated_distribution_name(self):
        with tempfile.TemporaryDirectory(prefix="continuum-sdist-test-") as temporary:
            directory = Path(temporary)
            archive = self.make_sdist(directory, "continuum-memory-0.1.0.dev0.tar.gz")
            self.assertEqual(find_sdist(directory), archive)

    def test_accepts_underscore_normalized_distribution_name(self):
        with tempfile.TemporaryDirectory(prefix="continuum-sdist-test-") as temporary:
            directory = Path(temporary)
            archive = self.make_sdist(directory, "continuum_memory-0.1.0.dev0.tar.gz")
            self.assertEqual(find_sdist(directory), archive)

    def test_rejects_missing_and_multiple_archives(self):
        with tempfile.TemporaryDirectory(prefix="continuum-sdist-test-") as temporary:
            directory = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "found 0"):
                find_sdist(directory)

            self.make_sdist(directory, "continuum-memory-0.1.0.dev0.tar.gz")
            self.make_sdist(directory, "continuum_memory-0.1.0.dev0.tar.gz")
            with self.assertRaisesRegex(RuntimeError, "found 2"):
                find_sdist(directory)

    def test_rejects_unrelated_archive_filename(self):
        with tempfile.TemporaryDirectory(prefix="continuum-sdist-test-") as temporary:
            directory = Path(temporary)
            self.make_sdist(directory, "unrelated-0.1.0.dev0.tar.gz")
            with self.assertRaisesRegex(RuntimeError, "unexpected project name"):
                find_sdist(directory)

    def test_rejects_wrong_embedded_name_and_version(self):
        invalid_metadata = [
            ("unrelated", EXPECTED_VERSION, "project name"),
            (EXPECTED_DISTRIBUTION, "9.9.9", "version"),
        ]
        for metadata_name, metadata_version, expected_error in invalid_metadata:
            with self.subTest(name=metadata_name, version=metadata_version):
                with tempfile.TemporaryDirectory(prefix="continuum-sdist-test-") as temporary:
                    directory = Path(temporary)
                    self.make_sdist(
                        directory,
                        "continuum-memory-0.1.0.dev0.tar.gz",
                        metadata_name,
                        metadata_version,
                    )
                    with self.assertRaisesRegex(RuntimeError, expected_error):
                        find_sdist(directory)

    def test_rejects_corrupt_archive(self):
        with tempfile.TemporaryDirectory(prefix="continuum-sdist-test-") as temporary:
            directory = Path(temporary)
            archive = directory / "continuum-memory-0.1.0.dev0.tar.gz"
            archive.write_bytes(b"not a tar archive")
            with self.assertRaisesRegex(RuntimeError, "invalid source distribution"):
                find_sdist(directory)

    def test_requires_named_distribution_files(self):
        with tempfile.TemporaryDirectory(prefix="continuum-sdist-test-") as temporary:
            directory = Path(temporary)
            archive = self.make_sdist(
                directory,
                "continuum-memory-0.1.0.dev0.tar.gz",
                files=("packaging/linux/approval-helper", "src/continuum_memory/approval.py"),
            )
            require_sdist_files(
                archive,
                ("packaging/linux/approval-helper", "src/continuum_memory/approval.py"),
            )
            with self.assertRaisesRegex(RuntimeError, "tests/test_approval.py"):
                require_sdist_files(archive, ("tests/test_approval.py",))


if __name__ == "__main__":
    unittest.main()
