import hashlib
import io
import json
import shutil
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.verify import (
    EXPECTED_AUDIT_DATE,
    EXPECTED_DISTRIBUTION,
    EXPECTED_LICENSE_FILE_DIGESTS,
    EXPECTED_MINIMUM_PATCHED_VERSIONS,
    EXPECTED_PREFERRED_REPLACEMENT_VERSIONS,
    EXPECTED_REPLACEMENT_STATUS,
    EXPECTED_REVIEWED_REPLACEMENT_SOURCES,
    EXPECTED_SQLCIPHER_WHEELS,
    EXPECTED_VERSION,
    ROOT,
    compare_reproducible_artifacts,
    find_project_wheel,
    find_sdist,
    find_sqlcipher_wheel,
    inspect_sqlcipher_wheel,
    require_sdist_files,
    require_wheel_compliance_files,
    runtime_check,
    third_party_manifest_check,
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


class SqlcipherWheelDiscoveryTest(unittest.TestCase):
    def test_accepts_exact_hash_pinned_wheel(self):
        with tempfile.TemporaryDirectory(prefix="continuum-wheel-test-") as temporary:
            directory = Path(temporary)
            wheel = directory / "sqlcipher3-0.6.2-cp39-cp39-test.whl"
            wheel.write_bytes(b"synthetic wheel fixture")
            expected = {wheel.name: hashlib.sha256(wheel.read_bytes()).hexdigest()}
            self.assertEqual(find_sqlcipher_wheel(directory, expected), wheel)

    def test_rejects_missing_multiple_unsupported_and_modified_wheels(self):
        with tempfile.TemporaryDirectory(prefix="continuum-wheel-test-") as temporary:
            directory = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "found 0"):
                find_sqlcipher_wheel(directory, {})

            first = directory / "sqlcipher3-0.6.2-cp39-cp39-first.whl"
            second = directory / "sqlcipher3-0.6.2-cp39-cp39-second.whl"
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            with self.assertRaisesRegex(RuntimeError, "found 2"):
                find_sqlcipher_wheel(directory, {})
            second.unlink()

            with self.assertRaisesRegex(RuntimeError, "unsupported"):
                find_sqlcipher_wheel(directory, {})
            expected = {first.name: hashlib.sha256(b"expected").hexdigest()}
            with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
                find_sqlcipher_wheel(directory, expected)


class SqlcipherWheelInventoryTest(unittest.TestCase):
    METADATA = (
        b"Metadata-Version: 2.4\n"
        b"Name: sqlcipher3\n"
        b"Version: 0.6.2\n"
        b"License-Expression: MIT\n"
        b"Project-URL: Repository, https://github.com/coleifer/sqlcipher3\n"
        b"License-File: LICENSE\n\n"
    )
    LICENSE = b"synthetic upstream license"
    MARKERS = (b"sqlcipher marker", b"sqlite marker", b"openssl marker")

    def make_wheel(
        self,
        directory: Path,
        metadata: bytes = METADATA,
        license_payload: bytes = LICENSE,
        native_payload: bytes = b"sqlcipher marker sqlite marker openssl marker",
        extra_native: bool = False,
    ) -> Path:
        wheel = directory / "sqlcipher3-0.6.2-cp314-cp314-test.whl"
        with zipfile.ZipFile(str(wheel), mode="w") as bundle:
            bundle.writestr("sqlcipher3/__init__.py", "")
            bundle.writestr("sqlcipher3/dbapi2.py", "")
            bundle.writestr("sqlcipher3/_sqlite3.cpython-314-test.so", native_payload)
            bundle.writestr("sqlcipher3-0.6.2.dist-info/METADATA", metadata)
            bundle.writestr(
                "sqlcipher3-0.6.2.dist-info/licenses/LICENSE",
                license_payload,
            )
            if extra_native:
                bundle.writestr("sqlcipher3.libs/unrecorded.dylib", b"native")
        return wheel

    def inspect(self, wheel: Path, metadata: bytes = METADATA, license_payload: bytes = LICENSE):
        inspect_sqlcipher_wheel(
            wheel,
            hashlib.sha256(metadata).hexdigest(),
            hashlib.sha256(license_payload).hexdigest(),
            self.MARKERS,
        )

    def test_accepts_complete_component_evidence(self):
        with tempfile.TemporaryDirectory(prefix="continuum-wheel-inventory-") as temporary:
            wheel = self.make_wheel(Path(temporary))
            self.inspect(wheel)

    def test_rejects_license_metadata_payload_and_native_component_drift(self):
        cases = (
            ("license", {}, "license digest mismatch"),
            (
                "metadata",
                {"metadata": self.METADATA.replace(b"MIT", b"BSD-3-Clause")},
                "license declaration changed",
            ),
            ("marker", {"native_payload": b"sqlcipher marker sqlite marker"}, "openssl marker"),
            ("native", {"extra_native": True}, "unrecorded native library"),
        )
        for name, changes, expected_error in cases:
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory(
                    prefix="continuum-wheel-inventory-"
                ) as temporary:
                    directory = Path(temporary)
                    if name == "license":
                        wheel = self.make_wheel(directory, license_payload=b"modified")
                        with self.assertRaisesRegex(RuntimeError, expected_error):
                            self.inspect(wheel)
                    elif name == "metadata":
                        metadata = changes["metadata"]
                        wheel = self.make_wheel(directory, metadata=metadata)
                        with self.assertRaisesRegex(RuntimeError, expected_error):
                            self.inspect(wheel, metadata=metadata)
                    else:
                        wheel = self.make_wheel(directory, **changes)
                        with self.assertRaisesRegex(RuntimeError, expected_error):
                            self.inspect(wheel)


class ThirdPartyManifestTest(unittest.TestCase):
    def copy_compliance_tree(self, destination: Path) -> None:
        required = [
            "THIRD_PARTY_NOTICES.md",
            "docs/architecture/010-encryption-dependency-decision.md",
            "requirements/sqlcipher-maintained.txt",
            "requirements/spdx-validation-linux-py314.txt",
            "sbom/continuum-memory.spdx.json",
            "security/dependency-audit.json",
            *EXPECTED_LICENSE_FILE_DIGESTS,
        ]
        for relative_path in required:
            target = destination / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative_path, target)

    def test_repository_inventory_is_complete(self):
        third_party_manifest_check()

    def test_rejects_missing_notice_and_license_files(self):
        missing_paths = (
            "THIRD_PARTY_NOTICES.md",
            "docs/architecture/010-encryption-dependency-decision.md",
            "third_party_licenses/SQLCipher-4.12.0.txt",
        )
        for missing_path in missing_paths:
            with self.subTest(path=missing_path):
                with tempfile.TemporaryDirectory(
                    prefix="continuum-license-inventory-"
                ) as temporary:
                    root = Path(temporary)
                    self.copy_compliance_tree(root)
                    (root / missing_path).unlink()
                    with self.assertRaisesRegex(RuntimeError, "missing"):
                        third_party_manifest_check(root)

    def test_rejects_missing_component_and_modified_wheel_hash(self):
        with tempfile.TemporaryDirectory(prefix="continuum-license-inventory-") as temporary:
            root = Path(temporary)
            self.copy_compliance_tree(root)
            sbom_path = root / "sbom" / "continuum-memory.spdx.json"
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            sbom["packages"] = [
                package
                for package in sbom["packages"]
                if package["SPDXID"] != "SPDXRef-Package-OpenSSL"
            ]
            sbom_path.write_text(json.dumps(sbom), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "missing component"):
                third_party_manifest_check(root)

        with tempfile.TemporaryDirectory(prefix="continuum-license-inventory-") as temporary:
            root = Path(temporary)
            self.copy_compliance_tree(root)
            sbom_path = root / "sbom" / "continuum-memory.spdx.json"
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            wheel_name = next(iter(EXPECTED_SQLCIPHER_WHEELS))
            wheel = next(package for package in sbom["packages"] if package["name"] == wheel_name)
            wheel["checksums"][0]["checksumValue"] = "0" * 64
            sbom_path.write_text(json.dumps(sbom), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "wheel checksum mismatch"):
                third_party_manifest_check(root)

    def test_rejects_duplicate_json_keys_and_overstated_license_conclusion(self):
        with tempfile.TemporaryDirectory(prefix="continuum-license-inventory-") as temporary:
            root = Path(temporary)
            self.copy_compliance_tree(root)
            sbom_path = root / "sbom" / "continuum-memory.spdx.json"
            text = sbom_path.read_text(encoding="utf-8")
            text = text.replace(
                '"SPDXID": "SPDXRef-DOCUMENT",',
                '"SPDXID": "SPDXRef-DOCUMENT",\n  "SPDXID": "SPDXRef-DOCUMENT",',
                1,
            )
            sbom_path.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "SPDX inventory is missing or invalid"):
                third_party_manifest_check(root)

        with tempfile.TemporaryDirectory(prefix="continuum-license-inventory-") as temporary:
            root = Path(temporary)
            self.copy_compliance_tree(root)
            sbom_path = root / "sbom" / "continuum-memory.spdx.json"
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            package = next(
                item
                for item in sbom["packages"]
                if item["SPDXID"] == "SPDXRef-Package-sqlcipher3"
            )
            package["licenseConcluded"] = "LicenseRef-sqlcipher3-0.6.2"
            sbom_path.write_text(json.dumps(sbom), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "component record mismatch"):
                third_party_manifest_check(root)

    def test_rejects_audit_or_validator_lock_drift(self):
        with tempfile.TemporaryDirectory(prefix="continuum-license-inventory-") as temporary:
            root = Path(temporary)
            self.copy_compliance_tree(root)
            audit_path = root / "security" / "dependency-audit.json"
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
            audit["releaseDecision"]["status"] = "READY"
            audit_path.write_text(json.dumps(audit), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "blocked release decision"):
                third_party_manifest_check(root)

        with tempfile.TemporaryDirectory(prefix="continuum-license-inventory-") as temporary:
            root = Path(temporary)
            self.copy_compliance_tree(root)
            audit_path = root / "security" / "dependency-audit.json"
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
            audit["components"]["OpenSSL"]["findings"]["High"].pop()
            audit_path.write_text(json.dumps(audit), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "OpenSSL finding counts changed"):
                third_party_manifest_check(root)

        with tempfile.TemporaryDirectory(prefix="continuum-license-inventory-") as temporary:
            root = Path(temporary)
            self.copy_compliance_tree(root)
            audit_path = root / "security" / "dependency-audit.json"
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
            low = audit["components"]["OpenSSL"]["findings"]["Low"]
            low[0] = "CVE-2099-99999"
            audit_path.write_text(json.dumps(audit), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "OpenSSL finding identifiers changed"):
                third_party_manifest_check(root)

        assessment_cases = (
            ("auditDate", "2099-01-01", "evidence date"),
            (
                "status",
                "READY",
                "replacement status must fail closed",
            ),
            (
                "selectedInstallableArtifact",
                "unreviewed.whl",
                "unreviewed installable artifact",
            ),
            (
                "publishedPatchedSqlcipher3WheelAvailable",
                True,
                "overstates patched wheel availability",
            ),
        )
        for field, value, expected_error in assessment_cases:
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory(
                    prefix="continuum-license-inventory-"
                ) as temporary:
                    root = Path(temporary)
                    self.copy_compliance_tree(root)
                    audit_path = root / "security" / "dependency-audit.json"
                    audit = json.loads(audit_path.read_text(encoding="utf-8"))
                    if field == "auditDate":
                        audit[field] = value
                    else:
                        audit["replacementAssessment"][field] = value
                    audit_path.write_text(json.dumps(audit), encoding="utf-8")
                    with self.assertRaisesRegex(RuntimeError, expected_error):
                        third_party_manifest_check(root)

        version_cases = (
            (
                "minimumPatchedVersions",
                EXPECTED_MINIMUM_PATCHED_VERSIONS,
                "OpenSSL",
                "3.6.3",
                "minimum patched versions",
            ),
            (
                "preferredReplacementVersions",
                EXPECTED_PREFERRED_REPLACEMENT_VERSIONS,
                "SQLite",
                "3.53.2",
                "preferred replacement versions",
            ),
        )
        for field, expected, component, value, expected_error in version_cases:
            with self.subTest(field=field, component=component):
                with tempfile.TemporaryDirectory(
                    prefix="continuum-license-inventory-"
                ) as temporary:
                    root = Path(temporary)
                    self.copy_compliance_tree(root)
                    audit_path = root / "security" / "dependency-audit.json"
                    audit = json.loads(audit_path.read_text(encoding="utf-8"))
                    self.assertEqual(audit["auditDate"], EXPECTED_AUDIT_DATE)
                    self.assertEqual(audit["replacementAssessment"][field], expected)
                    audit["replacementAssessment"][field][component] = value
                    audit_path.write_text(json.dumps(audit), encoding="utf-8")
                    with self.assertRaisesRegex(RuntimeError, expected_error):
                        third_party_manifest_check(root)

        source_cases = (
            ("SQLCipher", "sourceArchiveSha256", "0" * 64),
            ("OpenSSL", "sourceSignatureVerified", True),
            ("sqlcipher3", "masterOpenSSLRequirement", "3.5.8"),
        )
        for component, field, value in source_cases:
            with self.subTest(component=component, field=field):
                with tempfile.TemporaryDirectory(
                    prefix="continuum-license-inventory-"
                ) as temporary:
                    root = Path(temporary)
                    self.copy_compliance_tree(root)
                    audit_path = root / "security" / "dependency-audit.json"
                    audit = json.loads(audit_path.read_text(encoding="utf-8"))
                    self.assertEqual(
                        audit["replacementAssessment"]["reviewedSourceCandidates"],
                        EXPECTED_REVIEWED_REPLACEMENT_SOURCES,
                    )
                    audit["replacementAssessment"]["reviewedSourceCandidates"][component][
                        field
                    ] = value
                    audit_path.write_text(json.dumps(audit), encoding="utf-8")
                    with self.assertRaisesRegex(RuntimeError, "source evidence changed"):
                        third_party_manifest_check(root)

        with tempfile.TemporaryDirectory(prefix="continuum-license-inventory-") as temporary:
            root = Path(temporary)
            self.copy_compliance_tree(root)
            decision_path = root / "docs/architecture/010-encryption-dependency-decision.md"
            decision_path.write_text(
                decision_path.read_text(encoding="utf-8").replace(
                    EXPECTED_REPLACEMENT_STATUS, "READY", 1
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "decision is missing required evidence"):
                third_party_manifest_check(root)

        with tempfile.TemporaryDirectory(prefix="continuum-license-inventory-") as temporary:
            root = Path(temporary)
            self.copy_compliance_tree(root)
            lock_path = root / "requirements" / "spdx-validation-linux-py314.txt"
            text = lock_path.read_text(encoding="utf-8")
            lock_path.write_text(text.replace("d16c9b", "000000", 1), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "SPDX validator hash manifest"):
                third_party_manifest_check(root)

        with tempfile.TemporaryDirectory(prefix="continuum-license-inventory-") as temporary:
            root = Path(temporary)
            self.copy_compliance_tree(root)
            lock_path = root / "requirements" / "spdx-validation-linux-py314.txt"
            with lock_path.open("a", encoding="utf-8") as handle:
                handle.write("--extra-index-url https://example.invalid/simple\n")
            with self.assertRaisesRegex(RuntimeError, "unexpected directive"):
                third_party_manifest_check(root)


class ProjectWheelPackagingTest(unittest.TestCase):
    def make_wheel(self, directory: Path, include_compliance: bool = True) -> Path:
        name = "continuum_memory-0.1.0.dev0-py3-none-any.whl"
        wheel = directory / name
        stem = "continuum_memory-0.1.0.dev0"
        dist_info = "%s.dist-info" % stem
        with zipfile.ZipFile(str(wheel), mode="w") as bundle:
            bundle.writestr(
                "%s/METADATA" % dist_info,
                "Name: %s\nVersion: %s\n\n" % (EXPECTED_DISTRIBUTION, EXPECTED_VERSION),
            )
            if include_compliance:
                for relative_path in (
                    "LICENSE",
                    "THIRD_PARTY_NOTICES.md",
                    "third_party_licenses/OpenSSL-3.6.0.txt",
                    "third_party_licenses/SQLCipher-4.12.0.txt",
                    "third_party_licenses/sqlcipher3-0.6.2.txt",
                ):
                    bundle.writestr(
                        "%s/licenses/%s" % (dist_info, relative_path),
                        (ROOT / relative_path).read_bytes(),
                    )
                bundle.writestr(
                    "%s.data/data/share/continuum-memory/continuum-memory.spdx.json" % stem,
                    (ROOT / "sbom" / "continuum-memory.spdx.json").read_bytes(),
                )
                bundle.writestr(
                    "%s.data/data/share/continuum-memory/dependency-audit.json" % stem,
                    (ROOT / "security" / "dependency-audit.json").read_bytes(),
                )
        return wheel

    def test_discovers_wheel_and_requires_compliance_payload(self):
        with tempfile.TemporaryDirectory(prefix="continuum-project-wheel-") as temporary:
            directory = Path(temporary)
            wheel = self.make_wheel(directory)
            self.assertEqual(find_project_wheel(directory), wheel)
            require_wheel_compliance_files(wheel)

    def test_rejects_wheel_missing_compliance_payload(self):
        with tempfile.TemporaryDirectory(prefix="continuum-project-wheel-") as temporary:
            wheel = self.make_wheel(Path(temporary), include_compliance=False)
            with self.assertRaisesRegex(RuntimeError, "missing compliance files"):
                require_wheel_compliance_files(wheel)


class ReproducibleBuildTest(unittest.TestCase):
    def make_sdist(self, path: Path, payload: bytes, mtime: int) -> None:
        member = tarfile.TarInfo("continuum_memory-0.1.0.dev0/payload.txt")
        member.size = len(payload)
        member.mtime = mtime
        with tarfile.open(str(path), mode="w:gz") as bundle:
            bundle.addfile(member, io.BytesIO(payload))

    def test_accepts_sdist_timestamp_variance_and_identical_wheels(self):
        with tempfile.TemporaryDirectory(prefix="continuum-reproducible-") as temporary:
            root = Path(temporary)
            first_sdist = root / "first.tar.gz"
            second_sdist = root / "second.tar.gz"
            first_wheel = root / "first.whl"
            second_wheel = root / "second.whl"
            self.make_sdist(first_sdist, b"same payload", 1)
            self.make_sdist(second_sdist, b"same payload", 2)
            first_wheel.write_bytes(b"same wheel")
            second_wheel.write_bytes(b"same wheel")
            compare_reproducible_artifacts(
                first_sdist,
                second_sdist,
                first_wheel,
                second_wheel,
            )

    def test_rejects_payload_and_wheel_drift(self):
        with tempfile.TemporaryDirectory(prefix="continuum-reproducible-") as temporary:
            root = Path(temporary)
            first_sdist = root / "first.tar.gz"
            second_sdist = root / "second.tar.gz"
            first_wheel = root / "first.whl"
            second_wheel = root / "second.whl"
            self.make_sdist(first_sdist, b"first payload", 1)
            self.make_sdist(second_sdist, b"second payload", 2)
            first_wheel.write_bytes(b"same wheel")
            second_wheel.write_bytes(b"same wheel")
            with self.assertRaisesRegex(RuntimeError, "source distributions differ"):
                compare_reproducible_artifacts(
                    first_sdist,
                    second_sdist,
                    first_wheel,
                    second_wheel,
                )

            self.make_sdist(second_sdist, b"first payload", 2)
            second_wheel.write_bytes(b"different wheel")
            with self.assertRaisesRegex(RuntimeError, "project wheels are not"):
                compare_reproducible_artifacts(
                    first_sdist,
                    second_sdist,
                    first_wheel,
                    second_wheel,
                )


class SupportedRuntimeTest(unittest.TestCase):
    def test_accepts_declared_maintained_python_matrix(self):
        for version in ((3, 11), (3, 12), (3, 13), (3, 14)):
            with self.subTest(version=version):
                runtime_check(version)

    def test_rejects_eol_and_undeclared_python_versions(self):
        for version in ((3, 9), (3, 10), (3, 15)):
            with self.subTest(version=version):
                with self.assertRaisesRegex(RuntimeError, "maintained CPython"):
                    runtime_check(version)


if __name__ == "__main__":
    unittest.main()
