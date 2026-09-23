#!/usr/bin/env python3
"""Revalidate a previously signature-verified source bundle without network access."""

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

try:
    from scripts.fetch_patched_sqlcipher_sources import (
        DEFAULT_MANIFEST,
        inspect_project_inputs,
        inspect_sources,
        is_single_regular_file,
        iter_downloads,
        load_json_strict,
        sha256,
        validate_manifest,
    )
except ModuleNotFoundError:  # Direct script execution places scripts/ on sys.path.
    from fetch_patched_sqlcipher_sources import (
        DEFAULT_MANIFEST,
        inspect_project_inputs,
        inspect_sources,
        is_single_regular_file,
        iter_downloads,
        load_json_strict,
        sha256,
        validate_manifest,
    )


def verify_bundle(sources: Path, manifest_path: Path) -> None:
    manifest = validate_manifest(load_json_strict(manifest_path))
    inspect_project_inputs(ROOT, manifest)
    for label, record in iter_downloads(manifest):
        path = sources / record["filename"]
        if not is_single_regular_file(path) or sha256(path) != record["sha256"]:
            raise RuntimeError("verified input is missing or modified: %s" % label)
    inspect_sources(sources, manifest)
    evidence_path = sources / "source-verification.json"
    if not is_single_regular_file(evidence_path):
        raise RuntimeError("source signature evidence is missing, linked, or not regular")
    evidence = load_json_strict(evidence_path)
    if evidence.get("status") != "VERIFIED" or evidence.get("manifestSha256") != sha256(
        manifest_path
    ):
        raise RuntimeError("source signature evidence is missing or does not match the manifest")
    signatures = evidence.get("signatures")
    if not isinstance(signatures, dict):
        raise RuntimeError("source signature evidence is malformed")
    for label in ("SQLCipher", "OpenSSL"):
        expected = manifest["sources"][label]["signingKey"]["primaryFingerprint"]
        if signatures.get(label) != {
            "primaryFingerprint": expected,
            "signatureVerified": True,
        }:
            raise RuntimeError("source signature evidence changed: %s" % label)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    arguments = parser.parse_args()
    verify_bundle(arguments.sources.resolve(), arguments.manifest.resolve())
    print("patched SQLCipher build inputs: verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
