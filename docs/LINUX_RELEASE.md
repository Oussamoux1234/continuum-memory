# Verify Linux distributions before any release

This produces **unsigned, unpublished experimental prototype artifacts**. It does not
certify encryption, real polkit user presence, backups, native Windows/macOS support,
or production readiness. No publication or signing credentials are used by this workflow.

## Prerequisites and offline preparation

The encrypted application candidate requires Linux x86-64, CPython 3.11–3.14, and exactly
`continuum-sqlcipher3` 0.6.2.post2 with SQLCipher 4.19.0 / SQLite 3.53.4. The native artifact
gate has separate recorded results; the combined application/release verification has
not run successfully. There is no standard-library SQLite fallback or Python 3.9 support.
Both local transports enforce an explicit 64-container JSON nesting limit before parsing,
independent of a Python interpreter's recursion behavior. Delimiters inside strings do not
count. Over-deep input receives the existing bounded parse error and is never dispatched.

Start from the exact reviewed checkout. Two separate input directories are required:

- The strict native wheelhouse contains exactly the selected ABI's manifest-locked post2
  wheel, setuptools 80.9.0, and wheel 0.45.1. Obtain it through the
  [reviewed native pipeline](PATCHED_SQLCIPHER_WHEELS.md), not a package-index substitution.
- The build-tool wheelhouse contains the hash-pinned PEP 517 and SPDX verification tools
  from `packaging/build-requirements.txt`. Its backend subset is locked separately in
  `packaging/backend-requirements.txt`. Keep it separate from the three-wheel native directory.

The following **preparation** downloads only build/verification tools. It is separate from
native source acquisition, offline verification, and publication:

```bash
python3 -m venv .venv
.venv/bin/python -m pip download --only-binary=:all: --require-hashes \
  -r packaging/build-requirements.txt --dest work/build-wheels
.venv/bin/python -m pip install --no-index --find-links work/build-wheels \
  --require-hashes -r packaging/build-requirements.txt
```

An offline machine instead receives that exact reviewed wheelhouse via its normal trusted
transfer process. Do not remove `--require-hashes`, add an online fallback, or substitute
unreviewed wheels to make a missing dependency pass. The build-tool lock includes Linux
x86-64 and macOS arm64 hashes; those hashes do not establish an approved macOS native
backend or application support.

## Complete verification and artifacts

After installing the exact reviewed native runtime and build tools into the isolated
Linux environment, the combined candidate gate is:

```bash
export CONTINUUM_SQLCIPHER_WHEELHOUSE=/absolute/reviewed/native-wheelhouse
export CONTINUUM_BUILD_WHEELHOUSE="$PWD/work/build-wheels"
.venv/bin/python scripts/verify.py
.venv/bin/python scripts/release_package.py --output work/release \
  --wheelhouse "$CONTINUUM_BUILD_WHEELHOUSE"
```

These are verification entry points, not a recorded pass. The proposed Linux test policy
requires exactly 91 named platform-inapplicable skips: 62 Windows and 29 macOS methods.
The refreshed IDs and reasons were enumerated from source; this candidate's native
matrix remains unexecuted. No applicable cryptographic, encryption, rotation, or
recovery test may be skipped. See
[the evidence boundary](VERIFICATION.md).

The output directory must be empty or absent; the builder refuses to overwrite an earlier
result. The verifier needs the local wheelhouse and performs no package-index access.
Before creating output, it checks every installed tool version against the lock and uses
an offline hash-checked pip dry run, ignoring installed packages, to validate the complete
build-tool wheelhouse; installed-byte provenance still relies on the reviewed setup above.
`PIP_NO_INDEX=1`, `PIP_CONFIG_FILE=/dev/null`, no build isolation downloads, and no pip cache
are used during builds and installs. This is an offline dependency-resolution check, not
a packet-capture or operating-system network-isolation proof.

The output contains:

- `continuum_memory-0.1.0.dev0.tar.gz`: PEP 517 source distribution.
- `continuum_memory-0.1.0.dev0-py3-none-any.whl`: wheel built from that source archive.
- `sbom.spdx.json`: complete file/checksum inventory of both payloads, validated with the
  independent SPDX Python tools and reconciled against every archive member.
- `build-evidence.json`: unsigned local evidence with the source commit, dirty flag,
  source-input digest, timestamps, Python/SQLite/build versions, and subject hashes.

Both artifacts are installed into separate fresh virtual environments with offline pip.
Each installation exercises `continuum --version`, `memoryd --help`, `continuum-mcp --help`,
and `continuum-polkit-helper --help`, outside the source checkout and without `PYTHONPATH`.
Both fresh environments require the exact hash-locked native dependency; the source
install also provisions its hash-pinned PEP 517 backend.
No polkit privilege prompt, actual vault, or installed AI-client profile is touched.
Separately, the wheel environment is renamed and its original path removed; the relocated
interpreter runs `-I -m continuum_memory.polkit_helper --help` from an unrelated directory.
That verifies the installed wrapper's invocation strategy, not a real privileged approval.

The payload SBOM inventories the application archives and links the exact post2 dependency
as external and unbundled, with `NOASSERTION` declared/concluded licensing and hashes of
its manifest and source SBOM. The selected ABI wheel hash and installed-runtime proof are
recorded in `build-evidence.json`; native source/binary evidence remains in the separate
SQLCipher pipeline. The payload SBOM does **not** inventory the host OS or verification
toolchain. Build-tool pins/hashes live in
`packaging/build-requirements.txt`. Host versions appear in the build evidence. Licensing
conclusions remain `NOASSERTION`; `Apache-2.0` is the project's declared license, not a
third-party legal review. The native wheel is not bundled into the application wheel or
approved by this payload SBOM. Runtime metadata must name only the exact reviewed post2
dependency; unexpected dependencies fail the release gate. Neither payload checks nor the
native source SBOM settle the binding/aggregate `NOASSERTION` license hold.

## Reproducibility boundary

Each invocation builds twice in independent clean temporary trees and requires identical
artifact SHA-256 digests. Source bytes are copied from tracked and non-ignored new files;
dirty input is recorded explicitly, so a local development result cannot impersonate a
clean release revision. Publication must use a clean reviewed commit.

`SOURCE_DATE_EPOCH` defaults to the commit timestamp, with an explicit override permitted.
The source tarball uses sorted regular members, normalized ownership/modes/timestamps,
and a fixed gzip header timestamp. Its file bytes are unchanged. The wheel backend uses
the same epoch, deterministic Python hash seed, and pinned backend versions. The wheel
is always built from the normalized source distribution, not a stale build directory.

This proves repeatability within the recorded environment. It does **not** prove hermetic
or cross-operating-system builds, independently trusted builders, or equivalence across
Python/zlib versions. To investigate a mismatch, compare archive members and evidence;
never accept a changed hash merely to make CI green. GitHub runner images remain managed
inputs, not immutable machine images.

## Privileged approval-helper compatibility gate

The privileged stager requires the application's exact single dependency header,
`continuum-sqlcipher3==0.6.2.post2`; it rejects missing, additional or changed requirements.
The unchanged wheel is installed offline with `--no-deps` into an approval-only environment.
SQLCipher is deliberately absent there: the fixed helper's import closure uses only its
approval/security modules and the standard library, with system OpenSSL for signing.
This is not a usable environment for the daemon or the full application.

A separate packaging probe stages the actual built wheel, installs it without SQLCipher
in a fresh environment, verifies installed module origins and absent backend/storage imports,
and runs isolated helper `--help` before and after relocation. On success, build evidence
records `helper_only_runtime`; `privileged_installation_tested` remains false. This new
probe still needs hosted execution at the selected revision. Neither it nor the existing
native application smoke test proves privileged installation, provisioning or real human
presence. Those steps require separate operator approval and acceptance. Build tools are
never installed as root.

The wheel argument must be an absolute canonical regular path (no symlink/hardlink), with
the exact expected name and metadata. The installer copies it into root-owned staging
before installing offline, without executing a source build or an existing user virtual
environment. Filename and metadata checks are **not signatures**. The source launcher and
policy use the fixed helper path; the launcher invokes the activated environment's absolute
Python interpreter with `-I -m`, avoiding console-script shebangs pointing at the old staging
directory. The launcher and
policy must come from the same reviewed revision as the wheel; the operator remains
responsible for checking that evidence. See [the broker runbook](LINUX_APPROVAL_BROKER.md).

## Publication, signatures, and provenance gate

Issue #2 provides artifact-generation and verification machinery; it does not authorize a
release. Publish only after the exact clean revision passes the complete supported Linux
matrix and code review, and the owner explicitly approves the maturity label and release.
Any remaining encryption, approval, or platform limitation must remain visible.

Before a signed release, the owner must approve the release signer identity, allowed
repository/workflow/ref, key or workload-identity custody, verification policy, and
revocation/recovery process. No signing identity is selected or created here. Local JSON
and CI artifact hashes are integrity evidence, **not authenticated provenance**.

For a future owner-approved GitHub attestation workflow, verification would start with:

```bash
gh attestation verify ./continuum_memory-VERSION-py3-none-any.whl \
  --repo Oussamoux1234/continuum-memory \
  --signer-workflow Oussamoux1234/continuum-memory/.github/workflows/REVIEWED-RELEASE-WORKFLOW.yml \
  --source-ref refs/tags/REVIEWED-TAG
```

The uppercase values are placeholders, not an existing workflow/tag. Require the expected
subject digest, approved source commit/ref, signer workflow identity, and transparency
verification result. Also authenticate the SBOM and evidence subjects. Missing/invalid
attestations must fail the signed-release gate; do not treat an unsigned artifact as signed.
An offline consumer must receive and verify the attestation bundle plus an independently
approved trust root/policy; a downloaded checksum from the same untrusted location is not
such a root. GitHub CI here has read-only repository permissions and cannot sign or publish.

## Primary references

- [PEP 517 build and source-distribution contract](https://peps.python.org/pep-0517/)
- [Setuptools pyproject configuration](https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html)
- [SOURCE_DATE_EPOCH convention](https://reproducible-builds.org/docs/source-date-epoch/)
- [SPDX Python tools](https://github.com/spdx/tools-python)
- [GitHub attestation verification flags](https://cli.github.com/manual/gh_attestation_verify)
- [Python support lifecycle](https://devguide.python.org/versions/)
