# Patched SQLCipher wheel supply-chain gate

Status: Issue #13 vertical slice; CI test artifacts only.

## Scope

The first gate builds `continuum-sqlcipher3` 0.6.2.post1 for Linux x86-64 / CPython 3.14.
It preserves the `sqlcipher3` import and DB-API surface while replacing the vulnerable
native dependency set evaluated in Issue #7 with SQLCipher 4.18.0 / SQLite 3.53.4 /
OpenSSL 3.5.8 LTS. Windows is unsupported. macOS arm64 and Python 3.11-3.13 remain required
expansion targets, not current support claims.

## Trust and build sequence

1. `scripts/fetch_patched_sqlcipher_sources.py` downloads every source, detached signature,
   public key, setuptools wheel, and wheel build tool from the exact HTTPS URLs in
   `packaging/sqlcipher/manifest.json`.
2. It checks every SHA-256, archive root/path, SQLCipher commit comment, manifest UUID,
   embedded SQLite version, license digest, and signing-key primary fingerprint. GPG must
   validate both SQLCipher and OpenSSL detached signatures before it writes
   `source-verification.json`.
3. Two separate network-disabled containers use the same immutable manylinux image digest.
   Each rechecks the signed-source evidence, builds static OpenSSL without modules or shared
   libraries, runs SQLCipher `make verify-source`, generates the amalgamation, replaces the
   reviewed binding amalgamation, and builds/repairs one wheel. The minimal image omits
   IPC-Cmd and Time-Piece; two hash-locked project shims implement only the `can_run`,
   local-time, exact release-date parsing, and fixed output-format operations used by the
   reviewed OpenSSL 3.5.8 configure source. They reject empty PATH entries and unsupported
   date formats and are loaded from the read-only checkout.
4. The inspector requires byte-identical builds, the exact ABI/platform filename, one native
   member, no dynamic OpenSSL dependency, only the allowlisted host libraries, one exported
   initializer symbol, exact embedded version markers, exact license payloads, conservative
   license metadata, and eventually the locked wheel SHA-256.
5. A fresh virtual environment installs the wheel with no index or dependencies and tests
   version identity, active encryption, wrong/missing keys, encrypted header/WAL/FTS/temp
   canaries, crash recovery, and SQLite plus SQLCipher integrity.

The GitHub Actions artifact is retained for seven days for review. It is not a GitHub
Release, PyPI package, installer, container, or permanent distribution.

## Reproduce the CI slice

The documented path requires Docker, GPG, network access for acquisition, and the exact
Linux x86-64 builder. Do not use an unlocked or mutable image tag.

```bash
python3 scripts/fetch_patched_sqlcipher_sources.py \
  --destination work/patched-sqlcipher/sources
mkdir -p work/patched-sqlcipher/build-a work/patched-sqlcipher/build-b
docker pull quay.io/pypa/manylinux_2_28_x86_64@sha256:53390351aeb4688114b02c36a23b3e6ce1166ee9b7afc5df1a4f776354fc764c
```

The complete, quoted volume-mount commands are the source-controlled workflow in
`.github/workflows/patched-sqlcipher-wheel.yml`. Local macOS does not provide genuine Linux
build evidence; use the workflow rather than silently substituting the host compiler.

## Known variance and rollback

The container digest pins the manylinux filesystem, CPython, GCC/binutils, auditwheel, and
support tools as one immutable input. Their separately reported version strings are evidence,
not independent download pins. GitHub runner kernel, Docker engine, CPU model/scheduling, and
the Actions service remain outside that image and cannot be fully pinned. Network access is
disabled during both builds and all tests.

Rollback before publication means closing the focused PR and deleting its short-lived CI
artifacts. No application dependency changes in this PR, so Continuum runtime behavior does
not change. A future consumer PR must keep the previous reviewed wheel available until the
new wheel passes install, data-open, integrity, and rollback tests.

## Remaining decisions and gates

- Lock the first verified wheel SHA-256 after two builds and rerun the workflow.
- Expand the same two-build and runtime gate to Linux CPython 3.11-3.13.
- Add independently reviewed macOS arm64 builds for CPython 3.11-3.14.
- Complete independent security and license review, including the binding `NOASSERTION`.
- Select the artifact signing identity, trust root, transparency policy, verification
  procedure, and revocation procedure. This work defines the boundary but does not sign.
- Only then may a separate PR change Continuum Memory runtime dependencies. Issue #7 and
  PR #12 remain blocked until that consumer integration is independently accepted.
