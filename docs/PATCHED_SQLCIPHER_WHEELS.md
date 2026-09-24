# Patched SQLCipher wheel supply-chain gate

Status: Issue #13 native supply-chain gate, consumed by the held Issue #7 application
candidate in this branch. No release or human security/license acceptance is claimed.

The September 23 candidate updates SQLCipher to 4.19.0 for the vendor's September 8
fixes. Historical September 7 OSV evidence is preserved. See the
[dated source and security review](../packaging/sqlcipher/SOURCE_REVIEW_2026-09-23.md)
for the advisory, exact source identities, unresolved license status, and remaining
acceptance gates. Strict native CI passed for
`2e90daa6161139de37cccd659703d9fa8fc25aea` in the
[PR](https://github.com/Oussamoux1234/continuum-memory/actions/runs/35872266003),
[direct-head](https://github.com/Oussamoux1234/continuum-memory/actions/runs/35872463590), and
[push](https://github.com/Oussamoux1234/continuum-memory/actions/runs/35873404030) runs.
The dated source review preserves its earlier checkpoint. The separate application
checkpoint `79b74d9ef177710e9bf1e0d4fe7bfd51a49befd4` has 28 passing source tests;
its initial native application CI remains pending. The native results do not establish
application encryption or integration acceptance.

## Scope

The current gate builds `continuum-sqlcipher3` 0.6.2.post2 for Linux x86-64 on CPython
3.11, 3.12, 3.13, and 3.14. It preserves the `sqlcipher3` import and DB-API surface while
replacing the vulnerable native dependency set evaluated in Issue #7 with SQLCipher 4.19.0 /
SQLite 3.53.4 / OpenSSL 3.5.8 LTS.

This unmerged application candidate depends on the strict `0.6.2.post2` wheel and refuses
a missing or mismatched SQLCipher backend. The native wheels remain ephemeral CI test
artifacts; signing and permanent distribution are unapproved. See
[the held application contract](SQLCIPHER_STORAGE.md) for runtime, key, and migration limits.
Windows is unsupported. macOS arm64 is
blocked because the project has not identified and approved an immutable macOS builder and
toolchain equivalent to the digest-pinned manylinux environment. A mutable GitHub-hosted
macOS runner label is not sufficient evidence for the same reproducibility claim.

## Trust and build sequence

1. The native workflow checks out without persisted credentials, pulls one digest-pinned manylinux
   image, and uses that image for acquisition and every later phase. The acquisition container
   is read-only apart from bounded temporary/source mounts and is the only phase with network
   access. `scripts/fetch_patched_sqlcipher_sources.py` downloads every source, detached
   signature, public key, setuptools wheel, and wheel build tool from the exact HTTPS URLs in
   `packaging/sqlcipher/manifest.json`.
2. It checks every SHA-256, archive root/path, SQLCipher commit comment, manifest UUID,
   embedded SQLite version, license digest, and signing-key primary fingerprint. GPG must
   validate both SQLCipher and OpenSSL detached signatures before it writes
   `source-verification.json`.
3. For each Python ABI, two separate network-disabled, read-only containers use the same
   immutable manylinux image digest, fixed PATH/locale/timezone, bounded executable tmpfs,
   dropped capabilities, and `no-new-privileges`. Each rechecks the source evidence and
   hash-locked project recipe, builds static OpenSSL without modules or shared libraries,
   generates the SQLCipher amalgamation, runs its `sourcetest` structural check, replaces the
   reviewed binding amalgamation, and builds/repairs exactly one wheel with pinned offline
   build tools. SQLCipher
   intentionally differs from the SQLite Fossil manifest bundled in its release archive, so
   the inherited SQLite `make verify-source` target is not a valid SQLCipher authenticity
   check. Authenticity is instead bound to the pinned archive digest, detached signature,
   release commit, and embedded SQLite manifest UUID before extraction. The minimal image omits
   IPC-Cmd and Time-Piece; two hash-locked project shims implement only the `can_run`,
   local-time, exact release-date parsing, and fixed output-format operations used by the
   reviewed OpenSSL 3.5.8 configure source. They reject relative PATH entries and unsupported
   date formats and are loaded from the read-only checkout.
4. The inspector requires byte-identical builds and the manifest-locked artifact digest. It
   enforces the exact ABI/platform filename, bounded archive size, complete member and RECORD
   inventories, exact Python/metadata/license payloads, one native extension, x86-64 ELF and
   manylinux tags, the reviewed glibc symbol ceiling, no RPATH/RUNPATH, static OpenSSL, the
   exact host-library set, RELRO/non-executable-stack/stack-protector hardening, one exported
   initializer, and exact embedded component versions.
5. A fresh virtual environment outside the checkout installs the wheel with isolated pip,
   no index, cache, dependency resolution, bytecode compilation, user site, or `PYTHONPATH`.
   It tests interpreter/ABI and import origin, active encryption, default denial of loadable
   extensions, wrong/missing keys, encrypted header/WAL/FTS/temp canaries, crash recovery, and
   SQLite plus SQLCipher integrity.
6. Evidence binds the wheel to its producing commit/run context, raw source-verification
   record, retained dated exact-commit OSV responses, exact recipe hashes, native inspection,
   licenses, and artifact-specific SPDX 2.3 SBOM. An empty OSV response means no known
   finding at query time, not proof of safety. The unresolved binding license remains
   `NOASSERTION`.

The `patched-sqlcipher-wheel` workflow uploads only a fully validated wheel and its evidence.
A failed build, comparison, inspection, or runtime test cannot retain a wheel under the
normal artifact name. Successful artifacts from that workflow are retained for seven days
for review. They are not a GitHub Release, PyPI package, installer, container, or permanent
distribution.

The separate `encrypted-storage` workflow repeats the strict native gates, then installs
the locked wheel and pinned build tools into a fresh environment and runs full application
tests, the 17-check fixture demo, and offline source-package installation in a disposable
checkout with networking disabled. Missing or mismatched backends, skipped tests, and
incomplete verifier output fail its gate. It uploads no wheels. This describes the gate;
successful native application execution is still pending at the application checkpoint above.

## Reproduce the CI slice

The documented path requires Docker, GPG, network access for acquisition, and the exact
Linux x86-64 builder. Do not use an unlocked or mutable image tag.

```bash
docker pull quay.io/pypa/manylinux_2_28_x86_64@sha256:53390351aeb4688114b02c36a23b3e6ce1166ee9b7afc5df1a4f776354fc764c
```

Acquisition must also run inside that pinned container; the complete commands, isolation
flags, reviewed PATH, matrix keys, and volume mounts are the source-controlled workflow in
`.github/workflows/patched-sqlcipher-wheel.yml`. Do not substitute host Python, GPG, Perl,
compiler, linker, build tools, or auditwheel. Local macOS does not provide genuine Linux
build evidence.

## Known variance and rollback

The container digest pins the manylinux filesystem, four CPython runtimes, GCC/binutils,
auditwheel, GPG, Perl, and support tools as one immutable input. Their captured versions and
binary hashes are evidence, not independent download pins. GitHub runner kernel, Docker
engine, CPU model/scheduling, registry availability, and the Actions service remain outside
that image and cannot be fully pinned. Network access is disabled after verified acquisition.
`SOURCE_DATE_EPOCH` and deterministic environment controls cover the complete native build.

This branch changes the application dependency and storage behavior as an unmerged
candidate. Keep it unintegrated until its application evidence and independent reviews pass.
The previous plaintext application cannot be treated as a reader or recovery path for an
encrypted candidate vault. Plaintext conversion is not performed by normal open, bootstrap,
or schema upgrade. The separate migration and recovery boundaries are recorded in
[SQLCIPHER_STORAGE.md](SQLCIPHER_STORAGE.md); this candidate does not authorize migration of
a real vault. Existing ephemeral native test artifacts may expire without affecting an
installed application release.

## Remaining decisions and gates

- Obtain and approve an immutable macOS arm64 builder/toolchain before attempting CPython
  3.11-3.14 artifacts under the same trust standard.
- Complete independent security and license review, including the binding `NOASSERTION`.
- Select the artifact signing identity, trust root, transparency policy, verification
  procedure, and revocation procedure. This work defines the boundary but does not sign.
- Independently validate this held consumer's runtime and key handling, and separately
  authorize and validate plaintext migration, backup/restore, and rollback. Issue #7 and
  PR #12 remain blocked until the required application and release gates are accepted.
