# Verification gates and evidence

Integration state recorded 2026-09-24: current main's context/pagination, provider authority,
platform primitives and release packaging are combined with the held encrypted
application and offline rotation candidate. Native application verification has not run
successfully. Source-only checks, historical plaintext results and native-artifact passes
remain separate evidence; none establishes a pass for this combined application.

The earlier checkpoint `79b74d9ef177710e9bf1e0d4fe7bfd51a49befd4` recorded 28 passing
source/supply-chain tests. That count is historical, not the integrated suite's result.

## Supported application verification

Use Linux x86-64 and a supported CPython 3.11-3.14 interpreter in an isolated environment
with the exact manifest-locked `continuum-sqlcipher3` 0.6.2.post2 wheel, SQLCipher 4.19.0 /
SQLite 3.53.4, setuptools 80.9.0, and wheel 0.45.1. The native wheelhouse must contain exactly
those three matching wheels; filenames, regular-file status, and hashes are checked.
The separate build-tool wheelhouse must satisfy `packaging/build-requirements.txt` for
PEP 517 and SPDX validation; `packaging/backend-requirements.txt` locks the source-install
backend subset. Do not merge the two wheelhouse directories. The controlled setup
is implemented in `.github/workflows/encrypted-storage.yml` and
`scripts/verify_encrypted_application.py`. In an equivalent offline environment, run:

```bash
CONTINUUM_SQLCIPHER_WHEELHOUSE=/absolute/reviewed/wheelhouse \
  CONTINUUM_BUILD_WHEELHOUSE=/absolute/reviewed/build-tool-wheelhouse \
  /absolute/isolated/venv/bin/python scripts/verify.py
```

The command parses the checked-in JSON schemas, checks source whitespace, compiles every Python
module, runs the unit/integration suite with resource warnings promoted to errors, executes
the complete two-client fixture demo, builds a normalized PEP 517 source distribution and
wheel twice, requires identical hashes, validates their SPDX payload inventory and external
native dependency link, installs each artifact with the strict runtime into a fresh offline
environment, checks entry points and installed runtime origins, and runs
`git diff --check`. It also validates the checked-in patched-SQLCipher manifest, source SBOM,
recipe hashes, and negative regression tests. It requires the reviewed native backend and
offline build tools; it does not compile native wheels itself. The ordinary `verify` workflow
runs source/supply-chain checks. The four-ABI `encrypted-storage` workflow is the full native
application gate. See [SQLCIPHER_STORAGE.md](SQLCIPHER_STORAGE.md) for its scope and limits.

## Historical plaintext prototype result

Host: macOS 26.5.2, Darwin arm64; Python 3.9.6; Python SQLite 3.51.0 with FTS5.
The following records predate the encrypted application candidate. They are not evidence
that the current candidate runs on this host or supports Python 3.9. The prior plaintext
verifier also ran on GitHub-hosted Ubuntu 24.04; the current workflow split is described above.

## Native SQLCipher artifact gate

The separate `patched-sqlcipher-wheel` workflow targets Linux x86-64 on CPython 3.11-3.14.
For every matrix entry it performs two clean builds in the same digest-pinned manylinux
environment, requires byte-for-byte equality and a manifest-locked digest, deeply inspects
the wheel and ELF payload, installs it offline outside the checkout, and runs the encrypted
runtime/recovery suite, including default denial of loadable extensions. Only successful test
wheels are retained, for seven days.

Strict native runs passed for `2e90daa6161139de37cccd659703d9fa8fc25aea`; the exact three
run links are in [the native gate record](PATCHED_SQLCIPHER_WHEELS.md). Those runs validate
ephemeral native test artifacts. They do not establish that this later application candidate
passes, migrate a vault, publish a package, or prove release readiness. macOS arm64 is blocked
until an immutable builder/toolchain can satisfy the same evidence standard; Windows is not
a target.

## Held encrypted application gate

The separate `encrypted-storage` workflow repeats signed-source verification, A/B native
builds, strict wheel comparison/inspection, and the installed native regression suite for
all four supported ABIs. It then creates a fresh offline virtual environment with the three
hash-locked native wheels plus the separate locked build tools, verifies the installed
backend's version and origin, and runs the full application verifier in a disposable copy
of the checkout. All applicable tests, all 17 demo checks, reproducible distributions and
fresh offline installs must pass. This workflow uploads no wheels.

The refreshed Linux skip policy names exactly 91 platform-only methods with their
expected reasons: 62 Windows and 29 macOS methods, including the new native ACL,
SQLite-lock and recovery-journal cases. This inventory was enumerated from source,
not by importing or running tests. Native report acceptance remains unrun. Unknown,
missing, duplicate or changed skip IDs/reasons must fail; a count of 91 alone is insufficient. No cryptographic, encryption, rotation, recovery or
missing-runtime skip is allowed. This is a reviewed platform inventory, not a native pass.

The reproducible PEP 517/SPDX pipeline is implemented; combined application execution
remains pending. No source-test count replaces native evidence, independent human
acceptance, or the open license, privileged-installer compatibility, signing, macOS,
migration and backup/restore gates. Rotation tests prepare real native crash boundaries;
death observed inside the rekey call and power-loss durability are not demonstrated.

## Other platform checks

The macOS workflow runs source-only peer primitives. Four prepared macOS
application/APFS tests await an approved native artifact; no encrypted macOS startup or
full-verifier result is claimed. Windows filesystem and IPC primitives are isolated
experiments, not an application port. See [macOS](MACOS_BOUNDARY.md),
[Windows filesystem](WINDOWS_BOUNDARY.md), and [Windows IPC](WINDOWS_IPC.md).

## Historical initial-slice and native-only checklist

This table preserves the disposition before the current application integration. Its
plaintext behavior and passing counts describe that earlier evidence, not the held
application checkpoint. Current application status is recorded in the section above.

| Area | Result |
|---|---|
| Architecture/constitution/build brief/Relay contract | Passed review-by-construction; no external review claimed |
| Real SQLite lifecycle and FTS5 vertical slice | Passed on the macOS build host |
| Agent cannot self-accept through MCP; forged fields/replay | Passed fixture/API tests |
| Cross-project and provider-disclosure result/count isolation | Passed; timing/physical-shard noninterference not claimed |
| Correction, historical query, explicit conflict | Passed |
| Strict ISO/RFC 3339 validation and persisted retention expiry | Passed with deterministic injected-clock tests |
| Transactional forget, feedback removal, recall pruning, and live FTS cleanup | Passed |
| Filesystem owner/mode/type/link and socket identity checks | Passed on macOS; same-UID race resistance not claimed |
| Content-free HMAC audit verification/tamper detection | Passed prototype tests |
| Default runtime network access | No network code exists; packet-level instrumentation not run |
| Linux x86-64 validation | Full verifier passed on a GitHub-hosted Ubuntu 24.04 runner |
| Linux distribution package | Application source archive build/install passed; patched SQLCipher wheels are separate ephemeral CI test artifacts, not an application or release package |
| Windows runtime/CI | Unsupported and not run; POSIX boundary redesign tracked in issue #1 |
| SQLCipher/page/WAL/temp encryption | Native Linux artifact harness covers encryption, FTS5, WAL, temp, wrong-key, recovery, integrity, and plaintext canaries; application integration is not implemented and the prototype remains plaintext |
| Real Linux polkit/user-presence broker | Independent review and deterministic RSA/broker tests passed; real interactive pkexec/polkit smoke not run; issue #3 remains open |
| Backup/revocation/restore/key rotation/fault injection | Out of slice; not run |
| Native Codex/Claude/Antigravity profiles | Not run and never modified; fixtures only |
| Patched SQLCipher supply chain | Linux x86-64 CPython 3.11-3.14 pipeline pins and verifies sources/tools, builds twice, emits SBOM/provenance, and tests offline; independent acceptance, binding `NOASSERTION`, signing, application integration, and permanent distribution remain open |
| macOS patched SQLCipher artifacts | Blocked: no approved immutable macOS arm64 builder/toolchain currently meets the Linux evidence standard |
| Public retrieval benchmarks and latency distributions | Explicit non-goal; not run |

This historical result supports only the maturity label “experimental local prototype.” It is not
evidence for application encryption, production security, native-host compatibility, Linux packaging,
cross-platform behavior, physical erasure, backup revocation, or benchmark-leading recall.
