# Verification record

Historical plaintext prototype baseline recorded 2026-09-03; native supply-chain and held
application checkpoints recorded 2026-09-23. Results below identify their separate scopes.

Current application checkpoint: `79b74d9ef177710e9bf1e0d4fe7bfd51a49befd4`.
The 28 source/supply-chain verification tests passed locally. Initial native application CI
is pending; no successful encrypted application execution is claimed for this checkpoint.

## Supported application verification

Use Linux x86-64 and a supported CPython 3.11-3.14 interpreter in an isolated environment
with the exact manifest-locked `continuum-sqlcipher3` 0.6.2.post2 wheel, setuptools 80.9.0,
and wheel 0.45.1 installed. The wheelhouse must contain exactly those three matching wheels;
the verifier checks their filenames, regular-file status, and hashes. The controlled setup
is implemented in `.github/workflows/encrypted-storage.yml` and
`scripts/verify_encrypted_application.py`. In an equivalent offline environment, run:

```bash
CONTINUUM_SQLCIPHER_WHEELHOUSE=/absolute/reviewed/wheelhouse \
  /absolute/isolated/venv/bin/python scripts/verify.py
```

The command parses the checked-in JSON schemas, checks source whitespace, compiles every Python
module, runs the unit/integration suite with resource warnings promoted to errors, executes
the complete two-client fixture demo, builds a source distribution, installs that exact
archive offline into a temporary virtual environment, exercises its entry points, and runs
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

- 46 unit/integration tests: passed.
- MCP fixture protocol `2026-07-28`: discovery, exact six-tool list, strict unknown-field and
  size rejection: passed.
- Pinned legacy fixture protocol `2025-11-25`: initialization and tool listing passed.
- Lifecycle demo: 17 checks passed, including Agent A proposal, exact user review, Agent B
  provenance recall, correction/history, recorded-time lookup, conflict surfacing,
  grant/idempotency replay resistance, two-project and provider-policy isolation,
  forget/exact/FTS cleanup, and content-free audit/deletion receipts.
- SQLite `integrity_check`: `ok`; audit HMAC chain: valid; deliberate audit mutation:
  detected at the first invalid event.
- Secret canary rejection, FTS syntax generation, changed-preview rejection, feedback
  non-mutation, context byte budget, and second-daemon fail-closed behavior: passed.
- Forget regression: one contentful feedback canary deleted, all affected recall-result
  arrays pruned, and the pre-delete recall handle returned `not_found`: passed.
- Retention regression with an injected UTC clock: fixed-width normalization, one persisted
  `expired` transition and audit event, current recall denial, historical retrieval, and
  preview/apply deadline checks: passed.
- Strict time validation: invalid calendar dates, naive/space-separated timestamps,
  invalid 24-hour values, unknown/out-of-range offsets, and trailing data rejected; UTC
  offset and date-only normalization: passed.
- Filesystem boundary: data-directory/ancestor/database/capability/socket symlinks,
  database and capability hardlinks, and group/world-accessible directory/file modes
  rejected: passed.
- Portable hyphen/underscore source-distribution discovery, exact filename and embedded
  name/version validation, invalid/multiple artifact rejection, offline archive install,
  and the `continuum`, `memoryd`, `continuum-mcp`, and `continuum-polkit-helper` entry
  points: passed.
- Linux approval regressions: exact request binding, stdin-only broker transport,
  cancellation/malformed-helper failure, caller mismatch, fixed root-helper policy,
  per-UID key selection, real RSA sign/verify, HMAC downgrade rejection, cross-challenge
  rejection, replay rejection, unprovisioned-runtime failure, explicit test-only prototype
  injection, exact signed-field and daemon-expiry rejection, policy validation, locked
  provisioning and umask isolation, Unicode-safe preview rendering, isolated installer
  environment, and agent denial: passed without invoking polkit.

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
hash-locked wheels, verifies the installed backend's version and origin, and runs the full
application verifier in a disposable copy of the current checkout. All tests, all 17 demo
checks, and source-package installation must pass. Skipped tests or incomplete results fail
the gate. This workflow uploads no wheels.

This is implemented verification behavior, not a recorded application pass. At local
checkpoint `79b74d9ef177710e9bf1e0d4fe7bfd51a49befd4`, the 28 passing source tests do not
replace pending native application execution, independent human acceptance, or the open
license, signing, macOS, migration, and backup/restore gates.

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
