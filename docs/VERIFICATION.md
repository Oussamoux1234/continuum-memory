# Verification record

Last run: 2026-09-05.

## Supported command

```bash
python3 scripts/verify.py
```

After the exact hash-pinned SQLCipher and build-tool wheels are acquired and installed as
documented in `SQLCIPHER_STORAGE.md`, the command parses both JSON schemas, checks source whitespace,
validates the third-party notices, exact upstream license-file hashes, hash-pinned external SPDX
validator manifest, strict SPDX inventory, and frozen dependency-audit evidence, compiles every
Python module, runs the unit/integration suite with resource warnings promoted to errors,
executes the complete two-client fixture demo, independently builds two source distributions and
two project wheels under a fixed build epoch, requires identical wheel bytes and normalized sdist
payloads, requires the notices/licenses/SBOM/audit evidence in the built artifacts,
inspects the selected SQLCipher wheel's metadata, license, native payload, and compiled
component markers, validates the dependency wheel filenames and digests, installs those wheels
and the exact source archive offline without build isolation into a temporary virtual
environment with no checkout `PYTHONPATH`, exercises the installed entry points, and runs
`git diff --check`. A separate Actions job installs the hash-pinned `spdx-tools==0.8.5` toolchain
and performs full external SPDX 2.3 validation.

## Observed result

Host: macOS 26.5.2, Darwin arm64; Python 3.14.6; `sqlcipher3` 0.6.2 with
SQLCipher 4.12.0 community, SQLite 3.51.1, and FTS5.
The same command is required on GitHub-hosted Ubuntu 24.04 x86-64 across Python 3.11,
3.12, 3.13, and 3.14 by the
[verify workflow](https://github.com/Oussamoux1234/continuum-memory/actions/workflows/verify.yml).

- 72 unit/integration tests: passed.
- MCP fixture protocol `2026-07-28`: discovery, exact six-tool list, strict unknown-field and
  size rejection: passed.
- Pinned legacy fixture protocol `2025-11-25`: initialization and tool listing passed.
- Lifecycle demo: 17 checks passed, including Agent A proposal, exact user review, Agent B
  provenance recall, correction/history, recorded-time lookup, conflict surfacing,
  grant/idempotency replay resistance, two-project and provider-policy isolation,
  forget/exact/FTS cleanup, and content-free audit/deletion receipts.
- SQLite `integrity_check`: `ok`; audit HMAC chain: valid; deliberate audit mutation:
  detected at the first invalid event.
- SQLCipher `cipher_integrity_check`: no findings; audit diagnostics reported
  `sqlcipher_integrity=ok`.
- Encrypted-storage regressions: random 32-byte owner-only key creation; correct-key reopen;
  missing, malformed, wrong, linked, or permissive key rejection; no stdlib SQLite fallback;
  runtime-unavailable bootstrap without partial vault creation; plaintext legacy database
  rejection without mutation; committed-WAL recovery after unclean process exit: passed.
- Incompatible encrypted vault rejection: an unsupported schema stayed byte-for-byte
  unchanged, retained `journal_mode=DELETE`, and gained no sidecars: passed.
- Storage-key durability: file creation and fsync, vault-directory fsync, database creation,
  and database open occurred in the required order; a real directory descriptor was used:
  passed.
- Connection hardening: foreign keys, trusted schema, busy timeout, FULL sync, secure
  delete, in-memory temp storage, disabled memory mapping, query-only state, and WAL were
  all read back exactly; every simulated mismatch failed closed: passed.
- A canonical claim/evidence/subject canary remained searchable through FTS while absent
  from the live database, WAL, SHM, and configured SQLite temporary-file directory;
  `temp_store=MEMORY` and a non-plaintext database header were verified.
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
  name/version validation, invalid/multiple artifact rejection, exact SQLCipher/build-tool
  wheel filename/hash validation, offline dependency/archive install without build
  isolation, removed checkout `PYTHONPATH`, and the `continuum`, `memoryd`, `continuum-mcp`, and
  `continuum-polkit-helper` entry points: passed.
- Third-party inventory regressions: missing notices or copied licenses, component records,
  wheel hashes, license declarations/text, overstated license conclusions, duplicate JSON keys,
  changed validator hashes, suppressed audit blockers, embedded SQLCipher/SQLite/OpenSSL markers,
  dependency relationships, unexpected native libraries, and project-wheel compliance payloads
  all fail closed. All eight hash-pinned macOS arm64 and Linux x86-64 wheel archives passed the
  portable metadata/license/native-component inspection; the current job repeats it for its
  selected wheel.
- Point-in-time dependency audit: OpenSSL 3.6.0 has 48 vendor-classified findings (2 High,
  10 Moderate, 36 Low), and SQLite 3.51.1 predates fixes for CVE-2026-11822 and
  CVE-2026-11824. Exact sqlcipher3 and SQLCipher queries returned no known findings in the
  queried sources, which is explicitly not treated as proof of safety. The frozen audit keeps
  the release decision blocked.
- Replacement-decision regressions: the verifier requires the minimum patched SQLCipher,
  SQLite, and OpenSSL versions, the preferred LTS baseline, a null selected artifact, explicit
  patched-wheel unavailability, and the blocked decision record. A stale evidence date,
  weakened version floor, invented artifact, false wheel-availability claim, or missing
  decision evidence fails closed. Mutated source hashes, commit identities, build
  requirements, or overstated signature verification also fail. No dependency lock, native
  marker, license conclusion, or SPDX component was changed because no reviewed installable
  replacement exists.
- External SPDX validation: `spdx-tools==0.8.5` under CPython 3.14.6 validated the SPDX 2.3
  document with exit 0 and no messages. Actions repeats this on Ubuntu 24.04 / Python 3.14 from
  a complete hash-pinned validator wheel set.
- Reproducibility regressions: the two project wheels were byte-identical; the two sdists had
  identical normalized member paths, types, modes, owners, links, sizes, and content hashes.
  Their raw gzip/tar timestamps varied, so raw sdist byte reproducibility and cross-platform
  reproducibility are not claimed. Timestamp-only variance is accepted; payload drift fails.
- Distribution notices: the sdist and project wheel contain `LICENSE`,
  `THIRD_PARTY_NOTICES.md`, the exact sqlcipher3/SQLCipher/OpenSSL release license files, and
  `sbom/continuum-memory.spdx.json`; both also contain `security/dependency-audit.json`. The sdist
  additionally contains the validator lock, release-readiness record, and encrypted-storage
  dependency decision. The offline source
  installation remains the package install test.
- Focused standard-library trace coverage for the packaging/readiness verification paths was
  525 of 727 executable lines (72.2%) in `scripts.verify` and 379 of 385 (98.4%) in
  `tests.test_verify`; the complete gate separately exercises the packaging success path.
- Linux approval regressions: exact request binding, stdin-only broker transport,
  cancellation/malformed-helper failure, caller mismatch, fixed root-helper policy,
  per-UID key selection, real RSA sign/verify, HMAC downgrade rejection, cross-challenge
  rejection, replay rejection, unprovisioned-runtime failure, explicit test-only prototype
  injection, exact signed-field and daemon-expiry rejection, policy validation, locked
  provisioning and umask isolation, Unicode-safe preview rendering, isolated installer
  environment, and agent denial: passed without invoking polkit.

## Initial-slice checklist disposition

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
| Linux distribution package | Two-build wheel byte identity, normalized-sdist payload identity, content inspection, and source archive installation passed; raw sdist timestamps vary; signing and publication not run |
| Windows runtime/CI | Unsupported and not run; POSIX boundary redesign tracked in issue #1 |
| SQLCipher/page/WAL/temp/FTS candidate | Maintained-Python 3.14 local implementation and regression gate passed; the 3.11–3.14 Linux matrix is mandatory; known OpenSSL/SQLite findings and independent review block Issue #7 closure or an accepted encryption claim |
| Real Linux polkit/user-presence broker | Independent review and deterministic RSA/broker tests passed; real interactive pkexec/polkit smoke not run; issue #3 remains open |
| Backup/revocation/restore/key rotation/fault injection | Out of slice; not run |
| Native Codex/Claude/Antigravity profiles | Not run and never modified; fixtures only |
| Vulnerability/license audit, SBOM, signatures, reproducible Linux payload | Exact inventory, copied notices, conservative SPDX `NOASSERTION`, external SPDX validation, point-in-time audit, two-build comparison, and payload inspection passed; known vulnerable embedded versions, unresolved sqlcipher3 metadata/license conflict, raw/cross-platform sdist reproducibility, approved signing identity/workflow, and independent acceptance remain blockers |
| Public retrieval benchmarks and latency distributions | Explicit non-goal; not run |

This result supports only the maturity label “experimental local prototype” and an Issue #7
implementation candidate. Until independent review passes, it is not an accepted
encryption claim. It is not evidence for production security, native-host
compatibility, Linux packaging, cross-platform behavior, whole-vault confidentiality,
physical erasure, backup revocation, or benchmark-leading recall.
