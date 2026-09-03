# Verification record

Last run: 2026-09-03.

## Supported command

```bash
python3 scripts/verify.py
```

The command parses both JSON schemas, checks source whitespace, compiles every Python
module, runs the unit/integration suite with resource warnings promoted to errors, executes
the complete two-client fixture demo, builds a source distribution, installs that exact
archive offline into a temporary virtual environment, exercises its entry points, and runs
`git diff --check`.

## Observed result

Host: macOS 26.5.2, Darwin arm64; Python 3.9.6; Python SQLite 3.51.0 with FTS5.
The same command is required on GitHub-hosted Ubuntu 24.04 x86-64 with Python 3.9 by the
[verify workflow](https://github.com/Oussamoux1234/continuum-memory/actions/workflows/verify.yml).

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
| Linux distribution package | Source archive build/install passed; wheel, signing, and release artifact not built |
| Windows runtime/CI | Unsupported and not run; POSIX boundary redesign tracked in issue #1 |
| SQLCipher/page/WAL/temp encryption | Not implemented; plaintext prototype |
| Real Linux polkit/user-presence broker | Independent review and deterministic RSA/broker tests passed; real interactive pkexec/polkit smoke not run; issue #3 remains open |
| Backup/revocation/restore/key rotation/fault injection | Out of slice; not run |
| Native Codex/Claude/Antigravity profiles | Not run and never modified; fixtures only |
| Vulnerability/license audit, SBOM, signatures, reproducible Linux payload | Not run; no third-party runtime dependency, but host Python/SQLite remain supply-chain inputs |
| Public retrieval benchmarks and latency distributions | Explicit non-goal; not run |

This result supports only the maturity label “experimental local prototype.” It is not
evidence for encryption, production security, native-host compatibility, Linux packaging,
cross-platform behavior, physical erasure, backup revocation, or benchmark-leading recall.
