# Milestone backlog

## Prototype — current

- [x] Constitution and trust-boundary ADRs
- [x] SQLite ledger, FTS5, Unix-socket daemon, CLI, generic MCP bridge
- [x] Deterministic cross-agent fixture and lifecycle/isolation tests
- [x] Strict UTC dates, persisted retention expiry, complete logical forget projections
- [x] Symlink/hardlink/owner/mode checks for vault files, capabilities, and local socket
- [x] Historical prototype verifier on GitHub-hosted Ubuntu 24.04 x86-64 / Python 3.9
- [x] Require the current verifier on a maintained Python 3.11–3.14 Linux matrix in Actions

## Trustworthy local v1

- [ ] Reviewed SQLCipher integration covering database, WAL, temp, and FTS: implementation,
  fail-closed behavior, crash recovery, canary gates, exact wheel inventory, copied notices,
  conservative SPDX inventory, external SPDX validation, vulnerability evidence, reproducible
  build checks, and payload inspection are on Issue #7; known OpenSSL/SQLite findings, the
  sqlcipher3 license discrepancy, signing, and independent acceptance remain before closure
- [ ] Linux OS-backed human-presence broker and non-exportable keys: implementation and
  deterministic tests landed; real-host smoke and independent review remain ([issue #3](https://github.com/Oussamoux1234/continuum-memory/issues/3))
- [ ] Secret/DLP gates, encrypted backup/recovery, deletion revocation anchor
- [ ] Crash/fault injection, migration compatibility, lock/rotation, audit anchor hardening

## Adapters

- [ ] Version-pinned Codex, Claude Code, Antigravity, and generic conformance matrix
- [ ] Transactional plan/apply/status/uninstall using temporary profiles first
- [ ] Native-memory coexistence/import preview and deterministic echo suppression
- [ ] Optional Agent Relay MCP client under `AGENT_RELAY_INTEGRATION.md`

## Retrieval quality

- [ ] Frozen lexical benchmark manifest and measured baselines
- [ ] Optional local embeddings, RRF, diversity, and deep search as projections
- [ ] Sandboxed extractor that emits proposals only
- [ ] Temporal, conflict, abstention, poisoning, and cross-agent benchmark gates

## Hardening and release

- [ ] Adversarial, fuzz, performance, accessibility, and incident/repair suites
- [ ] Release-grade SBOM, resolved dependency-license policy, patched dependencies,
  cross-platform reproducibility, and an approved signing/revocation workflow; Issue #7 has a
  verifier-enforced candidate inventory and readiness evidence, but known findings and unresolved
  license/signing decisions block release certification
- [ ] Linux packaging and independently reviewed security claims ([issue #2](https://github.com/Oussamoux1234/continuum-memory/issues/2))
- [ ] Hardened macOS approval/filesystem boundary and native CI ([issue #10](https://github.com/Oussamoux1234/continuum-memory/issues/10))
- [ ] Trustworthy Windows IPC/filesystem boundary and native CI ([issue #1](https://github.com/Oussamoux1234/continuum-memory/issues/1))

## Future sync

- [ ] Re-run threat model after local deletion/key semantics stabilize
- [ ] Content-blind encrypted operation log, device identity, epochs, and deletion dominance
- [ ] Team ACL/membership without last-write-wins or server-side plaintext search
