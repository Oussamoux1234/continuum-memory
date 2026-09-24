# Milestone backlog

## Historical plaintext prototype and native gate

The completed prototype items record the 2026-09-03 baseline and subsequent plaintext
verification; the separate native gate was updated on 2026-09-23. They are not a passing
record for the held encrypted application candidate.

- [x] Constitution and trust-boundary ADRs
- [x] SQLite ledger, FTS5, Unix-socket daemon, CLI, generic MCP bridge
- [x] Deterministic cross-agent fixture and lifecycle/isolation tests
- [x] Strict UTC dates, persisted retention expiry, complete logical forget projections
- [x] Symlink/hardlink/owner/mode checks for vault files, capabilities, and local socket
- [x] Run the historical plaintext verifier on GitHub-hosted Ubuntu 24.04 x86-64 / Python 3.9
- [x] Hardened, reproducible SQLCipher test-artifact pipeline for Linux x86-64 /
  CPython 3.11-3.14; artifacts remain ephemeral, with application acceptance separate

The held application checkpoint `79b74d9ef177710e9bf1e0d4fe7bfd51a49befd4` requires
CPython 3.11-3.14 and the strict SQLCipher 4.19.0 runtime. Its 28 source tests passed locally;
initial native application CI and independent acceptance remain pending. No trustworthy-v1
checkbox is completed by that source-only result.

## Trustworthy local v1

- [ ] Reviewed SQLCipher application integration covering migration, database, WAL, temp,
  FTS, key management, failure recovery, and rollback; the native test-artifact pipeline is
  a prerequisite, not completion
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
- [ ] Complete independent acceptance of the native SBOM, provenance, deterministic payload,
  vulnerability evidence, and unresolved binding `NOASSERTION`
- [ ] Select and approve an artifact signing identity, trust root, verification procedure,
  custody policy, and revocation procedure; no identity or key is selected yet
- [ ] Establish an immutable macOS arm64 builder/toolchain before attempting the CPython
  3.11-3.14 native matrix
- [ ] Linux packaging and independently reviewed security claims ([issue #2](https://github.com/Oussamoux1234/continuum-memory/issues/2))
- [ ] Hardened macOS approval/filesystem boundary and native CI ([issue #10](https://github.com/Oussamoux1234/continuum-memory/issues/10))
- [ ] Trustworthy Windows IPC/filesystem boundary and native CI ([issue #1](https://github.com/Oussamoux1234/continuum-memory/issues/1))

## Future sync

- [ ] Re-run threat model after local deletion/key semantics stabilize
- [ ] Content-blind encrypted operation log, device identity, epochs, and deletion dominance
- [ ] Team ACL/membership without last-write-wins or server-side plaintext search
