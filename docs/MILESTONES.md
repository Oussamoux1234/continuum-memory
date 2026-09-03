# Milestone backlog

## Prototype — current

- [x] Constitution and trust-boundary ADRs
- [x] SQLite ledger, FTS5, Unix-socket daemon, CLI, generic MCP bridge
- [x] Deterministic cross-agent fixture and lifecycle/isolation tests
- [x] Strict UTC dates, persisted retention expiry, complete logical forget projections
- [x] Symlink/hardlink/owner/mode checks for vault files, capabilities, and local socket
- [ ] Validate the terminal broker and daemon on Linux x86-64 (current build host may differ)

## Trustworthy local v1

- [ ] Reviewed SQLCipher integration covering database, WAL, temp, and FTS
- [ ] Linux OS-backed human-presence broker and non-exportable keys
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
- [ ] SBOM, license/vulnerability policy, deterministic payload, signing rehearsal
- [ ] Linux packaging and independently reviewed security claims

## Future sync

- [ ] Re-run threat model after local deletion/key semantics stabilize
- [ ] Content-blind encrypted operation log, device identity, epochs, and deletion dominance
- [ ] Team ACL/membership without last-write-wins or server-side plaintext search
