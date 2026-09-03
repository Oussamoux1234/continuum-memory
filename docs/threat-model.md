# Prototype threat model and residual-risk register

## Assets and principals

Assets are claim/evidence bodies, provenance, project/disclosure metadata, capability keys,
audit integrity, deletion state, and availability. Principals are the user-control CLI,
daemon, project/provider MCP adapter, host/model, repository/import/tool content, and local
OS account. The daemon trusts possession of scoped capability material, not model text.

## Boundaries and mitigations

| Threat | Prototype mitigation | Residual risk / test |
|---|---|---|
| Agent forges approval, source, or project | MCP schema excludes fields; daemon assigns identity; packaged runtime requires an OS-backed proof; Linux proof binds UID/vault/nonce/operation/digest/expiry | Unprovisioned live use fails closed; real polkit path needs controlled-host evidence; forged/replay/RSA tests |
| Prompt injection or poisoning | proposals quarantined; memory labeled data; no action tools; conflicts stay explicit | Generic host may act on text; adversarial-memory test |
| Cross-project/provider disclosure | bound capability; authorization predicates inside exact/FTS/get queries; non-revealing errors | Shared canonical/FTS DB is not physically sharded and leaks access timing/size locally; isolation tests cover results/counts only |
| SQL/FTS injection | parameterized SQL; literal-token FTS query builder; bounded strings | SQLite/parser defects; injection tests |
| Oversized/malformed JSON | 64 KiB frames; strict keys/types/ranges; shallow expected objects | Resource exhaustion below OS boundary; malformed MCP tests |
| Replay/duplicate delivery | scoped idempotency table; nonce-bound single-use grants; packaged runtime rejects HMAC grants | Prototype HMAC exists only in an explicitly injected temporary test daemon; replay/cross-challenge tests |
| Crash or corruption | one writer, WAL, FULL sync, transactions, integrity check | No full power-loss/fault matrix yet; integrity tests only |
| Audit tamper/truncation | content-free HMAC chain and external head file | Same-UID attacker may alter DB and key/head; tamper/tail tests |
| Deleted content remnants | transactional canonical/feedback/recall/FTS removal, orphan cleanup, secure_delete, checkpoint | Plaintext copies/snapshots/WAL history/SSD not guaranteed; deletion tests |
| Stale retained content | strict UTC deadlines; serialized audited expiry before current reads; current-recall recheck | Expired history intentionally remains available; injected-clock lifecycle tests |
| Secrets stored in memory | README prohibition and small allowlist; no diagnostic bodies | Sophisticated DLP not implemented; use only synthetic data |
| Capability/file attacks | owner/type/mode/link-count checks, no-follow capability opens, socket inode and peer-owner checks; Linux policy/helper/key paths are fixed and root-owned; provisioning is locked | Same-UID replacement races remain for user-owned prototype files; root/admin replacement is outside the Linux broker boundary; symlink/hardlink/mode regressions |
| Supply-chain/network | no Python runtime dependencies, no network code/telemetry; Linux installer isolates PATH and Python/pip environment and stages a fresh runtime before replacement | The reviewed source checkout remains trusted installer input; Python/SQLite/OpenSSL/polkit are host-supplied; audits, signed artifacts, and distribution packaging not yet run |

The prototype does not claim confidentiality, secure deletion, fully reviewed human presence,
perfect timing noninterference, crash-proof audit anchoring, or enforcement inside unrelated
host tools. These are release blockers for stronger maturity language.
