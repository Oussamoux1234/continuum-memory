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
| Crash or corruption | one writer, encrypted WAL, FULL sync, transactions, SQLite and SQLCipher integrity checks | Committed-WAL unclean-exit recovery is tested; no full power-loss/fault matrix yet |
| Audit tamper/truncation | content-free HMAC chain and external head file | Same-UID attacker may alter DB and key/head; tamper/tail tests |
| Deleted content remnants | transactional canonical/feedback/recall/FTS removal, orphan cleanup, SQLCipher pages, secure_delete, checkpoint | Whole-vault copies, snapshots, exports, backups, and SSD behavior are not revoked; deletion tests |
| Stale retained content | strict UTC deadlines; serialized audited expiry before current reads; current-recall recheck | Expired history intentionally remains available; injected-clock lifecycle tests |
| Secrets stored in memory | README prohibition and small allowlist; no diagnostic bodies | Sophisticated DLP not implemented; use only synthetic data |
| Capability/file attacks | owner/type/mode/link-count checks, no-follow capability opens, socket inode and peer-owner checks; Linux policy/helper/key paths are fixed and root-owned; provisioning is locked | Same-UID replacement races remain for user-owned prototype files; root/admin replacement is outside the Linux broker boundary; symlink/hardlink/mode regressions |
| Storage artifact disclosure | SQLCipher encrypts database/WAL/FTS pages; temp storage is forced to memory; key/runtime failures reject access; incompatible encrypted vaults are validated query-only before hardening | The owner-only key is co-located with the vault; same-UID/root/process inspection and whole-vault theft remain out of boundary; canary, mutation and key-failure tests |
| Key durability | Storage key file and containing directory are fsynced before database creation | Broader multi-file bootstrap crash/fault recovery remains Issue #8; deterministic ordering test |
| Supply-chain/network | SQLCipher wheel name/version/hash is pinned for maintained CPython 3.11–3.14 Linux x86-64 and macOS arm64 artifacts; all eight payloads were inspected; exact upstream license texts, conservative SPDX 2.3 inventory, and frozen vulnerability evidence ship in project artifacts; the external SPDX validator and verification setuptools are hash-pinned; two same-host builds are compared; packaging installs offline; no runtime network code/telemetry | OpenSSL 3.6.0 has 48 known vendor-tracked findings and SQLite 3.51.1 predates two FTS5 fixes; sqlcipher3's MIT metadata conflicts with its shipped license text; raw sdist timestamps and cross-platform reproducibility remain; no approved signing identity/workflow exists; Linux runs the complete maintained matrix while native macOS evidence covers arm64 Python 3.14 only; source builds use external Conan resolution and are not accepted |

The prototype claims only encrypted SQLCipher artifacts under the stated key boundary. It
does not claim whole-vault confidentiality, secure deletion, fully reviewed human presence,
perfect timing noninterference, crash-proof audit anchoring, or enforcement inside unrelated
host tools. These are release blockers for stronger maturity language.
