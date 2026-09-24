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
| Oversized/malformed JSON or stalled local peer | Acquisition and response frames capped at 64 KiB; strict envelopes; 2-second absolute read/write deadlines; 16 daemon connections; serialized dispatch and bounded pipe queues | Continuous same-UID admission floods and slow kernel work can still deny service; actual socket/subprocess malformed, trickle, blocked-output, saturation, and recovery tests |
| Concurrent daemon startup or stale endpoint after a crash | Persistent validated OS-lock inode before Store opening; marked-version, refused-connect and unchanged-inode checks before stale endpoint removal; cleanup preserves replacements | Cooperating lock-aware versions on local POSIX filesystems only; no mixed-version/network-filesystem or malicious same-UID guarantee; concurrent/SIGSTOP/SIGKILL/startup-fault tests |
| Replay/duplicate delivery | project/provider delivery identity; atomic content-free purge tombstones; nonce-bound single-use grants; packaged runtime rejects HMAC grants | Fresh keys, old pre-v4 deletions, database rollback and HMAC-key changes are outside suppression; [contract and tests](PROPOSAL_ERASURE.md) |
| Crash or corruption | one writer, WAL, FULL sync, transactions, integrity check | No full power-loss/fault matrix yet; integrity tests only |
| Audit tamper/truncation | content-free HMAC chain and external head file | Same-UID attacker may alter DB and key/head; tamper/tail tests |
| Deleted content remnants | transactional canonical/feedback/recall/FTS removal, orphan cleanup, secure_delete, checkpoint | Plaintext copies/snapshots/WAL history/SSD not guaranteed; deletion tests |
| Stale retained content | strict UTC deadlines; serialized audited expiry before current reads; current-recall recheck | Expired history intentionally remains available; injected-clock lifecycle tests |
| Secrets stored in memory | Bounded local detectors before new content writes, startup owner policy with exact-field exceptions, content-free admission/argument errors | Unknown/encoded/split secrets and semantic sensitivity remain undetected; no retroactive purge; same-UID configuration tampering remains possible; synthetic persistence/diagnostic regressions |
| Capability/file attacks | owner/type/mode/link-count checks, no-follow capability opens, socket inode and peer-owner checks; Linux policy/helper/key paths are fixed and root-owned; provisioning is locked | Same-UID replacement races remain for user-owned prototype files; root/admin replacement is outside the Linux broker boundary; symlink/hardlink/mode regressions |
| Supply-chain/network | no Python runtime dependencies, no network code/telemetry; Linux installer isolates PATH and Python/pip environment and stages a fresh runtime before replacement | The reviewed source checkout remains trusted installer input; Python/SQLite/OpenSSL/polkit are host-supplied; audits, signed artifacts, and distribution packaging not yet run |

The prototype does not claim confidentiality, secure deletion, fully reviewed human presence,
perfect timing noninterference, crash-proof audit anchoring, or enforcement inside unrelated
host tools. These are release blockers for stronger maturity language.

The [native Windows candidate](WINDOWS_BOUNDARY.md) selects handle-based private
filesystem/SQLite guards and [bounded named-pipe IPC](WINDOWS_IPC.md). The POSIX
lock-inode/socket-removal description above does not apply to it: Windows holds
an immutable binding and first pipe instance before Store opening, with kernel
handle release rather than socket-file removal. Exact-head full native CI and
the remaining security fixtures are pending; old isolated primitive jobs do not
establish application acceptance. Native production approval, encryption/key
custody, hostile same-account resistance and power-loss durability are not added.
