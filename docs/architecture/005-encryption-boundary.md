# ADR 005: SQLCipher storage boundary

Status: implemented provisionally; independent review required before Issue #7 closes.

## Decision

The canonical ledger uses the pinned `sqlcipher3==0.6.2` binding and requires SQLCipher
`4.12.0 community`. There is no fallback to the Python runtime's plaintext SQLite. Every
new vault receives a random 32-byte raw storage key in an owner-only `storage.key` file;
the key is applied before the first database read, and the runtime identity and cipher
status are verified before schema access. Status reports `sqlcipher-4.12.0`.

Missing, malformed, wrong, or unavailable key/runtime states fail closed with content-free
errors. Existing plaintext databases are rejected before write-affecting pragmas and are
never silently converted. Key rotation and migration are explicit future administrative
operations, not agent-facing APIs. Their required boundary is documented in
`docs/SQLCIPHER_STORAGE.md`.

The co-located key is an intentionally narrow at-rest boundary. It protects a database,
WAL, SHM, temporary artifact, or FTS page copied without the key. It does not protect an
unlocked vault from the owning account, same-user malware, root/admin, process inspection,
screen capture, or an attacker who copies the whole vault directory. This milestone does
not add OS secure-store integration, per-object keys, encrypted backups, or cryptographic
deletion.

## SQLite posture

Every connection authenticates the encrypted header first, then enables foreign keys,
disables trusted schema and extension loading, bounds busy timeout, requires WAL plus
`synchronous=FULL`, forces temporary storage to memory, enables secure deletion, and avoids
memory mapping. Python does not expose every defensive `sqlite3_db_config`; this remains a
gap.
