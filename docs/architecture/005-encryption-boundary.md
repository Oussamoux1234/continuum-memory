# ADR 005: Prototype plaintext boundary; SQLCipher before trustworthy local v1

Status: accepted with explicit limitation.

## Decision

This dependency-free slice uses the Python runtime's SQLite with FTS5. It does not include
a reproducibly integrated SQLCipher build, per-object encryption, OS secure-store keys, or
encrypted backups. The README and status output label storage `plaintext_prototype`; users
must not store secrets or sensitive production data.

The storage API, schema migration, and daemon ownership boundary isolate database access so
a reviewed SQLCipher provider can replace the connection factory. The future design keeps
separate storage-root, user-presence, vault-wrapping, page, per-assertion/evidence,
projection, audit, export, and backup keys. Encryption at rest will still not protect an
unlocked vault from same-user malware, root/admin, screen capture, or disclosed content.

## SQLite posture

Every connection enables foreign keys, disables trusted schema, disables extension
loading, bounds busy timeout, uses WAL plus `synchronous=FULL`, and avoids memory mapping.
Python does not expose every defensive `sqlite3_db_config`; this is recorded as a gap.
