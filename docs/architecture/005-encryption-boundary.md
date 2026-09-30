# ADR 005: Prototype plaintext boundary; SQLCipher before trustworthy local v1

Status: historical decision accepted for the 2026-09-03 plaintext prototype, with explicit
limitation. The 2026-09-23 held application candidate below is not accepted for release.

## Historical decision

The original dependency-free slice used the Python runtime's SQLite with FTS5. It did not
include a reproducibly integrated SQLCipher build, per-object encryption, OS secure-store
keys, or encrypted backups. Its README and status output labeled storage
`plaintext_prototype`; that evidence did not support storing secrets or sensitive production
data.

The storage API, schema migration, and daemon ownership boundary isolate database access so
a reviewed SQLCipher provider can replace the connection factory. The longer-term design keeps
separate storage-root, user-presence, vault-wrapping, page, per-assertion/evidence,
projection, audit, export, and backup keys. Encryption at rest will still not protect an
unlocked vault from same-user malware, root/admin, screen capture, or disclosed content.

## Held application candidate

Local checkpoint `79b74d9ef177710e9bf1e0d4fe7bfd51a49befd4` requires the exact
`continuum-sqlcipher3` 0.6.2.post2 wheel with SQLCipher 4.19.0 community and SQLite 3.53.4
on Linux x86-64 / CPython 3.11-3.14. Its storage mode is `sqlcipher-4.19.0`; a missing or
mismatched backend fails closed, and ordinary startup refuses plaintext databases.
The candidate uses separate owner-only storage and audit keys, with the storage key
co-located with the database. It does not implement the complete future key hierarchy,
OS secure-store protection, or an accepted encrypted backup/migration system.

The 28 source tests passed locally; initial native application CI remains pending. The
earlier strict native-wheel results are not application execution or human acceptance.
See [the held storage contract](../SQLCIPHER_STORAGE.md) for connection sequencing, key
custody limits, migration and recovery boundaries, and the separate open release gates.

## SQLite posture

Every connection enables foreign keys, disables trusted schema, disables extension
loading, bounds busy timeout, uses WAL plus `synchronous=FULL`, and avoids memory mapping.
Python does not expose every defensive `sqlite3_db_config`; this is recorded as a gap.
