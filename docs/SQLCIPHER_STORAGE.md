# Held SQLCipher application candidate

This branch refreshes the unmerged application candidate for issue #7 on current
schema-5 application behavior and the strict issue #13 SQLCipher 4.19.0 native
candidate. It is not a release, human security/license acceptance, or permission
to migrate a real vault. PRs #12, #14 and #27 remain held.

## Runtime and key contract

The supported test slice is Linux x86-64 on CPython 3.11–3.14 with exactly
`continuum-sqlcipher3` 0.6.2.post2, SQLCipher 4.19.0 community and SQLite 3.53.4.
The reviewed source/build/wheel hashes in `packaging/sqlcipher/manifest.json`
remain mandatory. There is no standard-library SQLite fallback and no dependency
fetch from a package index during verification. macOS and Windows are not covered.

Bootstrap validates project input and local secret-admission policy before
creating vault material. It creates a random 32-byte `storage.key` with owner-only,
exclusive no-follow file handling and syncs the key and directory before database
creation. `audit.key` is separate: it authenticates the audit chain and existing
operation receipts. Neither key is returned in status, errors or CLI arguments.
A partial initialization is retained and rejected; bootstrap never overwrites it.

Opening requires the key before the first database read. The connection authenticates
pages and validates the encrypted storage marker, supported schema and vault ID
before enabling write-affecting PRAGMAs or schema migration. Supported encrypted
schema versions 2–4 retain the current atomic upgrade to version 5. Unsupported
schemas/modes and plaintext databases are refused; this is not format migration.
Owner-only DB/WAL/SHM paths are checked, extension loading is disabled, and settings
require FULL synchronous WAL, memory temporary storage, foreign keys, secure delete,
no mmap and an untrusted schema. Application audit checks include both SQLite and
SQLCipher integrity.

The key is co-located with the database. Protection does not cover a compromised
same-user process, a copy containing both files, old backups or OS snapshots.
Python byte objects do not promise reliable key erasure. No secure-erasure claim is
made for existing filesystem blocks or snapshots.

## Repeatable candidate verification

The `encrypted-storage` workflow builds the exact native wheel twice per ABI,
checks byte equality and strict hashes, verifies native/source evidence and the
installed native regression suite, then installs that wheel and the pinned build
tools into a fresh isolated environment. Full application tests, fixture demo and
source-package installation run in a disposable checkout with network disabled.
Skipped tests, wrong native imports or incomplete verifier output fail the gate.
That workflow does not upload native wheels.

For an equivalent offline Linux environment, provide a real directory containing
exactly the selected ABI wheel plus the manifest-pinned setuptools 80.9.0 and wheel
0.45.1 wheels. Every filename and digest must match the manifest. After those exact
inputs are installed into the selected interpreter, run:

```bash
CONTINUUM_SQLCIPHER_WHEELHOUSE=/absolute/reviewed/wheelhouse \
  /absolute/isolated/venv/bin/python scripts/verify.py
```

The workflow/helper records how the isolated environment is constructed. Do not
substitute an upstream public wheel, an unreviewed source build, or a mutable image.
The ordinary `verify` workflow checks source/supply-chain consistency; only the
four-ABI encrypted application workflow establishes native application results.

## Rotation and recovery boundary

Key rotation is being implemented as a separate explicitly approved offline
operation on this candidate. Until its complete state-machine, owner-approval and
crash tests pass, do not rotate or replace `storage.key` manually. The existing
SQLCipher `rekey` primitive alone cannot atomically publish a separate key file.
A pending rotation must block ordinary startup and backup admission. Storage-key
rotation must preserve `audit.key`, capability identities and receipt verification.
This checkpoint does not claim a completed rotation implementation.

## Plaintext migration plan: no conversion command

A future separately approved operation must take the same persistent daemon lock,
prove the source is offline, and export to a distinct new encrypted destination.
It must preserve the source, inventory its WAL and schema, carry forward canonical
rows, FTS content, audit/receipt identities and application/header versions, and
verify a fresh keyed reopen, integrity, row/schema parity and plaintext-canary
absence. Only a later explicit activation may select the new destination. Removal
of the original plaintext copy needs a separate decision; overwrite/unlink cannot
promise erasure of snapshots or storage history. Ordinary open, bootstrap and
schema upgrades never execute this plan automatically.

An encrypted database export alone is not a full vault backup. Backup/restore must
bind audit state and control identities, use its separately approved key contract,
and reject pending rotation. The issue #4/#6 work owns that interface.

## Acceptance remains open

The binding/aggregate license conclusion remains `NOASSERTION`. Human license and
security review, signing identity/trust/custody/revocation, immutable macOS builder
and application migration/backup/restore acceptance remain separate recorded
gates. Synthetic CI is not a genuine Linux polkit human-presence test.
