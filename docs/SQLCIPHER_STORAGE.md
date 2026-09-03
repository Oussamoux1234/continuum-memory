# SQLCipher storage boundary

Status: Issue #7 implementation candidate. Independent review is still required.

## Runtime and reproducibility

Continuum Memory pins `sqlcipher3==0.6.2` and accepts SQLCipher runtime
`4.12.0 community`. The supported verification targets for this issue are CPython 3.9 on
macOS 11+ arm64 and manylinux 2.28+ x86-64. Their wheel filenames and SHA-256 digests are
fixed in `requirements/sqlcipher-python39.txt` and `scripts/verify.py`.

Source builds are not a supported reproducible path for this milestone. The inspected
source distribution invokes Conan and external dependency resolution. CI first downloads
the matching hash-checked binary wheel into `work/dependencies`, installs it into the test
interpreter, and then runs the gate. The packaging smoke creates another clean virtual
environment and installs both that already-validated wheel and the built Continuum source
archive with `PIP_NO_INDEX=1`, `--no-deps`, and no checkout `PYTHONPATH`.

To prepare and run the same gate on a supported Python 3.9 host:

```bash
python3 -m pip download --require-hashes --only-binary=:all: --no-deps \
  --dest work/dependencies -r requirements/sqlcipher-python39.txt
python3 -m pip install --no-index --no-deps --find-links work/dependencies \
  sqlcipher3==0.6.2
python3 scripts/verify.py
```

Acquisition requires package-index access. The subsequent installation exercised by the
packaging smoke is offline and refuses an unknown filename, wrong digest, missing wheel, or
multiple candidate wheels.

## Key creation and storage

`continuum init` generates 32 random bytes with the operating system randomness source. It
writes them directly to `storage.key` in the owner-only vault directory using exclusive,
no-follow creation and mode `0600`. The key is never accepted from command-line arguments
or environment variables and is not included in status, logs, audit events, or errors.

The file is required to be a single owner-owned regular file with one link and no group or
world permissions. Missing, malformed, linked, substituted, or inaccessible key material
returns the same content-free `storage_key_unavailable` error.

## Open sequence and failure behavior

The daemon is the only post-bootstrap writer. For each connection it:

1. validates the vault directory, database, and key-file boundaries;
2. opens the SQLCipher binding and applies the raw 32-byte key as the first database operation;
3. requires the exact cipher version and an active cipher status;
4. reads `sqlite_master` to authenticate the encrypted header before write-affecting settings;
5. requires WAL, `synchronous=FULL`, and `temp_store=MEMORY`, disables extension loading and
   memory mapping, and checks FTS5 availability;
6. requires the schema version and metadata storage mode `sqlcipher-4.12.0`.

There is no stdlib SQLite fallback. A missing binding returns `sqlcipher_unavailable`; a
wrong key or plaintext database returns `storage_key_invalid`; an unsupported metadata mode
returns `storage_mode_mismatch`. These messages contain no key or database content.

`continuum status` reports the storage mode. `continuum audit verify` runs both SQLite and
SQLCipher integrity checks and reports `sqlite_integrity` and `sqlcipher_integrity`.

## Rotation boundary

Rotation is deliberately not implemented or exposed through CLI, daemon RPC, or MCP in
Issue #7. A future reviewed administrator-only flow must stop the daemon, lock the vault,
retain a recoverable copy of the old key, execute SQLCipher `PRAGMA rekey`, perform durable
database and directory syncs, pass both integrity checks, reopen with only the new key, and
atomically replace the key file. Any interruption must leave one verified key/database pair
recoverable. Agents must never invoke or authorize this operation.

## Plaintext migration boundary

There is no automatic migration. A vault without `storage.key`, a plaintext SQLite header,
or an unexpected storage-mode marker fails closed without conversion. A future explicit
offline tool must require a backup, create a separate encrypted destination, use reviewed
SQLCipher export semantics, verify counts and both integrity checks, and preserve the source
until the user separately authorizes removal. Issue #7 does not provide that tool.

## What encryption does not cover

The co-located key protects database, WAL, SHM, temporary, and FTS artifacts obtained
without `storage.key`. It does not protect against the owning account, root/admin, process
inspection, a copied complete vault, OS snapshots containing the key, exports, screen
capture, or unmanaged backups. The audit and approval keys remain separate files. This
prototype has no OS keystore, per-object encryption, backup revocation, or cryptographic
erasure claim.
