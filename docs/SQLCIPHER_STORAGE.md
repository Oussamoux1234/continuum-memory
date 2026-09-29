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

Ordinary startup refuses an unexpected rollback journal before any database open;
normal operation uses WAL. A journal must not be deleted to bypass that refusal.
Opening requires the key before the first database read. The connection authenticates
pages and validates the encrypted storage marker, supported schema and vault ID
before enabling write-affecting PRAGMAs or schema migration. Supported encrypted
schema versions 2–4 retain the current atomic upgrade to version 5. Unsupported
schemas/modes and plaintext databases are refused; this is not format migration.
Owner-only DB/WAL/SHM/rollback-journal paths are checked, extension loading is disabled, and settings
require FULL synchronous WAL, memory temporary storage, foreign keys, secure delete,
no mmap and an untrusted schema. Application audit checks include both SQLite and
SQLCipher integrity.

The key is co-located with the database. Protection does not cover a compromised
same-user process, a copy containing both files, old backups or OS snapshots.
Python byte objects do not promise reliable key erasure. No secure-erasure claim is
made for existing filesystem blocks or snapshots.

The local custody candidate publishes by renaming the already-durable
`storage.key.next` inode onto `storage.key`; it creates no third raw-key file.
It syncs the key inode and parent before rename and the parent again afterward.
A crash can leave the authenticated journal in `prepared` with the new active key
and no next-key file; only independently validated, freshly approved recovery may
continue that state. Missing next with an old active key is refused, never regenerated.

Older code could leave owner-only `.storage.key.<random>.tmp` files containing
raw key bytes. The new bounded, nonrecursive guard refuses that reserved filename
namespace, including malformed names and dangling links, without reading or deleting
the entries. More than 4096 top-level vault entries also fails closed. It does not
discover historical copies elsewhere or make existing residues safe: owner investigation
is required. Recovery only removes exact authenticated fixed-path material. There is no
glob cleanup, key-destruction, physical-erasure or old-ciphertext revocation claim.

## Repeatable candidate verification

The `encrypted-storage` workflow builds the exact native wheel twice per ABI,
checks byte equality and strict hashes, verifies native/source evidence and the
installed native regression suite, then installs that wheel and the pinned build
tools into a fresh isolated environment. Full application tests, fixture demo and
reproducible source/wheel packaging and both fresh installations run in a disposable
checkout with network disabled. The refreshed report requires exactly 91 source-enumerated
Linux platform exclusions (62 Windows and 29 macOS methods),
bound to explicit test IDs and reasons in `tests/platform-skips-linux.json`. Every
other skip, missing required crypto suite, wrong native import or incomplete result
fails the gate. This policy never admits a missing encryption backend as a skip.
That workflow does not upload native wheels.

For an equivalent offline Linux environment, provide a real directory containing
exactly the selected ABI wheel plus the manifest-pinned setuptools 80.9.0 and wheel
0.45.1 wheels. Every filename and digest must match the manifest. After those exact
inputs and the separate hash-locked `packaging/build-requirements.txt` tool closure
are installed into the selected interpreter, run:

```bash
CONTINUUM_SQLCIPHER_WHEELHOUSE=/absolute/reviewed/wheelhouse \
CONTINUUM_BUILD_WHEELHOUSE=/absolute/reviewed/build-tools \
  /absolute/isolated/venv/bin/python scripts/verify.py
```

The workflow/helper records how the isolated environment is constructed. Do not
substitute an upstream public wheel, an unreviewed source build, or a mutable image.
The ordinary `verify` workflow checks source/supply-chain consistency; only the
four-ABI encrypted application workflow establishes native application results.

## Rotation and recovery boundary

The candidate's offline maintenance entry points are `continuum storage rotate-key`
and `continuum storage recover-key`, with the ordinary global `--data-dir` option.
Each takes the persistent daemon lease and requires a fresh Linux polkit proof for
that specific operation and vault state. The daemon must be stopped. A running or
stopped process still holding the lease, an uncertain listener, unavailable OS
approval or a changed preview prevents progress. MCP has no rotation operation;
there is no terminal approval fallback or caller-supplied key argument.

The recovery contract uses two fixed private paths: `storage.rotation.json` and
`storage.key.next`. The bounded journal is authenticated with the unchanged
`audit.key` and binds the vault, generation, operation and candidate key hashes.
Normal startup and bootstrap refuse either path, including an orphan next key.
Backup callers must use the same `require_no_pending_rotation` admission check.

| Phase | Required durable state |
| --- | --- |
| Preparing | The authenticated operation journal exists before the new key is created. |
| Prepared | Before rekey: old active plus durable distinct next key. After publication rename: new active and next absent are allowed only after unique copied native integrity/audit/generation proof. The journal remains pending. |
| Published | A fresh new-key open and integrity checks succeeded, the active key was published durably, and the generation plus one audit event committed with a verified audit anchor. Cleanup can finish. |

Recovery probes each distinct candidate key against its own complete private copy
of the encrypted database and supported sidecars. A wrong key is never tried on
the original recovery artifacts: SQLite may replay a hot rollback journal before
an ordinary read, even with `query_only` enabled. Exactly one distinct key must
validate the expected vault and integrity before recovery touches the original.
The active and next files may legitimately contain the same new key after
publication; those are one candidate. Missing, corrupt or ambiguous evidence is
preserved and refused. Recovery never fabricates a missing key or starts an
unrelated rotation.

Rotation preserves `audit.key`, capability identities, receipts and application
content. The generation and content-free audit event commit together; a repeated
recovery must not append another event. A post-commit anchor or cleanup failure
keeps the pending state until separately approved recovery. A preparing operation
that never created its next key may be aborted only after the old-key vault is
verified and fresh recovery approval is obtained.
That abort removes only rotation preparation state. It preserves the original
database and sidecars; an unexpected rollback journal that existed before rotation
still requires offline investigation and continues to block ordinary startup.

After successful cleanup and daemon restart, the owner can use
`continuum status --project <project-id>` to read `storage_generation`. It is
`initial` before the first completed rotation and the last committed operation ID
afterward, including when the final rotation reply was lost. Provider status does
not expose that vault-wide generation.

Native application, rotation and crash results remain pending at this checkpoint.
The prepared tests cover deterministic crashes before and after native rekey;
process death observed inside the native rekey call is not yet demonstrated.
The implementation and synthetic proof fixtures do not establish genuine human
polkit acceptance, power-loss durability or permission to rotate a real vault.
Do not replace key files manually to clear an error.

The separately runnable filesystem suite uses only synthetic key bytes and real
file operations/subprocess deaths, not a fake cipher or approval provider:

```bash
PYTHONPATH=src:. python3 -m unittest tests.test_storage_key_custody -v
```

It covers key-inode custody before/after fsync and rename, SIGKILL, cleanup boundaries,
unsafe paths and preserved legacy residue. Passing this suite does not establish native
SQLCipher rotation, owner presence, Linux power-loss durability or release readiness.
The expanded native rotation fixture remains a separate required gate.

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
