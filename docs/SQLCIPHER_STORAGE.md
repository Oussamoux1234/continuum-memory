# SQLCipher storage boundary

Status: Issue #7 implementation candidate. Independent review is still required.

## Runtime and reproducibility

Continuum Memory pins `sqlcipher3==0.6.2` and accepts SQLCipher runtime
`4.12.0 community`. Python 3.9 is excluded because it is end-of-life and no longer receives
security updates. The declared maintained matrix is CPython 3.11–3.14. GitHub Actions runs
the full matrix on Ubuntu 24.04 x86-64. Native macOS evidence is limited to macOS arm64 with
Python 3.14; the other macOS wheel hashes are pinned for artifact identity but are not a
support claim. Wheel filenames and SHA-256 digests are fixed in
`requirements/sqlcipher-maintained.txt` and `scripts/verify.py`.

Source builds are not a supported reproducible path for this milestone. The inspected
source distribution invokes Conan and external dependency resolution. CI first downloads
the matching hash-checked binary wheel into `work/dependencies`, installs it into the test
interpreter, and then runs the gate. The verification-only `setuptools==80.9.0` wheel is
also hash-pinned because fresh maintained-Python environments do not implicitly provide it.
The packaging smoke creates another clean virtual environment and installs the pinned build
tool, the validated SQLCipher wheel, and the built Continuum source archive with
`PIP_NO_INDEX=1`, `--no-build-isolation`, `--no-deps`, and no checkout `PYTHONPATH`.

To prepare and run the same gate on a declared maintained Python host:

```bash
python3 -m pip download --require-hashes --only-binary=:all: --no-deps \
  --dest work/dependencies -r requirements/sqlcipher-maintained.txt
python3 -m pip download --require-hashes --only-binary=:all: --no-deps \
  --dest work/build-dependencies -r requirements/verification-tools.txt
python3 -m pip install --no-index --no-deps --find-links work/build-dependencies \
  setuptools==80.9.0
python3 -m pip install --no-index --no-deps --find-links work/dependencies \
  sqlcipher3==0.6.2
python3 scripts/verify.py
```

Acquisition requires package-index access. The subsequent installation exercised by the
packaging smoke is offline and refuses an unknown filename, wrong digest, missing wheel, or
multiple candidate wheels.

The 2026-09-05 replacement investigation found no patched published `sqlcipher3` wheel.
Minimum acceptable embedded versions are SQLCipher 4.17.0, SQLite 3.53.2, and OpenSSL 3.6.4;
the preferred project-build baseline is SQLCipher 4.18.0 / SQLite 3.53.4 / OpenSSL 3.5.8 LTS.
Those source versions are not a reviewed installable Python artifact, so the current lock and
runtime identity remain unchanged and blocked. Do not use the commands below for sensitive or
production data. See `docs/architecture/010-encryption-dependency-decision.md` for the rejected
alternatives and the explicit supply-chain ownership decision required before a native rebuild.

## Third-party contents and licenses

`THIRD_PARTY_NOTICES.md` is the canonical human-readable inventory for the eight supported
wheel files. It records their exact PyPI SHA-256 values, archive payloads, statically compiled
SQLCipher 4.12.0 / SQLite 3.51.1 / OpenSSL 3.6.0 components, and host-supplied dynamic
libraries. Exact upstream license texts are under `third_party_licenses/`; the interim
SPDX 2.3 JSON record is `sbom/continuum-memory.spdx.json`.

The 2026-09-05 point-in-time vulnerability and replacement findings, external SPDX validation,
reproducible-build comparison, final payload inspection, and signing blocker are recorded in
`security/dependency-audit.json` and `docs/RELEASE_READINESS.md`. The embedded OpenSSL and
SQLite versions have known findings, so this candidate remains blocked from merge or release.

The Continuum source distribution and pure-Python wheel do not embed a `sqlcipher3` wheel.
The dependency is installed as a separate distribution, while CI downloads it only into
ignored test storage. A combined installer, container, application bundle, or offline
wheelhouse that redistributes the native wheel must ship the recorded notices and be
reviewed as its own payload.

The upstream binding has a material metadata discrepancy: its project/wheel metadata says
`MIT`, but its shipped license file contains a different Gerhard Häring three-condition
text. The inventory preserves both facts and uses a custom SPDX `LicenseRef` instead of
guessing which declaration should control. PR #12 remains blocked on independent security
and license review.

The verifier checks exact copied-license hashes, required notice/component records, all
eight wheel records and dependency relationships, and the wheel used by the current job.
It also builds a Continuum wheel and requires the notices, licenses, and SPDX file in both
that wheel and the source archive while preserving the offline source-install smoke.

## Key creation and storage

`continuum init` generates 32 random bytes with the operating system randomness source. It
writes them directly to `storage.key` in the owner-only vault directory using exclusive,
no-follow creation and mode `0600`. The key file is fsynced, then the vault directory is
opened and fsynced before database creation so the directory entry is durable before any
encrypted database commit. The key is never accepted from command-line arguments or
environment variables and is not included in status, logs, audit events, or errors.

The file is required to be a single owner-owned regular file with one link and no group or
world permissions. Missing, malformed, linked, substituted, or inaccessible key material
returns the same content-free `storage_key_unavailable` error.

## Open sequence and failure behavior

The daemon is the only post-bootstrap writer. For each connection it:

1. validates the vault directory, database, and key-file boundaries;
2. opens the SQLCipher binding and applies the raw 32-byte key as the first database operation;
3. requires the exact cipher version and an active cipher status;
4. enables connection-level query-only mode and reads `sqlite_master` to authenticate the
   encrypted header;
5. validates schema version, storage mode, and vault identity while writes remain disabled;
6. only after acceptance disables query-only mode, applies WAL, `synchronous=FULL`,
   `temp_store=MEMORY`, `secure_delete=ON`, foreign keys, `trusted_schema=OFF`, bounded busy
   timeout, disabled memory mapping and extension loading, and checks FTS5 availability;
7. reads every critical PRAGMA back and fails closed unless each exact value is active.

There is no stdlib SQLite fallback. A missing binding returns `sqlcipher_unavailable`; a
wrong key or plaintext database returns `storage_key_invalid`; an unsupported metadata mode
returns `storage_mode_mismatch`. These messages contain no key or database content.
An unsupported encrypted schema or storage mode is rejected without changing database
bytes, journal mode, or sidecar artifacts.

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
