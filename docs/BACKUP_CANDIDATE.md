# Held encrypted backup primitives

This local candidate provides internal encrypted staging and read-only validation.
It does not expose a CLI or MCP backup command, publish an artifact, activate a
restore, or establish permission to back up a real vault. Native execution remains
pending in the pinned Linux environment; pure tests are not encryption evidence.

## Caller and key contract

The caller must hold the cooperating daemon lease **before opening the Store and
through the entire export** and serialize access to that Store. It must separately
obtain owner authorization for the operation, destination and backup-key path.
These primitives do not supply that authorization. The lease excludes cooperating offline rotation; it does not isolate
arbitrary same-user processes.

The runtime is exactly `continuum-sqlcipher3` 0.6.2.post2, SQLCipher 4.19.0 and
SQLite 3.53.4 on the reviewed Linux CPython 3.11–3.14 slice. No missing-runtime skip,
mock cryptography, standard-library SQLite fallback or automatic key generation is
part of export or validation.

The backup key must already exist as a private, single regular 32-byte file outside
both the source vault and staging tree, and must differ from the live storage key.
Source and staging directories must be distinct and cannot contain one another.
Pending rotation, an orphan next key, legacy key residue, an active transaction,
or an occupied destination/sidecar prevents export. Raw key files are never copied
beside the artifact; the source audit key is included only inside its encryption.
The external backup key's captured bytes and observed file identity are checked
before commit and again after validation. An observed replacement or change fails
the export and preserves any unpublished candidate; these checks do not establish
protection against unrestricted same-user races or future key loss.

## Staging and validation

Export uses a fixed attached-database alias, bound path/key values and native
`sqlcipher_export` inside a serialized transaction. It preserves canonical rows,
FTS rowids, receipts, audit state and policy bytes. The candidate uses a separate
storage-mode marker so ordinary vault opening cannot silently activate it.

New exports use **format version 2** and the marker
`continuum-backup-v2-sqlcipher-4.19.0`. The `revocation_checkpoint` field remains
mandatory, but an omitted `export_candidate` checkpoint argument is stored as JSON
`null` (not provided). No authority ID, generation or digest is fabricated. A
nonnull checkpoint must still contain exactly a bounded `authority_id`, an integer
`generation` from 0 through 2^63−1, and a lowercase 64-character hexadecimal digest.

Legacy **format version 1** candidates remain readable only with their original
`continuum-backup-v1-sqlcipher-4.19.0` marker and a strict nonnull checkpoint object.
Version 1 does not gain null-checkpoint support, and readers do not rewrite legacy
candidates. Each marker must match its manifest version. Unknown versions,
unknown/missing fields, boolean versions/generations and malformed checkpoints are
rejected. Both versions retain the same exact trusted schema and application ID.

The format accepts only the exact trusted fresh schema-v5 layout plus its two
fixed backup tables: `application_id=1129143636`, `user_version=5` and
`auto_vacuum=0`. Other valid migrated layouts are outside this candidate contract.
Validation does not replay archive-owned DDL, migrate, repair, advance an audit
anchor, or write out a plaintext policy. The shared admission parser checks the
exact captured policy bytes; a final source reread must still agree before commit.

Candidate limits are 256 MiB per file, 512 schema objects, 64 KiB aggregate schema
text, 100,000 audit rows and 4 KiB per audit text cell. Manifest, policy and selected
metadata values are bounded to 8 KiB, 16 KiB and 128 bytes respectively. These are
format limits, not general vault capacity promises or hard native execution-time
bounds. Validation checks encryption/SQLite integrity, foreign keys, the presented
audit chain/head and manifest identity. It does not certify every application-row
semantic or independent audit freshness.

The closed artifact must have no WAL, SHM or rollback-journal companion. File
identity and size/time checks before and after validation detect observed changes;
they do not promise protection against unrestricted same-user replacement races.
The caller must keep the candidate quiescent for validation. The connection uses
`mode=ro&immutable=1`: [SQLite's read-only WAL behavior](https://sqlite.org/wal.html#read_only_databases)
can otherwise create WAL/SHM files, while [immutable mode](https://sqlite.org/uri.html#uriimmutable)
avoids that companion/locking path. This is a closed-file precondition, not proof
of filesystem immutability; the native regression remains pending.
Returned states are `staged_not_published` or `validated_not_activated`, always with
`restore_ready: false`. A recorded revocation checkpoint is data, never proof that
it is current, trusted or reconciled. For **both** readable versions the internal
return contract now reports the candidate's actual `format_version`,
`freshness: unverified` and `revocation_reconciliation: not_performed`; the previous
`required` label is removed. This is an explicit internal API change, not evidence
of reconciliation and not authorization for activation. It does not introduce a
public CLI or MCP backup command.

## What remains for issue 4

Base backup/restore work still needs an approved fresh-vault restoration and
activation contract, its implementation, and native acceptance. Opening a closed
encrypted candidate in the same process or a fresh interpreter is validation, not
a fresh-vault restore. The prepared tests must not be presented as proof that a
restored vault can start or accept an authorized owner operation.

The encrypted snapshot preserves database capability IDs and token hashes, but it
does not archive the raw control/provider capability documents. Its extra private
material is the audit key and admission-policy bytes. A restore design must
therefore explicitly decide owner-access recovery or capability reissuance and
ordinary vault startup admission before activation; none is silently implemented
by the existing format. A partial or occupied destination must remain preserved,
not overwritten or automatically adopted.

Independent revocation/freshness guarantees are separate **issue 6** work, not a
prerequisite for implementing the base **issue 4** backup/restore contract. The
current checkpoint field is retained as untrusted format data. Until that separate
authority and reconciliation work is accepted, the product must not claim that an
old backup has been revoked or that forgotten data cannot return from one.

## Failure and acceptance boundaries

Cancellation or failure must roll back and detach; unsafe cleanup closes the Store
instead of returning a usable connection with a leftover transaction/attachment.
A precommit failure may leave private rejected residue. A postcommit failure may
leave a valid but unpublished candidate. Neither is reported as a successful
backup/restore operation, and neither is automatically deleted or blindly retried.

Actual native application/export validation, human approval, license acceptance,
restore activation, signer and key-custody decisions, and remote publication remain
open. No power-loss durability, physical erasure or old-key revocation claim is
made. Existing raw export probes and pure metadata tests are separate evidence
from the prepared production-API native tests.

The latest source-only increment prepares native truncation cases, fresh-process
closed-candidate validation using an existing private key file, and occupied
artifact/orphan-sidecar preservation cases. It does not pass key bytes in process
arguments or print private material in these new assertions. These cases have not
been executed; static parsing is not encryption, restore or acceptance evidence.
The pinned native runtime is mandatory, with no fallback or missing-runtime skip.

The subsequent format-v2 source-only increment adds strict v1/v2 metadata cases
and prepared native coverage for absent/present checkpoints, marker/version
mismatches and legacy validation. The pure metadata tests and native tests for
this increment are likewise unrun; no native acceptance claim follows from them.

## Source-only integration after initialization protection

The format-v2 sources from local checkpoint `238418d70783cb2c2133ec8ff2d162df448afa44`
are prepared on the newer held encrypted application after `06b6533`. The bounded
`AdmissionPolicy.from_bytes` parser validates captured policy bytes without a
plaintext staging file. Additional pure parser contracts remain unexecuted.
The native synthetic fixture initializes its vault before acquiring the daemon
lease, then holds that lease before opening the Store and through export/close.

The full-row snapshot oracle includes current receipt bindings and the
`bootstrap_protocol` metadata; source control-file comparisons include the
immutable initialization records. Those records are not archived as restore
authority. No completion markers, fresh-vault activation, capability reissuance or
owner-access recovery are produced by these primitives. Existing NOASSERTION,
license, custody and native execution gates remain unchanged. This integration
was inspected and parsed statically only, without application imports, tests,
native execution, builds, artifact retrieval or publication.
