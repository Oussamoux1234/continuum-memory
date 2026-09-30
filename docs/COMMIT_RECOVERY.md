# Recover an approved operation after a lost reply or CLI exit

This is the committed-result slice of [issue #8](https://github.com/Oussamoux1234/continuum-memory/issues/8),
not completion of its crash, lock, key-rotation and audit-hardening roadmap.
It applies to schema v5 owner operations through the local daemon. The database
in this branch requires the held SQLCipher backend. These recovery tests passed on
plaintext main separately; they have not executed against this refreshed candidate.
Use only synthetic data after native execution is separately authorized.

## Owner workflow

`remember`, `correct`, `review` and `forget` still require the existing exact
human-approved preview. Successful replies retain their result fields and add:

```json
{"commit":{"status":"committed","receipt_id":"gnt_EXAMPLE","audit_anchor":"synced"}}
```

If SQLite committed but the later audit-file write failed, the action is not
reported as failed: `audit_anchor` is `degraded`. Do not submit a new action merely
to repair that file. Forget can separately report `checkpoint: deferred`; logical
deletion committed, but WAL truncation did not complete. This does not promise
physical erasure or erase external copies.

The CLI validates the server-issued `recovery_locator`, obtains the existing exact
human approval, and then publishes the opaque locator in the private vault's
`recovery/<nonce>.json` journal **before sending any `admin_apply` bytes**. A failed
journal publication prevents that CLI from sending the action. The journal contains
only `version`, `vault_id`, `nonce` and a keyed `binding`: no preview, raw preview
digest, body, evidence, grant or capability token. It is neither an approval nor a
receipt and cannot establish whether the action committed.

After reconnecting, including from a new terminal after the original CLI has
exited, query the original outcome without approving or sending another action:

```bash
continuum --data-dir /path/to/vault --json recover --limit 25
continuum --data-dir /path/to/vault --json recover --after gnt_LAST_NONCE_FROM_PAGE
continuum --data-dir /path/to/vault --json recover --nonce gnt_EXACT_ORIGINAL_NONCE
continuum --data-dir /path/to/vault audit verify
continuum --data-dir /path/to/vault audit reconcile
```

Use the returned `next_cursor` verbatim for `--after`, or the exact original nonce
for targeted recovery. Do not combine `--nonce` and `--after`. The command reads
the local descriptors and asks the daemon for their receipts using the original,
still-valid control capability. Agent capabilities, other control capabilities,
revoked tokens, wrong vaults and incorrect bindings do not recover the receipt.
No grant is needed for this read; it does not authorize any new action or disclose
forgotten content.

`recover` returns `scope: "page"`, `operations`, `next_cursor` and `has_more`.
Each operation is `committed` with its original receipt, or `unknown`. The page's
`status` is `complete` only when every returned operation has a matching receipt;
otherwise it is `unresolved` and the command exits **2**. A fully resolved page
exits 0 even if `has_more` is true: follow the cursor before drawing a journal-wide
conclusion. An empty existing journal is an empty complete page, not proof that
every historical action has a receipt. Missing, unsafe or corrupt journal access
returns a content-free error and exits 2.

The CLI handles ambiguous daemon/transport failure by making one read-only receipt
lookup. It never automatically repeats the mutation. If the outcome cannot be
confirmed, it returns `operation_outcome_unknown` with only the bounded nonce.
An absent receipt is **not proof that retrying is safe**: the original request may
still be in flight and commit later. Retry the read-only recovery query, not the
action. Unavailable, revoked or invalid receipt responses likewise remain unknown.

## Journal limits and compatibility

Entries are immutable create-new files. Even an identical existing nonce is not
overwritten; failed publication can leave an empty or partial file that is retained.
Neither recovery nor forgetting memory deletes or repairs journal files. There is
no automatic cleanup, journal backfill or retroactive reconstruction of lost
locators. Operators must not treat a partial file, a directory listing, or a local
descriptor as execution evidence.

Listing has a maximum page size of 25 and validates every observed entry, including
entries outside the requested page, up to a **4,096-entry scan bound**. Unknown
filenames, unsafe files and corrupt records fail the listing rather than being
silently skipped. Exceeding the bound fails explicitly. Exact `--nonce` lookup
bypasses that scan bound and unrelated corrupt entries, but still validates its
own file and receipt. Cursors are lexical, not snapshots: a concurrent publication
with an earlier-sorting nonce requires restarting the listing to discover it.

On POSIX the CLI flushes the file, journal directory and vault parent directory
before applying. Native Windows uses owner-only creation, pinned handles and file
flush/readback through the existing boundary; it claims process-crash recovery,
**not** POSIX directory-fsync or host power-loss durability. Check the native
Windows jobs for the exact revision being accepted; prior prototype acceptance
alone is not evidence that a changed recovery path has passed native execution.

The new CLI refuses a daemon that omits the locator before requesting approval
(`recovery_unsupported`), and refuses a malformed or mismatched descriptor. The
CLI checks descriptor/receipt shape and matching identities; it does **not** possess
the audit key or independently verify the cryptographic binding. The authenticated
daemon verifies that binding and the receipt MAC.

The legacy command and daemon method remain available when an older client already
has the exact original nonce and digest:

```bash
continuum --data-dir /path/to/vault --json result \
  --nonce gnt_EXACT_ORIGINAL_NONCE --preview-digest EXACT_APPROVED_DIGEST
```

This is a compatibility path, not advice to newly persist or log raw preview
digests: a raw digest can permit guessing forgotten low-entropy content. Older
clients do not create the new journal. Pre-v5 operations have no receipts; existing
v5 receipts receive no automatic journal entries. A lost legacy locator cannot be
reconstructed by `recover`.

## Result and audit contracts

The control-only daemon method `admin_recover` takes exactly the v1 descriptor:
`version: 1`, `vault_id`, `nonce` and a lowercase 64-hex `binding`. Booleans are not
valid versions; missing or extra fields are rejected. The new domain-separated
binding covers the descriptor version, current vault ID, nonce, authenticated
control capability ID and existing keyed receipt-request binding. Relabeling a
copied vault cannot retarget an original locator. The receipt's stored integrity
MAC must also verify. This does not prove freshness of an unchanged-identity clone
or a coordinated database/key/anchor rollback.

The legacy control-only `admin_result` takes exactly `nonce` and `preview_digest`.
Both lookup methods return `receipt_id`, `operation`, `committed: true`,
the immutable original `result`, and the **current** `audit_anchor` verification
status. It does not claim the returned assertion still exists: deletion or later
correction can have changed memory since that historical operation.

The receipt is inserted in the same SQLite transaction as the mutation and grant
consumption. It contains generated result identifiers, counters and status fields,
capability/project binding, a keyed request binding and an integrity MAC. It contains no
raw preview hash, preview, body, evidence, reason, raw grant or exception text. The
keyed binding prevents a database-only reader testing forgotten-text guesses against
a raw request hash; the audit key remains sensitive. The receipt survives consumed
challenge cleanup and memory deletion. No receipt garbage collection is introduced.
Original result metadata is never overwritten when audit health changes.

`admin_apply` remains a one-shot operation: replay still fails; recovery is a
separate read. There are no new agent-facing MCP tools. Agent proposal retries keep
their existing delivery-key/tombstone semantics. Other audited transactions report
the content-free `committed_audit_degraded` error if their SQL commit succeeded but
anchor publication failed. That code identifies a committed transaction, **not
necessarily the requested owner operation**: retention preflight may have committed
first. Only the matching owner receipt confirms the requested operation.

`audit_reconcile` is control-only and takes no parameters. Both normal audited
commits and reconciliation verify the full HMAC chain and the exact MAC of the
existing anchor's sequence. A missing, malformed, ahead, mismatched or corrupted
anchor/chain is refused, never recreated or overwritten as a repair. After SQL
commit, anchor publication reacquires the SQLite writer lock and reads the current
head under that lock. An older writer cannot publish a stale captured head after a
newer writer. The filesystem replacement and parent-directory sync occur while
that lock is held. Bootstrap is the sole initial-anchor creation path.
Standalone audit diagnostics also acquire this lock, so they cannot mistake a
concurrent writer's newer anchor for rollback of an older database snapshot.

Reconciliation advances only a verified matching prefix. If it is refused, stop
and investigate; do not delete the anchor, replace it with database output, or
restore an old vault to silence an error. These checks rely on the retained local
anchor and HMAC key. They cannot establish freshness after coordinated restoration
of database/key/anchor, or resist same-user malware holding that key.

## Upgrade, validation and remaining work

Schema v4 → v5 transactionally adds the result table without inferring historical
receipts. The existing v2/v3 paths upgrade through v5 atomically. Interrupted DDL
rolls back; unsupported versions fail closed. Older binaries reject v5; no in-place
downgrade is provided. Do not run an older binary against an upgraded vault.

`tests/test_commit_recovery.py` covers precommit rollback, postcommit IO failure,
process exits before SQL commit/after commit/after anchor publication, reopen,
grant replay, exact receipt scope/integrity, deletion canaries, retention preflight,
late-writer ordering, refused anchor repair, deferred checkpoints, v4 migration,
and actual daemon/CLI read-only recovery surfaces. Only synthetic temporary vaults
are used. The [whole-CLI crash and journal matrix](FAILURE_MATRIX.md#whole-cli-exit-and-durable-journal-recovery)
adds real client-process exits, fresh-process reads, in-flight unknown outcomes,
opaque-journal privacy and authenticated recovery checks. Approval in those tests
is deliberately synthetic; they do not satisfy the real OS-backed human-presence
gate. Host power-loss, disk-controller guarantees, exhaustive OS fault injection,
key rotation, full platform lifetime guarantees, backup revocation and exactly-once
feedback are not certified by this slice and remain separate work under #8/#6.
Cooperating-daemon locks and guarded stale-socket restart are covered separately in
[daemon recovery](DAEMON_RECOVERY.md), including its offline-upgrade constraints.

Full chain verification on every audited commit/reconciliation is linear in audit
history; this favors correctness in the bounded prototype, not large-vault throughput.
SQLite's existing lock timeout still applies. This slice adds no encryption-key
rotation, protected key custody, backup restoration or revocation/freshness authority.
