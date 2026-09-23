# Recover an approved operation after a lost reply

This is the committed-result slice of [issue #8](https://github.com/Oussamoux1234/continuum-memory/issues/8),
not completion of its crash, lock, key-rotation and audit-hardening roadmap.
It applies to schema v5 owner operations through the local daemon. The database
is still the plaintext prototype; use synthetic data, not production secrets.

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

Clients should retain the server-issued challenge `nonce` and `preview_digest`
before submitting `admin_apply`, without logging previews, bodies or grants.
After reconnecting, query the original result without requesting another grant:

```bash
continuum --data-dir /path/to/vault --json result \
  --nonce gnt_EXAMPLE --preview-digest EXACT_APPROVED_DIGEST
continuum --data-dir /path/to/vault audit verify
continuum --data-dir /path/to/vault audit reconcile
```

Replace the example locator with the exact original challenge fields. `result`
uses the same control capability that submitted the operation; an agent capability,
another control capability or wrong digest cannot read it. No new human grant is
needed to read content-free metadata about an already-committed operation. This
does not authorize an action or expose forgotten content through a new read path.

The CLI handles ambiguous daemon/transport failure by making one read-only receipt
lookup. It never automatically repeats the mutation. If lookup is unavailable, it
returns `operation_outcome_unknown` with the bounded nonce/digest locator. Receipt
absence is **not proof that retrying is safe**. Pre-v5 operations have no receipts.
A client that loses its locator cannot reconstruct it using these commands. The
CLI does not yet maintain a local pending-request journal, so killing the entire
CLI before its locator is reported is not automatic end-to-end exactly-once recovery.

## Result and audit contracts

The control-only daemon method `admin_result` takes exactly `nonce` and
`preview_digest`. Its response contains `receipt_id`, `operation`, `committed: true`,
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
are used. Host power-loss, disk-controller guarantees, exhaustive OS fault injection,
key rotation, full platform lifetime guarantees, backup revocation and exactly-once
feedback are not certified by this slice and remain separate work under #8/#6.
Cooperating-daemon locks and guarded stale-socket restart are covered separately in
[daemon recovery](DAEMON_RECOVERY.md), including its offline-upgrade constraints.

Full chain verification on every audited commit/reconciliation is linear in audit
history; this favors correctness in the bounded prototype, not large-vault throughput.
SQLite's existing lock timeout still applies. Native Windows is not added.
