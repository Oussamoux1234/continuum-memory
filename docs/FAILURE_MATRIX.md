# Local failure-injection matrix

This is evidence for bounded slices of
[issue #8](https://github.com/Oussamoux1234/continuum-memory/issues/8), not its
completion. Tests use synthetic temporary vaults/databases. No host power-loss,
disk-controller durability, full native Windows runtime, or production encryption
claim follows from a process-exit test.

## Schema migration process crashes

Run the focused regression suite:

```bash
PYTHONPATH=src python3 -W error::ResourceWarning -m unittest discover \
  -s tests -p test_migration_crash.py -v
```

`tests/test_migration_crash.py` builds real v2/v3/v4 schemas from the committed
historical fixtures, seeds projects/capabilities, scoped assertions, disclosures,
FTS and an old recall, and uses SQLite WAL plus `synchronous=FULL`. All fixture
connections are closed before copying a database. These are migration-engine
tests using stdlib SQLite, not keyless opens of encrypted application vaults.

A proxy delegates real SQLite operations and calls `os._exit(73)` after each
migration `execute` and immediately before/after commit. The child cannot run
Python exception rollback or connection cleanup. Fresh processes/connections
reopen each crash artifact. The expected completed state comes from a successful
upgrade of the identical fixture; the comparison includes schema, all logical
rows (including FTS shadow tables), `user_version` and `application_id`. It excludes
WAL salts and checkpoint/file-layout differences, which are not logical state.
This establishes atomicity against that successful upgrade, not independent
semantic correctness of every migration; the existing migration-specific tests
cover audience backfill, recall invalidation and data preservation semantics.

| Boundary | Cases | Required recovered state |
|---|---|---|
| v2 -> v5 after every SQL call and before/after commit | 16 subprocess exits | Exact original v2 before commit, exact completed v5 after commit |
| v3 -> v5 after every SQL call and before/after commit | 9 subprocess exits | Exact original v3 before commit, exact completed v5 after commit |
| v4 -> v5 after every SQL call and before/after commit | 9 subprocess exits | Exact original v4 before commit, exact completed v5 after commit |
| Retry of every recovered state | 34 retries | Exact complete v5, SQLite integrity and foreign keys pass |
| Stale opener during another process's migration | v2/v3/v4 | Real writer-lock contention, locked-version recheck, no duplicate DDL/backfill |
| Unsupported versions | 0, 1, 999 | Engine returns unchanged version without executing DDL; Store refusal is separately tested |

The concurrency test uses pipe barriers, not sleeps. A leader holds the real
SQLite writer transaction; a follower observes the old version and demonstrates
an immediate lock refusal. It then retries normal migration while the leader is
released. The stale supplied version must not trigger a second upgrade after the
locked database version has advanced.

The boundary list is recorded from the real migration implementation. A future
new connection operation must be deliberately added to the proxy and its coverage
reviewed; bypassing it with an implicit-commit `executescript` is not accepted.

## Other current failure coverage

| Surface | Existing evidence | Remaining boundary |
|---|---|---|
| Owner mutation SQL commit and audit publication | `test_commit_recovery.py`: precommit failure, process exit before/after commit and after anchor, original receipts and reconciliation | Not every statement of every operation, no entire-CLI pending journal |
| Audit integrity and recovery | Exact-prefix MAC, missing/malformed/ahead/mismatched anchor refusal, late-writer serialization | Cannot prove freshness after coordinated DB/key/anchor rollback |
| Forget after committed deletion | Receipt remains committed when checkpoint fails; canonical/feedback/recall/FTS removal tests | No physical-erasure or external-backup revocation guarantee |
| Daemon startup, concurrency and stale endpoints | `test_daemon_lock.py`: real process locks, crashes, stopped live peer, startup faults, replacement-preserving cleanup | Cooperating lock-aware POSIX versions/local filesystems only |
| Interrupted migration exceptions | Projection/proposal/receipt migration tests reject DDL and compare rollback | Complementary to, not a replacement for, process-exit cases |

## Open gates

Issue #8 remains open for the complete operation/fault inventory, approved
encryption and approval-key rotation/recovery, and the relevant audit-anchor and
backup/revocation transitions once those implementations exist. SQLCipher must
rerun applicable migration/crash cases with its reviewed provider before those
results can be called encryption evidence. The full `python3 scripts/verify.py`
gate and current Linux CI must remain green; isolated test success is insufficient.
