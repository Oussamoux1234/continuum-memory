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

## Full-thread forget process crashes

Run the focused synthetic regression:

```bash
PYTHONPATH=src python3 -W error::ResourceWarning -m unittest tests.test_forget_crash -v
```

The fixture uses real prototype proposal/approval/correction/recall/feedback APIs
to create three versions, three exclusively owned evidence bodies, two provider
disclosures per version, an accepted proposal and a pending same-subject draft.
Two mixed recalls include an unrelated surviving assertion. An unrelated second
project also remains present. All affected sets are asserted nonempty. Legacy
`conflicts`/`conflict_members` rows are **manually seeded synthetic legacy state**,
not output of the current API or a migration; current conflict projection is
separately asserted. No shared evidence is seeded in this matrix. Its retention
branch remains covered separately by the existing proposal-erasure/snapshot tests.

Only closed, checkpointed synthetic vaults without WAL/SHM/journal companions are
copied. Each subprocess executes the real approved forget with real SQLite,
foreign keys, FTS and audit MACs. Test-only clocks and the newly generated deletion
receipt ID make a successful reference reproducible. A transparent proxy observes
each direct mutating SQL call; it refuses cursor/script/batch bypasses. It calls
`os._exit(73)` at the selected boundary, without Python rollback/cleanup. Every
case must report the matching constant ordinal/label and exit 73; an unrelated
exception or an unreached boundary fails the test. Trace output uses stdout, not
files in the vault.

| Transaction/transition inventory | Observed direct boundaries |
|---|---:|
| Consume challenge; update global sequence | 2 writes |
| Record opaque audience-sequence changes | 2 writes |
| Delete feedback; prune mixed recall references | 3 + 2 writes |
| Delete FTS rows and assertion/proposal provenance | 3 + 5 writes |
| Insert delivery tombstones; purge proposals (reviews cascade) | 2 + 2 writes |
| Delete thread; delete now-unreferenced owned evidence | 1 + 3 writes |
| Insert content-free deletion receipt, audit event and keyed owner-result receipt | 3 writes |
| Before/after mutation commit; before/after external anchor publication; before/after anchor transaction commit; before/after WAL checkpoint | 8 boundaries |
| **Total** | **36 actual subprocess exits** |

The thread deletion also exercises real FK cascades for versions, disclosures,
evidence references, attestations, consent receipts, relations and the seeded
legacy conflict/member rows. Cascades and FTS internals execute inside SQLite;
the harness does not claim a separate process exit inside every native cascade,
VFS call, filesystem rename or checkpoint internals.

Before reconciliation, all 29 pre-commit exits must reopen as the exact original
logical state, with an unused grant, no new receipt/tombstone, and the unchanged
valid anchor. All seven post-commit exits must expose the exact complete deletion
and durable original result. The two exits after SQL commit but before anchor
publication must report `external_anchor_stale`; the five after publication must
have the exact new valid anchor. Equality includes every table and FTS shadow row,
not nondeterministic WAL bytes. Independent assertions also require targeted
canonical/evidence/projection/proposal rows to be gone, proper content-free
tombstones, exact recall pruning and unchanged unrelated rows. Thus the reference
comparison is not the only semantic oracle.

Only after those original-state assertions does the test reconcile the anchor.
Every pre-commit case then retries the same approved challenge exactly once;
every committed grant replay is rejected. Delayed proposal deliveries remain
suppressed, old recalls cannot fetch deleted versions, and current/history/FTS
lookups stay empty after another close/reopen. SQLite and foreign-key integrity
checks pass. This is one fully inventoried plaintext operation under process
death, **not** host power-loss, encrypted rotation, physical erasure, old-backup
revocation, or completion of issue #8. Shared-evidence races and other mutation
operations require their separate coverage; the broader open gates below remain.

## Audience-narrowing correction process crashes

```bash
PYTHONPATH=src python3 -W error::ResourceWarning -m unittest tests.test_correction_crash -v
```

The correction and forget tests share only test-side subprocess, SQLite-observer,
snapshot and recovery machinery in `tests/admin_crash_support.py`. Their seeds,
reviewed inventories and semantic assertions remain separate. The helper contains
no discoverable tests or production/runtime selection seam. The existing forget
inventory and assertions are preserved.

The correction fixture accepts a real synthetic Codex proposal disclosed to both
Codex and Claude, then previews an owner correction with new claim/evidence and
Codex-only disclosure. Unrelated alpha and beta claims, the original proposal and
its review, and current/history/pinned-recorded recalls remain in the vault. Only
closed vaults with no WAL/SHM/journal companions are copied. The child controls
clocks and newly generated correction IDs, not SQLite, signatures, keyed digests,
existing ledger identities or audit MACs.

| Reviewed ordered transition inventory | Direct boundaries |
|---|---:|
| Consume challenge; advance global sequence; insert evidence/version | 4 writes |
| Insert disclosure, evidence reference and FTS row | 3 writes |
| Insert author/recorder/authorizer attestations, consent and provenance | 5 writes |
| Retire original version; insert supersedes relation | 2 writes |
| Advance both affected provider audiences; insert audit event and owner result | 4 writes |
| Before/after mutation commit, anchor publication and anchor transaction commit | 6 boundaries |
| **Total** | **24 actual subprocess exits** |

All 19 pre-commit exits must restore the exact original logical state; all five
post-commit exits must expose the complete correction and original durable result.
Two exits between SQL commit and anchor publication require the stale-anchor
diagnostic; three after publication require the exact new valid anchor. These
comparisons include FTS shadow rows and precede reconciliation or any search that
would create additional recall records. Each child must emit exactly the matching
constant boundary marker and exit 73, with bounded execution and no stderr.

Independent assertions require exactly two versions in the same thread, the
original body/evidence/provenance preserved, precise retirement and supersession,
new user-authored evidence and correction provenance, complete attestations and
consent, correct FTS entries, and unchanged unrelated records. Both affected
alpha provider sequences advance once; beta sequences do not change. Codex sees
the new version currently and both historically. Claude sees neither target
version currently and only the original historically, never the new restricted
claim/evidence. Original current recalls cannot retrieve the superseded version;
history and pinned old-recorded recalls still can, with pinned lifecycle active.
None of those original recalls authorizes the new version ID.

The same approved challenge retries exactly once after an uncommitted crash;
committed replays are refused. Anchor reconciliation preserves logical state, and
the semantic assertions repeat after close/reopen. This covers one existing-thread
correction with nonempty evidence and narrowed disclosure, not every correction
variant, native cascade/VFS instruction, concurrent writer, CLI pending journal,
SQLCipher, key rotation, power loss or backup transition. Issue #8 remains open.

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
