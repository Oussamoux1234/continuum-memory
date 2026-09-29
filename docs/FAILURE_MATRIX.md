# Local failure-injection matrix

This held encrypted branch imports the main `152450a` contracts and prepared tests.
Historical plaintext results below are not validation of this source refresh. No
application or native test ran for this checkpoint; see [the pending matrix](ISSUE7_SOURCE_REFRESH.md).

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

The synthetic child freezes its kernel-local approval clock immediately before
the original stored challenge expiry, so slower native runners exercise the same
crash boundaries instead of expiring halfway through the matrix. Production grant
lifetimes and subprocess timeout clocks are unchanged. A separate regression proves
the ordinary kernel still rejects that same expired grant without mutating state.

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
variant, native cascade/VFS instruction, concurrent writer, SQLCipher, key rotation,
power loss or backup transition. Whole-CLI journal coverage is described separately
below; it is not supplied by this correction fixture. Issue #8 remains open.

## Agent-proposal acceptance process crashes

```bash
PYTHONPATH=src python3 -W error::ResourceWarning -m unittest tests.test_accept_proposal_crash -v
```

The fixture accepts one actual pending Codex proposal, with nonempty agent evidence
and disclosure to Codex and Claude. It retains another pending proposal, accepted
claims in two projects, prior provenance/audit rows and empty pre-acceptance recalls.
Only closed synthetic vaults without SQLite companions are copied. It uses the
same transparent SQLite observer and recovery machinery as forget/correction;
the proposal-specific seed, exact ordered inventory and semantic oracle are separate.

| Reviewed transition inventory | Direct boundaries |
|---|---:|
| Consume challenge; sequence; claim thread; evidence; assertion | 5 writes |
| Two disclosures; evidence reference; FTS row | 4 writes |
| Author/recorder/authorizer attestations; consent; provenance | 5 writes |
| Two audience sequences; audit; proposal acceptance; review; owner result | 6 writes |
| Before/after SQL commit, anchor publication and anchor transaction commit | 6 boundaries |
| **Total** | **26 actual subprocess exits** |

All 21 pre-commit exits must recover the exact original logical state; the five
post-commit exits must recover the complete acceptance and original durable result.
The two exits between commit and anchor publication require the stale-anchor
diagnostic, and the three after publication require the exact new anchor. The
comparison includes all tables and FTS shadow rows before any reconciliation or
new recall can obscure partial state. Missing hooks, incorrect ordinals, unexpected
stderr, timeouts or an exit other than the selected real `os._exit(73)` fail.

Independent checks require one new claim/version/evidence/review/result, three
correct role attestations, exact consent and proposal provenance, unchanged
unrelated records, and one audience-sequence advance for each disclosed provider.
Agent evidence stays `agent_provided`; the claim remains authority `data`, with
Codex authorship distinct from the synthetic owner's authorization. Both agents
can newly recall the exact claim/evidence, but their old recalls cannot acquire
access retroactively and neither capability gains control permissions. Replayed
proposal delivery returns the original accepted proposal without mutation.

Pre-commit cases retry the original challenge once; committed approval replays
are refused. Logical state, SQLite/foreign-key integrity and the original receipt
survive reconciliation and another reopen. This slice is explicitly POSIX-only
on its main-branch fixture: it does not establish native Windows, OS-backed human
presence, encrypted storage, host power-loss or backup/revocation evidence.
It covers new-thread acceptance with evidence, not every acceptance variant or
completion of issue #8.

## Direct owner remember process crashes

```bash
PYTHONPATH=src python3 -W error::ResourceWarning -m unittest tests.test_remember_crash -v
```

This fixture remembers a new subject with nonempty user-authored evidence,
Codex/Claude disclosure and explicit policy/valid-time metadata. It retains
unrelated accepted memories in two projects, accepted and pending proposals,
reviews and prior recalls. It shares only the existing test-side crash/recovery
mechanics; its exact inventory and semantic assertions are operation-specific.

The reviewed inventory contains 18 direct writes: challenge consumption, sequence,
thread, evidence, assertion, two disclosures, evidence reference, FTS, three
attestations, consent, provenance, two audience sequences, audit and owner result.
Six before/after SQL commit, anchor publication and anchor-transaction commit
boundaries bring the total to **24 real process exits**. Nineteen are pre-commit;
five are committed, including two with a stale anchor and three with the new anchor.

Whole logical-state comparison precedes recovery or new recall writes. Independent
checks distinguish the owner's terminal authorship and `user_authored` evidence
from agent-proposal acceptance, require `data` authority, exact consent and
`user_remember` provenance, and preserve nonempty unrelated records. Both disclosed
providers can retrieve the new claim, but old recalls cannot gain access
retroactively and agent capabilities do not acquire control authority. Original
receipts, single pre-commit retry, refused committed replay, reconciliation and
reopen follow the shared matrix contract.

This is new-subject, nonempty-evidence plaintext/POSIX coverage, not all remember
variants, human presence, native Windows, encryption or power-loss acceptance.

## Proposal rejection process crashes

```bash
PYTHONPATH=src python3 -W error::ResourceWarning -m unittest tests.test_reject_proposal_crash -v
```

The fixture rejects an actual pending proposal while retaining unrelated drafts,
an accepted proposal and its genuine review, canonical memory/evidence, recalls,
feedback and another project. The target's evidence text is also present in
unrelated retained content: rejection purges the target's inline draft evidence,
not canonical evidence belonging to another assertion. A schema-valid review row
is **manually seeded synthetic legacy state** on the pending target before its
exact preview, solely to exercise the real review foreign-key cascade. It is not
claimed to be a pending-proposal state produced by the current API.

Seven direct writes consume the challenge, advance the sequence, insert a delivery
tombstone, remove proposal provenance and the proposal, then insert audit and owner
result records. Six commit/anchor transitions yield **13 real process exits**:
eight pre-commit and five committed, of which two have a stale anchor. There is no
rejection checkpoint or generated result identifier in this inventory.

Beyond pre-recovery whole-state equality, the oracle checks the exact keyed,
project/provider-scoped rejection tombstone, target/provenance/legacy-review
removal, no target-specific canaries in live logical tables, and preservation of
shared evidence and nonempty unrelated state. Delayed deliveries with the original
key are suppressed even if their body changes; this refusal must not mutate the
vault. Recovery preserves the original result and never repeats a committed action.

These are plaintext/POSIX process-crash results, not physical erasure, external
backup revocation, native Windows, encryption, host power loss or completion of #8.

## POSIX audit-anchor publication faults

```bash
PYTHONPATH=src python3 -W error::ResourceWarning -m unittest tests.test_anchor_publication_faults -v
```

This bounded matrix enters the actual private-file replacement **after** a real
synthetic owner operation's SQL commit. It targets only that operation's existing
`audit.head` path, the exact generated temporary path, and tracked live file or
directory descriptors whose device/inode/type still match. Closing a descriptor
removes its tracking, so reuse cannot redirect a fault to SQLite or unrelated I/O.
Bootstrap, preview, other paths and all unaffected calls use real implementations.
The test forces a real positive partial write and returns its byte count to the
normal write loop. It never substitutes a fictitious successful write or fsync.

| Fault point | Required anchor and temporary state before reconciliation |
|---|---|
| Process exit after temporary creation | Exact old anchor; one private empty temporary |
| Process exit after partial real write | Exact old anchor; one private new-anchor prefix |
| Process exit after file fsync or immediately before rename | Exact old anchor; one private complete new-anchor temporary |
| Process exit immediately after rename or after directory fsync | Exact new anchor; no temporary |
| ENOSPC on the write after a positive short write; EIO at file fsync or rename | Exact old anchor; normal exception cleanup removes the temporary |
| EIO at directory fsync after successful rename | Exact new valid anchor; no temporary; the response still truthfully reports committed/degraded |

There are six actual `os._exit(73)` cases, four exact-once errno injections, and a
successful control that reaches all six checkpoints in their reviewed order.
Each child has a bounded timeout/output and empty stderr; an unexpected exception,
missed hook or wrong exit/marker fails. Every crash leaves the SQL mutation, grant
consumption and content-free original receipt committed. Independent assertions
check expected table growth, retained original rows, claim/evidence/disclosure/FTS
semantics, sequence and audit target, plus database/foreign-key integrity. Expected
new anchor bytes are derived from the durable audit head, not the publication
implementation. Pre-rename cases report a stale verified prefix; post-rename
cases report the exact valid new anchor.

Reconciliation and refused grant replay leave every logical database row unchanged;
the original receipt survives another reopen. Crash leftovers are single-link,
owner-only regular files containing only empty/partial/complete anchor metadata.
They remain untouched and non-authoritative through recovery; no automatic orphan
cleanup is introduced. Windows is explicitly skipped because it uses a different
private-file implementation. These are POSIX process-exit/I/O-error results, not
power-loss or disk-controller durability, encrypted-key custody, malicious same-UID
isolation, full Windows evidence, or completion of issue #8.

## Whole-CLI exit and durable journal recovery

Run the focused synthetic suites:

```bash
PYTHONPATH=src python3 -W error::ResourceWarning -m unittest \
  tests.test_recovery_protocol tests.test_recovery_journal \
  tests.test_cli_recovery_control tests.test_cli_recovery -v
```

`tests/test_cli_recovery.py` runs actual daemon and CLI interpreters against a
temporary plaintext vault. Its test-only broker signs synthetic approvals; this
is not real human-presence acceptance. After approval, the product CLI durably
publishes the opaque v1 descriptor before sending `admin_apply`. The fault seam
then exits the actual CLI with `os._exit(73)`, or holds an incomplete frame with
bounded pipe barriers. The replacement `continuum recover` is a fresh, unpatched
interpreter with no original request, grant or in-memory locator.

| Whole-client boundary | Required result from fresh-process recovery |
|---|---|
| Exit before journal persistence | No journal, apply, mutation, receipt or consumed grant; recovery reports a missing journal, not safe-to-retry authority |
| Exit after journal, before send, or after an incomplete request frame | Opaque descriptor retained; zero committed actions; `unknown` with exit 2, repeatedly, without retry |
| Original incomplete request remains in flight | First lookup is `unknown`; releasing that original request produces exactly one commit; subsequent lookup is `committed` without a new apply |
| Exit after real SQL commit but before any response is scheduled/sent | Fresh CLI reads the original committed receipt without approval or mutation |
| Exit after receiving the real committed reply but before printing it | Fresh CLI still recovers the exact original result |
| Successful original CLI followed by a fresh CLI | Same receipt, no reapproval, no journal changes |

Every deliberate process exit must be 73 with empty stdout/stderr; setup failures
or missed hooks are not accepted as crashes. Assertions independently check exact
assertion/receipt/used-grant counts. A fixture-only method trace proves each targeted
recovery sends only `admin_recover`, never preview, approval or apply. Journal bytes
remain unchanged, and must contain none of the subject, body, evidence, raw preview
digest, capability token or grant. The committed-before-reply case additionally
forgets the memory, restarts the daemon, and recovers the unchanged historical
receipt while the canonical content and original digest remain absent.

`tests/test_recovery_protocol.py` verifies the exact descriptor, a separately
computed two-layer HMAC oracle, current capability authentication and revocation,
agent/other-control rejection, malformed/swapped fields, receipt-MAC tampering,
legacy-result compatibility, degraded audit status and forget/challenge cleanup.
An actual copied synthetic database/key/receipt with a relabeled vault ID cannot
retarget the original descriptor, even though the positive-control legacy receipt
still validates. This proves vault domain binding, not freshness against a clone
whose vault identity and key are unchanged.

`tests/test_recovery_journal.py` covers fresh-process roundtrips, exact-nonce
collisions, concurrent distinct/same-nonce writers, strict records, lexical pages,
the 4,096-entry scan bound, and targeted access past unrelated corruption. Listings
validate every observed bounded entry, not only the returned page. POSIX tests
also cover symlink/FIFO/type refusal, file→journal→parent flush ordering, partial/
zero writes, each flush failure and directory replacement. Unsafe or partial
residue remains untouched; nothing cleans, repairs, overwrites or treats it as a
receipt. Native macOS ACL refusal is covered on macOS.

Native Windows-only journal tests inject file-flush failure after real creation/
writing, and readback failure or mismatch after a real flush. They require the
exact opaque bytes to remain readable and refuse both identical and changed
replacement attempts. The CLI control-flow suite separately checks approval and
publication ordering, cancellation, malformed replies, descriptor copying, one
read-only lookup after ambiguous failure, and content-free unknown errors.

Results have `scope: "page"`, `has_more` and `next_cursor`; a complete page is not
a complete journal when another page exists. Unknown outcomes exit 2. Page size
is at most 25, and lexical cursors are not concurrent-publication snapshots. Exact
`--nonce` bypasses the listing bound and unrelated malformed entries, never its own
validation. See [the operator contract](COMMIT_RECOVERY.md) for commands and mixed
client/daemon-version behavior.

The process-exit/partial-socket matrix is POSIX-only. Native Windows CLI/protocol/
journal cases require passing jobs for the exact revision under review; earlier
Windows acceptance alone does not validate changed recovery behavior.
Windows uses the existing pinned-handle/private-file boundary with file flush and
readback, not POSIX directory sync. The tests do not prove host power-loss survival,
same-user isolation, production encryption, key rotation or backup freshness.
They neither add approval authority nor complete issue #8.

## Other current failure coverage

| Surface | Existing evidence | Remaining boundary |
|---|---|---|
| Owner mutation SQL commit and audit publication | `test_commit_recovery.py`: precommit failure, process exit before/after commit and after anchor, original receipts and reconciliation | Not every statement/variant of every operation; whole-CLI recovery is separately bounded above |
| CLI process exit and journal | `test_cli_recovery.py`, `test_recovery_protocol.py`, `test_recovery_journal.py`: original authenticated receipts, opaque retained locators and unknown in-flight outcomes | No retry authority, lost-locator backfill, cleanup, Windows socket-fault matrix or host power-loss guarantee |
| macOS SQLite lock preservation | `test_sqlite_lock_preservation.py`: normal independent SQLite reader, live WAL/SHM identity, abrupt writer death, multiple Store handles, unsafe-file/ACL refusal | Dedicated pathname ACL observation, not binding to SQLite's VFS descriptor or arbitrary same-user substitution protection |
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
