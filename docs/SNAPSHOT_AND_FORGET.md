# Snapshot isolation and exact forget approval

This change addresses independent-review F1, F2, F3 and the equal-body defect in F6.
It applies to the application on main, independently of the SQLCipher PRs.
The fix is tracked in [issue 15](https://github.com/Oussamoux1234/continuum-memory/issues/15).

## Read contract

Search, context, conflict expansion, get and feedback use the same `Eligibility`
contract: project, disclosure audience, recorded snapshot, temporal mode and optional
valid instant. The owner can inspect every disclosure audience in a project.
An agent sees a dispute only when at least two eligible, visible, unequal assertions
conflict. A hidden claim cannot suppress a visible card or create a singleton hint.

Recorded intervals are `[ingest, retirement)`. Both bounds of an explicit valid
interval are inclusive; `unknown` validity does not match an explicit `as_of_valid`.
Without `as_of_valid`, validity remains unfiltered. A pair conflicts only when its
recorded lifetimes and valid intervals overlap. Unknown validity is conservatively
unbounded for pairwise overlap. No semantic contradiction model is introduced.

Conflicts are derived from immutable assertion versions within each eligible thread.
Connected groups of overlapping, unequal claims form dispute sets. Group IDs derive
from opaque member IDs, not claim text, and change when eligible membership changes.
Legacy `conflicts`/`conflict_members` tables remain compatible deletion data; readers
no longer treat that mutable cache as truth. Correction cannot erase past membership.
Equal-body corrections resolve the current disagreement without erasing either version.
History-mode conflict groups have `status=historical`; a recorded snapshot reconstructs
the dispute at that point. Retirement metadata later than a requested snapshot is hidden.

FTS5 selects matching candidates. Ranking uses only matched spans in the candidate
document (subject weight two, body weight one), then visible relative ingestion order
and ID as a deterministic tie-breaker. It uses no BM25 or other corpus statistics.
Hidden documents in another project or disclosure audience cannot affect the score.
This changes ranking; it is not a claim of better semantic relevance or timing isolation.

## Sequence domains and receipts

Agent `projection_watermark`, card recorded intervals, provenance creation sequences
and `as_of_recorded` use a monotonic timeline scoped to the bound project/provider.
Read responses advertise `recorded_sequence_domain=project_provider_v1`. Use numbers
returned to that same audience. The owner uses `vault_v1`, including administrative
`recorded_seq` values. Do not pass an owner sequence to an agent query.

Only accepted-version admission, retirement or deletion affecting an audience advances
its timeline. Hidden proposals, feedback and mutations in other audiences do not advance
it. A correction changing disclosure affects audiences that could see either version;
forgetting a shared thread affects every audience with a version in that thread. These
are visible changes, not hidden-only mutations. Wildcards cover configured providers.

The durable timeline retains only project/provider and local/global numeric mappings
after forget. It contains no assertion IDs, bodies or evidence and does not renumber
surviving versions. These mappings are internal; global counters are not agent output.
Supersedes/provenance input IDs pointing outside an agent's visible assertion history
are omitted. The owner retains the full provenance inputs, including proposals.

A receipt stores the exact temporal mode, optional recorded cutoff and valid instant.
Get and feedback reapply those constraints. Current receipts stop resolving a retired
version; explicit historical snapshots retain their earlier interpretation. Forget
still revokes every receipt reference to deleted versions.

## Schema v2 to v3

Store opening performs a forward, transactional migration. It adds audience sequence
mappings, a thread lookup index and temporal receipt columns. It backfills timelines
from the surviving v2 versions and disclosures, preserving canonical bodies, IDs,
evidence and audit records. Historical conflicts are reconstructed even when v2's
mutable conflict cache lost old members. No encryption or native wheel changes occur.

V2 did not retain exact receipt temporal intent. Its receipts are invalidated by clearing
their result IDs; clients must search again. Old cached agent sequence numbers must also
be discarded. Pre-upgrade forget previews fail with `stale_preview` and need renewal.
Unsupported schema versions fail closed. Interrupted migration rolls back DDL and data;
retry and reopen are tested. Older binaries reject v3; no in-place downgrade is provided.

## Forget approval

The preview lists exact identifiers for every affected version and dependent row, plus
the version count and a keyed digest of their state. This includes proposals/reviews,
feedback, receipt references, evidence ownership, shared-reference preconditions,
disclosures, attestations, consent, provenance, relations, legacy conflicts and FTS.
Shared evidence retained by another assertion is shown separately from evidence removed.
Content is not copied into the stored approval challenge: only its digest is retained.

Apply verifies the approved preview and grant, holds `BEGIN IMMEDIATE`, recomputes the
scope and checks its state immediately before deletion. A correction, new dependency,
changed evidence reference, retirement or missing target returns typed `stale_preview`.
The transaction rolls back with no deletion or challenge consumption. The caller must
request and approve a new preview. An unchanged scope succeeds; successful grants remain
one-shot. Unrelated writes do not stale the preview.

## Evidence and limits

The independent probes reproduced the defects on main
`9dc86b4f4d29d7ee06b58852488f181f0bbaa25c`. The first nine intended-behavior regressions
failed there (10 assertion failures and four follow-on errors in subtests).
`tests/test_snapshot_forget.py` covers the repaired scenarios, complete database equality
after stale apply, and dependent writes through a separate SQLite connection.
`tests/test_projection_migration.py` uses an immutable copy of the actual v2 schema and
checks forward migration, preserved records, old receipt invalidation, fault rollback,
retry, reopen, integrity and unsupported-version rejection.

F4 proposal erasure/retry protection is addressed by the later
[v4 proposal lifecycle contract](PROPOSAL_ERASURE.md).
[F7/F9 transport hardening](https://github.com/Oussamoux1234/continuum-memory/issues/18) and
[F8 post-commit result ambiguity](https://github.com/Oussamoux1234/continuum-memory/issues/8)
remain separate work. F5 result categories and applicability are now covered by the
[v2 read contract](CONTEXT_CONTRACT.md). The same-subject conflict rule remains conservative.
This does not add an explicit resolve/retract API, prove production readiness, encrypt
storage, provide physical erasure or enforce revocation across backups.

Conflict grouping compares pairs within eligible matching threads; very large threads
still need a performance bound. Forget previews enumerate their exact scope and scan
project receipts; large scopes can reach existing frame limits and require future
pagination/normalized references. Search completeness and general history pagination
are described in the v2 read contract: candidate-limit completeness is now honest, while
history pagination remains follow-up work. No native wheel matrix or package publication
is needed for this fix.
