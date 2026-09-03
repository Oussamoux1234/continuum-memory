# Milestone 1 executable build brief

Status: accepted for the experimental local prototype. This brief narrows the larger
product constitution; its non-goals override broader milestone language in the source
architecture prompt.

Storage amendment: Issue #7 now carries a provisional SQLCipher implementation and
verification candidate beyond this original dependency-free slice. It is not part of the
Milestone 1 completion claim and remains unaccepted until independent review.

## Goal

Prove that two provider-neutral MCP clients can use one user-owned project ledger without
letting either agent approve truth, cross project/disclosure boundaries, erase history by
correction, hide a conflict, or leave deleted content in live canonical/FTS queries.

## Non-goals

No native host installers, Agent Relay changes, encryption claim, OS-backed user-presence,
backup/revocation, sync, teams, cloud, embeddings, vector database, model extraction,
semantic deduplication, sophisticated DLP, public benchmarks, signed releases, auto-update,
or cross-platform packaging.

## User journeys

1. Bootstrap an owner-only local vault, one opaque project, and project/provider-bound
   capabilities without modifying any host profile.
2. A client proposes an atomic claim and evidence. The proposal remains quarantined.
3. The user sees the exact claim, evidence, scope, disclosure, retention, and digest, then
   accepts it through an interactive one-shot grant.
4. A second allowed provider recalls the accepted version and provenance.
5. The user corrects it; ordinary retrieval returns the replacement while explicit
   history returns both immutable versions.
6. Another incompatible accepted assertion creates an open conflict; ordinary context
   lists the conflict and excludes both sides from verified-current items.
7. The user forgets the claim thread. Bodies, contentful feedback, FTS rows, and recall
   references disappear transactionally; content-free receipt/audit metadata remains.
8. Forged approval fields, replayed proposal IDs/grants, and cross-project/provider reads
   fail with typed, non-revealing errors.

## Canonical schema

SQLite tables represent projects, scopes, evidence, claim threads, assertion versions,
proposal/review state, typed relations, conflicts/members, attestations, consent receipts,
idempotency, feedback, content-free audit events, deletion receipts, and disposable FTS.
Opaque random IDs are public handles. `ingest_seq` is authoritative recorded order.
Assertions have explicit valid-time precision, normalized UTC bounds, a retention deadline,
and a transaction retirement sequence. Reaching a deadline creates one monotonic, audited
`expired` transition before a current read; explicit history remains available.

Admission, epistemic, lifecycle, classification, disclosure, authority, and scope are
separate columns or relations. Accepted model-visible assertions always use
`authority=data`. Bodies are immutable. A correction inserts a version and a `supersedes`
relation, retiring the previous current version. Incompatible active versions become a
conflict set; no timestamp breaks the tie.

## Interfaces

CLI: `init`, `remember`, `inbox`, `review`, `search`, `context`, `show`, `correct`,
`forget`, `status`, and `audit verify`.

MCP stdio: `memory_context`, `memory_search`, `memory_get`, `memory_propose`,
`memory_feedback`, and `memory_status`. Tool input schemas reject unknown fields and bind
project/provider/capability at process startup. No administrative tool exists.

Daemon protocol: owner-only Unix socket, newline-delimited bounded JSON, project/provider
capabilities, typed errors, and a single serialized request loop. `init` is the sole
offline bootstrap writer; afterward the daemon owns writes.

## Limits

- claim/evidence: 4,096 UTF-8 bytes each;
- subject/query/reason: 256/256/512 UTF-8 bytes;
- search: 1–25 results;
- context: 256–8,192 bytes (and a conservative `max_tokens * 4` ceiling);
- RPC frame: 64 KiB;
- retention: `forever`, `YYYY-MM-DD`, or timezone-aware RFC 3339 date-time; values normalize
  to fixed-width UTC and date-only means midnight UTC;
- valid precision: `unknown`, `instant`, `interval`, or `open`.

## Acceptance tests and exact demo

`python3 scripts/verify.py` must run unit/integration tests, schema checks, the complete
fixture demo, database integrity check, audit verification, and `git diff --check`.
Regression coverage also rejects invalid calendar dates, naive timestamps, unsafe UTC
offsets, symlink/hardlink paths, foreign or open file modes, stale current recalls after
expiry, and feedback/recall remnants after forget. The demo performs the seven-step flow
above and additionally proves grant/idempotency
replay rejection and isolation across two registered projects plus incompatible provider
policies. It operates only in a temporary home and never touches real host profiles.

## Definition of done

Done means the documented command passes on a machine with a declared maintained CPython
3.11–3.14 and the pinned SQLCipher/FTS5 runtime, and the
demo produces evidence for each scoped acceptance test. The slice is still a prototype:
real Linux polkit, independently accepted SQLCipher, native hosts, backup revocation,
independent security audit, signed package reproducibility, and benchmark gates remain
explicitly incomplete.
