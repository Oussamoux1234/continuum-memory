# Read contract v3: scoped pages and honest conflict fragments

For MCP and CLI client authors upgrading from the prototype's original context shape.
This contract addresses [issue 23](https://github.com/Oussamoux1234/continuum-memory/issues/23)
while retaining the truthfulness distinctions from [issue 17](https://github.com/Oussamoux1234/continuum-memory/issues/17).
It changes read projections only: no database migration, new verification writer,
approval grant, native adapter or transport change is required.

## Upgrade clients

1. Require `response_version: 3` on `memory_context`/`context` results.
2. Replace reads of `verified_current` with `accepted_claims`. The old key is removed,
   not retained as an alias: neither its verification nor its current-truth claim was valid.
3. Treat each card's `admission`, `epistemic`, `lifecycle`, and `applicability` separately.
   Display `open_conflicts` without silently selecting a winner.
4. Handle `status: partial` in both search and context. Do not assume the first page or
   capsule includes every matching memory, and never authorize actions from its contents.

The six MCP tools and both pinned MCP envelope versions are unchanged. Search/context
accept an optional `cursor`; owner show accepts `cursor` and a page `limit` of one to five.
CLI JSON and both MCP fixture clients receive the same v3 context. Strict v2 validators
must upgrade: conflict fragments can contain one displayed member, their completeness is
explicit, and large threads can be `not_fully_assessed` rather than open/historical.
There is no fabricated v1/v2 compatibility mode. Consumers requiring the old schema must
upgrade together with the service. Existing persisted receipts and scoped recorded
sequences stay valid; no storage migration is introduced. Search/get/show retain their
existing fields and gain optional continuation/assessment metadata.

The checked-in [response schema](../schemas/context-response.schema.json) describes the
v3 capsule and nested conflict cards. MCP discovery still advertises the generic object
output schema; clients must inspect the response version. The schema and this guide ship
in the source distribution. Existing installations must not assume new native OS support.

## Four independent dimensions

| Field | Meaning | What it does not prove |
| --- | --- | --- |
| `admission: accepted` | Exact content passed the owner-approval boundary | Factual accuracy or permission to act |
| `epistemic` | Stored label: `asserted`, `verified`, `disputed`, or `refuted` | Fresh verification by this read |
| `lifecycle` | Version state at the selected recorded snapshot | Applicability of the claim in the world |
| `applicability` | Comparison with the claim's declared valid-time bounds | Correctness of those bounds or the claim |

Production remember/accept/correct paths currently write `epistemic: asserted`. Approval,
evidence text, authorizer attestations and absence of a conflict do not promote it to
`verified`. A historical observation stored as verified retains that label, but is still
historical evidence, not an independent recheck. This change adds no verification-ingestion
API and does not certify arbitrary imported labels. The regression fixture's validator
attestation is synthetic, not a new production trust mechanism.

Every card continues to return `requires_current_verification: true` and `authority: data`.
The memory contract continues to forbid memory from authorizing actions. Even a verified,
active, in-interval memory may be wrong, stale in the real workspace, or contradicted by
current user instructions. Refuted/disputed labels must not be presented as verified facts.

## Default valid time is explicitly unfiltered

`temporal_mode: current` means **unretired at the selected recorded sequence**, not
"true now." `history` includes retired versions; a supplied `as_of_recorded` reconstructs
that recorded snapshot. These meanings and audience eligibility are unchanged.

Without `as_of_valid`, search/context continue to select unknown, past, present and future
valid-time declarations. This preserves unknown memories without inventing dates. Cards
with known bounds are classified against one UTC read-clock instant shared by the whole
response, including conflict members. Their `applicability.as_of` names that instant.

| `applicability.status` | Meaning |
| --- | --- |
| `unknown` | Validity was declared unknown; `as_of` is null |
| `not_yet_valid` | The comparison instant is before the declared start |
| `no_longer_valid` | The comparison instant is after the declared end |
| `within_declared_interval` | The comparison instant satisfies the declared bounds |

Both interval endpoints are inclusive; an instant matches exactly, and an open interval
uses its one declared bound. `within_declared_interval` deliberately does not say "current"
or "verified." A retention-expired historical version can still have this classification:
retention, lifecycle, and declared validity are separate dimensions.

Supplying `as_of_valid` filters candidates and conflict expansion to known intervals
containing that UTC instant and classifies cards at the same instant. Unknown validity
does not match this explicit filter. `as_of_recorded` does not imply an `as_of_valid`:
request both if you need both axes fixed. Classification never broadens eligibility.

Default receipts remain validity-unfiltered. A later `get` recalculates applicability at
its own read clock; an explicitly dated receipt stays pinned to its `as_of_valid`. One
instant is used for all records in a get/show response. Clock-derived classifications are
disposable views and do not mutate canonical memory or advance audience counters.

## Bounded results and honest completeness

Search probes one extra eligible, audience-visible candidate beyond `limit` (at most 25);
context does so beyond 25 candidates. A conservative encoded search payload cap also
reserves room for MCP's text and structured copies. Owner show returns at most five full
records per page and obeys the transport frame bound. Hidden records do not affect the
probe, counters, rankings or completeness flags.

Context returns an ordered prefix of candidates that fits `byte_budget`. `omitted_items`
counts only the candidate cards deferred by this page's byte packing, not every remaining
match or undisplayed conflict member. A continuation advances past **only returned
candidates**. If even one result and its safety metadata cannot fit, `budget_too_small`
asks for a larger budget instead of issuing a zero-progress cursor. A 512-byte budget
can no longer return a useful nonempty capsule; use the default 4096 bytes or up to 8192.
Compact claims can separately have `claim_truncated: true`.

### Continue a search or history query

Copy `next_cursor` into `cursor` on the same operation with the same project/capability,
query/ID, temporal mode, recorded filter and valid-time filter. Page size and context
budget may change. When `next_cursor` is absent, no matching candidates remain after
this page. A partial conflict assessment can still make the final context page partial.

```sh
continuum --data-dir /absolute/private/vault --json search --project PROJECT_ID --query engine --limit 5
continuum --data-dir /absolute/private/vault --json search --project PROJECT_ID --query engine --limit 5 --cursor CURSOR_FROM_PREVIOUS_RESPONSE
continuum --data-dir /absolute/private/vault --json show --project PROJECT_ID MEMORY_ID --history --limit 5
continuum --data-dir /absolute/private/vault --json show --project PROJECT_ID MEMORY_ID --history --limit 5 --cursor CURSOR_FROM_PREVIOUS_RESPONSE
```

For MCP use `memory_search` or `memory_context` with the same JSON arguments plus `cursor`;
the provider's project is server-bound. An exact `memory_id` query traverses that thread's
eligible versions; an exact version ID selects only that version. Owner `show --history`
traverses all surviving versions of one thread, oldest first; it is not a vault export.

The first page fixes the recorded snapshot. Search/context keysets use document-local
lexical score descending, ingest sequence descending, then version ID ascending. Exact
ID searches have no lexical score. Owner show uses ingest sequence and ID ascending.
New writes and later corrections/retention-expiry transitions do not change that snapshot:
an old version may still appear active **at the snapshot**, not active now. Without an
explicit valid-time filter, applicability is reassessed against each page's current clock.
Restart the query to see the latest recorded state.
Recall receipts from a multi-page query (including the first page) pin that recorded
snapshot for later `get`. A single-page query without an explicit recorded filter retains
the existing live-current receipt behavior. Applicability and forget checks remain live.

Deletion and disclosure are always rechecked from current storage. Forget immediately
revokes previously issued cursors and recall receipts for erased content; it is never
overridden by a historical snapshot. Surviving results continue in keyset order without
offset gaps. Replaying a cursor is allowed but not a stored replay of content: forgotten
or newly undisclosed results disappear. Revoked capabilities cannot make another request.

Tokens are opaque random identifiers, bound to the exact capability as well as its project
and audience. They reveal no global sequence, query or memory body. The daemon keeps at most
256 cursor states, each containing a keyed binding digest, a snapshot and one fixed-size
keyset; no cached result list. Each token expires after ten minutes. Daemon restart or oldest
token eviction invalidates it. Expired, evicted, unknown, tampered and cross-scope tokens all
return the same content-free `invalid_cursor`; restart the query. Tokens are not durable
bookmarks, evidence, authority, or credentials. Do not log them unnecessarily.

### Bounded conflict fragments are not winners

Context no longer expands every off-query conflict member. It includes only this page's
matching candidates in `open_conflicts`, with `membership_completeness: partial` whenever
other members are undisplayed. Even a one-member fragment is **not** an accepted winner.
Each group supplies its `memory_id` for a separate exact-thread search with the same
temporal scope (use the returned `projection_watermark` as `as_of_recorded`). `member_count`
is the assessed eligible group's size, or null when unknown.

Conflict assessment probes at most 26 eligible versions per selected thread. Up to 25,
the existing temporal connected-conflict calculation remains exact. Above that bound,
the thread is conservatively labeled `status: not_fully_assessed`, its cards carry
`conflict_assessment: not_fully_assessed`, and no claim is promoted into `accepted_claims`.
This is an explicit uncertainty group, **not proof that every version conflicts**. Members
remain traversable by exact-thread search/history, but this release does not promise a
complete conflict graph for arbitrarily large threads. No partial result silently claims
complete membership or authorizes an action. Search completeness refers to its candidate
traversal, not to conflict analysis, all evidence bodies or the entire ledger.

## Verification

`tests/test_truthful_context.py` freezes the clock to reproduce future/past/unknown
classification, historical and stored-verified observations, inclusive/instant/open
bounds, retention versus validity, pinned/default receipts, one instant per response,
visible-only result limits and byte packing. `tests/test_truthful_context_mcp.py` checks
modern and legacy clients through disposable real transports. Existing snapshot,
approval, deletion and audience-isolation tests continue to apply.
`tests/test_pagination.py` adds 31-match traversal, nine-version history, stable snapshots
under correction/expiry/new writes, deletion/disclosure rechecks, scoped replay rejection,
TTL/eviction/restart behavior, bounded state/frames and large-thread uncertainty. Both
pinned MCP modes exercise real two-page client round trips.
