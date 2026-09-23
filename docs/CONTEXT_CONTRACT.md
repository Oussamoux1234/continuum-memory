# Read contract v2: accepted does not mean verified or applicable now

For MCP and CLI client authors upgrading from the prototype's original context shape.
This contract addresses [issue 17](https://github.com/Oussamoux1234/continuum-memory/issues/17).
It changes read projections only: no database migration, new verification writer,
approval grant, native adapter or transport change is required.

## Upgrade clients

1. Require `response_version: 2` on `memory_context`/`context` results.
2. Replace reads of `verified_current` with `accepted_claims`. The old key is removed,
   not retained as an alias: neither its verification nor its current-truth claim was valid.
3. Treat each card's `admission`, `epistemic`, `lifecycle`, and `applicability` separately.
   Display `open_conflicts` without silently selecting a winner.
4. Handle `status: partial` in both search and context. Do not assume the first page or
   capsule includes every matching memory, and never authorize actions from its contents.

Input arguments, the six MCP tools, and both pinned MCP envelope versions are unchanged.
CLI JSON and both MCP fixture clients receive the same v2 context. Search/get/show cards
gain the additive `applicability` field; their outer shapes otherwise remain unchanged.
There is no fabricated v1 compatibility mode. Consumers requiring the old key must upgrade
together with the service. Existing v3 receipts and scoped recorded sequences stay valid.

The checked-in [response schema](../schemas/context-response.schema.json) describes the
v2 capsule and nested conflict cards. MCP discovery still advertises the generic object
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

Search probes one extra eligible, audience-visible candidate beyond `limit`; context
does so beyond its existing 25-candidate limit. Extra candidates make `completeness` and
`status` partial. The extra row cannot seed a new conflict or recall authorization;
conflict expansion from a selected thread still includes eligible members as before.
Hidden records do not affect the probe, counters, rankings or completeness flags.

Context byte packing also marks the result partial when it drops cards or whole conflict
groups. `omitted_items` counts only those byte-packing removals (a group counts as one),
not the total number of omitted search matches. A result can be partial with zero
`omitted_items` because the candidate limit was reached. `complete` refers only to this
query's eligible candidate set, not the entire ledger, a complete evidence body, or a
global history. Compact claim text can separately have `claim_truncated: true`.

The exact serialized capsule, including v2 metadata, must fit `byte_budget`. A typical
partial empty capsule still fits 512 bytes; budgets too small for the required contract
return `budget_too_small` rather than dropping safety fields. The required size also
depends on identifier/counter widths. Narrow the query or increase the budget.

### Explicit follow-up: complete history traversal

This patch does not add pagination, cursors, total counts, or a new promise of exhaustive
history. Owner `show --history` still returns at most five versions and reports partial
when more exist. Before any exhaustive-history/export claim, implement bounded cursors
bound to project/provider/query/recorded/valid scope; keep ordering stable under mutation;
enforce forget revocation during continuation; and test traversal without gaps or duplicates.
Large conflict expansion also remains a separate performance/frame-bound requirement.

## Verification

`tests/test_truthful_context.py` freezes the clock to reproduce future/past/unknown
classification, historical and stored-verified observations, inclusive/instant/open
bounds, retention versus validity, pinned/default receipts, one instant per response,
visible-only result limits and byte packing. `tests/test_truthful_context_mcp.py` checks
modern and legacy clients through disposable real transports. Existing snapshot,
approval, deletion and audience-isolation tests continue to apply.
