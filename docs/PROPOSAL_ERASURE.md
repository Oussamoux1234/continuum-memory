# Proposal erasure and delivery retries

This is the application contract for [issue #16](https://github.com/Oussamoux1234/continuum-memory/issues/16),
built on the snapshot and exact-forget changes merged in `029292b`.

## Lifecycle and owner review

| State/action | Content retained | Delivery retry |
|---|---|---|
| Pending, before retention deadline | Quarantined proposal and inline evidence; no accepted assertion | Identical payload returns the existing proposal; changed payload with the same key returns `idempotency_conflict` |
| Owner rejects | Proposal, inline evidence, reviews and proposal-targeted provenance are purged in the reviewed transaction | `delivery_suppressed` |
| Owner forgets a standalone proposal | Only the exact displayed proposal and its dependent draft rows are removed | `delivery_suppressed` |
| Proposal retention becomes due | Draft copies are purged on the next request touching that project | `delivery_suppressed` |
| Accepted proposal | The draft copy remains until due or included in thread forget; accepted memory is independently governed by its reviewed retention and deletion scope | Existing delivery replays while the draft exists; suppressed after its purge |
| Owner forgets accepted memory | Existing thread-forget scope removes versions, owned evidence, feedback, recall references, projections and associated proposals atomically | Every removed proposal delivery is tombstoned |

Rejection is an owner decision that now includes draft erasure. Its preview explicitly
sets `content_purge_on_rejection=true`. An expired proposal does not remain listed as
pending. Rejected and expired bodies are not a historical inbox archive; the terminal
disposition is retained only as content-free metadata and audit evidence. Already-purged
standalone proposal IDs are unavailable to forget because their content is gone.

`continuum forget --project PROJECT PROPOSAL_ID` previews standalone proposal deletion.
If that proposal was accepted, the preview resolves to the accepted memory thread and
displays its full affected scope. This also works after the draft copy expires, using
the opaque proposal ID retained in canonical acceptance provenance. Forgetting an
unaccepted proposal does not delete an independent memory or another proposal merely
because they share a subject.

Every owner action retains the existing control permission, exact preview digest,
OS-backed grant, nonce and expiry checks. Proposal previews additionally bind the
proposal, its reviews, proposal provenance and acceptance dependencies. Apply rechecks
under `BEGIN IMMEDIATE`. Acceptance or another dependency change returns `stale_preview`
and rolls back the requested operation without consuming its grant. Request and approve
a fresh preview. Agents cannot authorize deletion, reject, accept, or reuse a captured
owner grant through an agent capability.

Retention purge is a server policy, evaluated before project operations. It is not a
background scheduler: no promise is made to erase a closed or idle vault at wall-clock
expiry. A proposal's stored deadline cannot be changed by replaying the key with another
retention value. Expiry may independently purge due content before an old approval is
validated. Acceptance crossing its approved deadline keeps the `retention_expired`
error; other changed proposal scopes require a fresh preview.

## Delivery identity and deliberate new input

Delivery identity is `(project, authenticated provider, idempotency_key)`. This extends
the old capability-local namespace to the provider, so changing a capability within
the same project/provider does not evade a terminal delivery. Another project or
provider has a separate namespace. Model parameters cannot select either identity.

The tombstone stores only the opaque project ID, provider, a keyed delivery digest,
opaque proposal ID, terminal disposition and sequence. The digest uses the existing
vault HMAC key and includes project/provider/key. It is not a body or request fingerprint.
Raw delivery keys are not retained because callers can put content into them. Proposal
bodies, evidence, subject/locator text and request fingerprints are removed, not copied
into tombstones or diagnostics. Approval challenges retain their existing digest-only
representation. Live content remains visible in the owner-authorized interactive preview.

Purge and tombstone insertion share one writer transaction. A retry checks suppression
before payload processing and again after acquiring the writer lock. Terminal retries,
including changed or reordered payloads, return bounded `delivery_suppressed` without
writing content. Identical live retries return their prior proposal; changed live payloads
are rejected. Successful purge, reopen and restart do not reopen a terminal delivery.

A new input must use a fresh key. The server treats a fresh key as a new
quarantined proposal; it cannot prove human intent or recognize copied text under new
keys without retaining other information. Callers must reuse keys for retries and mint
new keys only for new input. Human acceptance is still required. This does not suppress
the same text submitted under a different project/provider/key, nor authorize automatic
capture or deliberate resaving on the user's behalf.

## Schema v3 to v4

Store opening transactionally creates the tombstone table and scoped delivery/retention
indexes. It preserves all existing proposal, canonical, receipt and audit rows. On the
next project request, existing rejected proposals and proposals with due retention are
purged by the same policy as new proposals. This includes retained v3 rejection content.
Canonical accepted history and evidence are not erased by draft expiry; they remain
governed by the earlier owner-approved memory lifecycle and explicit thread forget.

V3 receipt and audience timeline semantics are unchanged. Old proposal review previews
without the new dependency binding need renewal. V2 upgrades still perform their existing
receipt invalidation and audience backfill, then add v4 in the same transaction. Unsupported
versions fail closed. Interrupted upgrades roll back DDL/data and can be retried. Older
binaries reject v4; no in-place downgrade is provided.

The migration cannot reconstruct delivery keys erased before v4: those older retries
are outside this protection. V3 rows remain separate even if an older capability-local
namespace allowed duplicate provider/key pairs. Live lookup uses the earliest retained
row; an exact single-proposal forget removes only its reviewed scope, while a tombstone
blocks future submissions for that provider/key. Independently retained copies still
need their own reviewed deletion scope.

## Evidence and remaining limits

Synthetic probes on merged main `029292bdd91e36b2122cc61abc997b78fecbf179` reproduced pending
retention, standalone forget, retained rejection content and replay resurrection. The
first nine intended-behavior tests had four assertion failures and four errors there;
agent permission checks already passed.

`tests/test_proposal_erasure.py` covers pending/rejected/expired/accepted flows, logical
canaries across every live table, replay/new-key semantics, project/provider/capability
boundaries, reopen, separate-connection acceptance and deletion races, changed dependency
state, failed purge rollback/retry, grant replay, and legitimately shared evidence.
`tests/test_proposal_migration.py` uses the immutable v3 schema to test preservation,
legacy purge, suppressed retries, integrity, rollback/retry and reopen. The v2 migration
and #19 temporal/isolation/forget regressions remain in the verifier.

Tombstones have no automatic expiry; discarding them weakens replay suppression. Their
validity depends on retaining the current vault/HMAC key and database state. Backup or
database rollback, key rotation, forensic/WAL erasure, exported previews and copies are
not protected here. #6 backup revocation and #8 audit/commit/key work remain separate.
Purge cost grows with due proposals; existing exact-forget frame and large-vault limits
remain. #17 result categories, #18 transport hardening, capture hooks and SQLCipher
integration are outside this change.
