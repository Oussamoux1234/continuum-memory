# ADR 007: Forget is transactional removal with content-free receipts

Status: accepted for the live prototype boundary.

## Decision

A digest-bound `forget` transaction first resolves the exact project/thread, then deletes
FTS rows, disclosure projections, assertion/evidence references, assertion bodies,
record-linked provenance activities, relation and conflict membership, proposal bodies for
that thread, contentful feedback, every matching assertion ID in persisted recall-result
lists, and orphan evidence. Recall lists are parsed and rewritten as canonical JSON inside
the same transaction, so an old recall handle cannot fetch forgotten content. It appends a
deletion receipt containing only opaque IDs, affected projection kinds, sequence, status,
and policy version, plus a body-free audit event. After commit, exact, search, context,
history, and get return no content or existence detail.

SQLite `secure_delete=ON` and a WAL checkpoint reduce live-file remnants but do not prove
physical erasure. No managed backup exists in this slice, so no backup-revocation promise
is made. OS snapshots, copied databases, filesystem journals, SSD remapping, process memory,
and user exports remain outside the promise. The serialized writer makes the logical
deletion atomic, but no unbounded-latency claim is made for pruning a large recall table.
Future encrypted storage adds per-object key
destruction and an externally anchored deletion manifest before backup support.
