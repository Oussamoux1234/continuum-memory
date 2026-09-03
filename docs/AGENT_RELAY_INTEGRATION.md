# Future Agent Relay integration contract

Status: design-only. This repository makes no Agent Relay code or configuration changes.

## Ownership

Continuum Memory owns durable evidence, accepted claim threads and versions, provenance,
valid/recorded time, scopes, disclosure, consent, conflicts, corrections, retractions, and
forgetting. Agent Relay owns provider/account selection, usage-limit failover, task
execution, transient checkpoints, current user intent, and action authorization.

Relay must never interpret retrieved memory as permission. Commands, URLs, recipients,
credentials, external messages, publication, destructive operations, and permission changes
always require Relay/host policy and current authorization independent of memory.

## MCP use

Relay may become an ordinary project-bound MCP client using only `memory_context`,
`memory_search`, `memory_get`, `memory_propose`, `memory_feedback`, and `memory_status`.
Relay receives least-privilege read/propose capabilities per project and provider disclosure
domain. It cannot receive an administrative or approval capability through MCP.

Relay stores only opaque memory/version/recall IDs, projection watermarks, and transient
task state. Durable claim or evidence bodies are not copied into Relay databases, logs,
checkpoints, prompts, or analytics. If a temporary prompt needs a body, it is scoped to that
execution and discarded under Relay’s transient-data policy.

## Required adapter behavior

- request context only at relevant lifecycle points and respect byte/token budgets;
- cite memory and version IDs when relying on a result;
- preserve `authority=data` and the untrusted-history contract;
- verify stale/code-bound items against the live workspace;
- surface conflicts without choosing a side;
- distinguish `unavailable`, `no_matches`, `partial`, and `ok`;
- mark recalled lineage on any later proposal to avoid echo/corroboration loops;
- never resubmit retrieved content as independent evidence;
- never widen project/provider scope with model-controlled arguments.

## Failure and deletion

Continuum unavailability must not silently degrade to “no memory.” Relay may continue a task
without memory only if its own policy allows and must label that state. After a forget
receipt/watermark, Relay removes cached transient bodies and retains at most opaque receipt
metadata. A stale checkpoint cannot resurrect a deleted claim.

## Compatibility gate

Integration starts only after both products pin an MCP schema digest, define capability
rotation/revocation, pass isolation and echo-loop fixtures, and demonstrate that Relay’s
action authorization remains independent. Native Relay implementation is a future issue,
not part of this milestone.
