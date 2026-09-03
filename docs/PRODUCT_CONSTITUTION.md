# Product constitution

Continuum Memory is a provider-neutral, user-owned ledger of evidence and versioned claims.
Its promise is: **“Your agents change. Your project memory doesn’t.”**

## Principles and invariants

1. Canonical memory is small, explicit, evidence-bearing, scoped, temporal, correctable,
   and deletable. Retrieval, FTS, embeddings, graphs, summaries, and cards are replaceable
   projections, never accepted truth.
2. Memory is historical untrusted data with `authority=data`. It never grants permission,
   conveys a credential, proves current consent, or authorizes a command, URL, recipient,
   external message, publication, destructive action, or policy change.
3. Current verified workspace/tool evidence outranks applicable accepted memory, which
   outranks historical, proposed, imported, or derived material. Retrieval failure is
   `unavailable`, never a fabricated `no_matches`.
4. Agents may search, read, propose, and report bounded feedback. They may never approve,
   correct, retract, delete, export, link projects, change disclosure/policy, manage keys,
   configure integrations, or authorize external actions.
5. The service assigns identity, origin, trust, admission, authority, project, and
   disclosure. Client claims such as `source=user` or `accepted=true` are ignored or
   rejected. Unknown fields and impossible transitions fail closed.
6. No last-write-wins exists for claim bodies, deletion, project linkage, ACLs, or future
   membership. Concurrent incompatible accepted assertions remain explicit conflicts.
7. Every accepted assertion has evidence or a user-authored attestation, provenance, a
   stable claim thread, an immutable version, explicit valid-time precision, authoritative
   recorded order, and a consent receipt bound to the exact preview.
8. Raw transcripts, hidden reasoning, complete tool output, environment dumps, credentials,
   keys, and command logs are not ordinary memories. `no_store` creates no record.
9. Applicability, audience, classification, disclosure, authority, retention, admission,
   epistemic state, and lifecycle are orthogonal.
10. Native host memories are not disabled, scraped, or imported automatically.

## Trust boundaries and threat model

The user-control surface, memory kernel, agent-facing MCP bridge, host, repository content,
and storage are separate trust domains. Repository text, model output, tool output, imports,
and recalled memory are untrusted. The system anticipates prompt injection, memory
poisoning, forged approval/origin/scope, capability replay, SQL/FTS injection, malformed or
oversized input, project/disclosure leakage, audit tampering, deletion remnants, and a
compromised adapter.

The core reduces these risks with strict bounded schemas, server-bound context, quarantined
proposals, one-shot exact-preview grants, parameterized SQL, eligibility filters in every
candidate query, immutable revisions, explicit conflicts, content-free HMAC-chained audit,
transactional deletion, owner-only local IPC, and no network or telemetry by default.

Residual limits must stay visible. A same-UID process able to read capability files,
control a terminal/GUI, debug the daemon, or inspect an unlocked database can cross the
prototype boundary. Root/admin, malware, screen capture, host misuse of historical data,
exports, OS snapshots, copied databases, and third-party host tools are outside the core’s
enforcement. The prototype is plaintext; it makes no encryption or physical-erasure claim.

## Temporal truth, correction, and conflict

Validity describes when a claim applies in the world and has explicit precision: unknown,
instant, open, or interval. Transaction time is a monotonic local sequence plus recorded
timestamp. Corrections append immutable versions and explicit `supersedes` links; they do
not rewrite old bodies. Current and historical/as-recorded queries are distinct.
Overlapping incompatible accepted assertions form a conflict. Normal context surfaces the
bundle under `open_conflicts` and excludes its members from verified-current claims.

## Provenance, consent, and disclosure

Author, recorder, authorizer, and validator are distinct roles. Evidence is minimal and
traceable to an opaque source locator and observation time. Signatures prove integrity and
origin, never truth. Consent binds a canonical digest over exact content, evidence IDs,
scope, classification, retention, disclosure, policy version, and operation. Any changed
byte invalidates approval; grants are nonce-bound and single-use.

Project identity is an opaque registration, not a directory basename, branch, remote URL,
or public content hash. Every connection is bound to a server-known project, provider, and
least-privilege capability. Forbidden records must not enter candidate sets, counts,
ranking, explanations, or output. Storage visibility and model disclosure are distinct.

## Forgetting and its limits

Retraction, expiry, supersession, ranking decay, rejection, redaction, and deletion are
different. Forget makes the selected canonical body/evidence and every live projection
unretrievable in one transaction, then leaves only opaque, content-free deletion and audit
receipts. Shared evidence is removed only when its last surviving reference is removed.

This slice has no managed backups and therefore no backup-revocation promise. SQLite file
reuse, OS snapshots, copied databases, exports, SSD behavior, and external backups may
retain plaintext. Future encrypted storage will use per-object keys and cryptographic
erasure, but cannot erase copies outside the managed boundary.

## Integration boundaries

Continuum owns durable accepted claims, evidence, versions, provenance, time, scopes,
conflicts, corrections, retractions, consent, disclosure, and forgetting. Host adapters are
thin clients: bind host/project context, request bounded retrieval, submit structured
proposals, and preserve citations plus the historical-data label. They do not own accepted
truth or memory intelligence.

Agent Relay owns provider/account routing, limit failover, task execution, transient
checkpoints, and action authorization. A future Relay client may store opaque Continuum IDs
and transient task state only; it must not duplicate durable claim bodies.

## Roadmap discipline

The sequence is prototype ledger, trustworthy encrypted local v1, native adapters,
measured retrieval quality, hardening/packaging, then separately threat-modeled sync.
Embeddings, extractors, graphs, sync, teams, browser UI, cloud storage, and automation may
extend the system only through reviewed interfaces. None may mutate accepted truth or
become the canonical source.
