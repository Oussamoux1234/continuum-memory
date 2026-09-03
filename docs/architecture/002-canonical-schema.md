# ADR 002: Evidence ledger and immutable assertion versions are canonical

Status: accepted.

## Decision

Canonical state consists of opaque projects/scopes, minimal evidence, stable claim threads,
immutable assertion-version bodies, admission/review state, attestations, consent receipts,
typed relations, explicit conflicts, feedback, audit events, and deletion receipts.

The canonical ledger never stores embeddings or treats FTS as truth. Every derived row has
lineage to an assertion/version and can be rebuilt. Assertions separate admission,
epistemic state, lifecycle, authority, classification, retention, applicability, and
disclosure. Model-visible authority is always `data`.

## Invariants

- every accepted assertion has evidence or user-authored attestation and consent;
- claim/version IDs are opaque random values, never public body hashes;
- bodies are bounded and immutable; lifecycle retirement is separate metadata;
- shared evidence uses explicit references;
- client-supplied identity, source authority, acceptance, and project are not trusted;
- parameterized SQL is mandatory; FTS syntax is generated from bounded literal tokens.
