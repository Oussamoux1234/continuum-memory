# ADR 003: Explicit valid time plus monotonic recorded order

Status: accepted.

## Decision

Each assertion records `valid_precision` (`unknown`, `instant`, `open`, `interval`), optional
valid bounds, `ingest_seq`, `recorded_at`, and optional `retired_seq`/`retired_at`.
`ingest_seq`, allocated inside the writer transaction, is authoritative local transaction
order; wall-clock timestamps are descriptive.

A correction appends a new immutable assertion, adds an explicit `supersedes` relation,
and retires the previous current assertion. `as_of_recorded` reconstructs what the vault
considered current at that sequence. Historical queries include retired versions.
`as_of_valid` filters explicit valid-time bounds without inventing dates for `unknown`.

Retention is separate from valid time. `forever` has no deadline; otherwise input must be
`YYYY-MM-DD` or a timezone-aware RFC 3339 date-time and is normalized to a fixed-width UTC
timestamp. Date-only means `00:00:00` UTC. Past deadlines are rejected at proposal/preview
time and checked again at acceptance. On the first request at or after a stored deadline,
the serialized writer allocates a sequence, marks the assertion `expired`, resolves any
conflict left with fewer than two active members, and appends a content-free audit event
before serving current results. Current recall handles stop resolving it. Explicit
historical queries can still retrieve the expired version because expiry is a lifecycle
transition, not a claim of physical deletion.

Overlapping incompatible active accepted assertions create a conflict set. Context returns
the set under `open_conflicts` and excludes all members from verified-current output. No
timestamp, recorder, or provider silently wins.

Without a semantic model, the prototype uses a conservative deterministic rule: two
different active bodies under the same normalized user-reviewed subject are incompatible
unless one explicitly supersedes the other. This can over-report conflicts, but it cannot
silently hide one. Smarter contradiction suggestions remain non-canonical roadmap work.
