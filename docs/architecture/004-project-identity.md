# ADR 004: Project identity is explicit and opaque

Status: accepted for prototype.

## Decision

`init` registers an opaque project ID with a user-reviewed display name and canonical path
hint. The path, basename, Git remote, branch, and content are never authoritative identity.
Capabilities bind a server-known project ID and provider; MCP arguments cannot override it.

The prototype does not write repository markers or auto-link clones/worktrees. A moved or
new checkout requires a future previewed rebind/link flow. This is safer than guessing.
Project/provider eligibility predicates are present in exact, FTS, get, history, context,
feedback, and status paths. Errors equalize unauthorized and missing records where useful.

The prototype keeps FTS in one SQLite virtual table and filters by project/disclosure in
the candidate SQL. Tests prove result/count isolation, but this is not physical shard or
timing noninterference. Trustworthy local v1 must move FTS into encrypted per-project and
disclosure-domain shards before making a stronger information-flow claim.

## Future compatibility

Trustworthy local v1 will add authenticated external registry bindings plus opaque Git
common-dir/worktree markers as discovery hints, preserving fresh-clone isolation.
