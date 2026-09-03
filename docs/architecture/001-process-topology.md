# ADR 001: One local daemon and one serialized writer

Status: accepted for prototype.

## Decision

After bootstrap, one per-user daemon owns the SQLite write connection and serves a bounded,
newline-delimited JSON protocol over an owner-only Unix-domain socket. Its single request
loop serializes writes. CLI and MCP processes are clients; adapters never open the vault.
`init` is the only offline writer and refuses to run while the socket is active.

The stdio MCP bridge holds one project/provider-bound capability and exposes only the six
model-facing memory tools. The user CLI holds a separate control capability. The daemon
does not expose TCP/HTTP, execute commands, read project files, or make network requests.

## Rationale and consequences

Direct SQLite access from every MCP process makes capability enforcement, transaction
ordering, audit sequencing, and later key handling ambiguous. A daemon supplies one policy
and writer boundary. The prototype is deliberately single-process and low throughput;
later readers may use consistent read snapshots while writes remain serialized. If the
daemon is absent, clients return `unavailable` and never start a competing writer.
