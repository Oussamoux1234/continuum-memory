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

The daemon holds a persistent owner-only `memoryd.lock` inode with a nonblocking
OS lock before Store opening/migration until cleanup completes. Cooperating new
daemons can recover a refused stale socket only under the validated version marker
and unchanged inode checks. First adoption of a legacy socket is fail-closed;
mixed-version startup is unsupported. See [daemon recovery](../DAEMON_RECOVERY.md)
for the offline upgrade, failure matrix and same-user/local-filesystem limits.

## Local transport limits

Frames are UTF-8 JSON objects terminated by LF, with a 65,536-byte limit including
that LF. Duplicate keys, non-finite JSON numbers, invalid UTF-8, and invalid
request envelopes are rejected. Request IDs are signed 64-bit integers (excluding
booleans) or UTF-8 strings of at most 128 bytes; methods are 1–64 characters.
Validation diagnostics omit input field names and values, apart from valid
correlation IDs.

The daemon uses nonblocking selector I/O with at most 16 admitted connections and
a bounded listen backlog. Each connection gets an absolute 2-second frame-read
deadline from admission and a separate absolute 2-second response-write deadline.
Trickled bytes do not renew either deadline. Excess connections are closed;
incomplete, expired, and disconnected connections are closed without dispatch.
Each connection handles one request. Complete malformed frames receive bounded
errors when the peer can receive them. Kernel dispatch and SQLite access stay on
the daemon's original thread; no socket worker accesses the database. Clients use
one absolute 5-second connect/send/read deadline and validate response envelopes.

The stdio bridge reads fixed 8 KiB chunks through a single-entry queue, bounding
allocation before a newline arrives. An unfinished frame has a 2-second absolute
deadline from its first acquired bytes; idle stdin has no deadline. Oversized or
unfinished frames cause one bounded parse error, then exit status 2, without
trying to drain or resynchronize arbitrary input. Complete malformed frames are
recoverable. Each output frame is capped at 64 KiB and has a 2-second write
deadline; blocked or disconnected stdout causes exit status 2. EOF between frames
exits successfully. Two fixed helper threads perform only raw pipe I/O through
bounded queues, including where selectors cannot watch pipes. The process exits
on failure without waiting indefinitely for those daemon threads.

These limits prevent an individual stalled peer from monopolizing socket I/O;
they do not guarantee service under continuous same-user admission floods or
preempt long-running synchronous kernel/SQLite operations. Slow peers may need to
reconnect/restart the bridge. This remains an owner-only, local, low-throughput
prototype, not a network service. Native Windows daemon support is not claimed.
