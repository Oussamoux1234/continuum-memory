# Daemon ownership and crash restart

This is the daemon-lifecycle slice of issue #8, not completion of its key-rotation,
power-loss, platform, and audit/backup rollback roadmap. Use synthetic data: the
default-branch database is still the plaintext prototype.

## Prerequisites

Use one private vault on a local POSIX filesystem with working `flock` and
no-follow opens. Every daemon accessing that vault must use this lock-aware version.
This runbook covers POSIX, not the [native Windows plaintext prototype](WINDOWS_IPC.md),
which uses held pipe instances and no socket-file cleanup. Its hosted Windows Server
2025 acceptance is documented in [Windows verification](WINDOWS_VERIFICATION.md);
that is not desktop certification or native approval/encryption acceptance.
Network filesystems, concurrent old/new daemons, and
protection against malicious same-user processes replacing private files are not supported.
Development-host macOS tests do not certify the macOS runtime/approval boundary.

Start the daemon with its normal command:

```bash
memoryd --data-dir /absolute/path/to/vault
```

The daemon acquires an exclusive, nonblocking OS lock before opening SQLite or
running migrations. Another contender returns `already_running` without opening
the store, changing the socket, or reading/writing the lock marker. A stopped
process still holds its lock; it must not be mistaken for a dead process.

## Normal stop and restart

SIGINT/SIGTERM stop the request loop, close connections/listener/store, and remove
only the socket inode created by that process. The lock is released last. If the
process is forcibly killed, the OS releases the lock, but its socket may remain.
Restart using the same command: automatic removal is allowed only when all of
these conditions hold:

1. The persistent `memoryd.lock` is an owner-only, single regular file with a valid
   version-one marker and the process acquired its exclusive OS lock.
2. The existing endpoint is an owner-only, single Unix socket.
3. A connect-only probe, with a 0.5-second timeout and no capability/request data,
   receives `ECONNREFUSED`.
4. Lock and socket identities still match their validated inodes.

A live listener, timeout, uncertain error, unsafe endpoint, or changed inode is
not removed. Retry never signals or kills another process. The probe is only safe
within the cooperating-version boundary: an older daemon between bind and listen
could also refuse connections, which is why mixed-version startup is unsupported.

`memoryd.lock` is deliberately retained after shutdown. **Do not delete, replace,
or truncate it to clear an error.** PID files or age/timestamps are not authority.
The file has only a fixed version marker, not a PID, token, body, or request. Its
descriptor is non-inheritable across exec; this does not promise fork isolation.

## Interrupted initialization

New homes use permanent private `bootstrap.claim` and `bootstrap.complete`
records bound to the vault identity. The claim is exclusively created before any
key, capability or database. Completion is published only after the initial SQL
commit, verified audit anchor, private-file/database readback, successful WAL
checkpoint and closed connection. A partially written record is not completion.
An existing private directory may contain admission policy or unrelated files;
initialization does not replace that directory or adopt existing product files.

`initialization_incomplete` means the initialization records or their database
binding are incomplete or inconsistent. Preserve the entire home for diagnosis.
Do not delete markers, copy in an anchor, modify metadata, rerun initialization
over the same location, or treat file age as permission to reclaim it. Choose a
fresh, unrelated data directory for a new initialization and leave the interrupted
one untouched. Repeated initialization of an occupied home returns
`already_initialized`; there is no in-place repair/reset command in this slice.

A visible incomplete record is refused before reading the audit key, opening
SQLite, or acquiring/cleaning a daemon endpoint. The Store rechecks after observing
database presence to catch a cooperating initializer that created its claim in
between. A transactional `bootstrap_protocol='1'` flag also prevents a new vault
whose **both** records are missing from silently becoming legacy. That second
check uses the existing guarded SQLite connection before mutating configuration
or migration. SQLite itself may still recover WAL/sidecars while opening/reading;
there is no zero-filesystem-effects promise for this metadata-only refusal.
The daemon may already own its endpoint lock or have checked a stale endpoint in
that both-records-missing case; it still refuses application admission.

Genuine older homes without either record or the database flag follow the existing
legacy admission/migration path. No marker or missing audit anchor is backfilled.
Older already-stranded homes are not repaired or retrospectively certified.
Completed new homes retain normal audit diagnostics and exact-prefix recovery;
these markers never authorize reconstructing a missing anchor. A lost reply after
completion publication can mean initialization succeeded: inspect with normal
commands, never overwrite the home. Cooperating current-version initialization
is supported; mixed old/new initializers, malicious same-user edits, coordinated
rollback and host power-loss durability are not established by this protocol.

## First upgrade and fail-closed diagnostics

Before first starting this version, stop all older daemons and their automatic
restart mechanisms in a controlled maintenance window. A clean old-daemon stop
removes its socket. Only when no socket exists will the new daemon initialize and
sync the lock marker, before binding its own endpoint.

If an old crashed daemon left a socket, startup returns `stale_socket_unverified`.
Repeated attempts leave the lock unmarked and preserve that socket. Recovery then
requires operator-controlled offline maintenance: positively establish that no old
daemon or launcher can access the vault, verify the leftover endpoint type/owner,
and move only that stale endpoint to an unused quarantine location. If ownership
or process state cannot be established, stop and investigate; socket age or a
failed connection alone is insufficient. No automatic legacy-cleanup command is
provided, and no real vault was changed during validation.

`daemon_lock_invalid` means a nonempty partial/unrecognized marker: fail closed and
investigate, do not manufacture a marker. `daemon_lock_changed` means the held
descriptor no longer matches the pathname. The serving loop checks this identity
before I/O dispatch and exits on detected changes. These checks detect ordinary
replacement mistakes; they cannot atomically prevent all malicious same-UID races.
`socket_state_unknown` preserves the endpoint for investigation.

The packaged daemon's diagnostics remain bounded and omit paths/input content.
Cleanup is attempted on startup failures and Python interruptions, including after
bind/chmod/listen/selector registration and partial signal-handler installation.
Signal handlers are restored; failure in one cleanup does not skip the others.
SIGKILL or host failure cannot execute cleanup and instead relies on restart checks.

## Validation and limits

`tests/test_daemon_lock.py` uses temporary synthetic vaults and real processes to
cover concurrent startup, SIGSTOP ownership, SIGKILL/restart with durable proposal
retry and valid audit, graceful shutdown, exec descriptor closure, persistent lock
identity, legacy refusal on repeated attempts, malformed markers, unsafe file
types/ownership/modes, bounded/ambiguous probes, inode replacement, and injected
startup/cleanup failures. Run the complete gate with `python3 scripts/verify.py`.

The lock coordinates daemon instances, not arbitrary direct SQLite clients. It
does not add a backup lock, distributed consensus, key rotation, physical erasure,
power-loss certification, or exactly-once request delivery. A lost reply still
uses the separate [committed-result recovery](COMMIT_RECOVERY.md) contract.

Locking API reference: [Python fcntl](https://docs.python.org/3/library/fcntl.html).
