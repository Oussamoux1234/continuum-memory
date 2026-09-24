# Native Windows pipe boundary and runtime

The Windows daemon and client select this boundary only on native Windows. It
builds on the [filesystem boundary](WINDOWS_BOUNDARY.md). Native acceptance must
cover the complete runtime and full verifier, not just these low-level primitives.
Production owner mutation remains unavailable without an OS approval broker;
the disposable fixture's explicit prototype broker is not production approval.

## Narrow contract

The primitive provides one local named-pipe instance and one bounded exchange.
The runtime scheduler below owns the bounded multi-client pool. Its opaque name is derived from a nonsecret random
32-byte vault binding and process user SID; no project path, content or capability
belongs in this name. Bootstrap persists the exact 32-byte binding separately;
the daemon holds its validated file and ancestors with write/delete sharing denied
before opening SQLite and until after shutdown. No TCP or AF_UNIX fallback exists.

Creation supplies the process-user-only protected DACL, `FILE_FLAG_FIRST_PIPE_INSTANCE`
and `PIPE_REJECT_REMOTE_CLIENTS`. An occupied name is refused, never adopted or
deleted. Closing the final instance handle releases that kernel instance; there
is no socket file to unlink. This excludes administrator/SYSTEM and malicious
same-account processes from its security guarantee. Such processes can squat on
the namespace or impersonate the owner; name uniqueness is not user presence.

Before capability/application bytes may be sent, the client:

1. Opens only its derived local pipe using overlapped I/O and explicit
   `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` with static tracking.
2. Validates the native pipe owner and its exact protected owner-only DACL.
3. Obtains the server PID, opens the actual process handle and token, validates
   token user SID, records process creation time, and checks PID/liveness again.
4. Sends only the fixed public protocol hello and requires the fixed reply.

The server similarly holds the client process/token identity, reads only that
bounded public hello, identifies its pipe-bound security context, and immediately
reverts to its own context. The impersonation token must have exactly
`SecurityIdentification` level and the expected user SID. No file or application
operation occurs while identifying the client. This avoids granting the server
the client's impersonation/delegation authority.

Public entry and identification refuse an already-impersonating thread without
clearing or replacing its existing token. Only `ERROR_NO_TOKEN` establishes the
expected process context; access-denied, anonymous or other token-query failure
also refuses. Native tests retain the caller's actual SID and identification
level across these refusals.

A PID is never sufficient authority: the process handle, creation time, pipe PID,
liveness and SID are rechecked through I/O. The pre-process-open PID reuse gap is
additionally guarded by the pipe object's owner on the client and pipe-bound
identification token on the server. Same-account collusion, privileged handle
duplication and hostile administrators are not claimed to be distinguishable.

## Bounds and exceptional cleanup

The daemon creates exactly sixteen pipe instances before opening Store. The first
uses `FILE_FLAG_FIRST_PIPE_INSTANCE`; subsequent instances require that still-held
anchor. Existing endpoints are refused without adoption or removal. All handles
remain held across requests and are non-inheritable. Shutdown order is workers,
Store, pipe instances (anchor last), then binding/ancestor guards. A process crash
releases its native handles; no persistent socket pathname is removed or trusted.

Sixteen fixed workers perform only peer-verified raw I/O. Workers receive neither
Store nor Kernel. An immutable frame/deadline plus a unique, locked reply state
cross a sixteen-slot queue; only the owning main thread authenticates capabilities
and dispatches application/SQLite operations. Expired/cancelled pending requests
are dropped. A reply can never be attached to a recycled connection or worker slot.
An unexpected worker failure stops the daemon instead of silently reducing capacity.

Idle accept waits are bounded to 250 ms and do not consume a newly connected peer's
two-second handshake/frame budget. Waiting for main-thread dispatch/reply is bounded
to five seconds; response write and drain acknowledgment share a two-second budget.
The client retains its five-second absolute exchange budget. A trickle cannot renew
any phase. Application callbacks themselves are not a timed sandbox; a lost reply
after a committed owner mutation still requires the existing commit-receipt lookup.

After reading a complete response, the client sends a fixed, nonsecret drain ACK.
This is not action authorization and failure to send it does not invalidate the
obtained response (which still undergoes normal JSON/envelope validation).
The server waits only until its response deadline before disconnecting. This is
necessary because [DisconnectNamedPipe discards unread data](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-disconnectnamedpipe).
It never calls synchronous pipe `FlushFileBuffers`, which could wait indefinitely
for a stalled client.

The standalone primitive and client each use one absolute monotonic deadline,
at most ten seconds, covering connect, handshake, reads and writes. The runtime
server uses the separately bounded phases above. Frames are at most 64 KiB including one
terminal newline, with 8 KiB chunks. A busy/missing endpoint fails immediately;
there is no unbounded `WaitNamedPipe`, retry loop, background thread or synchronous
`FlushFileBuffers` on a pipe. The caller's application callback is not a sandbox
and is not timed out by this transport.

Timeout requests `CancelIoEx` and allows at most one additional second to observe
completion. A normal timeout raises a content-free error after completion.
Pending OVERLAPPED memory cannot be freed safely before the OS completes it.
If completion remains unknown after that grace, the **entire process exits 74**.
If `RevertToSelf` fails, the **entire process exits 75** so no caller continues in
an uncertain impersonation context. These exceptional fail-stops are explicit
prototype behavior, not normal timeout recovery or a crash-durability claim.
The runtime also exits 74 if workers cannot join within their bounded cancellation
window, rather than closing handles beneath outstanding I/O. Normal timeout and
shutdown tests must show worker/handle cleanup; fatal fixtures are not normal
recovery evidence. Process-crash recovery is not a power-loss durability claim.

## Evidence boundaries

The separate native job tests CPython 3.11/3.14 x64 on `windows-2025`, recording the
actual hosted image because the runner label is mutable. Native cases use real
pipes and child processes: roundtrip/max-frame, endpoint collision and release,
pipe object owner rejection, real peer token comparison, connect/read/write
timeouts, peer death, and malformed/oversized/truncated frames.

The Administrators-owned pipe fixture genuinely exercises **object owner**
rejection. The token mismatch fixture compares a real native token with a
deliberately different expected SID. Neither is a real second-account peer
process. That fixture needs an explicitly authorized account/token environment
and remains a gate; no local account or credential is created here. Remote-client
rejection is configured through the native flag; a separate-host negative probe
is not claimed by this local suite.

Cancellation-noncompletion and revert-failure exits are deterministic **injected
API fault** fixtures in child processes. They prove bounded fail-stop control
flow, not that Windows itself exhibited those failures. Native tests skip on
non-Windows and therefore do not supply native proof there.

## Primary API references

- [CreateNamedPipe and pipe modes](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [Named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [CreateFile SQOS and overlapped flags](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [Pipe-bound client identification](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [Cancellation does not mean completion](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex)

Issue #1 remains open until complete native runtime and filesystem acceptance,
including a genuine different-account peer fixture, has been reviewed. Isolated
pipe CI alone is not native application acceptance.
