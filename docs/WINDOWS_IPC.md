# Isolated native Windows pipe candidate

This is the second experimental slice of [issue #1](https://github.com/Oussamoux1234/continuum-memory/issues/1).
It is **not selected by the vault, client, MCP bridge or daemon**. Native Windows
application support remains blocked on storage, lifecycle, approval and full
verification. It builds on the [filesystem boundary](WINDOWS_BOUNDARY.md).

## Narrow contract

The module provides one local named-pipe instance and one bounded exchange, not a
multi-client daemon scheduler. Its opaque name is derived from a nonsecret random
32-byte vault binding and process user SID; no project path, content or capability
belongs in this name. The caller must persist that binding separately before any
future runtime integration. No TCP or AF_UNIX fallback exists.

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

A PID is never sufficient authority: the process handle, creation time, pipe PID,
liveness and SID are rechecked through I/O. The pre-process-open PID reuse gap is
additionally guarded by the pipe object's owner on the client and pipe-bound
identification token on the server. Same-account collusion, privileged handle
duplication and hostile administrators are not claimed to be distinguishable.

## Bounds and exceptional cleanup

Each exchange has one absolute monotonic deadline, at most ten seconds, covering
connect, handshake, reads and writes. Frames are at most 64 KiB including one
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
Any future daemon integration must review this policy and its storage recovery.

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

This document and isolated CI do not close issue #1 or claim native product support.
