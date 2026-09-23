# Native Windows boundary: experimental filesystem slice

Native Windows remains **unsupported** by the daemon and vault. This module is
not imported by the POSIX runtime. It is an independently testable first
slice of [issue #1](https://github.com/Oussamoux1234/continuum-memory/issues/1), not
its completion. Do not move a real vault onto it or interpret the isolated
Windows job as a full `scripts/verify.py` pass.

## Filesystem contract

`windows_boundary.WindowsBoundary` uses Win32 handles through the Python standard
library. It creates a single private directory or a new bounded file, inspects
an existing private object, and reads bounded bytes. No existing object is
overwritten, its ACL repaired, or its owner changed.

- Only absolute DOS drive paths on local fixed NTFS volumes are accepted. UNC,
  device namespaces, SUBST drive aliases, alternate data stream syntax, reserved
  device names, ambiguous dot/space components and long paths are refused.
- Every ancestor is opened without delete sharing, checked for reparse points,
  and held throughout the path-dependent operation. System ancestors need not
  belong to the user; the private leaf must. Junctions, symlinks and other reparse
  points are refused, including on ancestors. Held handles request data-read /
  directory-list access: metadata-only opens do not enforce this share lock.
  An ancestor that denies directory-list access is therefore refused.
- Each private object must belong to the current **process token user SID**, with
  a protected, present, non-null DACL containing exactly one explicit full-control
  allow ACE for that SID. Broader or unusual ACLs are refused, not interpreted as
  an equivalent policy. Creation supplies this descriptor atomically.
- A private file must be a disk file with exactly one hardlink. Security and file
  metadata are checked on the open handle, not a later pathname lookup. Handles
  are non-inheritable and closed on success and errors.
- Reads and writes are bounded to at most 64 KiB; creation is exclusive. A failed
  creation/write may leave an owner-only partial file that must be inspected and
  removed explicitly; it is not silently overwritten or treated as successful.

The Microsoft sources behind these choices are [CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[handle security queries](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo),
[file identity](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle),
[volume ACL capabilities](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw),
and [security descriptor format](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format).

## Native evidence and residual risks

The dedicated workflow uses `windows-2025`, x64 CPython 3.11 and 3.14. Actions are
commit-pinned; the hosted runner label is **not an immutable OS image**, so each
run records its actual image version, Python, Windows and SQLite versions.
The filesystem module itself never opens SQLite. This is a candidate test matrix,
not an application support matrix or a reproducible Windows distribution claim.

Run the isolated native suite with PowerShell from a source checkout:

```powershell
$env:PYTHONPATH = "src"
python -W error::ResourceWarning -m unittest discover -s tests -p test_windows_boundary.py -v
```

It uses synthetic temporary fixtures only. Wrong-owner and symlink tests require
the privileges present on the hosted test runner; inability to create those
fixtures is a **failure**, not a skipped security check. On other platforms all
native cases are explicitly skipped; only path parsing and unsupported-platform
refusal can be evidence there.

This is not a boundary against malicious code running as the same account,
administrators, SYSTEM, kernel code or compromised storage. A writable ancestor
can cause creation/open denial of service; pinned ancestor and leaf handles
prevent ordinary rename/delete substitution during an accepted operation, but
do not grant availability. ACLs can change under a privileged/same-account actor;
pre/post checks are not continuous authorization. Directory creation durability,
power loss, atomic replacement, encryption, backup and SQLCipher integration are
not implemented by these primitives.

## Remaining gates before native application support

1. Review and implement a local-only named-pipe transport: explicit pipe DACL,
   remote-client rejection, both-side process/token identity validation, bounded
   overlapped I/O and cancellation, endpoint squatting/replacement tests. Never
   substitute unauthenticated localhost TCP or assume Windows AF_UNIX grants
   Unix peer-credential semantics. Relevant Microsoft references are
   [named pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
   and [server process identity](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid).
2. Integrate secure creation, SQLite sidecars, identity and lifecycle ownership
   without POSIX UID/mode assumptions. Verify exclusive daemon ownership, crash
   cleanup and stale endpoint behavior using native processes.
3. Define the native approval broker separately from Linux polkit. No human
   approval fallback or silent adoption of terminal confirmation.
4. Run the **full** verifier and all native-negative equivalents, document exact
   Python/SQLite support, and get an independent security review. Unix tests must
   continue passing; marking Unix tests skipped is not equivalent Windows proof.

Only after these gates can issue #1 be considered for closure.
