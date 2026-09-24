# Native Windows filesystem and storage candidate

The candidate runtime connects this boundary to plaintext SQLite and the
[bounded native pipe daemon/client](WINDOWS_IPC.md). This is still acceptance
work for [issue #1](https://github.com/Oussamoux1234/continuum-memory/issues/1):
local macOS regressions and earlier isolated Windows primitive jobs are **not**
a full native application verifier pass. Integrated Windows CI is pending.
Use disposable synthetic vaults only; do not migrate a real vault onto this
candidate or interpret it as production Windows security support.

Native owner mutation remains `os_approval_unavailable`. The fixture broker's
explicit synthetic approval is not human presence. This port adds neither a
Windows approval broker nor encryption, SQLCipher, protected key custody or
encrypted backup/restore.

The process's default file owner (`TokenOwner`) must equal its user SID
(`TokenUser`). Elevated processes can instead default to Administrators ownership.
Production refuses that configuration before bootstrap metadata writes or SQLite
opening with `unsupported_token_owner`; it never changes tokens or repairs owners.
Use a compatible non-elevated process for normal operation. This requirement is
separate from filesystem DACL inheritance.

## Filesystem contract

`windows_boundary.WindowsBoundary` uses Win32 handles through the Python standard
library. The platform facade selects it only on Windows; the POSIX implementation
retains its own UID/mode and socket checks.

- Only absolute DOS drive paths on local fixed NTFS volumes are accepted. UNC,
  device namespaces, SUBST drive aliases, alternate data streams, reserved device
  names, ambiguous dot/space components and long paths are refused.
- Every ancestor is opened without delete sharing, checked for reparse points,
  and held throughout each path-dependent operation. System ancestors need not
  belong to the user; private leaves must. Junctions and symlinks are refused,
  including on ancestors. Handles request data-read/directory-list access because
  metadata-only handles do not enforce the needed sharing restriction. A path
  whose ancestor denies directory-list access is refused.
- Private directories require the process token's user SID as owner and a
  protected DACL containing exactly one full-control allow ACE for that SID.
  Newly created directories use **object and container inheritance**; the vault
  guard requires both flags before SQLite may create sidecars. The lower-level
  inspection primitive also accepts a non-inheritable explicit owner-only ACE.
  Creation supplies its descriptor
  atomically; existing objects are never adopted by repairing ACLs or ownership.
- Private files require either the protected explicit owner-only ACE or exactly
  the owner-only ACE inherited from their **validated, held immediate private
  parent**. An arbitrary safe ancestor alone does not authorize inheritance.
  Broader or unusual ACLs are refused rather than interpreted as equivalent.
- Every file must be a disk file with exactly one hardlink. Security and metadata
  are checked on open handles. Handles are non-inheritable and released on success
  and error paths. Reads and private-file writes are bounded to 64 KiB.

The Microsoft references are [CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[handle security queries](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo),
[file identity](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle),
and [security descriptor format](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format).

## Vault lifetime and metadata publication

Before opening SQLite, the Windows daemon holds the exact 32-byte nonsecret
`ipc.binding` file with read sharing only: writes, truncation, rename and deletion
are denied for that lifetime. Its private parent and ancestors remain pinned.
The first-instance pipe ownership handle is acquired before Store construction;
a losing daemon never opens the database. Missing, short or oversized bindings
are refused, not regenerated or guessed.

`windows_storage.VaultGuard` keeps the private vault directory and database pinned
until SQLite closes. The guard validates ownership, ACLs, file identity properties
and every present `-wal`, `-shm` and `-journal` before connection configuration and
later SQL statements. SQLite-created children inherit the single owner-only ACE.
The wrapper preserves SQLite's owning-thread restriction. Workers never access
Store or Kernel; see [runtime scheduling and shutdown](WINDOWS_IPC.md#bounds-and-exceptional-cleanup).

New private material uses `CREATE_NEW`, never truncation of an existing object.
Metadata replacement writes and flushes a new private sibling, holds that exact
source plus its parent, and uses `SetFileInformationByHandle` for same-directory
replacement. The destination is the strictly validated absolute path with a null
root-directory field; its non-reparse parent and every ancestor remain pinned
throughout the native call. The Windows 2025
[diagnostic run](https://github.com/Oussamoux1234/continuum-memory/actions/runs/36001151215/job/107637834225)
rejected relative-name variants with error 87; the absolute form succeeded without
relaxing handle sharing, ACLs or access checks. This does not add a same-user
tamper guarantee.
A failed rename preserves the old target and requests deletion of
the held temporary object, not an unverified pathname. A failed initial write
can leave an owner-only partial file requiring explicit inspection/cleanup.
Failure after publication must be treated as an uncertain committed result.

This is **process-crash consistency**, not power-loss durability, directory-fsync,
secure erasure, encrypted-key publication or backup revocation. The relevant API
is [SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle).

## Native validation and limits

Run focused native suites in PowerShell from a source checkout:

```powershell
$env:PYTHONPATH = "src"
python -W error::ResourceWarning -m unittest tests.test_windows_boundary tests.test_windows_storage tests.test_windows_pipe tests.test_windows_runtime -v
```

These suites are not a substitute for the complete `scripts/verify.py` gate,
including normal lifecycle, migration, admission, MCP, packaging, installed
entrypoint and provenance checks. CI records its actual Windows image, Python
and SQLite versions: `windows-2025` is a mutable runner label, not an immutable
or reproducibly built Windows distribution. Final support claims require exact
integrated-head native evidence; skipped native tests on macOS/Linux provide none.

### Explicit CI-only owner fixture

The owner authorized the disposable GitHub-hosted Windows CI process to temporarily
set **only its own token's default owner to its existing user SID**, then restore
the exact previous owner. `fixtures/windows_test_owner.py` wraps the fixed verifier;
it is outside production and absent from the runtime wheel. It requires the exact
reviewed checkout, native x64 hosted Windows Actions markers, and the workflow's
explicit process-only opt-in. These environment checks prevent accidental use;
they are not a security boundary or replacement for authorization.

Before mutation, the fixture queries a held parent token and requires a distinct
token-object identity. It never writes the parent token, changes a privilege,
group, default DACL, account, host policy or macOS setting, and never accepts an
arbitrary SID or command. Native preflight checks production refusal under an
incompatible original owner, real child-process/file-owner inheritance, exact
restoration after success and a deliberate exception, and an unchanged parent
owner. Unexpected restoration failure exits the fixture process with status 79.
It must not report a normal verification success after uncertain restoration.
The verifier subprocess has a bounded timeout, but this wrapper does not claim
to terminate every descendant after a timeout or abrupt process death. Residual
test descendants are contained by disposal of the dedicated hosted CI VM; this
is not a general-purpose local process-tree cleanup tool.

The full workflow uploads no artifacts. The CI fixture does not authorize a
different-account process test, provide human approval, or make elevated
production use supported. Its native
evidence must be reported separately from deterministic injected unit-test faults.

Relevant APIs are [TokenOwner](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_owner),
[TokenId](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics),
and [token access rights](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects).

All fixtures use synthetic temporary vaults. Symlink and wrong-object-owner
tests need hosted-runner privileges; failure to establish their fixtures is a
failure, not a skipped security pass. A pipe object owned by Administrators and
a comparison against another SID do **not** prove rejection of a real peer
running as a different account. That separately authorized fixture remains
pending; no local account or credential is created by these tests.

This is not a boundary against malicious same-account code, administrators,
SYSTEM, kernel code or compromised storage. Those actors can change ACLs or
bytes; pre/post checks are not continuous authorization. Writable ancestors can
cause denial of service, and held handles do not promise availability. Native
production human approval and encryption/key custody remain separate gates.

Issue #1 remains open until the integrated native verifier, applicable negative
fixtures and independent security review are complete. The [IPC contract and
remaining evidence limits](WINDOWS_IPC.md) must be evaluated with this document.
