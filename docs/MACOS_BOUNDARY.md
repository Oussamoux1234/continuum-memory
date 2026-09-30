# macOS: peer primitives only; encrypted application acceptance pending

Issue #10 remains open. The encrypted application requires a reviewed SQLCipher artifact,
and no macOS artifact has met that gate. There is also no native macOS human-presence
broker, protected approval/encryption key custody, or signed installer. Historical
plaintext results and source-only peer checks do not establish encrypted application support.

## Candidate test matrix

The integration narrows the `macOS boundary` workflow to source-only connected-peer
primitive checks. It must not run the encrypted application verifier or claim native
SQLCipher coverage. The proposed hosted matrix is `macos-14` and `macos-15` arm64 with
CPython 3.11–3.14; workflow review and execution remain pending. Runner labels are not
immutable machine images. No signing credential, Keychain operation, privileged
installation, or human prompt belongs to this primitive gate.

The prepared application/APFS fixture resolves the temporary directory's real device and checks
`diskutil` reports APFS with ownership permissions enabled. An unavailable or different
filesystem must fail that future native gate. These application tests remain pending until
an approved native backend is available. The refreshed Linux inventory excludes 29
macOS-only methods: four APFS, 17 extended-ACL, seven SQLite-lock and one journal-ACL
method. This is source enumeration, not native execution. Intel Macs,
network volumes, other macOS majors, case-sensitive variants, unusual inherited ACLs, and
actual user-presence hardware are outside this candidate matrix.

## Connected-peer identity

The client checks socket owner/mode/type and inode identity before and after connecting.
Before transmitting a capability, it also requires the connected peer's kernel-supplied
effective UID to match its own. The daemon performs the same UID check on accepted sockets
before reading requests. Missing, failed, malformed, or invalid-sentinel credentials are
rejected; absence of a Python socket API never means success.

On Darwin, the standard Python socket object lacks a `getpeereid` method. The adapter calls
the documented OS `getpeereid` function through the fixed `/usr/lib/libSystem.B.dylib`, with
explicit `int`, unsigned 32-bit UID/GID pointers, and errno handling. Linux retains its
`SO_PEERCRED` path, including unsigned UID/GID representation. Other peer interfaces are
unsupported and fail closed. These are OS **user identity** checks, not proof of a trusted
application, approved code signature, or human action.

Prepared peer tests cover real native connected sockets, closed descriptors, missing/error credentials,
short Linux records, wrong-UID injection, and deterministic endpoint replacement between
validation and connection. Replacement or unverifiable peers receive no capability bytes.
Wrong-UID injection is a unit check, not evidence from a real second OS account. Existing
daemon-lock tests separately verify that cleanup does not unlink a replacement endpoint.

## Filesystem evidence and explicit limits

Prepared native application tests check database, WAL/SHM, capability and audit-key ownership/modes/link counts;
atomic replacement staging uses private regular files. Controlled races replace synthetic
files with symlinks, FIFOs, or hardlinks immediately before open and must be rejected without
blocking or reading the target. The full-suite tests also cover directory/database/socket
links, unsafe modes, lease replacement, stale sockets, and crash cleanup. Their presence
is not evidence of execution with an encrypted macOS runtime.

Those checks do **not** isolate arbitrary processes running as the same account. A prepared
native test checks that a same-UID child can read a synthetic prototype audit key;
it returns only its hash, not key bytes. A same-user attacker can also read capabilities,
change files/permissions, or impersonate another same-user process. Observing one inode
replacement is not proof against every substitution/ABA race or malicious writable ancestor.

### Extended ACL guard

On macOS, private regular files and directories must also have **no extended ACL entries**.
The guard deliberately refuses all entries, including owner-only, deny, and inherited
entries; it does not interpret or repair them. Files with `600`/`700` mode bits can still
carry ACL permissions. Existing synthetic homes with ACLs will now be refused; inspect
them and choose a fresh owner-only evaluation directory instead of automatically stripping
permissions from an existing path.

Ordinary private-file/directory preflights open a nofollow `O_EVTONLY` metadata descriptor and check
the same device, inode, type/mode, link count, owner/group, and change timestamp before and
after the native ACL query. Private content reads and writes independently query the actual
content descriptor before bytes are read/written, and reads recheck before returning bytes.
An ACL inherited between the parent preflight and new-file creation is rejected before
payload bytes are written; an empty file may remain. No automatic cleanup/retry is claimed.
The adapter binds Darwin's `O_EVTONLY` ABI constant directly because Python 3.9 does not
export it; this uses the same native open mode, not a reduced-permission-check fallback.

The adapter loads only `/usr/lib/libSystem.B.dylib` with explicit opaque-pointer ABI types.
Darwin reports absent ACLs as `NULL`/`ENOENT`; only that fresh errno, corroborated by unchanged
existing-object metadata, is accepted. Other query errors fail closed as `acl_unavailable`.
For allocated ACLs, acceptance requires native validity, a bounded size equal to the same
runtime's empty ACL, and an empty first-entry result with Darwin's exact status/errno and
null output pointer. Allocations are freed on success and failure. There is no ACL text
parser, opaque structure cast, permission-repair subprocess, or additional dependency.
This contract is reviewed/tested on local APFS, not arbitrary network/filesystem drivers.

Unix socket pathnames cannot be opened this way on macOS. Their ACL check uses nofollow
`acl_get_link_np`, bracketed by matching `lstat` metadata. That is a **pathname observation**,
not a descriptor-bound socket-path guarantee or protection against every ABA substitution.
The connected-peer checks above still apply before any capability is sent.

SQLite files are a deliberate exception to metadata descriptor opening. Database, WAL,
SHM and rollback-journal validation uses `acl_get_link_np`, bracketed by exact `lstat`
device/inode/type/mode/link-count/owner/group/ctime checks. Type, single-link, owner-only
mode and safe ancestors are still required. This no-follow **pathname observation** does
not bind to SQLite's own descriptor and does not provide arbitrary same-user/ABA race
protection. Disappearance, replacement, permissions changes and ACL query errors fail
closed; there is no directory-churn retry for SQLite files.

The exception preserves SQLite's advisory locks: opening and closing an unrelated
metadata descriptor for a live database or sidecar can release the process's locks.
That caused independently reproduced committed-data loss in
[issue #45](https://github.com/Oussamoux1234/continuum-memory/issues/45). Every production
SQLite-file check, including constructor/bootstrap and both connection preflight and
post-configuration, uses the dedicated helper. Ordinary keys/private files keep their
descriptor-based validation; Windows behavior is unchanged. See
[SQLite's locking warning](https://www.sqlite.org/howtocorrupt.html#posix_advisory_locks_canceled_by_a_separate_thread_doing_close_).

Existing database and companion files are checked before SQLite connects and again after
configuration, so a pre-existing unsafe companion is refused before engine access.
Native tests cover real allow/deny/owner-only/inherited ACLs despite private mode
bits, safe no-ACL objects, file/socket substitutions, read/create races, and each database
companion. Injected ABI tests cover failed/malformed native responses and cleanup paths;
they complement, rather than replace, the native fixtures.

`tests/test_sqlite_lock_preservation.py` pairs a no-extra-open oracle with real separate
processes: a normal writable-mode SQLite reader must leave a live Store's WAL/SHM identities
intact, and the writer's committed row must remain independently visible after abrupt exit.
It also exercises multiple Store handles in one process. Read-only observers alone do not
establish this property; the original writable-observer trigger must pass on the exact
revision and native platform under review.

Ancestor identity pinning, arbitrary concurrent ACL/path changes, malicious SQLite sidecar
substitution after preflight, and stronger same-user process isolation remain unresolved.
Directory-entry creation legitimately changes the containing directory's timestamp/link
count. The directory preflight allows at most eight fresh complete observations after an
`unsafe_file` metadata race, only when the original device/inode, owner/group and mode
remain identical and the change timestamp changed. Each attempt repeats the full native
ACL check; it never adopts a replacement directory, ignores an ACL error, or repairs
permissions. Sustained churn exhausts the bound and fails closed. Regular-file and socket
observations remain strict and are not retried. Do not use the vault directory for unrelated
files or sockets. Inspect other refusals before retrying/restarting.
The synthetic MCP fixture waits for a validated, stateless discovery response from each
child before returning it to the demo. This bounded startup barrier finishes private-path
checks before another fixture starts writing. A failed or stalled child is reaped, not
retried. It prevents the demo's asynchronous startup race; it does **not** establish that
production clients starting during daemon writes cannot encounter a metadata refusal.
Do not claim complete APFS access control or store sensitive data in this prototype.
FileVault, APFS snapshots/clones, and
`secure_delete` do not establish application encryption or physical erasure. Backup and
restore protection is unimplemented, so no backup acceptance is claimed here.

## Encrypted application evaluation is blocked

There is no current macOS install, initialization, daemon, or full-verifier runbook for
this candidate. The Linux-only post2 wheel cannot satisfy macOS runtime admission, and
ordinary build-tool wheels do not replace it. Do not substitute stdlib SQLite, an upstream
wheel, or a locally unreviewed native build. The source-only peer workflow does not create
a vault or establish application encryption.

Before restoring an application evaluation runbook, approve an immutable macOS
builder/toolchain and exact native artifact, then run the application/APFS tests and
review key custody, ACLs, installation, upgrade, and removal. A terminal confirmation
fallback is not available. No LaunchAgent, Keychain item, system helper, or signing identity
is installed by this source-only slice.

## Native approval/key boundary: proposed next gate, not implemented

The proposed next implementation is a small signed/hardened native broker with an OS-owned
confirmation UI and authenticated IPC to the ledger service. It must validate the caller's
code identity and display the exact operation/project/claim/disclosure preview before asking
for OS user presence. A plain success result from an agent-controlled prompt is insufficient.

The daemon should verify a versioned signature bound to the exact canonical challenge bytes,
vault/project, caller identity, operation, preview digest, nonce, key ID, and expiry. It must
consume a grant once, reject changed previews/replay/expired grants, and preserve the rule
that recalled memory never authorizes an action. Cross-platform golden vectors and negative
tests must be reviewed before adopting a new signature format or changing Linux contracts.

A design candidate is a broker-generated Secure Enclave P-256 signing key with private-key
usage and a reviewed Keychain user-presence access policy. The key is device-bound; a software
Keychain alternative must be a separate explicitly accepted tier, never a silent fallback.
Cancellation, locked session, unsupported hardware, unavailable broker, or failed key access
must leave the action unapproved. No new cryptographic implementation is proposed here.

Approval signing and database encryption are separate: SQLCipher still needs a symmetric key
in its owning process. Returning that key to an agent process, storing it in a same-UID file,
or merely moving it to a keychain does not prove isolation. A reviewed service/process and
code-signing boundary, key retrieval policy, debug/entitlement restrictions, and adversarial
same-user tests are required. The existing Python prototype does not satisfy that gate.

Before support is declared, an owner-controlled native run must demonstrate actual OS
presence, cancellation, caller substitution, replay, key non-exportability, unavailable and
revoked keys, rotation/recovery, and disclosure isolation. It must also settle service
installation/update/uninstall, access groups, signing identity/custody/revocation, Developer
ID/hardened-runtime entitlements, notarization/stapling verification, and offline upgrade
policy. Hosted synthetic CI is not evidence for those hardware/UI/security properties.

## Primary references

- [Apple getpeereid contract](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpeereid.3.html)
- [Apple descriptor and nofollow ACL query implementation](https://github.com/apple-oss-distributions/Libc/blob/main/posix1e/acl_file.c)
- [Apple absent ACL property semantics](https://github.com/apple-oss-distributions/Libc/blob/main/gen/filesec.c)
- [Apple ACL entry status semantics](https://github.com/apple-oss-distributions/Libc/blob/main/posix1e/acl_entry.c)
- [Apple native ACL size implementation](https://github.com/apple-oss-distributions/Libc/blob/main/posix1e/acl_translate.c)
- [Python socket API](https://docs.python.org/3/library/socket.html)
- [Standard hosted runner labels and limitations](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [Secure Enclave key restrictions](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Keychain user-presence access flag](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence)
- [Apple Local Authentication](https://developer.apple.com/documentation/localauthentication)
- [Notarizing macOS software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
