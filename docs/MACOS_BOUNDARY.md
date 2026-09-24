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
an approved native backend is available; four are platform-inapplicable on Linux. Intel Macs,
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

**Extended ACLs are not inspected by the current POSIX boundary.** An APFS ACL may grant
access beyond the mode bits. Do not claim complete APFS access control, use inherited or
custom ACLs, or store sensitive data in this prototype. Descriptor-bound ACL validation,
ancestor identity pinning, malicious SQLite sidecar substitution, and stronger same-user
process isolation require separate reviewed work. FileVault, APFS snapshots/clones, and
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
- [Python socket API](https://docs.python.org/3/library/socket.html)
- [Standard hosted runner labels and limitations](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [Secure Enclave key restrictions](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Keychain user-presence access flag](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence)
- [Apple Local Authentication](https://developer.apple.com/documentation/localauthentication)
- [Notarizing macOS software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
