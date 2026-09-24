# macOS: native verification slice, not complete platform acceptance

Issue #10 remains open. This is an **experimental plaintext prototype**, without a native
macOS human-presence broker, protected approval/encryption key custody, or signed installer.
Use synthetic data only. Passing native tests does not make those missing boundaries safe.

## Candidate test matrix

The `macOS boundary` workflow runs the complete `scripts/verify.py` gate on explicit
standard GitHub-hosted `macos-14` and `macos-15` runners, each with CPython 3.11, 3.12, 3.13,
and 3.14. The workflow requires observed arm64 architecture and the matching OS major;
it records the actual macOS, Python, SQLite, and runner image versions. Actions are pinned
to commits, but runner labels are not immutable machine images. No paid/custom runner,
signing credential, Keychain operation, privileged installation, or human prompt is used.

The native fixture test resolves the temporary directory's real device and checks
`diskutil` reports APFS with ownership permissions enabled. An unavailable or different
filesystem fails that native gate; it is not silently described as APFS. Intel Macs,
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

Tests cover real native connected sockets, closed descriptors, missing/error credentials,
short Linux records, wrong-UID injection, and deterministic endpoint replacement between
validation and connection. Replacement or unverifiable peers receive no capability bytes.
Wrong-UID injection is a unit check, not evidence from a real second OS account. Existing
daemon-lock tests separately verify that cleanup does not unlink a replacement endpoint.

## Filesystem evidence and explicit limits

Native tests check database, WAL/SHM, capability and audit-key ownership/modes/link counts;
atomic replacement staging uses private regular files. Controlled races replace synthetic
files with symlinks, FIFOs, or hardlinks immediately before open and must be rejected without
blocking or reading the target. Existing full-suite tests cover directory/database/socket
links, unsafe modes, lease replacement, stale sockets, and crash cleanup.

Those checks do **not** isolate arbitrary processes running as the same account. A native
test deliberately proves that a same-UID child can read a synthetic prototype audit key;
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

## Install and run a synthetic evaluation

Use a reviewed checkout and Python 3.11–3.14 on the candidate macOS/arm64 matrix. Prepare
the hash-pinned build toolchain/wheelhouse using [distribution verification](LINUX_RELEASE.md);
that guide's ordinary Python build commands also run on macOS. Do **not** run its Linux
polkit installer on macOS. Dependency preparation is the separate network step.

```bash
.venv/bin/python scripts/macos_environment.py
.venv/bin/python scripts/verify.py
.venv/bin/python -m pip install --no-index --no-deps --no-build-isolation -e .
export PATH="$PWD/.venv/bin:$PATH"
export CONTINUUM_HOME="$(mktemp -d /private/tmp/continuum-macos-demo.XXXXXX)"
continuum init --project-name demo --project-path "$PWD" --providers codex,claude
memoryd --data-dir "$CONTINUUM_HOME"
```

Keep the daemon in the foreground. In another terminal, set the same `PATH` and exact
temporary `CONTINUUM_HOME`, then use the project ID printed by initialization:

```bash
continuum status --project PROJECT_ID
continuum approval status
continuum audit verify
```

Administrative remember/review/correct/forget actions are expected to fail closed because
macOS approval is unavailable. There is no terminal-confirmation bypass. The full verifier's
temporary fixture demo supplies its explicit test-only approval seam; live commands never
select that seam. This runbook does not install a LaunchAgent or persistent background job.

If identity is unavailable, stop and inspect the native test results and interpreter;
do not remove the UID check. For `unsafe_*` errors, inspect owner/mode/type, ACLs, and links
on the exact synthetic directory; do not automatically chmod, follow, or replace it.
For daemon lease errors, follow [daemon recovery](DAEMON_RECOVERY.md). Never unlink or
truncate the persistent lock to force a second daemon to start.

### Upgrade and uninstall

Stop the foreground daemon with Ctrl-C and stop any separately configured restart mechanism
before changing versions. Verify a clean reviewed candidate in a separate virtual environment
and with a new synthetic vault. Do not mix daemon versions or downgrade a schema migrated by
a newer executable; this prototype has no accepted encrypted backup/restore procedure.

To remove only the package from the dedicated evaluation environment, stop the daemon and
run `.venv/bin/python -m pip uninstall continuum-memory`. This does not delete vaults or
OS files. Keep synthetic vault paths explicit and inspect them before separately choosing
cleanup. Uninstall is not an audited forget operation, backup revocation, or secure erasure.
No Keychain item, system helper, signing identity, or LaunchAgent was installed by this slice.

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
