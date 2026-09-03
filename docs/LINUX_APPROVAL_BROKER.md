# Linux OS-backed approval broker

Status: implemented but not yet exercised by a real interactive polkit run in project CI.
Unprovisioned live vaults fail closed; the terminal signer is retained only as an explicitly
injected temporary-test fixture.

## Boundary

The Linux broker sends a bounded JSON request over standard input to a fixed root-owned
helper through `/usr/bin/pkexec`. No preview, digest, vault identifier, private key material,
or grant is placed in process arguments or environment variables. The fixed private-key
pathname is passed only from the privileged helper to its root OpenSSL child and is not a
secret. Polkit requires administrator authentication on every invocation; cached
authorization is not requested. After polkit
authorization, the helper renders the exact preview on `/dev/tty` and requires the digest
prefix before signing. Non-ASCII characters are escaped in that rendering so Unicode
direction controls cannot visually reorder untrusted preview text.

The helper owns a per-OS-user RSA-3072 private key under
`/var/lib/continuum-memory/approval-keys`. The daemon can read only the matching root-owned
public key under `/etc/continuum-memory/approval-keys`. The signed payload binds schema,
OS user ID, vault ID, nonce, operation, exact preview digest, and expiry. Selecting the key
by OS user ID prevents a same-user database edit from downgrading a provisioned vault to
the terminal signer; including the vault ID prevents cross-vault grant reuse.

The control capability still authenticates the user CLI to the daemon, but it cannot create
a valid administrative grant in the packaged runtime. Without a root public key,
administrative preview/apply calls fail closed. HMAC grants are accepted only by the
explicitly injected temporary test kernel. Existing nonce consumption, expiry,
exact-preview verification, and replay protection remain enforced by the daemon.

## Source installation

This development installer is intentionally separate from application initialization. It
must be reviewed and run explicitly on Linux from a clean checkout:

```bash
sudo packaging/linux/install-polkit.sh
```

It creates an offline root-owned helper environment under `/opt/continuum-memory-polkit`,
installs the fixed launcher at `/usr/libexec/continuum-memory/approval-helper`, and installs
the polkit policy under `/usr/share/polkit-1/actions`. It canonicalizes its own source path,
uses fixed system executables, and starts Python/pip with an isolated environment. It does
not execute an existing runtime: it builds in a new root-created staging directory, rejects
an unsafe existing runtime, and swaps the staged runtime into place only after the offline
install succeeds. It does not create approval keys. The reviewed checkout is still trusted
installation input; signed distribution artifacts remain issue #2.

With `memoryd` running for the selected vault, provision the per-user key through polkit:

```bash
continuum approval status
continuum approval provision-linux
continuum approval status
```

The final status must report `linux_polkit_rsa_sha256`. Restart is not required.
Provisioning is serialized with a root-only lock, and both existing and newly installed key
pairs are cryptographically checked before success is returned. The helper sets known
directory and private-file umasks instead of inheriting the caller setting.

## Diagnostics

`continuum approval status` reports the daemon view of the current user key. It does not
prove that every executable component is installed. On Linux, also verify:

```bash
/usr/bin/pkaction --action-id org.continuummemory.approval --verbose
/usr/bin/stat -c '%U %G %a %n' \
  /usr/bin/pkexec \
  /usr/bin/openssl \
  /usr/libexec/continuum-memory/approval-helper \
  /usr/share/polkit-1/actions/org.continuummemory.approval.policy
```

The action must require `auth_admin` for an active session, not an authorization-retaining
`*_keep` result. The helper validates that exact policy, fixed helper path, ownership, and
permissions again before it handles a request. The real smoke test below is the final
end-to-end diagnostic; file checks alone are insufficient.

## Opt-in real smoke test

Project CI uses deterministic fake-process and real-signature tests and never opens an OS
authentication prompt. On a Linux workstation, copy the vault ID from `continuum approval
status`, then run this explicit non-mutating check from a terminal:

```bash
python3 scripts/polkit_smoke.py --vault-id vlt_EXAMPLE
```

The command requests real polkit authorization, displays only a synthetic preview, verifies
the returned signature, and does not contact `memoryd` or change memory.

## Removal

Stop `memoryd`, remove the policy first, then remove only these installed code paths:

```text
/usr/share/polkit-1/actions/org.continuummemory.approval.policy
/usr/libexec/continuum-memory/approval-helper
/opt/continuum-memory-polkit
```

Key directories are deliberately not removed by the installer or ordinary uninstall
instructions. Component-only removal therefore preserves the key pair for a later reinstall.
`continuum approval status` will still report the public key as provisioned, but approval
attempts fail closed because the helper or policy is unavailable.

A full per-user deprovision is a separate destructive operation: after stopping `memoryd`,
an administrator must remove both `uid-<UID>.pem` files from
`/etc/continuum-memory/approval-keys` and `/var/lib/continuum-memory/approval-keys` using the
same exact numeric UID and no wildcard. Removing only one half deliberately leaves a
fail-closed partial state. Destroying the private file removes approval authority and is
irreversible unless separately backed up; this is not part of ordinary uninstall.

## Remaining limitations

- This is not an encryption boundary; the database and current control capability remain
  plaintext prototype material.
- The real interactive path still needs controlled Linux-host evidence before issue #3 or
  trustworthy local v1 can be marked complete. The independent review is recorded in the
  issue and its focused pull request.
- OpenSSL and polkit are Linux system dependencies. Distribution packaging, SBOM, and
  signing remain issue #2.
- A local administrator can override polkit policy through system rules or replace
  root-owned files; root/admin remains outside this boundary.
- macOS and Windows require their own OS-specific approval designs in issues #10 and #1.
