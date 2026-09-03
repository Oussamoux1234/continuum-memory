# Linux OS-backed approval broker

Status: implemented but not yet exercised by a real interactive polkit run in project CI.
Unprovisioned live vaults fail closed; the terminal signer is retained only as an explicitly
injected temporary-test fixture.

## Boundary

The Linux broker sends a bounded JSON request over standard input to a fixed root-owned
helper through `/usr/bin/pkexec`. No preview, digest, vault identifier, key path, or grant is
placed in process arguments or environment variables. Polkit requires administrator
authentication on every invocation; cached authorization is not requested. After polkit
authorization, the helper renders the exact preview on `/dev/tty` and requires the digest
prefix before signing.

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
the polkit policy under `/usr/share/polkit-1/actions`. It does not create approval keys.

With `memoryd` running for the selected vault, provision the per-user key through polkit:

```bash
continuum approval status
continuum approval provision-linux
continuum approval status
```

The final status must report `linux_polkit_rsa_sha256`. Restart is not required.

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

Stop using the broker before removing it. Remove only these installed code/policy paths:

```text
/usr/share/polkit-1/actions/org.continuummemory.approval.policy
/usr/libexec/continuum-memory/approval-helper
/opt/continuum-memory-polkit
```

Key directories are deliberately not removed by the installer or ordinary uninstall
instructions. Destroying `/var/lib/continuum-memory/approval-keys` removes private approval
authority and is irreversible; it requires a separate explicit recovery decision.

## Remaining limitations

- This is not an encryption boundary; the database and current control capability remain
  plaintext prototype material.
- The real interactive path still needs controlled Linux-host evidence and independent
  review before issue #3 or trustworthy local v1 can be marked complete.
- OpenSSL and polkit are Linux system dependencies. Distribution packaging, SBOM, and
  signing remain issue #2.
- macOS and Windows require their own OS-specific approval designs in issues #10 and #1.
