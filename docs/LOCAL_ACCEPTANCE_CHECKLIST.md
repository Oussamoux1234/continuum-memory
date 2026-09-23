# Owner acceptance checks: Linux approval and encryption dependency

Status: **not executed / not approved**. This checklist does not close issues
[#3](https://github.com/Oussamoux1234/continuum-memory/issues/3),
[#7](https://github.com/Oussamoux1234/continuum-memory/issues/7), or
[#13](https://github.com/Oussamoux1234/continuum-memory/issues/13).
The owner requested checklists and explicitly kept the gates open on 2026-09-23.

## 1. Genuine Linux human-presence check

Audience: a human operator on a controlled Linux workstation or desktop VM, with
administrator authority and a real terminal. CI mocks, an automatically answered
prompt, a macOS host, or merely finding `pkexec` are not acceptance evidence.
Use only synthetic data and a new disposable vault. Do not test on a real vault.

### Before installing anything

- Record the exact reviewed commit, clean checkout status, Linux distribution,
  architecture, Python/OpenSSL/polkit versions, and test date. Do not collect an
  environment dump or publish local usernames, private paths, credentials, or keys.
- Read [the broker boundary, installer, diagnostics, and removal guide](LINUX_APPROVAL_BROKER.md).
  Independently review the helper, policy, and privileged installation steps for
  that exact revision. The recorded review of PR #11 is not automatic approval of
  later installer changes.
- Run `python3 scripts/verify.py` successfully on that checkout and retain the
  content-free summary. This is necessary, not a substitute for human presence.
  For an encrypted candidate, first follow that revision's verified runtime and
  offline wheelhouse instructions; an arbitrary system Python is not sufficient.
- Inspect `packaging/linux/install-polkit.sh` at the selected revision and follow
  its matching installation guide. Packaging issue #2 is changing the installer
  from an offline source install to a verified-wheel input: do not mix a newer
  command or wheel with an older installer. Record the artifact hash if applicable.
- Ask the operator to approve the exact privileged installation. Nothing in this
  checklist authorizes an agent to install root-owned software, provision keys,
  type a password, or answer the approval prompt for the operator.

### Run from a real terminal

From the reviewed checkout, create a synthetic private location and initialize it:

```bash
umask 077
CM_SMOKE_WORK=$(mktemp -d -t continuum-polkit-XXXXXXXX)
printf '%s\n' "$CM_SMOKE_WORK"
PYTHONPATH=src python3 -m continuum_memory.cli \
  --data-dir "$CM_SMOKE_WORK/vault" init \
  --project-name polkit-smoke --project-path "$CM_SMOKE_WORK" \
  --providers codex,claude
PYTHONPATH=src python3 -m continuum_memory.daemon \
  --data-dir "$CM_SMOKE_WORK/vault"
```

Leave this daemon in the foreground. In a second terminal, enter the same reviewed
checkout and set `CM_SMOKE_VAULT` to the exact printed temporary directory plus
`/vault` (not an existing personal vault). Then run:

```bash
PYTHONPATH=src python3 -m continuum_memory.cli \
  --data-dir "$CM_SMOKE_VAULT" approval status
PYTHONPATH=src python3 -m continuum_memory.cli \
  --data-dir "$CM_SMOKE_VAULT" approval provision-linux
PYTHONPATH=src python3 -m continuum_memory.cli \
  --data-dir "$CM_SMOKE_VAULT" approval status
/usr/bin/pkaction --action-id org.continuummemory.approval --verbose
/usr/bin/stat -c '%U %G %a %n' \
  /usr/bin/pkexec /usr/bin/openssl \
  /usr/libexec/continuum-memory/approval-helper \
  /usr/share/polkit-1/actions/org.continuummemory.approval.policy
```

The human must approve provisioning. It creates or verifies a real per-user
approval key pair; this is an OS change even though the vault is disposable.
Retain the exact content-free status and policy/path diagnostics. The active
policy must be `auth_admin`, not an authorization-retaining `*_keep` policy.
The provisioned boundary must be `linux_polkit_rsa_sha256`.

Copy the synthetic vault ID reported by the CLI into `CM_SMOKE_VAULT_ID` and run:

```bash
PYTHONPATH=src python3 scripts/polkit_smoke.py --vault-id "$CM_SMOKE_VAULT_ID"
```

1. First cancel the OS prompt; retain the content-free error and exit status.
   Expect exit status 2. It must not report success or mint an approval.
2. Run again. Personally inspect the synthetic preview, complete OS authentication,
   and type `ACCEPT ` followed by the displayed first 12 digest characters only if
   they match the preview. Follow the helper's exact prompt, not a bare digest.
3. Require the exact success object:
   `{"approval_boundary":"linux_polkit_rsa_sha256","status":"passed"}`.
   This proves the script verified the returned signature; the script does not
   submit a memory mutation.

Do not pipe or redirect the interactive smoke's standard input/output: it
deliberately checks for a terminal. Do not record password entry, signatures,
private key contents, capability files, or whole terminal sessions. Manually copy
only the permitted diagnostics and content-free outcomes into the evidence record.

### Record, review, and stop

Record commit/artifact identity, host versions, policy/path diagnostics, successful
signature-verification output, cancellation outcome, operator, reviewer, date,
and any deviations. Leave unchecked items explicit. A reviewer must compare the
evidence to the actual current helper and installer before closing #3.

Stop the foreground daemon with Ctrl-C. Keep key removal separate: uninstalling
code or deleting the synthetic vault does not remove the per-user approval key.
Follow the broker guide's component-only removal or separately reviewed per-user
deprovision procedure; do not recursively delete broad paths or key directories.

## 2. Human review of the SQLCipher binding license

Audience: an owner-authorized person qualified to make the project's licensing
decision. This is an evidence checklist, not a legal conclusion or permission to
redistribute. AI review and green CI do not supply that acceptance.

- Identify the exact proposed source archives, tags/commits, patches, wheel hashes,
  SBOM, notices, and provenance. Use the current candidate's issue #13 evidence;
  do not accept a different wheel merely because its version string matches.
- Compare `sqlcipher3` 0.6.2's released package metadata with the LICENSE actually
  shipped in its source and candidate wheels. The reported conflict is **MIT
  metadata versus a different Gerhard Haering notice**. A metadata classifier
  alone does not resolve that conflict.
- Review the upstream metadata changes and unchanged license text, patch marking,
  attribution/notice preservation, and all bundled dependencies. Keep exact
  source bytes and checksums with the decision record.
- Decide whether written upstream clarification is required, whether the exact
  candidate is acceptable for the proposed use/distribution, or whether the
  binding must be replaced. Record unresolved questions; do not silently choose
  MIT or another SPDX identifier.
- Record reviewer identity/authority, date, precise artifact scope, conclusion,
  conditions, and supporting references. Preserve `NOASSERTION` until a supported
  conclusion is explicitly accepted and the SBOM/notices are reviewed accordingly.

Source evidence to compare, not a resolution:

- [Released package metadata](https://pypi.org/pypi/sqlcipher3/0.6.2/json)
- [Tagged LICENSE](https://github.com/coleifer/sqlcipher3/blob/0.6.2/LICENSE)
- [Metadata change](https://github.com/coleifer/sqlcipher3/commit/859fe362ef94f1d898b5cf121b91d7948d53ebf7)
- [Later metadata removal](https://github.com/coleifer/sqlcipher3/commit/dfee7e5fe6a1422d9e5e23edc0727a2e1e2128ed)

License acceptance alone does not approve the security review, release signing
identity, trust/revocation policy, native macOS builder, or package publication.
Those remain separately recorded gates. Until accepted, candidate wheels stay
temporary GitHub Actions artifacts, held PRs stay held, and the product makes no
production-encryption claim.
