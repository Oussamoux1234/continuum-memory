# Local secret and prohibited-content admission

New user/agent content is checked before persistence. This is a deterministic,
local safety net, not a secret manager, universal DLP scanner, or proof that content
is safe. Do not send or store real credentials in memory.

## Default detection

The fixed detectors reject these high-confidence shapes in bounded text fields:

- PEM private-key headers (including RSA, EC, DSA, OpenSSH and encrypted keys) and
  PGP private-key block headers. Public-key and certificate headers are allowed.
- AWS `AKIA`/`ASIA` access-key IDs with 16 following uppercase alphanumeric bytes;
  GitHub classic token prefixes with at least 30 suffix characters and
  `github_pat_` with at least 20; `sk-` API tokens and Slack `xox*` token forms with
  at least 20 suffix characters.
- JWT-shaped three-part values whose first two parts have JSON-style base64url
  prefixes and whose signature has at least 16 characters; bearer credentials of
  at least 20 characters; `Authorization: Basic` values of at least 16 characters.
- Credential URLs containing a username and an at-least-eight-character password.
- Assignments to password/passwd, API-key, access/refresh-token, client-secret or
  secret-key names: the value must contain letters and digits and be at least
  12 characters long. This intentionally does not classify every short password
  or prose passphrase as a credential.

Expressions are fixed and run only on bounded fields. No network service,
telemetry, arbitrary regular expression, dependency, or external transmission is
involved. Short prefixes, explicit placeholder syntax such as `<token>` or
`${PASSWORD}`, and ordinary documentation are not automatically secrets.
Literal examples that exactly resemble credentials can still be rejected.

## Write boundaries and failure behavior

Checks cover proposal subjects, bodies, evidence, source locators, delivery keys,
disclosure/providers and declared metadata; remembered/corrected assertions and
evidence; inherited subjects and older proposals when accepted; feedback reasons,
labels and source providers; and bootstrap project names, path hints and providers.
Bootstrap validates before creating vault files. Admission is checked again at the
accepted-content write boundary, including an approved preview created under an
older policy. Denial rolls back the operation and leaves the approval challenge
unconsumed. Existing capability and OS-approval requirements are unchanged.

A denial returns the bounded `secret_rejected` error with no input excerpt,
matched value, field name or detector name. Denials do not create audit events or
content rows; successful events retain the existing content-free audit format.
Ordinary due-retention maintenance can still occur before request validation.
Unknown-field errors omit caller-supplied field names. CLI, daemon and MCP startup
argument errors omit offending argument values, and filesystem errors at these
entrypoints omit paths and tracebacks. Credential-shaped JSON request IDs
are invalid (using the default detectors, without policy exceptions), so error and
result correlation cannot reflect a recognized credential. Ordinary bounded IDs
and `--help`/`--version` behavior are preserved.

These checks are not retroactive deletion or read redaction. Existing admitted
content, owner-approved benign exceptions, ordinary reads and deliberate control
previews can contain matching text. Reject/forget remain available for legacy
material, with the existing exact owner approval; such cleanup previews may show
already stored content. Admission diagnostics are distinct from those deliberate
read/review outputs. Shell history, caller logging and privileged helper diagnostic
behavior are outside this application slice.

## Owner policy and false-positive handling

The vault owner may create `admission-policy.json` inside the private vault
directory. It must be a single, owner-only regular file owned by the current user;
symlinks, hardlinks, devices, FIFOs and permissive modes are rejected. The file is
read once when a kernel/daemon starts, as an immutable snapshot. Restart the daemon
after changing it. Missing configuration uses defaults; malformed, ambiguous,
unsafe or oversized configuration fails closed with `admission_policy_invalid`.

```json
{
  "version": 1,
  "deny_literals": ["SYNTHETIC-PROHIBITED-CONTENT"],
  "allow_sha256": []
}
```

Only these three keys are allowed. Each list has at most 32 unique entries. Deny
literals are case-sensitive UTF-8 substrings of 4–128 bytes; they can enforce a
small local prohibition on known content. A policy file is at most 16 KiB. There
are no wildcards, operator regexes or global detector-disable switches.

For a confirmed **benign lookalike**, an owner may add its exact whole-field
SHA-256 hex digest to `allow_sha256`. Hash the UTF-8 bytes with no added newline,
case change, whitespace trim or Unicode normalization. A lowercase 64-character
hex digest exempts only that entire field from default and extra literal checks;
adding context or changing one byte removes the exception. The digest is an
operator declaration, not evidence that real credential material is safe. Prefer
replacing the example with a short placeholder. Never place raw credentials in
this policy file, and never derive an exception just because a model asks.

Policy applies per vault, including project bootstrap when configuration already
exists in an empty private directory. It has no MCP or administrative request
setter; `allow_secret`, policy paths and exemption fields in requests are rejected.
The owner configuration is trusted local launch/configuration state, not another
form of model authorization. As elsewhere in this prototype, a process already
able to edit same-user private files can change configuration; this does not claim
isolation from a malicious same-UID process.

## Limits and verification

Unknown credential formats, unlabelled random values, short passwords, deliberate
obfuscation/encoding, and secrets split across fields are not reliably detected.
General PII or semantic sensitivity is not inferred. Literal prohibitions can help
with known local restrictions but cannot cover every sensitive document. No
existing content is scanned or purged automatically.

Synthetic tests exercise each detector family and benign counterparts, persisted
metadata/delivery keys, remember/correct/feedback, older proposal acceptance,
policy tightening between preview and apply, exact-byte exceptions, invalid/unsafe
configuration, and preserved rejection/forget. They check database/FTS/WAL/audit
canaries and actual CLI/MCP/stdout/stderr errors. No real secrets are test inputs.
