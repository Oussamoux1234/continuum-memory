# ADR 006: Exact-preview, one-shot grants behind a broker interface

Status: accepted; terminal prototype retained for unprovisioned vaults and Linux polkit
implementation pending real-host evidence.

## Decision

Administrative mutations use a two-step protocol. The daemon generates a canonical preview,
digest, nonce, operation, and short expiry. The terminal broker renders exact claim,
evidence, project scope, disclosure, retention, and effects; it requires a TTY confirmation
matching the digest prefix. It returns an HMAC grant bound to every preview byte. The daemon
consumes a stored nonce once, verifies expiry/digest/operation, and rejects replay.

MCP capability files cannot call preview or administrative methods. No MCP tool exists for
accept, correct, forget, export, project/policy/key/integration administration, or external
action. Forged proposal fields cannot become accepted state.

On a provisioned Linux account, the broker sends the exact bounded challenge over standard
input to a fixed root-owned helper through `pkexec`. The helper revalidates the preview
digest, operation, nonce, vault, OS user, and short expiry; polkit requires uncached
administrator authentication, then the helper renders the preview on `/dev/tty` and
requires its digest prefix. It signs a canonical payload with a root-only per-user RSA key.
The daemon reads only the root-owned public key and rejects legacy HMAC grants while that
key exists.

The system key path is selected by daemon/vault owner UID, not by user-writable database
metadata. The signed payload still includes the vault ID, preventing cross-vault replay.
Preview and key material never appear in broker process arguments or environment variables.

## Limitation and replacement

The terminal fallback still uses the owner-only control capability as its HMAC key. A
shell-capable same-UID agent can cross that fallback boundary. Provisioning the Linux key
prevents capability possession from minting grants, but it does not encrypt the database,
prevent direct same-UID mutation of user-owned files, stop daemon replacement, or create a
trusted display path independent of the local desktop. A controlled real-polkit smoke test
and independent review remain required before trustworthy local v1.
