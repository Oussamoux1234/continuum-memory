# ADR 006: Exact-preview, one-shot grants behind a broker interface

Status: accepted as prototype boundary.

## Decision

Administrative mutations use a two-step protocol. The daemon generates a canonical preview,
digest, nonce, operation, and short expiry. The terminal broker renders exact claim,
evidence, project scope, disclosure, retention, and effects; it requires a TTY confirmation
matching the digest prefix. It returns an HMAC grant bound to every preview byte. The daemon
consumes a stored nonce once, verifies expiry/digest/operation, and rejects replay.

MCP capability files cannot call preview or administrative methods. No MCP tool exists for
accept, correct, forget, export, project/policy/key/integration administration, or external
action. Forged proposal fields cannot become accepted state.

## Limitation and replacement

The control HMAC key is an owner-only file. A shell-capable same-UID agent that can read it,
allocate a PTY, automate input, debug the daemon, or control the UI can cross this boundary.
Therefore this proves API separation and replay resistance, not human presence. The broker
interface must be replaced by a Linux polkit/key-backed signer before trustworthy local v1;
the authority key must be unavailable to agent-facing processes.
