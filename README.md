# Continuum Memory

> Your agents change. Your project memory doesn’t.

[![verify](https://github.com/Oussamoux1234/continuum-memory/actions/workflows/verify.yml/badge.svg)](https://github.com/Oussamoux1234/continuum-memory/actions/workflows/verify.yml)

**Maturity: experimental local prototype.** Continuum Memory is not production-ready,
encrypted, hardened against same-user malware, or validated with native Codex, Claude
Code, or Antigravity installations. It is a narrow, offline, Linux-first vertical slice
that demonstrates the ledger and trust-boundary design with deterministic MCP fixtures.

Continuum Memory is a provider-neutral, user-owned ledger of evidence and versioned
claims for AI coding agents. Accepted assertions, provenance, temporal validity,
conflicts, corrections, and deletion receipts are canonical. Search results and context
capsules are disposable views. Returned memory always has `authority=data`; it can
inform an answer but never authorize a command, URL, recipient, credential, permission
change, destructive operation, publication, or external message.

This is a standalone product. Agent Relay is not a dependency and will only become an
optional MCP client under the contract in `docs/AGENT_RELAY_INTEGRATION.md`.

## What this prototype proves

- a single local daemon is the post-bootstrap SQLite writer;
- users can accept exact, previewed claims using a one-shot terminal grant;
- agents can search, read, propose, send feedback, and inspect status, but cannot accept,
  correct, forget, export, or change policy through MCP;
- immutable correction history and explicit open conflicts are returned honestly;
- retention deadlines are strict UTC values and due assertions receive an audited,
  monotonic `expired` transition before current reads;
- project and provider-disclosure filters are applied inside retrieval queries;
- forget removes canonical bodies, contentful feedback, FTS rows, and stale recall-result
  references in one transaction, leaving only a content-free receipt and audit event;
- vault files and the Unix socket reject symlinks, hardlinks, foreign ownership, and
  group/world-accessible modes at the access boundary;
- two deterministic stdio MCP clients can share approved project memory.

## Five-minute safe quickstart

Requires Python 3.9+ with SQLite 3.37+ and FTS5. No package download or network service is used.
Use a temporary directory while evaluating the prototype:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --no-deps -e .
export CONTINUUM_HOME="$(mktemp -d)"
continuum init --project-name demo --project-path "$PWD" --providers codex,claude
memoryd --data-dir "$CONTINUUM_HOME"
```

In another terminal, using the project ID printed by `init`:

```bash
export CONTINUUM_HOME=/path/printed/above
continuum remember --project PROJECT_ID --subject database \
  --claim "This project uses SQLite because the local slice must stay offline." \
  --evidence "Milestone 1 build decision"
continuum search --project PROJECT_ID --query SQLite
continuum context --project PROJECT_ID --query database
continuum status --project PROJECT_ID
continuum audit verify
```

Administrative commands require an interactive TTY confirmation over the exact preview.
There is deliberately no `--yes` bypass. This is a truthful prototype boundary: the
terminal broker does **not** resist a shell-capable same-UID agent. See
`docs/architecture/006-approval-boundary.md`.

To run the verified fixture demo and complete local test suite:

```bash
python3 scripts/verify.py
```

The demo prints an ephemeral directory, assertion/version IDs, provenance, correction
history, conflict output, deletion receipt, replay rejection, and isolation checks.

Native agent installers and plugins are roadmap work. Nothing here mutates real Codex,
Claude Code, Antigravity, or Agent Relay profiles.

For a generic MCP client, launch the bridge with a capability file printed by `init`:

```bash
continuum-mcp --data-dir "$CONTINUUM_HOME" \
  --capability-file "$CONTINUUM_HOME/capabilities/PROJECT_ID.codex.cap"
```

Project and provider identity come from that owner-only capability file, never model tool
arguments. The checked-in clients under `fixtures/` are conformance fixtures, not proof of
native Codex or Claude Code compatibility.

## Storage notice

The prototype database is **not encrypted**. Python's bundled SQLite has FTS5 but no
reproducible SQLCipher binding in this dependency-free slice. File permissions, strict
date parsing, lifecycle expiry, and deletion semantics are tested, but plaintext can remain
in filesystem or OS snapshots. The owner-only directory blocks other local accounts; it
does not resist a malicious process already running as the same user. Do not store secrets
or sensitive production data. The storage interface is isolated so a reviewed SQLCipher
implementation can replace it later.

## Repository map

- `docs/PRODUCT_CONSTITUTION.md` — durable product rules.
- `docs/architecture/` — accepted architecture decisions.
- `BUILD_BRIEF_M1.md` — executable slice and acceptance contract.
- `src/continuum_memory/` — daemon, ledger, CLI, MCP bridge, and policy.
- `schemas/` — protocol and canonical schema contracts.
- `fixtures/` — deterministic provider-neutral clients and demo.
- `tests/` — lifecycle, retention, date, filesystem, isolation, MCP, deletion, and audit tests.

Licensed under Apache-2.0.

Upstream: `github.com/Oussamoux1234/continuum-memory`.
