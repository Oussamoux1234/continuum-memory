# Continuum Memory

> Your agents change. Your project memory doesn’t.

[![verify](https://github.com/Oussamoux1234/continuum-memory/actions/workflows/verify.yml/badge.svg)](https://github.com/Oussamoux1234/continuum-memory/actions/workflows/verify.yml)

**Maturity: experimental local prototype.** Continuum Memory is not production-ready,
release-approved for encrypted storage, hardened against same-user malware, or validated with native Codex, Claude
Code, or Antigravity installations. It is a narrow, offline, Linux-first vertical slice
that demonstrates the ledger and trust-boundary design with deterministic MCP fixtures.

Continuum Memory is a provider-neutral, user-owned ledger of evidence and versioned
claims for AI coding agents. Accepted assertions, provenance, temporal validity,
conflicts, corrections, and deletion receipts are canonical. Search results and context
capsules are disposable views. Returned memory always has `authority=data`; it can
inform an answer but never authorize a command, URL, recipient, credential, permission
change, destructive operation, publication, or external message.

Context response v3 uses `accepted_claims`, not `verified_current`: user acceptance,
recorded verification, and declared date applicability are separate. Existing clients
must update their JSON field access. See the [read contract and upgrade guide](docs/CONTEXT_CONTRACT.md).

Owner operations retain content-free committed-result receipts. After exact human
approval and before sending the action, the CLI privately journals an opaque
recovery locator, so a fresh `continuum recover` process can query the original
outcome after the CLI exits. It never repeats the action; a missing receipt remains
unknown, not permission to retry. See the [recovery commands, pagination and
prototype boundaries](docs/COMMIT_RECOVERY.md).

This is a standalone product. Agent Relay is not a dependency and will only become an
optional MCP client under the contract in `docs/AGENT_RELAY_INTEGRATION.md`.

## What this prototype proves

- a single local daemon is the post-bootstrap SQLite writer;
- persistent OS-held daemon ownership and guarded crash restart; see
  [daemon recovery and offline upgrade](docs/DAEMON_RECOVERY.md);
- users can accept exact, previewed claims using a one-shot approval grant;
- provisioned Linux users approve through a polkit-authorized, root-keyed proof that the
  user daemon verifies using only a public key;
- agents can search, read, propose, send feedback, and inspect status, but cannot accept,
  correct, forget, export, or change policy through MCP;
- immutable correction history and explicit open conflicts are returned honestly;
- bounded search/context/history continuations preserve a recorded snapshot while rechecking
  forget and disclosure on every page; see the [read contract](docs/CONTEXT_CONTRACT.md);
- retention deadlines are strict UTC values and due assertions receive an audited,
  monotonic `expired` transition before current reads;
- project and provider-disclosure filters are applied inside retrieval queries;
- forget removes canonical bodies, contentful feedback, FTS rows, and stale recall-result
  references in one transaction, leaving only a content-free receipt and audit event;
- vault files and the Unix socket reject symlinks, hardlinks, foreign ownership, and
  group/world-accessible modes at the access boundary;
- two deterministic stdio MCP clients can share approved project memory.

Context clients must now support `response_version: 3`: conflict fragments can be partial
or not fully assessed. Strict v2 consumers must upgrade with the service. Tiny budgets
that cannot fit a result return `budget_too_small`, not an empty continuation.

## Held Linux candidate evaluation

This held candidate requires Linux x86-64, CPython 3.11–3.14, and the exact
project-built `continuum-sqlcipher3` 0.6.2.post2 wheel. There is no published
package or stdlib SQLite fallback. Combined native application verification remains
pending. Complete the reviewed offline runtime setup in
[encrypted storage](docs/SQLCIPHER_STORAGE.md) and prepare the separate hash-locked
build tools in [distribution verification](docs/LINUX_RELEASE.md) before these
synthetic-only evaluation commands.
Use only a temporary directory while evaluating the candidate:

```bash
.venv/bin/python -m pip install --no-index --no-deps --no-build-isolation -e .
export PATH="$PWD/.venv/bin:$PATH"
export CONTINUUM_HOME="$(mktemp -d)"
continuum init --project-name demo --project-path "$PWD" --providers codex,claude
memoryd --data-dir "$CONTINUUM_HOME"
```

In another terminal, using the project ID printed by `init`:

```bash
export CONTINUUM_HOME=/path/printed/above
continuum search --project PROJECT_ID --query SQLite
continuum context --project PROJECT_ID --query database
continuum status --project PROJECT_ID
continuum audit verify
```

Administrative commands require an interactive OS-backed confirmation over the exact
preview. There is deliberately no `--yes` bypass, and live use fails closed when no native
broker is provisioned. The current privileged helper stager rejects all runtime
dependencies and must refuse the encrypted application wheel; installation compatibility
needs separate review before live owner writes. See
[the broker boundary](docs/LINUX_APPROVAL_BROKER.md). The old same-UID terminal/HMAC seam is injectable only by
the temporary test harness; the packaged daemon and CLI never select it.

The prepared fixture demo, application suite and reproducible PEP 517/SPDX gate use two
separate reviewed wheelhouses: exactly the selected native wheel plus setuptools/wheel,
and the full hash-locked build-tool set. In the prepared Linux environment, run:

```bash
CONTINUUM_SQLCIPHER_WHEELHOUSE=/absolute/reviewed/native-wheelhouse \
  CONTINUUM_BUILD_WHEELHOUSE=/absolute/reviewed/build-tool-wheelhouse \
  .venv/bin/python scripts/verify.py
```

The demo prints an ephemeral directory, assertion/version IDs, provenance, correction
history, conflict output, deletion receipt, replay rejection, and isolation checks.
This command is not a recorded native application pass. The proposed Linux allowance for
91 exact platform-only skip IDs/reasons (62 Windows and 29 macOS methods) is
source-enumerated in `tests/platform-skips-linux.json`; its refreshed native execution
remains unrun. Encryption, rotation and missing-backend skips are forbidden.

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

Provider names are labels, not permissions. `user_control` is reserved for the
unbound owner capability; custom providers cannot use it. Existing project-bound
capabilities with that label fail closed. Pending proposals with that reserved
source cannot be accepted, but the owner can still reject or forget them. This
hardening does not rewrite previously accepted history; inspect proposal-acceptance
provenance when reviewing older records, whose evidence/author labels may be wrong.

## Storage notice

This branch is a **held encrypted-storage candidate** for issue #7. New synthetic
vaults require the exact SQLCipher 4.19.0 / SQLite 3.53.4 runtime and a random
32-byte owner-only `storage.key`. Missing, malformed, wrong or unsupported keys,
runtimes and legacy plaintext vaults fail closed. The key is stored beside the
database: this does not protect against same-user malware or copying the complete
vault and key. Do not store production secrets.

The candidate preserves schema-5 migrations, secret admission, daemon locking,
operation receipts and audit recovery. Existing plaintext vaults are never
silently converted. See [storage and migration boundaries](docs/SQLCIPHER_STORAGE.md).
The native pipeline and all applicable application tests must pass independently. Main's
reproducible source/wheel/SPDX pipeline is retained with the exact external post2 dependency;
combined native application verification, human security/license acceptance, privileged
installer compatibility, and artifact signing/publication decisions remain open.
macOS is limited to planned source-only peer checks until an approved native artifact
exists; prepared APFS application tests remain pending. Neither macOS nor Windows encrypted
application support is established by Linux CI.

See [the source-refresh checkpoint](docs/ISSUE7_SOURCE_REFRESH.md) for the exact
152450a integration, static evidence, preserved holds and still-unrun validation plan.

## Repository map

- `docs/PRODUCT_CONSTITUTION.md` — durable product rules.
- `docs/architecture/` — accepted architecture decisions.
- `docs/LINUX_APPROVAL_BROKER.md` — Linux polkit boundary, blocked encrypted-installer compatibility, controlled smoke test, and removal.
- `docs/LINUX_RELEASE.md` — separate locked tool/native inputs, reproducible packaging, SPDX evidence, and release holds.
- `docs/PATCHED_SQLCIPHER_WHEELS.md` — native test-artifact supply chain and its blockers.
- `docs/MACOS_BOUNDARY.md` — source-only peer checks and pending native artifact, APFS, approval/key/ACL gates.
- `BUILD_BRIEF_M1.md` — executable slice and acceptance contract.
- `src/continuum_memory/` — daemon, ledger, CLI, MCP bridge, and policy.
- `schemas/` — protocol and canonical schema contracts.
- `fixtures/` — deterministic provider-neutral clients and demo.
- `tests/` — lifecycle, retention, date, filesystem, isolation, MCP, deletion, and audit tests.

Licensed under Apache-2.0.

Upstream: `github.com/Oussamoux1234/continuum-memory`.
