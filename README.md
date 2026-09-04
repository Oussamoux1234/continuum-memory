# Continuum Memory

> Your agents change. Your project memory doesn’t.

[![verify](https://github.com/Oussamoux1234/continuum-memory/actions/workflows/verify.yml/badge.svg)](https://github.com/Oussamoux1234/continuum-memory/actions/workflows/verify.yml)

**Maturity: experimental local prototype.** Continuum Memory is not production-ready,
independently security-reviewed, hardened against same-user malware, or validated with
native Codex, Claude Code, or Antigravity installations. It is a narrow, offline,
Linux-first vertical slice
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
- users can accept exact, previewed claims using a one-shot approval grant;
- provisioned Linux users approve through a polkit-authorized, root-keyed proof that the
  user daemon verifies using only a public key;
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

## Five-minute reproducible quickstart

Requires CPython 3.11–3.14 and the pinned `sqlcipher3==0.6.2` runtime. Linux x86-64 runs
the complete gate on every declared Python version. The native macOS evidence is limited
to arm64 with Python 3.14; no broader macOS support is claimed. Artifact acquisition uses
the package index, but installation and runtime operation use no network service. Use a
temporary directory while evaluating the prototype:

```bash
python3.14 -m venv .venv
.venv/bin/python -m pip download --require-hashes --only-binary=:all: --no-deps \
  --dest work/dependencies -r requirements/sqlcipher-maintained.txt
.venv/bin/python -m pip download --require-hashes --only-binary=:all: --no-deps \
  --dest work/build-dependencies -r requirements/verification-tools.txt
.venv/bin/python -m pip install --no-index --no-deps --find-links work/build-dependencies \
  setuptools==80.9.0
.venv/bin/python -m pip install --no-index --no-deps --find-links work/dependencies \
  sqlcipher3==0.6.2
.venv/bin/python -m pip install --no-build-isolation --no-index --no-deps -e .
source .venv/bin/activate
export CONTINUUM_HOME="$(mktemp -d)"
continuum init --project-name demo --project-path "$PWD" --providers codex,claude
memoryd --data-dir "$CONTINUUM_HOME"
```

On a verified Linux target, select any Python from 3.11 through 3.14 for the virtual
environment. A plain `pip install -e .` is only an unverified developer convenience because
it may resolve artifacts without the repository's reviewed hashes.

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

Administrative commands require an interactive OS-backed confirmation over the exact
preview. There is deliberately no `--yes` bypass, and live use fails closed when no native
broker is provisioned. Linux users can install and provision the broker described in
`docs/LINUX_APPROVAL_BROKER.md`. The old same-UID terminal/HMAC seam is injectable only by
the temporary test harness; the packaged daemon and CLI never select it.

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

The Issue #7 implementation candidate routes the canonical database, WAL, and FTS pages
through SQLCipher 4.12.0 using the pinned `sqlcipher3` 0.6.2 binding. The verifier checks
plaintext canaries, correct/wrong/missing key behavior, crash recovery, runtime identity,
and an offline wheel installation. This is not yet an accepted encryption guarantee;
Issue #7 remains open for independent review, and sensitive production data remains out of
scope.

The exact reviewed wheel hashes, compiled and linked component inventory, upstream license
texts, redistribution boundary, and unresolved `sqlcipher3` metadata/license discrepancy
are recorded in `THIRD_PARTY_NOTICES.md`. An interim SPDX 2.3 JSON inventory is shipped at
`sbom/continuum-memory.spdx.json`. The verifier requires both records and all copied license
texts in the source distribution and project wheel; this is engineering evidence, not a
legal-compliance or independent-review claim.
The point-in-time vulnerability findings, external SPDX validation, reproducible-build
limits, payload inspection, signing blocker, and blocked release decision are recorded in
`docs/RELEASE_READINESS.md` and `security/dependency-audit.json`.

This is not a complete confidentiality claim. The random storage key is an owner-only file
beside the vault, so copying the entire vault directory also copies the key. The boundary
does not resist the owning user, root/admin, malware in that account, process inspection,
OS snapshots, exports, or unmanaged backups. Existing plaintext vaults are rejected and
are not migrated automatically. Key rotation and explicit plaintext migration are not yet
implemented. See `docs/SQLCIPHER_STORAGE.md`.

## Repository map

- `docs/PRODUCT_CONSTITUTION.md` — durable product rules.
- `docs/architecture/` — accepted architecture decisions.
- `docs/LINUX_APPROVAL_BROKER.md` — Linux polkit installation, boundary, smoke test, and removal.
- `docs/SQLCIPHER_STORAGE.md` — encrypted-storage runtime, key lifecycle, verification, and limits.
- `docs/RELEASE_READINESS.md` — dependency, SPDX, reproducibility, payload, and signing evidence.
- `THIRD_PARTY_NOTICES.md` — reviewed SQLCipher wheel contents, licenses, and redistribution boundary.
- `security/dependency-audit.json` — point-in-time exact-component vulnerability findings.
- `sbom/continuum-memory.spdx.json` — interim SPDX 2.3 dependency and artifact inventory.
- `BUILD_BRIEF_M1.md` — executable slice and acceptance contract.
- `src/continuum_memory/` — daemon, ledger, CLI, MCP bridge, and policy.
- `schemas/` — protocol and canonical schema contracts.
- `fixtures/` — deterministic provider-neutral clients and demo.
- `tests/` — lifecycle, retention, date, filesystem, isolation, MCP, deletion, and audit tests.

Licensed under Apache-2.0.

Upstream: `github.com/Oussamoux1234/continuum-memory`.
