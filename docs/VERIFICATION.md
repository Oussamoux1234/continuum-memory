# Verification gates and evidence

## Run the supported gate

Prepare the pinned toolchain/wheelhouse as described in
[Linux distribution verification](LINUX_RELEASE.md), then run:

```bash
.venv/bin/python scripts/verify.py
```

The command parses the project's JSON schemas, checks whitespace, compiles Python modules,
runs all unit/integration tests with resource warnings promoted to errors, executes the
17-check two-client lifecycle demo, verifies the source/wheel distributions below, and
runs `git diff --check`. The current test count is printed by the run; do not interpret an
old count as evidence for a newer revision.

The [verify workflow](https://github.com/Oussamoux1234/continuum-memory/actions/workflows/verify.yml)
runs the same gate on Ubuntu 24.04 x86-64 with Python 3.11, 3.12, 3.13, and 3.14. Its
networked preparation obtains hash-pinned verification dependencies first. The actual
build/install verifier uses offline dependency resolution and emits host/tool versions.
Every matrix job must pass for the exact candidate revision before a release decision.

## What the gate exercises

- Ledger proposal, review, correction/history, recorded-time queries, conflicts, retention,
  project/provider isolation, forget cleanup, and content-free audit integrity.
- MCP fixture discovery/validation, transport and response limits, context honesty, and
  explicit test-only approval seams. Fixtures are not real client compatibility claims.
- Filesystem owner/mode/type/link checks, transactional commit-result recovery, secret
  admission, schema migration regressions, daemon lifetime locks and stale-socket guards.
- Deterministic Linux broker/signature tests without invoking interactive polkit.
- PEP 517 source and wheel builds twice in independent clean trees, byte-for-byte digest
  comparison, wheel construction from the source archive, metadata and required-file checks.
- Each artifact installed in its own clean offline environment; all four entry points
  executed outside the source checkout, without source imports through `PYTHONPATH`.
- Full payload/file SPDX 2.3 inventory reconciled against the archives and validated by
  independent SPDX tools. Mutated/missing files, false hashes and changed license
  conclusions are rejected. This is not a host/toolchain SBOM or legal certification.
- Explicit reviewed-wheel staging for the privileged Linux installer, without actually
  running that installer or altering system paths during the verifier.

## Reading a result honestly

The current application remains an **experimental plaintext local prototype**. A green
gate is not evidence of real OS user presence, encrypted pages/WAL/FTS, encrypted backups,
deletion across restored backups, universal DLP, Windows runtime support, macOS OS-backed
approval, native Codex/Claude/Antigravity profiles, same-UID malware resistance, physical
erasure, independent trusted builders, signed provenance, or production readiness.

Issue #3 still requires an owner-controlled interactive Linux polkit smoke test. Encryption
and platform acceptance remain tracked separately. No real vault/profile is touched by
the fixture suite. Distribution artifacts are unsigned and unpublished; artifact retention
in CI for review is not a release.

For a durable acceptance record, save the exact commit, clean/dirty state, command, host
and SQLite versions, full test/demo result, artifact SHA-256s, and CI run links. The
`build-evidence.json` records packaging evidence but is explicitly unsigned. A changed
revision or dependency set needs a fresh run. See [release verification](LINUX_RELEASE.md)
for reproducibility limits, signing/provenance policy, and the publication hold.

## Historical evidence

The initial 2026-09-03 slice passed 46 tests and the lifecycle demo on the macOS build host
and the original Ubuntu/Python 3.9 CI job. That was source-archive-only evidence and did
not establish the newer packaging gate or any of the security/platform claims above.
