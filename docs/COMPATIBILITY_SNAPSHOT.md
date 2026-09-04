# Compatibility snapshot

Recorded 2026-09-04 for design; runtime and builds make no network requests.

| Component | Design source | Prototype use |
|---|---|---|
| MCP | https://modelcontextprotocol.io/specification/2026-07-28 and official 2026-07-28 release notes | Stateless per-request metadata, `server/discover`, tools; legacy fixture initialization retained |
| SQLite FTS5 | https://www.sqlite.org/fts5.html | Unicode61 FTS virtual table and `bm25()` |
| SQLite defensive posture | https://www.sqlite.org/security.html and https://www.sqlite.org/pragma.html | foreign keys, `trusted_schema=OFF`, integrity check, no extension loading |
| SQLCipher | https://www.zetetic.net/sqlcipher/sqlcipher-api/ | Issue #7 candidate pins `sqlcipher3` 0.6.2 / SQLCipher 4.12.0, raw 32-byte key, encrypted WAL, integrity check, eight-wheel component/license inventory and interim SPDX record; independent security and license review pending |
| W3C provenance | https://www.w3.org/TR/prov-o/ | compact author/recorder/authorizer/validator roles only; no conformance claim |

Current local evidence at bootstrap: Python 3.14.6, SQLCipher 4.12.0 community over SQLite
3.51.1 with FTS5, no Rust toolchain. Native Codex, Claude Code, and Antigravity
versions/configurations were not probed or modified. Runtime operation makes no network
request; acquiring the hash-pinned SQLCipher wheel is a separate installation step.

## Platform evidence

| Platform | Status |
|---|---|
| macOS 26.5.2 arm64, Python 3.14.6 | Full local verifier passed; this is the only native macOS target in Issue #7 and remains development evidence, not a packaged support promise |
| GitHub-hosted Ubuntu 24.04 x86-64, Python 3.11–3.14 | Complete maintained-version matrix required by the verify workflow |
| Windows | Unsupported: POSIX IPC and filesystem security assumptions require a separate design; tracked in issue #1 |
