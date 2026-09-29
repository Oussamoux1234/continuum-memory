# Compatibility snapshot

Recorded 2026-09-03 for design; runtime and builds make no network requests.

| Component | Design source | Prototype use |
|---|---|---|
| MCP | https://modelcontextprotocol.io/specification/2026-07-28 and official 2026-07-28 release notes | Stateless per-request metadata, `server/discover`, tools; legacy fixture initialization retained |
| SQLite FTS5 | https://www.sqlite.org/fts5.html | Unicode61 FTS virtual table and `bm25()` |
| SQLite defensive posture | https://www.sqlite.org/security.html and https://www.sqlite.org/pragma.html | foreign keys, `trusted_schema=OFF`, integrity check, no extension loading |
| W3C provenance | https://www.w3.org/TR/prov-o/ | compact author/recorder/authorizer/validator roles only; no conformance claim |

Current local evidence at bootstrap: Python 3.9.6, SQLite CLI 3.51.0 with FTS5, no Rust
toolchain. Native Codex, Claude Code, and Antigravity versions/configurations were not
probed or modified. URL content is not fetched during build or runtime.

## Platform evidence

| Platform | Status |
|---|---|
| macOS 26.5.2 arm64, Python 3.9.6 | Full local verifier passed; development evidence, not a packaged support promise |
| GitHub-hosted Ubuntu 24.04 x86-64, Python 3.9 | Full verifier passed in Actions run 33742253644 |
| Windows | [Native plaintext runtime candidate](WINDOWS_BOUNDARY.md): filesystem/SQLite guards and bounded named-pipe client/daemon are integrated; exact-head full native CI and security acceptance remain pending in issue #1. No production Windows approval or encryption claim. |

The Windows candidate's full matrix is GitHub-hosted Windows Server 2025 x64 with
CPython 3.11–3.14; each job records its exact runner image, Python and bundled
SQLite versions. The separate real different-account gate runs CPython 3.14.
These are mutable hosted images, not immutable Windows builds or Windows 10/11
desktop evidence. Follow [the native verification contract](WINDOWS_VERIFICATION.md)
and inspect the exact integrated-head results; older passing runs do not validate
new changes. This remains a plaintext prototype with production approval refused.
