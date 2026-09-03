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
