# Compatibility snapshot

Application baseline recorded 2026-09-03; native supply-chain state updated 2026-09-07.
The application runtime makes no network requests. The patched-wheel workflow permits network
access only in its pinned source-acquisition container and disables it for build and test.

| Component | Design source | Prototype use |
|---|---|---|
| MCP | https://modelcontextprotocol.io/specification/2026-07-28 and official 2026-07-28 release notes | Stateless per-request metadata, `server/discover`, tools; legacy fixture initialization retained |
| SQLite FTS5 | https://www.sqlite.org/fts5.html | Unicode61 FTS virtual table and `bm25()` |
| SQLite defensive posture | https://www.sqlite.org/security.html and https://www.sqlite.org/pragma.html | foreign keys, `trusted_schema=OFF`, integrity check, no extension loading |
| Patched SQLCipher test artifact | Signed SQLCipher 4.18.0 source with SQLite 3.53.4 and OpenSSL 3.5.8 LTS | Separate Linux native supply-chain gate; not selected by the application runtime |
| W3C provenance | https://www.w3.org/TR/prov-o/ | compact author/recorder/authorizer/validator roles only; no conformance claim |

Current local evidence at bootstrap: Python 3.9.6, SQLite CLI 3.51.0 with FTS5, no Rust
toolchain. Native Codex, Claude Code, and Antigravity versions/configurations were not
probed or modified.

## Platform evidence

| Platform | Status |
|---|---|
| macOS 26.5.2 arm64, Python 3.9.6 | Full local verifier passed; development evidence, not a packaged support promise |
| GitHub-hosted Ubuntu 24.04 x86-64, Python 3.9 | Full application verifier is required by GitHub Actions |
| manylinux_2_28 x86-64, CPython 3.11-3.14 | Hardened reproducible-wheel workflow; ephemeral test artifacts only, not application integration or a support promise |
| macOS arm64, CPython 3.11-3.14 native wheel | Blocked: no approved immutable macOS builder/toolchain currently satisfies the Linux evidence standard |
| Windows | Unsupported: POSIX IPC and filesystem security assumptions require a separate design; tracked in issue #1 |
