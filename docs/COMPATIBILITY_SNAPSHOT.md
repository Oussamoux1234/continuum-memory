# Compatibility snapshot

Historical plaintext application baseline recorded 2026-09-03; native supply-chain and
held application state updated 2026-09-23. The current application checkpoint is
`79b74d9ef177710e9bf1e0d4fe7bfd51a49befd4`: 28 source tests passed locally, while initial
native application CI is pending. Earlier prototype/native results do not establish a pass
for this application candidate.
The application runtime makes no network requests. The patched-wheel workflow permits network
access only in its pinned source-acquisition container and disables it for build and test.

| Component | Design source | Use and evidence scope |
|---|---|---|
| MCP | https://modelcontextprotocol.io/specification/2026-07-28 and official 2026-07-28 release notes | Stateless per-request metadata, `server/discover`, tools; legacy fixture initialization retained |
| SQLite FTS5 | https://www.sqlite.org/fts5.html | Unicode61 FTS virtual table and `bm25()` |
| SQLite defensive posture | https://www.sqlite.org/security.html and https://www.sqlite.org/pragma.html | foreign keys, `trusted_schema=OFF`, integrity check, no extension loading |
| Patched SQLCipher test artifact | Signed SQLCipher 4.19.0 source with SQLite 3.53.4 and OpenSSL 3.5.8 LTS | Strict `continuum-sqlcipher3` 0.6.2.post2 backend required by the held application candidate; native artifact evidence passed separately, application execution pending |
| W3C provenance | https://www.w3.org/TR/prov-o/ | compact author/recorder/authorizer/validator roles only; no conformance claim |

Historical local evidence at prototype bootstrap: Python 3.9.6, SQLite CLI 3.51.0 with FTS5,
no Rust toolchain. This is not the current encrypted application's runtime contract. Native
Codex, Claude Code, and Antigravity versions/configurations were not probed or modified.

The held application test slice is Linux x86-64 with CPython 3.11-3.14 and the exact pinned
native/build wheels. It refuses a missing or mismatched SQLCipher backend and plaintext
databases; there is no standard-library SQLite fallback. See
[SQLCIPHER_STORAGE.md](SQLCIPHER_STORAGE.md) and [VERIFICATION.md](VERIFICATION.md).

## Platform evidence

| Platform | Status |
|---|---|
| macOS 26.5.2 arm64, Python 3.9.6 | Historical plaintext verifier passed; no current encrypted application support claim |
| GitHub-hosted Ubuntu 24.04 x86-64, Python 3.9 | Historical plaintext verification only; no current Python 3.9 application support |
| GitHub-hosted Ubuntu 24.04 x86-64, Python 3.11 | Ordinary `verify` workflow checks source/supply-chain consistency; full application execution belongs to the four-ABI encrypted workflow |
| manylinux_2_28 x86-64, CPython 3.11-3.14 | Strict native artifact gate passed for `2e90daa`; separate held application workflow repeats the native gates and runs full offline application tests, with initial application CI pending |
| macOS arm64, CPython 3.11-3.14 native wheel | Blocked: no approved immutable macOS builder/toolchain currently satisfies the Linux evidence standard |
| Windows | Unsupported: POSIX IPC and filesystem security assumptions require a separate design; tracked in issue #1 |
