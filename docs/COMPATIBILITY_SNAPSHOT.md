# Compatibility snapshot

Source integration updated 2026-09-29 against merged main `152450a`. Durable owner
receipt recovery, macOS SQLite-lock-preserving ACL checks, platform primitives and
packaging changes are combined with the held encrypted application/rotation candidate.
Only syntax/static inspection was performed for this refresh; native application CI
remains pending. See [the exact checkpoint and validation plan](ISSUE7_SOURCE_REFRESH.md). The earlier
`79b74d9ef177710e9bf1e0d4fe7bfd51a49befd4` checkpoint's 28 passing source tests and the
2026-09-03 plaintext baseline do not establish a pass for this integration.
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
post2 backend. Its native wheelhouse contains exactly that ABI wheel, setuptools 80.9.0
and wheel 0.45.1. PEP 517/SPDX build tools have a separate hash-locked wheelhouse.
Reproducible sdist/wheel creation and external native-dependency SBOM links are implemented;
combined execution, license acceptance, signing and publication remain pending.
The application refuses a missing or mismatched SQLCipher backend and plaintext
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
| macOS peer/APFS boundary | Source-only peer workflow integration is pending; prepared encrypted application/APFS tests are not a macOS application pass |
| Windows | Encrypted runtime explicitly refused before keys or database access. Main's separately accepted plaintext runtime and closed issue #1 do not establish encrypted support; the imported Windows runtime/account workflows are disabled in this candidate. |

The refreshed Linux skip policy requires exactly 91 named platform-only methods
(62 Windows and 29 macOS), enumerated statically with exact reasons
and no encryption/cryptographic skips. The privileged Linux helper stager still rejects
all runtime dependencies; the encrypted application wheel must fail that separate
compatibility gate. See [verification](VERIFICATION.md) and [release gates](LINUX_RELEASE.md).
