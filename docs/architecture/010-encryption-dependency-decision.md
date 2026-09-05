# ADR 010: encrypted-storage dependency replacement

Status: **blocked pending supply-chain ownership decision**

Evidence date: 2026-09-05

## Context

Issue #7 currently evaluates `sqlcipher3==0.6.2`. Its published wheels embed SQLCipher
4.12.0, SQLite 3.51.1, and OpenSSL 3.6.0. OpenSSL 3.6.0 has vendor-confirmed findings and
SQLite 3.51.1 predates the 3.53.2 fixes for CVE-2026-11822 and CVE-2026-11824. The candidate
therefore remains blocked regardless of passing functional tests.

The minimum acceptable embedded versions established from upstream security records are:

- SQLCipher 4.17.0 or later, because 4.17.0 moved its SQLite base beyond the two recorded
  SQLite fixes;
- SQLite 3.53.2 or later;
- OpenSSL 3.6.4 or later when remaining on the 3.6 series.

For a project-owned rebuild, SQLCipher 4.18.0 with SQLite 3.53.4 and OpenSSL 3.5.8 LTS is
the preferred reviewed starting point. OpenSSL 3.5.8 receives upstream support through
2030, whereas the 3.6 series reaches end of life in 2026. These versions are a floor for a
future build review, not approval of an artifact that does not yet exist.

## Evidence

- `sqlcipher3` 0.6.2 remains the latest PyPI release. Its eight relevant wheels embed the
  vulnerable component set above. Upstream `master` at
  `dfee7e5fe6a1422d9e5e23edc0727a2e1e2128ed` changes documentation and removes the
  prior `license = "MIT"` declaration, but does not update the binding, vendored
  amalgamation, or `openssl/3.6.0` Conan requirement.
- SQLCipher 4.18.0 is commit
  `63697beb0fafcb61faa7a3e6fd267036548ab11b` and embeds SQLite 3.53.4. The official source
  archive inspected for this review has SHA-256
  `20518a87ca38dc6565c3cb0d8a243d2abd3bd16c0f9a9a9e6bfdf2a487d01c90`. It is source-only
  and does not provide a Python wheel or generated `sqlite3.c` amalgamation.
- The official OpenSSL 3.5.8 source archive has SHA-256
  `a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2`; OpenSSL 3.6.4 has
  SHA-256 `9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef`.
- A local, non-publishing SQLCipher 4.18.0 source probe on macOS 26.5.2 used the exact tag,
  Clang 21, Make 3.81, Tcl 8.5.9, and the locally available OpenSSL 3.6.3. `configure`
  stopped with `Error: couldn't create error file for command: not owner`, so neither
  `make verify-source` nor amalgamation generation completed. GPG was unavailable, so the
  detached upstream signature was not claimed as verified. This probe is negative build
  evidence, not proof that a reviewed build is impossible on a controlled builder.
- Exact-commit OSV queries and public GitHub advisory endpoints returned no entries for
  SQLCipher 4.18.0 and the current `sqlcipher3` master commit. This is only a no-known-
  finding result in the queried sources on the evidence date, not proof of safety.

Authoritative sources:

- <https://pypi.org/project/sqlcipher3/>
- <https://github.com/coleifer/sqlcipher3/compare/0.6.2...master>
- <https://github.com/sqlcipher/sqlcipher/releases/tag/v4.18.0>
- <https://www.zetetic.net/blog/2026/08/18/sqlcipher-4.18.0-release/>
- <https://www.zetetic.net/sqlcipher/verify/>
- <https://www.sqlite.org/cves.html>
- <https://openssl-library.org/source/>
- <https://openssl-library.org/news/vulnerabilities-3.6/>

## Alternatives evaluated

| Path | Security and reproducibility | Platform and maintenance | Decision |
| --- | --- | --- | --- |
| Newer published `sqlcipher3` wheel | No release newer than 0.6.2 exists; no patched artifact to hash or inspect | Existing 3.11-3.14 macOS arm64/Linux x86-64 matrix only | Unavailable |
| Build unmodified `sqlcipher3` source | Still pins OpenSSL 3.6.0; Conan resolves and builds dependencies dynamically | Toolchain and transitive inputs are not fully pinned | Rejected |
| Project-owned `sqlcipher3` fork and wheels | Can select the preferred component set, but requires signed-source verification, pinned builders, two-build comparison, native inspection, and artifact signing | Makes Continuum the maintainer and distributor of native wheels | Requires explicit ownership decision |
| Zetetic commercial package | No compatible Python DB-API wheel; the reviewed 4.18.0 non-Apple package records OpenSSL 3.5.7, below the 2026-08-25 patch level | Requires a commercial license and a new integration path | Rejected for this change |
| APSW with custom SQLCipher | Upstream PyPI wheels contain plain SQLite; SQLCipher still requires a custom native build | API migration is architectural work and expands regression scope | Rejected for this change |
| `pysqlcipher3`, `sqlcipher3-binary`, or system SQLCipher | Older, narrower, or dynamically selected native dependencies do not provide the required reviewed artifact | Does not meet the maintained matrix or deterministic offline-install boundary | Rejected |

## Decision

The decision is that no replacement is selected and no lock file, package metadata, SPDX
component, license conclusion, or runtime claim is changed. Packaged runtime continues to
identify the existing
candidate exactly and the release gate continues to fail closed with status
`BLOCKED_NO_INSTALLABLE_ARTIFACT`.

The lowest-risk next path is to consume an upstream-published, hashable wheel only after it
contains at least the minimum patched versions and passes the existing native, license,
offline-install, and platform-matrix review. If schedule requires a project-owned build, the
smallest required decision is explicit authorization for Continuum Memory to own and maintain
a native binding fork and wheel supply chain, including the supported ABI/platform matrix,
artifact distribution location, signing identity, trust policy, and revocation procedure.
No such authority is inferred by this ADR.

## Consequences

- PR #12 and Issue #7 remain open and must not be merged or closed on this evidence.
- The passing encrypted-storage tests remain implementation evidence only; sensitive or
  production data stays out of scope.
- A future replacement PR must update hashes, licenses/notices, SPDX, native markers, audit
  evidence, and offline payload tests together. It must also verify upstream signatures and
  produce reproducible native artifacts on controlled builders before publication.
