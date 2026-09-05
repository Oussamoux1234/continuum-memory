# Issue #7 release-readiness evidence

Status: **blocked; implementation candidate only**

Evidence date: 2026-09-05

Audience: the independent security/license mentor reviewing PR #12

This document records independently reproducible evidence for the exact SQLCipher candidate.
It is not a legal opinion, a vulnerability-free claim, a signature, or permission to merge or
release.

## Exact candidate scope

- Continuum Memory: `0.1.0.dev0` from PR #12.
- Binding: `sqlcipher3==0.6.2`, tag commit
  `14fc2632676b20011e0bba64fdda49763a2dd2ec`.
- SQLCipher Community Edition: `4.12.0`, tag commit
  `ab223bd801ec225d1497a077da08777d21d1266d`.
- SQLite: `3.51.1`, source ID
  `2025-11-28 17:28:25 281fc0e9afc38674b9b0991943b9e9d1e64c6cbdb133d35f6f5c87ff6af38a88`.
- OpenSSL: `3.6.0`, tag commit
  `7b371d80d959ec9ab4139d09d78e83c090de9779`, statically linked into every reviewed wheel.
- Reviewed artifacts: the eight macOS arm64 and manylinux x86-64 wheels listed in
  `THIRD_PARTY_NOTICES.md` and `sbom/continuum-memory.spdx.json`.

## Blocking findings

### Known vulnerable embedded versions

An OSV exact-commit query for OpenSSL 3.6.0 returned 48 findings. The corresponding OpenSSL
vendor CVE JSON records classify them as 2 High, 10 Moderate, and 36 Low. The complete ID set
is preserved in `security/dependency-audit.json`. OpenSSL's 3.6 vulnerability and release
records show that these findings were fixed across security patch releases 3.6.1 through
3.6.4.

SQLite's own CVE status page records CVE-2026-11822 and CVE-2026-11824 as FTS5 heap-write
issues fixed in 3.53.2. It states that exploitation requires arbitrary SQL, FTS5, and
`SQLITE_DBCONFIG_DEFENSIVE` disabled. Continuum enables FTS5 but does not expose arbitrary SQL
through its public interfaces. That reduces the known route but does not make SQLite 3.51.1 a
patched version or justify a safety claim.

The SQLCipher amalgamation calls OpenSSL's AES-256-CBC, digest, MAC, PBKDF, and random APIs; it
does not call the vulnerable CMS, PKCS7, PKCS12, TLS, QUIC, CMP, OCSP, AES-OCB, AES-CFB, or
one-shot `EVP_Cipher()` paths found in the reviewed advisories. However, symbol inspection
shows that the statically linked extension still exports broad libcrypto functionality,
including affected API families. This reachability review is context, not a waiver. A patched
upstream wheel or separately reviewed rebuild is required before release acceptance.

OSV exact-version/commit queries and the public GitHub advisory endpoints returned zero
entries for sqlcipher3 0.6.2 and SQLCipher 4.12.0 on 2026-09-04. That means only “no known
finding in the queried sources at that time”; it is not proof of safety.

Authoritative inputs:

- <https://openssl-library.org/news/vulnerabilities-3.6/>
- <https://openssl-library.org/news/secjson/>
- <https://www.sqlite.org/cves.html>
- <https://api.osv.dev/v1/query>
- <https://github.com/coleifer/sqlcipher3/tree/0.6.2>
- <https://github.com/sqlcipher/sqlcipher/tree/v4.12.0>

### Replacement investigation

The 2026-09-05 investigation established these minimum patched versions: SQLCipher 4.17.0,
SQLite 3.53.2, and OpenSSL 3.6.4 when using the 3.6 series. The preferred project-build
baseline is SQLCipher 4.18.0, which embeds SQLite 3.53.4, with OpenSSL 3.5.8 LTS. OpenSSL
3.5.8 has the longer upstream support window. These version floors do not identify an
installable artifact by themselves.

No patched published `sqlcipher3` wheel exists. The latest PyPI release remains 0.6.2.
Current upstream `master` removes the prior MIT declaration but retains version 0.6.2,
the same binding and SQLCipher amalgamation, and the `openssl/3.6.0` Conan requirement.
The source build dynamically creates a Conan profile, changes a remote, and builds missing
dependencies, so the unmodified build is not a pinned or reviewable replacement path.

SQLCipher 4.18.0's official source archive was inspected and hashed, but it is source-only:
it supplies neither a Python wheel nor the generated amalgamation consumed by `sqlcipher3`.
A non-publishing local generation probe did not complete; exact evidence and the evaluated
alternatives are in `docs/architecture/010-encryption-dependency-decision.md`. No source
signature is claimed as verified because GPG was unavailable on the review host.

`pysqlcipher3`, `sqlcipher3-binary`, system SQLCipher, Zetetic's commercial package, and APSW
with a custom SQLCipher build do not provide a patched, hashable DB-API wheel for the existing
maintained matrix without either older dependencies, dynamic host selection, commercial and
API changes, or a new project-owned native build. The machine-readable outcome is therefore
`BLOCKED_NO_INSTALLABLE_ARTIFACT`, with `selectedInstallableArtifact` set to `null` in
`security/dependency-audit.json`.

Authoritative inputs:

- <https://pypi.org/project/sqlcipher3/>
- <https://github.com/coleifer/sqlcipher3/compare/0.6.2...master>
- <https://www.zetetic.net/blog/2026/08/18/sqlcipher-4.18.0-release/>
- <https://www.zetetic.net/sqlcipher/verify/>
- <https://openssl-library.org/source/>

### Unresolved binding license conclusion

The tag's `pyproject.toml`, PyPI page, source-distribution `PKG-INFO`, and all eight wheel
`METADATA` files declare MIT. The tag, sdist, and wheels instead ship the same Gerhard Häring
three-condition text, SHA-256
`fa23cf250126548e90008fe92de4ee76d485bfbb3592f5be8aa731775892a960`. That text is preserved
verbatim in `third_party_licenses/sqlcipher3-0.6.2.txt`.

Because the declaration and shipped text conflict, SPDX keeps `MIT` as the upstream-declared
value but uses `NOASSERTION` for the concluded binding and aggregate wheel licenses. The
extracted `LicenseRef-sqlcipher3-0.6.2` retains the actual text without pretending the conflict
has been resolved. An independent license reviewer must decide the acceptable distribution
treatment.

Authoritative inputs:

- <https://github.com/coleifer/sqlcipher3/blob/0.6.2/pyproject.toml>
- <https://github.com/coleifer/sqlcipher3/blob/0.6.2/LICENSE>
- <https://pypi.org/project/sqlcipher3/0.6.2/>

## External SPDX validation

The SPDX document was parsed and fully validated with SPDX `tools-python`:

- tool: `spdx-tools==0.8.5`;
- tool wheel SHA-256:
  `7c2d5865941be9d2e898f5b084e8d5422dd298dc5a29320ddb198fec304f59c4`;
- local interpreter: CPython 3.14.6;
- command: `pyspdxtools --infile sbom/continuum-memory.spdx.json --version SPDX-2.3`;
- result: exit 0 with no validation messages.

The `spdx-validation` GitHub Actions job repeats that command on Ubuntu 24.04 / Python 3.14
using the complete hash-pinned wheel set in
`requirements/spdx-validation-linux-py314.txt`. The validator and its dependencies are CI
tools and are not included in Continuum Memory's wheel.

## Reproducible-build comparison

`scripts/verify.py` performs two independent builds with
`SOURCE_DATE_EPOCH=1700000000` using the same pinned setuptools runtime.

- The two pure-Python wheels must be byte-for-byte identical.
- Setuptools 80.9.0 sdists retain build-time gzip and tar member timestamps, so raw `.tar.gz`
  hashes may differ. The gate compares every tar member's path, type, mode, ownership,
  link target, size, and content hash while excluding only timestamps and timestamp PAX
  headers. Any payload or metadata difference fails.
- This same-host comparison does not prove cross-platform reproducibility. Platform path,
  filesystem-mode, ownership, newline, or toolchain differences remain outside the evidence.

## Final payload inspection

The complete gate requires exactly one versioned sdist and one versioned pure-Python wheel per
build. It verifies that both builds agree and that the inspected candidate contains the exact
source files. The wheel must contain byte-identical copies of:

- Continuum Memory's `LICENSE`;
- `THIRD_PARTY_NOTICES.md`;
- the sqlcipher3, SQLCipher, and OpenSSL license files;
- `sbom/continuum-memory.spdx.json`;
- `security/dependency-audit.json`.

The offline installation test then installs the sdist with the hash-pinned build and SQLCipher
wheels, with no index, dependency resolution, build isolation, or checkout `PYTHONPATH`, and
executes all four installed entry points. No project artifact has been published.

## Signing and rollback

No artifact was signed. The user has not approved an artifact-signing identity or private key,
and the repository has no reviewed signing workflow, trust root, certificate identity,
transparency-log policy, or verification instructions. A cryptographic signing rehearsal with
an arbitrary or ephemeral identity would not validate the intended release trust chain and was
therefore not performed. This remains a release blocker, not a silently skipped success.

Rollback is currently simple because PR #12 is unmerged and no release artifact has been
published: leave the PR open or close the branch. After any future release, rollback and key
revocation procedures must be defined before signing or publication.

## Required next decisions

1. Prefer a future upstream wheel that contains at least the recorded minimum patched
   versions. If schedule requires a project-owned build, explicitly authorize Continuum to
   own and maintain a native binding fork and wheel supply chain, including the ABI/platform
   matrix, artifact distribution location, signing identity, trust policy, and revocation
   procedure.
2. Obtain independent acceptance or correction of the sqlcipher3 license treatment.
3. Approve a signing identity, verification policy, and revocation/rollback procedure.
4. Rerun the live vulnerability queries and the complete verification gate immediately before
   any merge or release decision.

Until all four decisions are complete, PR #12 and Issue #7 must remain open and no accepted
encryption, dependency-safety, compliance, or release-readiness claim may be made.
