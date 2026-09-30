# OpenSSL security recheck — 2026-09-29

Status: **open security disposition; source-only review, not clearance**.
For maintainers deciding whether the held native candidate can advance toward v1.
Before production acceptance, upgrade and revalidate the dependency or obtain an
explicitly qualified, independently reviewed reachability disposition for the
exact candidate. This document makes neither decision on the owner's behalf.

The [manifest](manifest.json) still pins `continuum-sqlcipher3 0.6.2.post2`,
SQLCipher 4.19.0 / SQLite 3.53.4, and OpenSSL 3.5.8 at commit
`f4dc4d58b48d346a8270183f89acf826d459b0ca`. No pin, artifact, or historical
evidence was changed for this recheck.

## New official evidence

OpenSSL's [September 29 advisory](https://openssl-library.org/news/secadv/20260929.txt)
and [vulnerability list](https://openssl-library.org/news/vulnerabilities/)
include the pinned 3.5.8 in affected version ranges, with 3.5.9 as the fixed
3.5-series release. The following groups summarize the required feature review;
they do not assert that those features are reachable through Continuum.

| Feature required by the advisory | CVEs in the September 29 advisory | Upstream severity / scope |
| --- | --- | --- |
| DTLS handshake/record processing | CVE-2026-84782, CVE-2026-75806 | High and Low respectively; 3.5.8 is in range. |
| QUIC or TLS context switching | CVE-2026-35191, CVE-2026-42772, CVE-2026-54873, CVE-2026-72897, CVE-2026-75804, CVE-2026-84784 | Low; 3.5.8 is in range. |
| Certificate distribution-point or CMP processing | CVE-2026-35189, CVE-2026-75805 | Low; 3.5.8 is in range. |
| Generic-curve or SM2 private-key operations | CVE-2026-54872, CVE-2026-54875, CVE-2026-77696 | Low; 54875 additionally requires AArch64 or RISC-V, outside the current Linux x86-64 slice. |
| Concurrent X.509 extension-cache use | CVE-2026-84783 | Moderate, but upstream explicitly limits this issue to 4.0; 3.5 is unaffected. |

The [official download record](https://openssl-library.org/source/) lists 3.5.9
released September 29, 2026. The [release strategy](https://openssl-library.org/policies/releasestrat/index.html)
still gives the 3.5 LTS series an end-of-support date of April 8, 2030. Series
support does not make an older affected patch release current. No 3.5.9 archive,
signature, source identity, or resulting wheel was acquired or verified here.

## What the inspected source establishes

The observations below concern the current Linux x86-64 native wheel recipe,
not arbitrary OpenSSL use elsewhere on the host.

- [build_patched_sqlcipher_wheel.sh](../../scripts/build_patched_sqlcipher_wheel.sh)
  configures 3.5.8 with `no-shared`, `no-module`, `no-dso` and
  `no-autoload-config` (lines 99–103). It selects `lib64/libcrypto.a` and passes
  that archive to the SQLCipher build and binding build (lines 109–119 and
  151–155). Building OpenSSL tools is not evidence that all their dependencies
  are included in the final Python extension.
- [setup_continuum.py](setup_continuum.py), `build_extension`, uses
  `extra_objects=[libcrypto]` (line 114). The recipe does not link `libssl`.
  [inspect_patched_sqlcipher_wheel.py](../../scripts/inspect_patched_sqlcipher_wheel.py)
  also restricts ELF dynamic dependencies to its explicit `ALLOWED_NEEDED`
  system-library set; that set includes neither `libcrypto` nor `libssl`.
  These are inspected source constraints, not a new binary-inspection result.
- The exact pinned SQLCipher [OpenSSL provider source](https://github.com/sqlcipher/sqlcipher/blob/c4b275a47932888216bade83aff2bbc73df0ff85/src/crypto_openssl.c)
  selects `EVP_aes_256_cbc` (line 83), obtains random bytes through `RAND_bytes`,
  uses the OpenSSL 3 HMAC interface, and derives keys with
  `PKCS5_PBKDF2_HMAC`. Its inspected provider calls use AES-CBC,
  HMAC/SHA, PBKDF2 and random generation. No TLS, DTLS, QUIC, X.509, CMP,
  generic-curve signing, or SM2 call path was found in that provider file.
  The file was read from the official repository at the manifest commit; it
  is not a new locally verified source archive.

Inference: the affected feature preconditions have not been demonstrated on the
inspected SQLCipher path, and the DTLS High finding is not evidence of a remote
DTLS exploit in this wheel. This is **not** proof that affected code is absent
from the statically linked archive or unreachable through every indirect
provider/dispatch path. This review did not perform whole-program reachability,
fresh binary inspection, exploit tests, or native runtime tests. The separate
host `/usr/bin/openssl` used by approval code is not the pinned wheel library;
its distribution and exposure are outside this narrow recheck.

## Preserved evidence and remaining decision

[SOURCE_REVIEW_2026-09-23.md](SOURCE_REVIEW_2026-09-23.md) and
[security-evidence-2026-09-23.json](security-evidence-2026-09-23.json) remain
historical observations. Their empty exact-commit OSV responses were not
refreshed and must not be presented as a current no-findings result. A vendor
advisory remains relevant even when an aggregator has no matching entry.

The preferred next candidate is a separately reviewed OpenSSL 3.5.9 update with
fresh source verification and rebuild evidence. If retaining 3.5.8 instead, a
qualified review must explicitly map every applicable advisory to the exact
build, binary, architecture and reachable inputs, record its limitations, and
obtain the required acceptance. This note supplies neither that acceptance nor
an exemption. Bounded synthetic CI can still collect diagnostic evidence; a
passing test run does not close this dependency-security disposition.

No license conclusion, binding `NOASSERTION` change, artifact signing decision,
release permission, macOS/Windows support claim, or other acceptance gate is
changed by this record.

## Minimal upgrade inventory — planned, not performed

1. In [manifest.json](manifest.json) and
   [fetch_patched_sqlcipher_sources.py](../../scripts/fetch_patched_sqlcipher_sources.py),
   review the new OpenSSL version, tag/commit/tag object, URLs, archive and
   detached-signature SHA-256 values. Revalidate the trust key and license-file
   bytes rather than assuming they changed or remained identical. Preserve the
   old dated evidence and add new dated source/security records; update the
   manifest's evidence hash and strict mirrored expectations to those records.
2. Update the OpenSSL paths in
   [build_patched_sqlcipher_wheel.sh](../../scripts/build_patched_sqlcipher_wheel.sh)
   and the expected native version marker in
   [inspect_patched_sqlcipher_wheel.py](../../scripts/inspect_patched_sqlcipher_wheel.py).
   Give changed native bytes a distinct distribution identity via
   [setup_continuum.py](setup_continuum.py); do not overwrite the identity or
   reuse the wheel hashes of `0.6.2.post2`.
3. Obtain genuine independent duplicate-build results for CPython 3.11–3.14.
   The four `expectedArtifacts.*.sha256` values must come from those exact
   resulting wheels, with byte agreement, native/metadata inspection, offline
   installation and runtime evidence. Revalidate or recompute the inspector's
   `EXPECTED_METADATA_SHA256` from actual reviewed metadata. Source archive,
   signature, license and project-file hashes come from their corresponding
   verified bytes, not from a guessed wheel hash or a version substitution.
4. Refresh only the changed entries in `builder.reviewedProjectFiles`, while
   retaining strict checks in
   [verify_patched_sqlcipher_inputs.py](../../scripts/verify_patched_sqlcipher_inputs.py),
   [test_patched_sqlcipher_install.py](../../scripts/test_patched_sqlcipher_install.py),
   [test_patched_sqlcipher_runtime.py](../../scripts/test_patched_sqlcipher_runtime.py)
   and [patched-sqlcipher-wheel.yml](../../.github/workflows/patched-sqlcipher-wheel.yml).
   Review metadata/native identities and application consumers before any new
   artifact is admitted; this document does not relax a hash or CI gate to
   bootstrap new evidence.
5. Coordinate the distinct distribution version through `pyproject.toml`,
   `src/continuum_memory/storage.py`, `scripts/application_inputs.py`,
   `scripts/verify_encrypted_application.py`, `scripts/release_package.py`,
   `packaging/linux/stage-polkit-wheel.py`, the strict native scripts above,
   corresponding supply-chain/storage/package tests, and current notices.
   Re-run native and application acceptance on the resulting exact candidate;
   do not relabel the September 23 source/wheel results as new-version evidence.

Only this new Markdown record was authored for the recheck. No project code was
imported or executed, no native artifact was downloaded or built, and no
repository issue, PR, or release was changed.
