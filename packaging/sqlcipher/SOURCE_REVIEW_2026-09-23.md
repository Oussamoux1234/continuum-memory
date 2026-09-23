# SQLCipher 4.19.0 source and native evidence

Evidence date: 2026-09-23. Candidate distribution: `continuum-sqlcipher3`
`0.6.2.post2`; import remains `sqlcipher3`. This record supports the explicitly
approved, unmerged 4.18.0-to-4.19.0 remediation for issue #13 / PR #14.
It does not certify a native wheel or application integration.

At the initial source-review checkpoint, Actions verification of the candidate's
detached source signature, native builds, runtime tests, and wheel hashes were
pending. The subsequent native bootstrap results are recorded below. The old
`0.6.2.post1` hashes and expired artifacts are not evidence for `0.6.2.post2`.
The restricted bootstrap must not upload wheels. Normal artifact retention may
resume only after reviewed candidate hashes and all strict validation locks are
restored and the corresponding exact-head checks pass.

## Native bootstrap validation

[Run 35869810191](https://github.com/Oussamoux1234/continuum-memory/actions/runs/35869810191)
at `31cf7aaaec85b44f8271877dd260229cbe8773fc` passed signed-source acquisition,
two independent builds, byte comparison, exact native/metadata inspection, offline
installation, and the complete runtime suite on all four Linux ABIs. SQLCipher
and OpenSSL detached signatures verified against their pinned primary fingerprints.
The metadata digest was first derived by reproducing post1's locked metadata and
confirming that only `Version: 0.6.2.post2` changed.

| ABI | Observed wheel SHA-256, identical in both builds |
| --- | --- |
| cp311 | `bb6df23d39a1021256e0fe5bc8268c93fb6502a1ad2b5bbabf6bce48a8ba72f5` |
| cp312 | `45bc9bd447772b3fef50ad630c41cc031bfec785901f63b5c9d62315a02f48ae` |
| cp313 | `a4b0abac3223a0ca61a5f4bc412bac657b4be374793e039f7b1bd27bc0f5f5a3` |
| cp314 | `ab1ae989bfe8d1542bd647158cde7e4fe2ca0d6bbff4d951d40ec60c4ddb3be5` |

Each installed wheel reported SQLCipher 4.19.0 community / SQLite 3.53.4, rejected
invalid URI key material, passed the valid-key control and quoted-schema export,
and passed the existing encryption, extension-denial, WAL, FTS, crash recovery,
integrity, and plaintext-canary checks. Each job then failed only at the explicit
final stop. The bootstrap workflow contained no upload action and retained zero
artifacts. These are observed build results; normal strict-hash CI must reproduce
them before retaining a test artifact. This record grants no human acceptance.

## Reason for the explicit dependency update

Zetetic's [September 8 advisory](https://www.zetetic.net/blog/2026/09/08/sqlcipher-4.19.0-release/)
identifies two issues in 4.18.0 and earlier and identifies 4.19.0 as their fix:

- Unquoted attached-schema aliases can alter generated `sqlcipher_export` SQL
  when attacker-controlled aliases reach it. Upstream says this issue preserves
  encryption and per-page integrity.
- A nonempty invalid URI `hexkey` can create a new plaintext database without an
  error. The fix rejects a value containing no valid key material.

These are separate failure modes; they do not establish an exploit in Continuum's
current plaintext application. They do invalidate treating the held 4.18.0 source
as cleared merely because an OSV exact-commit query returns an empty object.
The companion `security-evidence-2026-09-23.json` retains today's candidate OSV
responses and the vendor advisory with its conditions and qualifications.
The September 7 OSV file remains historical evidence and is not refreshed in place.

## Candidate source identity

The [official release](https://github.com/sqlcipher/sqlcipher/releases/tag/v4.19.0)
was published 2026-09-08T14:31:26Z. Its
[tag object](https://api.github.com/repos/sqlcipher/sqlcipher/git/tags/58beb4a302f0e3c37341d2312cef521f858b1273)
and source archive were observed on September 23:

| Field | Observed value |
| --- | --- |
| Tag | `v4.19.0` |
| Tag object | `58beb4a302f0e3c37341d2312cef521f858b1273` |
| Commit and ZIP archive comment | `c4b275a47932888216bade83aff2bbc73df0ff85` |
| Archive | [sqlcipher-4.19.0.zip](https://www.zetetic.net/downloads/sqlcipher/verify/4.19.0/sqlcipher-4.19.0.zip), 20,675,387 bytes |
| Archive SHA-256 | `268d603ff040fa669556fe8be2e8ae8f353d86d799279e3a86e683eb5fb25c95` |
| Detached signature | [sqlcipher-4.19.0.zip.sig](https://www.zetetic.net/downloads/sqlcipher/verify/4.19.0/sqlcipher-4.19.0.zip.sig), 459 bytes |
| Signature SHA-256 | `f5adf1c55a52af2a362dc76a63e10af0df76a0f811b6ebd355e852ff58acec33` |
| Embedded SQLite `VERSION` | `3.53.4` |
| Embedded `manifest.uuid` | `bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc` |
| SQLCipher `LICENSE.md` SHA-256 | `2a2826f6acf46fa650730cf42cbb22a642be33a7ef119c9c4f4bf6daf3bef48e` |

The archive, signature, and public key are linked from the vendor's
[verification instructions](https://www.zetetic.net/sqlcipher/verify/). The public
key's pinned SHA-256 remains
`b5fa10e62b50478db1236f3a8c7157074d71450a1f6a245eb77a71802202eefd`;
the published primary fingerprint remains
`D83F5F9EB811D6E6B4A0D9C5D1FA3A2A97ED25C2`, with expiry 2027-08-02.
Byte hashes and GitHub tag identity do not replace mandatory detached-signature
verification against that fingerprint in the pinned Actions acquisition phase.
GitHub's tag API reports `unknown_key`, which is neither an independent
verification nor evidence that the detached source signature is invalid.

## Unchanged source and tool inputs

No update to the following inputs is proposed by this review:

| Input | Existing pin retained | Evidence and qualification |
| --- | --- | --- |
| OpenSSL | 3.5.8, commit `f4dc4d58b48d346a8270183f89acf826d459b0ca`, tag object `090eec6d3628aa0520bdf2cf97b063fafc34e7be` | Official archive, checksum, detached signature, and key hashes matched existing pins on September 23. |
| SQLite | 3.53.4, source ID shown above | Candidate archive metadata agrees with the [SQLite release record](https://www.sqlite.org/releaselog/3_53_4.html). No separate SQLite source archive is substituted. |
| sqlcipher3 | 0.6.2, commit `14fc2632676b20011e0bba64fdda49763a2dd2ec` | [Upstream tag](https://api.github.com/repos/coleifer/sqlcipher3/git/ref/tags/0.6.2) and sdist SHA-256 matched existing pins. |
| Builder | `quay.io/pypa/manylinux_2_28_x86_64@sha256:53390351aeb4688114b02c36a23b3e6ce1166ee9b7afc5df1a4f776354fc764c` | Retained immutable Linux image produced the bootstrap results above; strict-head CI remains pending at this checkpoint. |
| Python build tools | setuptools 80.9.0 and wheel 0.45.1 | Existing hash-locked inputs retained; no independent upgrade or new support assertion. |

The [OpenSSL lifecycle](https://openssl-library.org/policies/releasestrat/) lists
3.5 LTS support through 2030-04-08. The
[download record](https://openssl-library.org/source/) lists 3.5.8, and the
[security list](https://openssl-library.org/news/vulnerabilities/) observed during
this review lists the relevant August 25 fixes with affected 3.5 ranges ending
before 3.5.8. These are dated source observations, not a claim of absence of
unknown or unlisted vulnerabilities. No SQLCipher version-specific EOL promise
or binding maintenance guarantee is inferred.

The OSV queries are point-in-time exact-commit responses: OpenSSL and the binding
were queried at approximately 13:20 UTC; candidate SQLCipher at 13:23 UTC on
September 23. All returned empty objects. OSV coverage, vendor advisories,
signature verification, native behavior, and application exposure remain distinct
parts of the review.

## License and acceptance gates

The candidate SQLCipher license file is byte-identical to the previously pinned
file identified as BSD-3-Clause. Existing OpenSSL Apache-2.0 and SQLite
`LicenseRef-SQLite-Public-Domain` metadata remain unchanged. The binding remains
`NOASSERTION`; neither its tag nor the unchanged license-file hash supplies a new
legal conclusion for the binding or the combined distribution.

The following gates remain open:

- Normal strict-hash CI must repeat source signatures, duplicate builds, native
  inspection and runtime checks; independent exact-head acceptance remains required.
- Binding and combined-distribution license acceptance, including `NOASSERTION`.
- Artifact signing identity, trust root, transparency policy, and verification and
  revocation procedures. This candidate is not signed.
- An approved immutable native macOS arm64 builder; Windows remains unsupported.
- Human acceptance and separate application integration, migration, key management,
  backup/restore, and rollback validation. No real vault or profile was used here.

This source review does not merge or close a PR/issue, authorize a release,
publish a package, or remove the application's plaintext-storage warning.
