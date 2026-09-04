# Third-party notices and SQLCipher wheel inventory

This file records the third-party code used by the Continuum Memory 0.1.0.dev0
SQLCipher implementation candidate. It is an engineering inventory, not legal advice or a
claim that Issue #7 is accepted. The exact license texts copied from the reviewed upstream
releases are in `third_party_licenses/`, and the machine-readable interim inventory is
`sbom/continuum-memory.spdx.json`.

## Redistribution boundary

The Continuum Memory source tree, source distribution, and pure-Python wheel do **not**
contain a `sqlcipher3` wheel or its native extension. `setup.cfg` declares
`sqlcipher3==0.6.2` as a runtime dependency, so an installer obtains that distribution
separately. GitHub Actions downloads one hash-pinned wheel into the ignored `work/`
directory for testing and does not publish it as a Continuum artifact.

A working installation nevertheless contains both distributions. These notices therefore
ship in Continuum's source distribution and wheel. Anyone producing a combined installer,
application bundle, container, offline wheelhouse, or other payload that redistributes a
reviewed `sqlcipher3` wheel must keep these notices with that payload and re-run the wheel
inventory checks. Host operating-system and CPython files are not redistributed by
Continuum Memory.

## Reviewed wheel set

On 2026-09-04, all eight files below were downloaded from the `sqlcipher3` 0.6.2 PyPI
release and their complete archives were inspected. Their SHA-256 values match both PyPI
and `requirements/sqlcipher-maintained.txt`.

| Wheel | SHA-256 |
| --- | --- |
| `sqlcipher3-0.6.2-cp311-cp311-macosx_11_0_arm64.whl` | `22e6502c364706fe64695219877f2bb01cdb25450bec81e69c8a08deff8c14ee` |
| `sqlcipher3-0.6.2-cp311-cp311-manylinux_2_28_x86_64.whl` | `0f08e5bb5eb1ab93819c444ebec61fa3349e9690c14f5d0276fd4f61c3049fd9` |
| `sqlcipher3-0.6.2-cp312-cp312-macosx_11_0_arm64.whl` | `bc2edd981e65783bc0d4e337704a9eb436871ab91c68af02ed76354876087642` |
| `sqlcipher3-0.6.2-cp312-cp312-manylinux_2_28_x86_64.whl` | `6b26d28ca844dc2a69b8f74b390e940db47760f0be4c96d93337c57ae8250a48` |
| `sqlcipher3-0.6.2-cp313-cp313-macosx_11_0_arm64.whl` | `8e1ff6079603dfd955d57c26dad5eab14f6baacdc643d8753dd651913ba789cf` |
| `sqlcipher3-0.6.2-cp313-cp313-manylinux_2_28_x86_64.whl` | `9fb7109981583b631ac795e7e955d4bf78058f64b54c7f334ccc437adc322d4b` |
| `sqlcipher3-0.6.2-cp314-cp314-macosx_11_0_arm64.whl` | `5c1f4a5805faa418c9c7290e6a556a8c5abae40ea59b04d76e960e33c257e618` |
| `sqlcipher3-0.6.2-cp314-cp314-manylinux_2_28_x86_64.whl` | `e00988174ecd67ecd4537504c3df55bf8daeb75fce98401f099dff8e22c43ae1` |

Every reviewed archive has the same logical payload:

- `sqlcipher3/__init__.py` and `sqlcipher3/dbapi2.py`;
- one platform-specific `sqlcipher3/_sqlite3...so` native extension;
- wheel metadata and `RECORD` files;
- one `sqlcipher3-0.6.2.dist-info/licenses/LICENSE` file;
- no `.libs` directory, extra `.so`, `.dylib`, `.dll`, or `.pyd` payload.

Across all eight archives, `METADATA` has SHA-256
`09be93bd3c50a008a0d86a86d4d52ea79e4212033051cd31be1e0bf4dc840aa9` and the shipped
license has SHA-256
`fa23cf250126548e90008fe92de4ee76d485bfbb3592f5be8aa731775892a960`.

The binding is derived from Python's historical pysqlite implementation, but no separate
pysqlite distribution or independently versioned pysqlite payload is present in the reviewed
wheels. The exact inherited binding license text is therefore recorded under `sqlcipher3`
rather than inventing a second package or version.

## Shipped and linked components

| Component | Evidence in every reviewed wheel | License conclusion | Redistributed inside the wheel |
| --- | --- | --- | --- |
| sqlcipher3 Python/C binding 0.6.2 | Package files match tag `0.6.2` commit `14fc2632676b20011e0bba64fdda49763a2dd2ec`; wheel metadata names version 0.6.2 | `LicenseRef-sqlcipher3-0.6.2`; see the unresolved metadata conflict below | Yes |
| SQLCipher Community Edition 4.12.0 | Native extension contains `4.12.0`; vendored amalgamation at the binding tag contains Zetetic SQLCipher code and reports this runtime version | BSD-3-Clause; exact upstream release text is shipped | Yes, compiled into the native extension |
| SQLite 3.51.1 | Native extension contains the exact 2025-11-28 source ID; the vendored amalgamation identifies SQLite 3.51.1 and Fossil check-in `281fc0e9afc38674b9b0991943b9e9d1e64c6cbdb133d35f6f5c87ff6af38a88` | `LicenseRef-SQLite-Public-Domain`; SQLite's official copyright page states the deliverable code is public domain | Yes, as the SQLCipher base compiled into the native extension |
| OpenSSL 3.6.0 | Native extension contains `OpenSSL 3.6.0 1 Oct 2025`; OpenSSL symbols are defined in the extension; upstream binding tag pins Conan `openssl/3.6.0` and links `-lcrypto` | Apache-2.0; exact upstream release text is shipped | Yes, statically linked into the native extension |

The upstream build explicitly sets `openssl/*:no_zlib=True`. No reviewed wheel links or
ships zlib, and no reviewed archive contains a zlib library payload.

The macOS extensions list only `/usr/lib/libSystem.B.dylib` in `otool -L`. The Linux
extensions list only `libm.so.6`, `libpthread.so.0`, and `libc.so.6` as `NEEDED` entries.
Those libraries are supplied by the target operating system, are not copied into the
wheel, and have runtime-selected versions. The wheel evidence therefore cannot establish
one exact version or license file for them. The interim SPDX record deliberately uses
`NOASSERTION` and leaves their notices to the host OS rather than guessing.

The extension also consumes the CPython C API selected by its wheel ABI tag. CPython
3.11-3.14 is an external interpreter/runtime, not wheel content; its own installation and
notices remain the responsibility of the interpreter distributor.

## License evidence

### sqlcipher3 0.6.2 metadata conflict

The tag's `pyproject.toml` and every reviewed wheel's `METADATA` declare `MIT`. The tag and
every reviewed wheel instead include the same Gerhard Häring three-condition license text,
which is not the canonical MIT text. The repository UI classifies that file as Zlib.

Continuum Memory does not hide or resolve this upstream inconsistency. The exact shipped
text is copied verbatim to `third_party_licenses/sqlcipher3-0.6.2.txt`; the SPDX record keeps
the upstream declaration as `MIT` but uses `LicenseRef-sqlcipher3-0.6.2` as the concluded
license. Independent mentor/license review must accept that treatment before PR #12 may be
merged or Issue #7 may be self-certified.

Authoritative sources:

- [sqlcipher3 0.6.2 project metadata](https://github.com/coleifer/sqlcipher3/blob/0.6.2/pyproject.toml)
- [sqlcipher3 0.6.2 shipped license](https://github.com/coleifer/sqlcipher3/blob/0.6.2/LICENSE)
- [sqlcipher3 0.6.2 OpenSSL pin](https://github.com/coleifer/sqlcipher3/blob/0.6.2/conanfile.py)
- [sqlcipher3 0.6.2 native build recipe](https://github.com/coleifer/sqlcipher3/blob/0.6.2/setup.py)

### SQLCipher 4.12.0

The Community Edition release is BSD-3-Clause. Its exact license text, including the
binary-redistribution notice requirement, is copied verbatim to
`third_party_licenses/SQLCipher-4.12.0.txt` from the
[v4.12.0 release](https://github.com/sqlcipher/sqlcipher/blob/v4.12.0/LICENSE.txt).

### SQLite 3.51.1

SQLite states that its deliverable code is in the public domain and does not require a
license. The SPDX manifest uses a custom public-domain `LicenseRef` rather than forcing an
inaccurate OSI license identifier. Source: [SQLite copyright](https://www.sqlite.org/copyright.html).

### OpenSSL 3.6.0

OpenSSL 3.6.0 is licensed under Apache-2.0. The exact tag's license text is copied verbatim
to `third_party_licenses/OpenSSL-3.6.0.txt` from the
[OpenSSL 3.6.0 release](https://github.com/openssl/openssl/blob/openssl-3.6.0/LICENSE.txt).

## Inspection method and limits

The inspection used archive listing and extraction, SHA-256 checks, wheel `METADATA` and
license parsing, `file`, `strings`, native symbol tables, `otool -L` for Mach-O files, and
ELF dynamic-section `NEEDED` entries. The upstream tag, sdist, build recipe, vendored
amalgamation, and authoritative release licenses were cross-checked. The verifier repeats
the portable archive, metadata, license-hash, native-member, and embedded-version checks
for the wheel used in each CI job.

This is an interim SPDX 2.3 engineering SBOM. It has not been certified by an external SPDX
validator, legal counsel, or a reproducible-build comparison. It does not inventory an
unknown future OS image, CPython distribution, installer, container, or application bundle.
Any change to a wheel filename, digest, component version, license file, or packaging path
must be reviewed and recorded before the verifier will pass.
