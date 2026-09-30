# Patched SQLCipher wheel third-party notices

Status: ephemeral CI test artifact only; not released or approved for permanent distribution.

The `continuum-sqlcipher3` 0.6.2.post2 wheel retains the `sqlcipher3` Python/C binding API
from upstream 0.6.2 and replaces only its vendored amalgamation and cryptographic provider
build. The CI artifact contains:

| Component | Exact source | Relationship | License conclusion |
| --- | --- | --- | --- |
| sqlcipher3 binding | 0.6.2, commit `14fc2632676b20011e0bba64fdda49763a2dd2ec` | Python/C binding files | `NOASSERTION`; upstream metadata says MIT but the shipped Gerhard Häring text differs |
| SQLCipher Community Edition | 4.19.0, commit `c4b275a47932888216bade83aff2bbc73df0ff85` | Compiled into the extension | BSD-3-Clause |
| SQLite | 3.53.4 from the signed SQLCipher source | SQLCipher base | `LicenseRef-SQLite-Public-Domain` |
| OpenSSL | 3.5.8 LTS, commit `f4dc4d58b48d346a8270183f89acf826d459b0ca` | Statically linked `libcrypto` | Apache-2.0 |

The wheel embeds four exact notice files under its `.dist-info/licenses/` directory. Their
SHA-256 values are enforced by `scripts/inspect_patched_sqlcipher_wheel.py`:

- sqlcipher3 `LICENSE`: `fa23cf250126548e90008fe92de4ee76d485bfbb3592f5be8aa731775892a960`;
- SQLCipher `LICENSE.txt`: `2a2826f6acf46fa650730cf42cbb22a642be33a7ef119c9c4f4bf6daf3bef48e`;
- SQLite `SQLITE_LICENSE.md`: `595e823c2ada6c839679e693bee1f4d7f88e2d34ac99a913ae41e3d43fb10c7d`;
- OpenSSL `LICENSE.txt`: `7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a`.

The source and signature hashes, signing-key fingerprints, support windows, immutable
builder identity, and build-tool hashes are in `packaging/sqlcipher/manifest.json`. The
generated CI evidence bundle adds the exact wheel checksum, native dependency and license
inventory, source-signature verification result, runtime result, exact reviewed-recipe
hashes, producing commit/run identity, build provenance, and artifact-specific SPDX 2.3
SBOM. The two small OpenSSL compatibility shims are project-controlled Apache-2.0 files;
their SHA-1/SHA-256 values are inventoried without making a clean-room provenance claim.

The `sqlcipher3` license discrepancy remains unresolved. Retaining the exact text and using
`NOASSERTION` is an engineering disclosure, not a legal conclusion. Independent license
acceptance remains mandatory before any permanent distribution.
