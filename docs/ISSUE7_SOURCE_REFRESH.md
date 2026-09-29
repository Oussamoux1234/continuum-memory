# Held issue #7 source refresh against main 152450a

Recorded 2026-09-29. This is an unsigned local source checkpoint, not native
acceptance, publication, a release, or issue closure. No application imports,
provider/broker/key/custody/installer execution, tests, package builds, artifact
retrieval or real-vault operations were performed for this refresh.

## Exact inputs and scope

- Encrypted application: `17a73e20477c5d5382c2d737cebb90bcbe858e0c`.
- Previously integrated main: `2cf9c52f27dabd55c3dec4ae1b1fc7ec9d087035`.
- New main source input: `152450a7d91c9c1a6ace07835ddb80fc2f35de05`.
- Local branch: `codex/issue-7-source-refresh-152450a`.
- A three-way application of the old-main/new-main source delta preserves the
  encrypted candidate's history. This is not a merge of held PRs #12/#14/#27.
- PR46 and the issue #4 backup candidate are outside this checkpoint.

## File-level compatibility decisions

| Files | Result |
|---|---|
| `cli.py`, `kernel.py`, `results.py`, `recovery_locator.py`, `recovery_journal.py`, `client.py` | Main's durable four-scalar recovery locator, original-capability/vault/HMAC binding, journal-before-apply and one receipt lookup are retained. Encrypted status/generation and separate `storage rotate-key` / `storage recover-key` commands remain. Receipt recovery never authorizes retry or key recovery. |
| `security.py`, `macos_acl.py`, `storage.py` | Main's bounded fixed-identity directory revalidation and SQLite-specific no-extra-descriptor ACL observation are retained. Encrypted DB and every present sidecar are checked before native open, after keyed page authentication, after hardening and during bootstrap. Ordinary private-key checks retain their descriptor semantics. |
| `storage.py` | Exact post2 backend admission, key-first query-only preflight, metadata/schema admission before writes/migration, pending-rotation/legacy-residue refusal and cipher integrity remain. Windows storage is refused before key/files/backend access; main's plaintext connector is not used. The copied IPC-binding name is treated as occupied, not created. |
| `storage_key_custody.py`, `storage_rotation.py`, original custody/rotation fixtures and tests | Preserved byte-for-byte from the encrypted input. Genuine offline fingerprint/read/fsync operations remain strict and occur under the existing lease/closed-connection contract. |
| `fixtures/harness.py`, `test_cli_recovery.py`, `test_macos_acl.py`, `test_sqlite_lock_preservation.py` | Shared main harness behavior combines with keyed fixture access. A narrowly scoped read-only URI option keeps live-daemon observers from requesting a writable SQLite open. The future macOS lock regression deliberately retains a keyed writable observer. |
| `test_encrypted_platform_contract.py`, `test_encrypted_storage.py`, `test_encrypted_recovery_compatibility.py` | Prepared, unexecuted checks cover Windows refusal before side effects, read-only/hardening incompatibility, actual native read-only behavior/live sidecar preservation, and durable receipt recovery across native storage-key rotation. No new acceptance is inferred. |
| `scripts/release_package.py`, `packaging/build-requirements.txt` | Main's portable archive-member checks and installed Unicode CLI smoke are combined with exact native dependency/origin verification and the existing privileged-installer incompatibility flag. Main's platform-conditional tool lock additions are retained; Linux native pins are unchanged. |
| `scripts/application_test_results.py`, `tests/platform-skips-linux.json`, `scripts/verify.py` | Source-enumerated exact Linux exclusions now name 91 methods: 62 Windows and 29 macOS. IDs/reasons, missing outcomes and required crypto/recovery suites remain strict. No encryption/rotation/missing-backend skip is allowed. New recovery files must appear in the sdist. |
| `.github/workflows/windows-runtime.yml`, platform/recovery docs | Imported plaintext Windows runtime/account jobs are explicitly disabled for this encrypted branch. Main's historical evidence and closed plaintext issue #1 are distinguished from encrypted support. macOS remains a primitive-only workflow with native encrypted acceptance held. |

The 29 macOS exclusions are four APFS, 17 extended-ACL, seven SQLite-lock and
one recovery-journal ACL method. Windows exclusions are 11 filesystem, 15 pipe,
15 runtime, 15 storage, three daemon, one hosted-owner and two journal methods.
This is static enumeration; unittest discovery and native outcomes were not run.

## Still-unrun validation plan

After separate authorization and reviewed inputs are available, use non-root
Linux x86-64 with each CPython ABI 3.11, 3.12, 3.13 and 3.14. For each ABI:

1. Verify signed sources, all 13 manifest-bound project inputs and the immutable
   builder. Repeat independent offline A/B wheel builds, equality/locked hash,
   ELF inspection and installed native runtime regression gates. Do not retain,
   download or republish held artifacts as a shortcut.
2. Install the exact post2 wheel with its two pinned backend wheels plus the
   separate hash-locked verification tools. Confirm native module origins,
   SQLCipher 4.19.0 community, SQLite 3.53.4 and expected OpenSSL evidence.
3. Run the full application verifier, not selected passing tests. Require all
   discovered outcomes and precisely the 91 platform-only skip IDs/reasons;
   enforce every required encryption, export, rotation, custody and recovery suite.
4. Exercise wrong/missing/unsupported keys, key-first admission, no plaintext
   fallback, schema-2/3/4-to-5 keyed migration and unchanged unsupported metadata.
   Re-run all real statement/process-exit, audit-publication and whole-CLI recovery
   tests imported from main with the actual pinned SQLCipher backend.
5. Exercise prepared read-only observer behavior, WAL/SHM preservation and repeated
   writer commits. Verify each rotation/recovery fault and stable audit key, vault,
   capabilities and original receipts. Verify a durable pre-rotation locator still
   retrieves only its original receipt after successful rotation and after each
   recoverable rotation interruption; the latter combined fault matrix remains
   an explicit follow-up beyond the new successful-rotation contract.
6. Run all 17 demo checks; create reproducible sdist/wheel/SPDX twice; validate
   exact native dependency/provenance; install both archives offline in fresh
   environments, Unicode init and relocated helper smoke. Verify that the current
   privileged installer still rejects the runtime dependency. Do not activate it.

macOS arm64 encrypted application/APFS/ACL/SQLite-lock execution remains blocked
on the accepted immutable native builder/artifact and minimum-OS contract. Linux
results cannot replace that native regression. Windows encrypted execution remains
unsupported and disabled. Native rekey interruption inside the native call, host
power loss, physical erasure, independent backup freshness/revocation, real user
presence and real-vault acceptance remain separate unproved properties.

## Risks and holds

Syntax and static equality cannot prove provider/API compatibility, SQLCipher
exception behavior, real runtime locks or packaging execution. The prepared
observer and receipt-through-rotation tests have not run. Existing native source
and wheel hashes, source SBOM, NOASSERTION, custody, license/security review,
privileged installer, signing/trust/revocation, publication and platform gates
remain unchanged. No backup surface or native authority was added. Keep #7 and
all dependent issues open until their actual acceptance criteria are satisfied.
