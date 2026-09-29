# Held issue #7 source refresh: main 152450a plus PR46/47 crash tests

Recorded 2026-09-29. This is an unsigned local source checkpoint, not native
acceptance, publication, a release, or issue closure. No application imports,
provider/broker/key/custody/installer execution, tests, package builds, artifact
retrieval or real-vault operations were performed for this refresh.

## Exact inputs and scope

- Encrypted application: `17a73e20477c5d5382c2d737cebb90bcbe858e0c`.
- Previously integrated main: `2cf9c52f27dabd55c3dec4ae1b1fc7ec9d087035`.
- New main source input: `152450a7d91c9c1a6ace07835ddb80fc2f35de05`.
- Subsequent bounded test/docs inputs: PR #46
  `4b1eaf55ee43ba6bc9727f9b6e88506c67fa79c6` and PR #47
  `1e0bb0f772f66f497cec13129674a004a479c738`.
- Local base before this source-only test/docs follow-up:
  `07856f7b43bfc00c1911f310dadb66b3e31c234f`.
- Local branch: `codex/issue-7-source-refresh-152450a`.
- A three-way application of the old-main/new-main source delta preserves the
  encrypted candidate's history. This is not a merge of held PRs #12/#14/#27.
- Only the five new crash helper/test files and their bounded documentation
  sections are imported from PR46/47, not a new production-code integration.
  The later, unmerged bootstrap/preview batch and issue #4 backup candidate are
  outside this checkpoint.

## File-level compatibility decisions

| Files | Result |
|---|---|
| `cli.py`, `kernel.py`, `results.py`, `recovery_locator.py`, `recovery_journal.py`, `client.py` | Main's durable four-scalar recovery locator, original-capability/vault/HMAC binding, journal-before-apply and one receipt lookup are retained. Encrypted status/generation and separate `storage rotate-key` / `storage recover-key` commands remain. Receipt recovery never authorizes retry or key recovery. |
| `security.py`, `macos_acl.py`, `storage.py` | Main's bounded fixed-identity directory revalidation and SQLite-specific no-extra-descriptor ACL observation are retained. Encrypted DB and every present sidecar are checked before native open, after keyed page authentication, after hardening and during bootstrap. Ordinary private-key checks retain their descriptor semantics. |
| `storage.py` | Exact post2 backend admission, key-first query-only preflight, metadata/schema admission before writes/migration, pending-rotation/legacy-residue refusal and cipher integrity remain. Windows storage is refused before key/files/backend access; main's plaintext connector is not used. The copied IPC-binding name is treated as occupied, not created. |
| `storage_key_custody.py`, `storage_rotation.py`, original custody/rotation fixtures and tests | Preserved byte-for-byte from the encrypted input. Genuine offline fingerprint/read/fsync operations remain strict and occur under the existing lease/closed-connection contract. |
| `fixtures/harness.py`, `test_cli_recovery.py`, `test_macos_acl.py`, `test_sqlite_lock_preservation.py` | Shared main harness behavior combines with keyed fixture access. A narrowly scoped read-only URI option keeps live-daemon observers from requesting a writable SQLite open. The future macOS lock regression deliberately retains a keyed writable observer. |
| `test_encrypted_platform_contract.py`, `test_encrypted_storage.py`, `test_encrypted_recovery_compatibility.py` | Prepared, unexecuted checks cover Windows refusal before side effects, read-only/hardening incompatibility, actual native read-only behavior/live sidecar preservation, and durable receipt recovery across native storage-key rotation. No new acceptance is inferred. |
| `lifecycle_crash_support.py`, `test_retention_crash.py`, `test_proposal_purge_crash.py`, `test_propose_crash.py`, `test_recall_feedback_crash.py` | Source-only PR46/47 copies preserve merged test logic and literal boundary inventories; only module docstrings identify the hold. Existing helper/fixtures already use the held keyed `Store` interface; no direct stdlib database open or backend bypass was added. These application matrices have not run with SQLCipher. |
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
   Re-run applicable application statement/process-exit, audit-publication and
   whole-CLI recovery tests with the actual pinned SQLCipher backend. The imported
   `test_migration_crash.py` deliberately uses stdlib SQLite and remains a separate
   engine matrix even inside the full suite. A keyed native process-exit migration
   matrix is still unprepared and unrun; this refresh does not supply that evidence.
   The prepared PR46/47 application cases add 16 expiry, 26 proposal-purge,
   10 proposal-creation, three search-recall, three context-recall and nine feedback
   process-exit points (67 selected points total). Run their exact statement/anchor
   inventories, independent scoped-state assertions and full verifier only after
   authorization. Recall/feedback have no idempotency guarantee: only test-proven
   pre-commit cases retry, never ambiguous committed calls. These counts describe
   source coverage, not executed or accepted encrypted behavior.
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

## Independent review repairs after checkpoint 267e0ce

Three source defects were identified and repaired in a bounded follow-up:

- Restored `storage.ensure_private_regular` as the strict security compatibility
  export used by `fixtures/rotation.py` for key validation. The fixture and custody
  sources remain byte-identical; the SQLite metadata observer is not used for keys.
- Replaced the build-tool bare-line parser with strict bare-name/exact-version
  validation plus the already-pinned `packaging` PEP 508 marker parser. Extras,
  URLs, ranges, wildcard/invalid versions and normalized duplicates across all
  entries are refused, including inactive branches. Only matching host pins are
  queried in installed metadata; the original full requirements and hash set pass
  unchanged to the existing offline, hash-required pip dry run. Four focused
  tests are prepared for host selection, malformed/inactive pins, duplicate
  aliases and metadata/resolver behavior; none was executed.
- Corrected `LINUX_RELEASE.md` from 30 to the 91 source-enumerated exclusions
  (62 Windows, 29 macOS), explicitly retaining unexecuted native status.

Follow-up evidence is limited to AST/compile parsing, source diff inspection,
unchanged protected-input hashes and unchanged ignored-file inventory. No project
imports, test execution, resolver/package build or native/key activity was used.
Independent exact-diff review and all runtime gates above remain outstanding.

## PR46/47 source-only test refresh

The five imported Python files retain the merged executable ASTs; only their
module docstrings label them as held/unexecuted here. No runtime-interface change
was indicated by source inspection: the existing helper opens the keyed `Store`,
and `Kernel.status` adds encrypted status metadata without altering the lifecycle
transaction inventory. Native provider behavior, logical dump ordering, crash
recovery, filesystem locking and runtime duration remain unverified.

The corresponding failure-matrix sections are marked as future gated checks.
MAIN's hosted Windows plaintext evidence is distinguished from this branch's
unsupported encrypted Windows path. No bootstrap state markers, preview matrix,
new production code, platform skip exception, dependency pin, hash, license or
NOASSERTION change is part of this follow-up. Validation is limited to stdlib AST
parsing/comparison, textual diff hygiene and unchanged protected/ignored source
inventory. There were no application imports, test runs, native execution, key or
vault access, builds, artifact retrieval or remote publication in this refresh.
An independent source-only review confirmed executable AST equality for all five
files, the existing keyed-Store interfaces and unchanged protected inputs before
the unsigned local checkpoint. This is not native acceptance.
