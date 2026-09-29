# Held issue #7 source refresh: main 152450a, PR46/47/48 and backup preparation

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
- Subsequent keyed initialization/preview source input: PR #48
  `d0ba7f56306515090956982954005a7a800fd657`, applied after local checkpoint
  `03d67b862bf97e10311a2985b1946b419cb3f1c2`.
- Subsequent format-v2 backup candidate input:
  `238418d70783cb2c2133ec8ff2d162df448afa44`, applied after keyed-initialization
  checkpoint `06b6533e7b7ee317133750607ce3637c01334bd2`.
- Local base before this source-only test/docs follow-up:
  `07856f7b43bfc00c1911f310dadb66b3e31c234f`.
- Local branch: `codex/issue-7-source-refresh-152450a`.
- A three-way application of the old-main/new-main source delta preserves the
  encrypted candidate's history. This is not a merge of held PRs #12/#14/#27.
- PR46/47 imported only five crash helper/test files and bounded documentation.
  The subsequent PR48 source-only follow-up adds initialization containment and
  prepared bootstrap/preview checks while retaining the native keyed backend.
  The later issue #4 source-only integration adds held staging/validation
  primitives and prepared tests, not a public backup command or restore activation.

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
| `bootstrap_state.py`, `storage.py`, `daemon.py`, `test_bootstrap_crash.py`, `test_preview_crash.py`, `test_recovery_protocol.py` | PR48 initialization records/metadata are adapted to native keyed admission. Prepared bootstrap coverage adds storage-key write/directory-sync hooks and uses keyed fixture mutation only; preview preserves its four-point operation oracle. The relabel fixture first expects initialization refusal, then explicitly tampers both synthetic records to reach the independent receipt-binding checks. All native execution remains unrun. |
| `backup.py`, `admission.py`, `test_backup_contract.py`, `test_backup_native.py`, `BACKUP_CANDIDATE.md` | Held format-v2 staging/validation is imported with the bounded captured-policy parser. The native fixture initializes before taking its lease, while retaining lease ownership through Store/export/close. Current receipt and initialization metadata remain in full-row comparisons; no restore authority is inferred. Parser and native cases remain unexecuted. |
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
   PR48 additionally prepares 51 keyed-bootstrap and four preview process-exit
   points (55 additional; 122 across PR46/47/48). The three bootstrap additions
   versus MAIN cover the existing storage-key write and directory sync; these
   are literal source inventories, not observed native runtime outcomes.
5. Exercise prepared read-only observer behavior, WAL/SHM preservation and repeated
   writer commits. Verify each rotation/recovery fault and stable audit key, vault,
   capabilities and original receipts. Verify a durable pre-rotation locator still
   retrieves only its original receipt after successful rotation and after each
   recoverable rotation interruption; the latter combined fault matrix remains
   an explicit follow-up beyond the new successful-rotation contract.
6. Run all 17 demo checks; create reproducible sdist/wheel/SPDX twice; validate
   exact native dependency/provenance; install both archives offline in fresh
   environments, Unicode init and relocated helper smoke. Verify the exact native
   dependency metadata and the separate helper-only runtime without SQLCipher.
   This isolated probe does not authorize privileged installation or activation.

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
remain unchanged. No public backup surface or native authority was added. Keep #7 and
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
unsupported encrypted Windows path. At this PR46/47 checkpoint, no bootstrap
state markers, preview matrix, new production code, platform skip exception,
dependency pin, hash, license or NOASSERTION change was included; the subsequent
PR48 preparation is described separately below. Validation is limited to stdlib AST
parsing/comparison, textual diff hygiene and unchanged protected/ignored source
inventory. There were no application imports, test runs, native execution, key or
vault access, builds, artifact retrieval or remote publication in this refresh.
An independent source-only review confirmed executable AST equality for all five
files, the existing keyed-Store interfaces and unchanged protected inputs before
the unsigned local checkpoint. This is not native acceptance.


## PR48 keyed initialization and preview preparation

This subsequent source-only adaptation starts from local `03d67b8` and merged MAIN
`d0ba7f5`. It preserves native platform/runtime admission, key-first SQLCipher
configuration, query-only metadata admission, rotation/custody refusal, current
backend pins and license holds. Immutable private claim/completion records and a
transactional protocol flag contain interrupted initialization without silently
repairing an anchor or adopting incomplete residue. Their guarantee is no usable
partially initialized new-protocol vault, not filesystem rollback or same-user
tamper/freshness resistance.

`test_bootstrap_crash.py` is intentionally adapted rather than AST-identical:
its source inventory has 51 points, native storage-mode/cipher-integrity checks,
distinct synthetic storage/audit keys and keyed metadata-fixture mutations. The
existing native directory sync remains real inside its observer hooks. No native
guard is replaced, no missing backend is skipped and no plaintext connection is
used for the encrypted fixture. The 11 bootstrap methods include incomplete and
malformed records, daemon/initializer races, structural readback, lost markers,
metadata/schema refusal before hardening/migration, and unmodified legacy/missing
anchor semantics. Completion remains after verified checkpoint and close.

`test_preview_crash.py` retains MAIN's executable behavior except its Windows skip
reason; its four-point matrix creates no target grant or canonical memory. The
recovery-protocol relabel fixture keeps both initialization refusal and original
MAC/locator positive/negative controls. Neither preview nor an unknown result
authorizes replay. Required verification remains the full native application gate
on each approved ABI; tests, native provider activity, key/vault access and builds
were not run for this source-only preparation. Source parsing and review are not
runtime acceptance. Windows encrypted execution and real human-presence, custody,
backup-freshness and license gates remain unchanged.

## Format-v2 backup candidate integration

The subsequent source-only increment adds the reviewed internal candidate from
`238418d` and its prepared tests. Its schema and audit verifier match this held
application. New exports use format 2 with an optional untrusted checkpoint;
legacy format 1 still requires its strict nonnull checkpoint and matching marker.
Results remain `staged_not_published` / `validated_not_activated`,
`restore_ready: false`, `freshness: unverified` and
`revocation_reconciliation: not_performed`.

The narrow parser extraction lets both private-file admission and embedded-policy
validation use the same bounded captured bytes. Three additional pure contracts
cover absent/default policy, agreement with a real private-file load, and uniform
refusal of malformed, duplicate, oversized and nonbyte inputs. The native fixture
now bootstraps before taking its daemon lease, which is then held before Store
opening and through export and close. Full-row/control-file comparisons preserve
newer receipt bindings and initialization records without granting them authority.

No CLI/MCP wiring, restore/activation implementation, authority selection, native
execution, test execution, build, artifact retrieval, publication, pin/hash or
NOASSERTION change is part of this integration. Base issue #4 still needs an
approved fresh-vault restore/owner-access contract and native acceptance;
independent freshness/revocation remains separate issue #6 work. See
[the held backup contract](BACKUP_CANDIDATE.md) for exact limits and open gates.

## Authorized Linux evaluation (2026-09-29)

The owner subsequently authorized publishing this source as a **draft PR** and
running the pinned Linux SQLCipher application tests on disposable runners with
synthetic data only and **no artifact uploads**. This supersedes the earlier
execution/publication hold only for that evaluation. It is not license, merge,
release, real human-presence, OS-managed custody, or restore-activation approval.

The source includes main's PR49 approval-key tests and PR50 proposal-forget crash
tests, reconciled against main `829369b`. The existing encrypted application
workflow runs once per PR update across CPython 3.11–3.14. Each job verifies
signed, hash-pinned inputs, performs two network-disabled native builds, compares
the locked wheel, tests offline installation, and runs full application discovery,
the 17-check synthetic demo and offline package verification. Source and runtime
version pins, expected wheel digests and license `NOASSERTION` remain unchanged.

The standalone native wheel job is held and its artifact uploader removed; only
that reviewed workflow's manifest digest changes. The other platform/source
workflows are manual-only on this evaluation draft, because this gate includes
the complete Linux verifier. Main's platform CI is unchanged. These evaluation
trigger restrictions must be reviewed before any eventual merge.

Native results are pending until the hosted run completes; source review is not
runtime acceptance. Real Linux polkit approval, qualified binding-license review,
isolated key custody, backup freshness/revocation and activated restore remain
open. Native macOS and Windows encrypted operation are not evaluated here. No
release tag or asset is changed by this draft.

### First runtime evaluation and focused repairs

Run `36639313203` at `f48622e` passed both independent native builds, locked wheel
comparison and encrypted runtime smoke on all four ABIs. Full application
verification failed: 619 tests, 14 failures, 101 errors and 91 platform skips per
ABI. It did not pass the full application or packaging gate.

The first repairs preserve the tests and production guards: use CPython's Python
SQL serializer on the existing SQLCipher connection where that binding lacks
`iterdump`; fix a synthetic report count after removing a whole module; retain
completed-bootstrap records in the rotation fixture; and import Store in two
transport tests. A real native snapshot regression checks FTS, blobs, quoting and
unchanged connection/anchor state. Backup failures still need their exact native
predicate isolated; test-only stage diagnostics do not weaken production refusal.

The installer compatibility repair admits only the exact existing dependency
metadata and adds a separate actual-wheel, offline helper-only import/relocation
probe without SQLCipher. It leaves privileged installation and real polkit
acceptance unexecuted. These repairs require another hosted evaluation; no local
application/native tests, privileged installation, merge or release are claimed.
