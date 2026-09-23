# Zizium verified progress report

Phases 0–7 remain complete for their recorded milestones. Phase 8 remains ACTIVE.
This checkpoint implements the host-tested disabled identity database/store and
corrects a ZiFS checkpoint-recovery prerequisite. It does not implement native
database boot integration, production enrolment, credentials or logon.
The previous report is archived in
[the private-storage checkpoint](docs/reports/2026-09-19-private-storage.md).

## 1. Date and time

Work continued across 2026-09-19, 2026-09-20 and 2026-09-21.
Final gate observation: 2026-09-21 18:07 Europe/Madrid (UTC+02:00).
Source, logs and process state were rechecked after interruptions.

## 2. Summary

Added a 36,864-byte version-one database with 64 bounded records, issuer/volume/
database binding, exact UTF-8 names, dynamic identity high-water values, disabled
states, group references, tombstones and CRC32C. A kernel-only store validates
the actual private file descriptor and supplied token before payload reads,
commits the complete database through ZiFS, and publishes an ID only after
commit succeeds. Uncertain commit freezes the store pending trusted recovery.

Host tests interrupt all 39 write/flush boundaries of both issuance and deletion
and require the complete recovered database to equal the old or new snapshot.
They found that ZiFS rejected a valid durable CHECKPOINT before final empty
journal-header publication. Recovery now validates that evidence against the
complete redo set and matching COMMIT; six malformed variants fail before writes.

No account database is installed or used by normal boot. This is a persistence
prerequisite, not authenticated account management or Phase 8 completion.

## 3. Exact files created

- kernel/include/zi/identity_database.h
- kernel/include/zi/identity_store.h
- kernel/executive/security/identity_database.c
- kernel/executive/security/identity_store.c
- tests/host/phase8_database_test.c
- tests/host/phase8_store_test.c
- docs/identity_database.md
- docs/reports/2026-09-19-private-storage.md

## 4. Exact files modified

- kernel/fs/zifs/recovery.c
- scripts/build_driver.py
- tests/host/phase8_tests.h
- tests/host/test_main.c
- README.md
- docs/README.md
- userland/services/manifests/README.md
- docs/accounts.md
- docs/architecture.md
- docs/boot.md
- docs/build.md
- docs/continuation.md
- docs/identity.md
- docs/identity_security.md
- docs/security.md
- docs/zifs.md
- ZIZIUM_PLAN.md
- ZIZIUM_PROGRESS.md

These lists describe the database checkpoint relative to the previous report,
not every dirty Git path. Git metadata is now present at this workspace, unlike
the previous checkpoint; HEAD observed as 2027db6. Existing edits in .clangd,
.clang-tidy, identity.c, main.c, mkzifs and earlier identity/private-storage
files were preserved. No commit, reset, staging or unrelated rewrite was made.
ZIZIUM_PLAN.md and ZIZIUM_PROGRESS.md are currently ignored by Git but remain
real maintained workspace files. Generated artefacts and logs are under build/.

## 5. Exact files deleted

None. Builds regenerated only scoped build artefacts.

## 6. Build commands run

All commands ran from C:\dev\osdev\Zizium through the existing Make/PowerShell
graph. The wrappers load the installed x64 Visual Studio environment.

| Command | Log beneath build/ | Result |
| --- | --- | --- |
| make image | phase8-database-image1.log | pass; raw and GPT inspection valid |
| make release | phase8-database-release1.log | pass |
| make release | phase8-database-release2.log | pass |
| make intel | phase8-database-intel1.log | pass; 41 groups/4,401 counted assertions |
| make intel | phase8-database-intel2.log | pass; strengthened tests, 41 groups/4,481 |
| make image | phase8-database-image2.log | pass; normal debug image restored |
| make deps | phase8-database-deps1.log | pass; existing pins verified, no downloads |

The two release builds were separated by Get-FileHash SHA256 snapshots of
exactly 21 files: kernel/zizium.efi, images/zizium-root.zifs, images/zizium.img,
and every directly contained native .exe/.dll/.lib/.sys artefact. Count and
every hash matched. The command reported all 21 byte-identical and exited zero.
PDBs and host tools are outside that comparison. The later changes strengthened
host tests only; production sources did not change after these release builds.

Optional Intel runs prepended
C:\Program Files (x86)\Intel\oneAPI\compiler\2026.0\bin to PATH for that
command. They do not replace the normal toolchain or qualify every kernel/tool
under Intel. No toolchain or dependency was installed.

## 7. Test and analysis commands run

| Command | Log beneath build/ | Result |
| --- | --- | --- |
| make test | phase8-database-baseline.log | pass; 39 groups/3,465 |
| make test | phase8-database-test1.log | pass; codec, 40 groups/3,793 |
| make test | phase8-database-test2.log | fail; 40/41 groups, remount failure |
| make test | phase8-database-test3.log | fail; same defect, first diagnostic placed too early |
| make test | phase8-database-test4.log | fail; operation 37 remount returned -15 |
| make test | phase8-database-test5.log | pass after recovery fix; 41 groups/4,533 |
| make test | phase8-database-test6.log | pass with negative checkpoint cases; 41 groups/4,558 |
| make analyse | phase8-database-analyse1.log | fail; arithmetic-parenthesis diagnostics |
| make analyse | phase8-database-analyse2.log | fail; missing direct ZiAccessMask include |
| make analyse | phase8-database-analyse3.log | fail; codec-test complexity and test arithmetic |
| make analyse | phase8-database-analyse4.log | fail; store-test complexity |
| make analyse | phase8-database-analyse5.log | fail; test diagnostic bool conversion |
| make analyse | phase8-database-analyse6.log | pass |
| make test | phase8-database-test7.log | pass after helper refactor; 41 groups/4,401 |
| make sanitise | phase8-database-sanitise1.log | pass; AddressSanitizer, 41 groups/4,401 |
| make boot-test | phase8-database-boot1.log | pass; all required normal markers |
| make zifs-test | phase8-database-zifs1.log | pass; all 32 persistent QEMU cases |
| make storage-test | phase8-database-storage1.log | pass; timeout and corrupt-GPT cases |
| make fault-test | phase8-database-fault1.log | pass; invalid opcode, page fault, guard and user fault |
| make analyse | phase8-database-analyse7.log | pass; stronger snapshot tests |
| make test | phase8-database-test8.log | pass; 41 groups/4,481 |
| make sanitise | phase8-database-sanitise2.log | pass; AddressSanitizer, 41 groups/4,481 |
| python scripts/check_spelling.py | tool output | pass before report; repeated after report |

clang-format -i formatted the new headers/sources/tests, recovery.c and affected
test declarations/registration. Analysis includes the repository format gate,
Clang-Tidy and analyser checks with project diagnostics treated as errors.
Host gates include strict compilation, self-contained headers, the private
formatter fixture, inspector/repair fixtures and service-manifest validation.
Sanitisation means AddressSanitizer here, not a UBSan/TSan claim.

The helper refactor replaced some counted EXPECT wrappers with equivalent
failure-return checks and direct helper propagation. Thus 4,558 became 4,401
without removing crash prefixes or weakening the conditions. Exact whole-file
snapshot comparisons then added 80 counted checks, yielding 4,481.

## 8. Results and evidence

All final validation chains reached terminal success. The older 10589 session
handle was missing after interruption; completed analysis/test/sanitisation
logs and process state were inspected rather than assuming a timeout meant
failure. The later image/boot/ZiFS, storage/fault/release/Intel and strengthened
analysis/test/ASan/Intel/image/dependency chains all returned exit zero directly.
No build was restarted solely because an observation timed out.

Codec tests cover header golden bytes, reserved bytes, truncated/oversized input,
CRC failures, every binding UUID byte, generation floors, record shape, duplicate
NIDs, high-water exhaustion, capacity, disabled/tombstone states, group references,
exact case, spaces and canonically distinct names. Semantic corruption fixtures
recompute checksums so rejection is not hidden behind a checksum mismatch.

The store fixture creates the real database file through ZiFS transactions and
uses private descriptor ID 7, proving policy is not inferred from formatter ID 2.
Unauthorised users with administrator membership and wrong file/volume bindings
are rejected without payload reads. Valid but broadly readable policy fails even
for SYSTEM. Issuer/database substitution and stale generation fail closed.

Both 39-boundary crash campaigns require old-or-new complete database bytes,
coherent counters/states, unchanged unpublished output and recovery-required
poisoning after an uncertain commit. Tests reject wrong checkpoint sequence,
image count or digest, duplicate checkpoint, missing COMMIT and wrong COMMIT
image count with recomputed CRCs and zero recovery writes.

All 32 existing QEMU ZiFS durability cases remain green. They are regression
evidence for the changed recovery path, not native identity-store boot evidence.

SHA-256 after final normal debug restoration:

- debug/kernel/zizium.efi:
  53fbe3d6e6628aec157b86be33b0ccfea013be27e9619d4cc3ac26606fa17f63
- debug/images/zizium-root.zifs:
  6728c645e9f54705bca34e38c0a73269ba7f8d76158931062396311d101bc194
- debug/images/zizium.img:
  35535f410c544ba3809e9a95bab00a940067de6ba9e535c6715b710211e998a2
- release/kernel/zizium.efi:
  423dd1f23af77e5cee8e4af30000c2ca43675eacbfe71d3c0bc7eae5b4b85516
- release/images/zizium-root.zifs:
  98c882fb793691dd3d8179f2d56aba81daeae3069c6cdab74893afa52d6f6eac
- release/images/zizium.img:
  044a042c628bd01b442283c3259a090638375e2fa8233ca127251e24a3a337ea

## 9. Errors encountered

The original storage fault tests found the real ZiFS operation-37 checkpoint
window described above. It was fixed rather than weakening the recovery test.

Analysis failures were repaired with explicit arithmetic grouping, a direct
types include, focused test helpers and an explicit diagnostic-string branch.
No new warning suppression or lint exclusion was added. One documentation
patch failed context validation and was reapplied with the exact current lines;
there was no partial source edit from that failed submission.

## 10. Warnings and style conflicts

No unresolved project diagnostic remains in the final gates. No root style
file changed during this database checkpoint. The previously observed narrow
public ABI naming exceptions and existing cert-err33-c/function-size exclusions
remain. Existing .clangd MissingIncludes: None was preserved. Analysis claims
refer to the actual configuration, not disabled checks. Strict
-Weverything -Werror and its central documented exception inventory remain.

## 11. Missing dependencies

None for the executed gates. Approved credential code, native entropy,
protected secret memory/input, trusted production enrolment and broker IPC are
unfinished implementation prerequisites, not missing build tools.

## 12. Dependencies downloaded

None. make deps verified the existing manifest pins:

- Limine 12.5.2:
  a4b4539e4229c25f5ceba93ada8a71b8a2c57d7b7900ea5f86c588e1b7afe621
- Limine protocol 630686a3dd3ce40f9e510a7dd9fea6b4c60d952e:
  4de542d1c232b230ca4af04c5b89a78f51c9bdacb928a94ac44fc88377208a63
- Spleen 2.2.0:
  ec42925c6b56d2138c862b2f97147c872e472f674bf03423417d827a08d69a89
- Unicode UCD 17.0.0:
  2066d1909b2ea93916ce092da1c0ee4808ea3ef8407c94b4f14f5b7eb263d28e

## 13. Downloads not completed

None attempted unsuccessfully. No cryptographic dependency was adopted.

## 14. Implemented

Host-tested database codec, actual private-policy and token checks, supplied
issuer/volume/database/file binding, in-session generation floor, atomic disabled
issuance and high-water commit, tombstone non-reuse, bounded group references,
uncertain-commit poisoning, adversarial/crash tests and the ZiFS recovery fix.

## 15. Scaffolded, not implemented

Normal-boot database integration, trusted production binding/enrolment, account
broker IPC, enabled account state, credentials, profile provisioning, logon
tokens, inheritance, descriptor updates, privilege enforcement, revocation,
elevation and durable security audit remain incomplete.

## 16. Intentionally absent

No database or default credential is installed in normal images. No password,
new authenticated account, token constructor, implicit legacy identity migration
or custom cryptography was introduced. Fixture UUIDs are not production issuers.
The database has no credential fields and accepts no enabled account state.

## 17. Remaining implementation sequence

1. Add dedicated native NVMe identity persistence acceptance: disabled issuance,
   reboot, tombstone, reboot, same-name reissuance and final reboot validation.
2. Supply the expected issuer/volume/database/file binding independently through
   trusted test provisioning. Add wrong-binding and non-SYSTEM denial cases.
3. Implement production enrolment, approved entropy and explicit recovery/
   migration policy; do not treat fixture acceptance as installed-system trust.
4. Add reviewed credential handling, protected IPC/input/memory and atomic or
   resumable disabled profile/ACL provisioning.
5. Complete two-user logon/isolation, inheritance, revocation, audit and elevation
   before declaring Phase 8 done; then continue the roadmap.

## 18. Boot status

Normal UEFI/Limine/QEMU boot passes, retaining all architecture, memory, Ring-3,
service/session, denial, private-policy and clean-unmount markers. Storage/fault
paths and all 32 ZiFS cases pass. The normal debug image was restored after tests.
The database C sources build with the kernel but no live boot path uses them yet.

## 19. ZiFS status

Direct NVMe root, bounded transactions, journal, lifecycle, inspector and narrow
offline repair remain verified. Recovery now recognises a fully validated
durable CHECKPOINT before final header publication and checks COMMIT image count.
It still rejects ambiguous/corrupt evidence and never reconstructs ACLs.
The new store uses the existing nine-data-block write path; no ZiFS format change.

## 20. Scheduler status

32 priorities and live uniprocessor kernel-thread pre-emption remain boot-tested.
No scheduler change. SMP and concurrent scheduled user execution remain future.

## 21. ACL/security status

Store access requires actual SYSTEM:1-only file policy and ordinary token
evaluation; administrator membership is not a bypass. Normal private initial
placement still uses descriptor ID 2. ServiceHost and SecurityHost share
bootstrap SYSTEM trust; no resident isolated credential broker exists.

CRCs and UUIDs do not authenticate hostile storage. The generation floor protects
one canonical running store only; whole-volume rollback across reboot remains
undetectable. Unknown high-water history requires explicit trusted recovery or
a new authority, never silent resumption under an old issuer.

## 22. Terminal/Luma status

The bounded user-mode session and standard-C child launch still pass. USER:21
is a restricted bootstrap demonstration, not a durable authenticated user.
Serial/history/scrollback remain forbidden credential channels.

## 23. Unicode status

UTF-8/UTF-16 and exact-case paths remain unchanged. Database names preserve
spaces, case and canonical distinctions, reject controls and path separators,
and are attributes rather than unchecked profile paths.

## 24. Driver status

ACPI/PCIe, DMA/MMIO, IRP, GPT and polling QEMU NVMe continue to pass. No broader
hardware support, loadable driver lifecycle, USB/PnP or physical qualification
is claimed.

## 25. PE/COFF status

Native PE kernel/programmes/DLLs, mapping/linking and per-image ACL enforcement
remain verified. No native-format or syscall ABI change.

## 26. ZCC/ZiCRT status

Ordinary C main and the minimal runtime still execute in QEMU. ZCC remains a
host Clang-driver scaffold and ZiCRT is not a complete C library.

## 27. ZIA/Zx status

Existing bounded process/debug/channel/wait/close interfaces remain. No account,
credential, privilege, ACL-mutation or elevation syscall was introduced.

## 28. Documentation status

Added the database wire/ownership/recovery contract and archived the prior report.
Updated all affected project READMEs, accounts/security/identity, architecture,
boot/build, ZiFS, roadmap and continuation documents. Unrelated subsystem and
third-party READMEs did not require changes. This report is written last;
subsequent spelling/read-only checks do not change source state.

## 29. Known limitations

The database has 64 lifetime occupied slots including tombstones, names up to
128 UTF-8 bytes and 16 memberships. It is single-writer, disabled-only and has
no compaction, nesting, membership-edit API, credentials or native boot use.
Trusted caller state must remain stable and non-overlapping with workspaces.
Fixture persistence is not installed-system identity provenance or logon.
ZiFS and the full operating system remain unsuitable for irreplaceable data
or a daily-use security claim.

## 30. Technical debt

- Native database boot acceptance and trusted production provisioning.
- Durable recovery/non-reuse policy across snapshots/clones and reboot.
- Concurrent store/volume locking, revocation and immutable validation snapshots.
- Writes currently use timestamp zero; integrate a real time provider explicitly.
- Journalled descriptor changes, inheritance and private profiles.
- Credential dependency, entropy, secret lifecycle and protected broker IPC.
- Migration beyond bounded records/inline extents without reusing identities.
- Preserve unrelated dirty Git state and the current style configuration.

## 31. Suggested next prompt

Continue Phase 8 from the host-tested database checkpoint. Read AGENTS, this
report, the roadmap, continuation and identity_database/identity_security/ZiFS
contracts. Implement dedicated native NVMe identity issuance/deletion/reissuance
reboot tests with independent trusted fixture binding and negative access cases.
Do not derive expected trust from the file under test or enable credentials.
Retain all existing gates, then implement production enrolment and the remaining
credential/profile/ACL prerequisites. Update affected READMEs/docs and progress
last. Keep the full daily-use OS goal active.

## 32. Continuation instructions

All final validation processes are terminal; no live QEMU or build job is being
handed off. Recheck authoritative process state on resume. Do not restart a job
merely because observation times out.

Use the source as truth: database/store exist and pass host/ASan/Intel gates;
normal boot contains no database. Read docs/identity_database.md for the exact
next six-stage native fixture and binding requirements. Keep the operation-37
regression, six negative checkpoint cases and full old/new byte comparisons.
Do not publish codec candidates before store commit or automatically retry
after an uncertain commit. Do not reset a running store's generation floor.

## 33. Frozen decisions

Preserve product names, GPL-3.0-or-later work and third-party licences; x64 first,
UEFI/Limine behind ZiBootContext, native PE/COFF, Microsoft x64 C ABI,
RAX/R10/RDX/R8/R9 syscalls, C17/minimal assembly, ZiFS-only root and frozen GUID
9ef9e22a-3719-44d4-89af-de9cc7b6b255, FAT32 ESP only, exact UTF-8 paths,
ordinary main/optional ZIA, default-deny ACLs without SYSTEM/admin bypass,
32 priorities, rational per-output scaling, British English and the calm theme.
Keep explicit identity migration, reserved/bootstrap separation, strict warnings,
crash recovery, fail-closed repair and evidence-based milestone claims.
