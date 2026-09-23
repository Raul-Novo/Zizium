> Historical checkpoint. Later progress reports supersede its current-state claims.

# Zizium verified progress report

Phases 0–7 remain complete for their recorded milestones. Phase 8 remains ACTIVE.
This checkpoint completes initial private Security-directory provisioning.
It does not implement a persistent identity database, credentials or logon.
The preceding checkpoint is archived in
[the native-identity report](docs/reports/2026-09-16-native-identity.md).

## 1. Date and time

Work resumed across 2026-09-16, 2026-09-17 and 2026-09-19.
Final verification: 2026-09-19 approximately 17:42 Europe/Madrid (UTC+02:00).
The repository and process state were inspected again after each interruption.

## 2. Summary

The formatter now serialises two real ZiFS security descriptors. Public initial
records retain ID 1. The exact Zizium\Security relative path and its descendants,
including formatter-imported files, receive ID 2. That descriptor grants only
SYSTEM:1 explicit FullControl. Owner is SYSTEM:1; primary group Administrators
does not confer access. No path-based runtime bypass was added.

An independent host fixture checks the actual encoded descriptor and eight
exact-case paths. Boot exercises the real authorised lookup and requires the
new ZIFS_PRIVATE_SECURITY marker. All existing boot and durability gates remain.

## 3. Exact files created

- scripts/private_storage_tests.py
- docs/reports/2026-09-16-native-identity.md

## 4. Exact files modified

- .clang-tidy
- tools/mkzifs/main.c
- kernel/init/main.c
- scripts/build_driver.py
- README.md
- docs/README.md
- userland/services/manifests/README.md
- docs/security.md
- docs/zifs.md
- docs/identity.md
- docs/accounts.md
- docs/identity_security.md
- docs/architecture.md
- docs/boot.md
- docs/build.md
- docs/continuation.md
- ZIZIUM_PLAN.md
- ZIZIUM_PROGRESS.md

This is the known edit inventory, not a Git diff: this workspace has no Git
metadata. Generated images, logs and non-secret test payloads remain in build/.
The archived report preserves the prior body beneath a historical banner.

## 5. Exact files deleted

None. Build commands regenerated only their scoped build artefacts.

## 6. Build commands run

Commands ran from C:\dev\osdev\Zizium through the existing build graph.
The PowerShell helpers loaded the installed x64 Visual Studio environment.

| Command | Log beneath build/ | Result |
| --- | --- | --- |
| make image | phase8-private-image1.log | pass |
| make release | phase8-private-release.log | pass |
| make release | phase8-private-release-repeat.log | pass; all 21 selected artefacts match |
| make intel | phase8-private-intel.log | pass; 39 groups/3,465 assertions |
| make image | phase8-private-image-final.log | pass; normal debug image restored |
| make deps | phase8-private-deps.log | pass; existing pins verified, no downloads |

Intel validation used the installed compiler by prepending
C:\Program Files (x86)\Intel\oneAPI\compiler\2026.0\bin to that command's PATH.
It does not replace the normal toolchain and is not a claim that every host
tool or the kernel was compiled with Intel.

Release comparison required exactly 21 files: kernel/zizium.efi,
images/zizium-root.zifs, images/zizium.img and all 18 directly contained native
.exe/.dll/.lib/.sys files. PowerShell Get-FileHash SHA256 compared both builds
and reported all 21 identical. PDBs and host tools are outside that claim.

## 7. Test and analysis commands run

| Command | Log beneath build/ | Result |
| --- | --- | --- |
| make test | phase8-private-baseline.log | baseline log: 39 groups/3,465 assertions and inspector/repair/manifests completed |
| make test | phase8-private-test1.log | pass; 39 groups/3,465 assertions plus new private-storage fixture |
| make analyse | phase8-private-analyse1.log | failed: required public ABI naming exceptions absent |
| make analyse | phase8-private-analyse2.log | failed: new Boolean-to-integer conditional diagnostic |
| make analyse | phase8-private-analyse3.log | pass after narrow fixes |
| make sanitise | phase8-private-sanitise1.log | pass; 39 groups/3,465 assertions plus private fixture |
| make boot-test | phase8-private-boot1.log | pass; all old and new required markers |
| make zifs-test | phase8-private-zifs.log | pass; all 32 persistent QEMU cases |
| make storage-test | phase8-private-storage.log | pass; timeout and corrupt-GPT cases |
| make fault-test | phase8-private-fault.log | pass; invalid opcode, page fault, memory guard and user-fault containment |
| python scripts/check_spelling.py | tool output | pass before report; repeated after report |

clang-format -i was run on tools/mkzifs/main.c and kernel/init/main.c.
Analysis includes the format gate and current Clang-Tidy configuration.
Host tests include strict compilation, self-contained headers, inspector/repair
fixtures and fifteen service manifests. Sanitisation is AddressSanitizer, not
a UBSan/TSan claim.

The old baseline handle 57421 was absent after interruption. Its final log and
absence of live processes were inspected; fresh test1 supplied a directly
observed terminal-success baseline for the changed formatter. No process was
restarted solely because an observation timed out.

## 8. Results and evidence

All final command handles reached terminal success. Host group/assertion
counts are unchanged because the additional test is a formatter integration
fixture, not an extra C unit-test group.

The fixture runs the actual formatter and read-only C inspector, checks
non-mutation, then independently verifies the exact SYSTEM-only descriptor.
It checks Security, two child names differing only in case and containing
spaces, SecurityOther, lowercase security, Temp\Security, Temp and Zizium.
Distinct exact paths must resolve to distinct records. Parent protection
cannot conceal a wrongly public child: the child record's own ID is checked.

Boot checks all eight individual rights on Security under SYSTEM:1, USER:21,
SERVICE:1 and SYSTEM:2. Tokens include Administrators, Users and Guests groups,
so group metadata cannot supply an implicit grant. SYSTEM:1 succeeds; other
principals fail with unchanged output. A nonexistent child yields NotFound to
SYSTEM:1 but AccessDenied to others before traversal. This is a runtime ACL
decision, not merely a wire-format assertion.

Normal boot also retains SERVICE_POLICY_DENIED, IMAGE_ACCESS_DENIED,
USER_SESSION and ZIFS_CLEAN_UNMOUNT. All 32 durability boots retain the
private marker, including the explicit clean recovery-module case after
security corruption. Persistent file operations, crash recovery and repair
tests did not regress.

SHA-256 after normal debug restoration:

- debug/kernel/zizium.efi:
  494e638b10fa8c2fc4df1e10bac3ea4d6d3791b9a363aac755fba6b56eba8290
- debug/images/zizium-root.zifs:
  6728c645e9f54705bca34e38c0a73269ba7f8d76158931062396311d101bc194
- debug/images/zizium.img:
  a710d3229992b06691ef3764c5e8195908bae5b4d2cc3c5fe54b9c4d2c6a1826
- release/kernel/zizium.efi:
  f2cfbccc1bf774858d2faae3f99a1fee631a84e7beecf8fb8bd23e0664dba3eb
- release/images/zizium-root.zifs:
  98c882fb793691dd3d8179f2d56aba81daeae3069c6cdab74893afa52d6f6eac
- release/images/zizium.img:
  5131404972da5c762bcc2e28eb6be00df7778b158fa80fda78e83c0c27383657

## 9. Errors encountered

Analysis first rejected existing ZkKernelMain/ZiSucceeded/ZiFailed because
the current root configuration again lacked the mandated ABI-name exceptions.
Both previously documented public-family exceptions were restored.

The next analysis rejected a new conditional's implicit bool-to-int conversion.
An explicit if replaced that conditional; no diagnostic suppression was added.
Two patch submissions were rejected during validation and reapplied correctly;
no partially applied source change or unresolved build failure remains.

## 10. Warnings and style conflicts

Only FunctionIgnoredRegexp and GlobalConstantIgnoredRegexp for Zi/Zx/Zk/ZiFs
were added to the observed Clang-Tidy configuration. Public ABI naming is a
frozen contract conflicting with the generic function/constant naming rules.

The observed configuration also contained -cert-err33-c and
-readability-function-size exclusions, unlike the earlier report. Those
separate existing changes were preserved, not introduced here. Analysis
success reflects the actual current configuration, not coverage of those
disabled checks. No assumptions are made about who changed the file.

The strict -Weverything -Werror compiler policy and central exception inventory
were not relaxed. The other four root style files were not edited.

## 11. Missing dependencies

None for these verified gates. Native entropy, credential-library approval,
secret-memory/input infrastructure and the trusted identity database remain
implementation prerequisites rather than missing build tools.

## 12. Dependencies downloaded

None. make deps reused and verified these existing pins:

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

Initial private Security-directory and imported-child ACL provisioning,
independent formatter-image verification, real boot-time allow/deny/traversal
checks, mandatory marker integration, and unchanged public default policy.
The earlier native-identity codec and unpublished reservation primitive remain.

## 15. Scaffolded, not implemented

Database format/persistence, trusted issuer/volume/database-object binding,
transaction-backed issuance, tombstones, account provisioning, credentials,
logon tokens, dynamic ACL inheritance, descriptor updates, revocation,
privilege enforcement, elevation and persistent security audit remain incomplete.

## 16. Intentionally absent

No database file, credential, default password, new user account, token minting
API, implicit identity migration or custom cryptography was introduced.
The host fixture contains explicitly non-secret text and is not installed in
normal system images. No existing volume was rewritten to migrate its ACLs.

## 17. Remaining implementation sequence

1. Define and implement bounded identity-database records and trusted
   issuer/volume/file binding, using the existing native-identity codec.
2. Validate actual private metadata at the database boundary. Neither a path
   nor numeric security ID alone proves the correct policy or provenance.
3. Commit the high-water state and disabled record together through ZiFS before
   publishing an issued ID; preserve non-reuse and refuse ambiguous rollback.
4. Test malformed records, references, interruption and every relevant durable
   operation. Provisioning remains disabled until credentials/profile/ACLs exist.
5. Add reviewed credential handling, secure entropy/input/memory, two-user
   isolation, persistent inheritance, revocation, audit and explicit elevation.

## 18. Boot status

Normal UEFI/Limine/QEMU boot passes, including the new private-policy marker
and all previous process, service, storage, pre-emption and cleanup markers.
Fault/storage recovery paths and all 32 ZiFS cases also pass. Normal debug
images have been restored after validation. No account issuer runs at boot.

## 19. ZiFS status

Direct NVMe root, bounded transactions, journalling, recovery, inspection and
narrow offline repair remain verified. New volumes have two security
descriptors without changing the on-disk format or existing eight-byte IDs.
The private subtree uses ID 2; public records retain ID 1.

This is formatter placement, not runtime inheritance. Trusted transaction
callers still explicitly choose an existing security ID. A future database
must select and validate the private policy; no user file API can be inferred
from the existing kernel-only raw mutation interfaces.

## 20. Scheduler status

32 priorities and live uniprocessor kernel-thread pre-emption remain boot-tested.
No scheduler implementation changed. SMP and concurrent scheduled user
execution remain future work.

## 21. ACL/security status

Only SYSTEM:1 has an explicit grant on the new private descriptor. Administrator
membership and primary-group ownership do not bypass evaluation. ServiceHost
and SecurityHost currently share SYSTEM:1 bootstrap trust; this is not yet
a narrowly isolated resident credential broker.

No protection against hostile host/kernel/boot media or whole-volume rollback
is claimed. CRCs, UUIDs and generations do not supply authentication by themselves.

## 22. Terminal/Luma status

Existing bounded user-mode Luma and nested child launch still pass. USER:21
remains a restricted bootstrap demonstration, not a durable authenticated user.
Serial recovery input is not a secure credential channel.

## 23. Unicode status

UTF-8/UTF-16 and exact-case paths remain. Private policy placement preserves
case and separator boundaries; no case folding or normalisation was added.
Spaces and distinct child case are exercised in the formatter fixture.

## 24. Driver status

ACPI/PCIe, DMA/MMIO, IRP, GPT and polling QEMU NVMe continue to pass. No new
hardware support is claimed. Loadable drivers, broad USB/PnP and physical
hardware qualification remain incomplete.

## 25. PE/COFF status

Native PE kernel/programmes/DLLs, mapping/linking and per-image ACL enforcement
remain verified. No ABI, relocation, import policy or executable-format change.

## 26. ZCC/ZiCRT status

Standard C main and the minimal runtime still execute in QEMU. ZCC remains a
host Clang-driver scaffold; ZiCRT is not a complete C library. No new compiler
or runtime implementation was added.

## 27. ZIA/Zx status

Existing bounded process/debug/channel/wait/close calls remain. No account,
credential, privilege, ACL-mutation or elevation syscall was added.

## 28. Documentation status

All three project READMEs and affected architecture, boot, build, account,
security, identity, ZiFS, roadmap and continuation documents were updated.
The previous report is archived. This report was written last; subsequent
spelling and read-only verification do not alter source state.

## 29. Known limitations

Phase 8 and the daily-use OS objective remain incomplete. The private directory
is a prerequisite, not secure logon or complete access control. Old disposable
development images must be rebuilt; installed-system migration requires a
separately implemented journalled policy update. Existing kernel raw metadata
interfaces are trusted, not general authorised user file APIs.

## 30. Technical debt

- Trusted database binding and immutable snapshots across validation/use.
- Durable issuance, non-reuse, deletion, migration and provisioning state.
- Journalled descriptor updates, inheritance and isolated profiles.
- Credential dependency, entropy, secret lifecycle and protected broker IPC.
- Concurrent file/security locking, revocation and audit obligations.
- Review the separately observed Clang-Tidy exclusions without silently changing user configuration.
- No VCS metadata; preserve unrelated edits and keep explicit inventories.

## 31. Suggested next prompt

Continue Phase 8 from the verified private-storage checkpoint. Read AGENTS,
roadmap, this report, continuation, identity/security/accounts and ZiFS contracts.
Implement the bounded identity database and trusted issuer/volume/file binding,
then atomically persist disabled records with high-water state before publishing
IDs. Validate the actual private policy, not a path or descriptor number.
Add adversarial and crash tests, retain every old denial/durability gate, update
all affected READMEs/docs and write progress last. Keep the full OS goal active.

## 32. Continuation instructions

All reported validation command handles are terminal. Recheck processes before
starting later work; do not restart merely because an observation times out.
No account database or pending issuance exists in this checkpoint.

Preserve ID 1 for the public initial template and ID 2 for private initial
placement unless an explicit policy migration changes them. Runtime access
must remain descriptor-based. A file moved later retains its descriptor;
the formatter helper is not an inheritance or move-policy engine.
Do not publish zi_identity_reserve outputs before committing the database.

## 33. Frozen decisions

Keep product names and GPL-3.0-or-later work with separate third-party notices;
x64 first, UEFI/Limine through ZiBootContext, native PE/COFF, Microsoft x64 C ABI,
RAX/R10/RDX/R8/R9 syscalls, C17/minimal assembly, ZiFS-only root with frozen GPT
GUID 9ef9e22a-3719-44d4-89af-de9cc7b6b255, FAT32 ESP only, exact UTF-8 paths,
ordinary main/optional ZIA, default-deny ACLs with no implicit SYSTEM/admin
bypass, 32 priorities, rational per-output scaling, British English and the calm
palette. Preserve explicit identity migration, reserved/bootstrap separation,
strict warnings, crash recovery, fail-closed repair and truthful milestone claims.
