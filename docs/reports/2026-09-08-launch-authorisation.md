# Historical report — launch authorisation prerequisite

Preserved from the preceding checkpoint; the root progress report is current.

# Zizium verified progress report

Phases 0–7 remain complete for their recorded milestones. Phase 8 is ACTIVE.
This checkpoint completes the bootstrap service/image authorisation prerequisite,
not identity issuance, secure logon, or Zizium 1.0. The preceding checkpoint is
preserved in [the historical report](docs/reports/2026-09-08-phase8-prerequisites.md).

## 1. Date and time

2026-09-08, Europe/Madrid (UTC+02:00). Final release/dependency evidence was
collected at approximately 21:46–21:47. The preceding user-requested summary
was a status-only turn; this continuation made and verified repository changes.

## 2. Summary

- Replaced FNV-1a service principal generation with an explicit approved
  name/path/declared-identity/token-policy table.
- Removed Administrators memberships from bootstrap services, SessionHost,
  Luma and the ordinary-C acceptance programmes.
- Restricted SYSTEM launches to ServiceHost and SecurityHost; their tokens
  have no groups. LogHost, MountHost and SessionHost use distinct reserved
  SERVICE values 1, 2 and 3 with Users membership and zero privileges.
- Corrected SessionHost's manifest to NID:SERVICE:SessionHost.
- Added token-bound directory traversal and EXE/DLL access checks to the
  actual filesystem image source path, before image payload allocation/read.
- Checked core DLL sources separately for each acceptance process token.
- Added hostile host fixtures and live QEMU service/image denial markers.
- Updated every project README and all affected subsystem/continuation docs.

## 3. Exact files created

- kernel/include/zi/service_identity.h
- kernel/executive/service/identity.c
- tests/host/phase8_service_identity_test.c
- docs/reports/2026-09-08-phase8-prerequisites.md

## 4. Exact files modified

- README.md
- ZIZIUM_PLAN.md
- ZIZIUM_PROGRESS.md
- docs/README.md
- docs/accounts.md
- docs/architecture.md
- docs/boot.md
- docs/continuation.md
- docs/identity_security.md
- docs/pe_coff.md
- docs/processes.md
- docs/security.md
- docs/services.md
- docs/terminal.md
- docs/zifs.md
- kernel/executive/service/manifest.c
- kernel/fs/zifs/zifs.c
- kernel/include/zi/zifs_image_source.h
- kernel/include/zi/zifs_security.h
- kernel/init/main.c
- kernel/init/system_bootstrap.c
- kernel/pe/zifs_image_source.c
- scripts/build_driver.py
- tests/host/phase6_service_test.c
- tests/host/phase6_zifs_test.c
- tests/host/phase8_tests.h
- tests/host/test_main.c
- userland/services/manifests/README.md
- userland/services/manifests/SessionHost.zsvc

No Git metadata is available. This is the known edit inventory, not a Git diff.
Generated build outputs/logs/images remain beneath build/ and are not counted
as source additions. All five root style files were read and left unchanged.
No unrelated source edits were deliberately reverted.

## 5. Exact files deleted

None. Builds regenerate their scoped artefacts; no project source or installed
firmware template was deleted.

## 6. Build commands run

Commands ran from C:\dev\osdev\Zizium through the existing Make/PowerShell graph.
The PowerShell wrappers loaded the installed x64 Visual Studio environment.

| Command | Log beneath build/ | Result |
| --- | --- | --- |
| make image | phase8-service-image.log | pass |
| make image | phase8-image-image1.log | pass |
| make image | phase8-launch-image.log | pass |
| make release, twice | phase8-launch-release1.log, phase8-launch-release2.log | both builds pass; first comparison accidentally covered only 20 artefacts |
| make intel | phase8-launch-intel.log | pass, 38 groups/3,285 assertions |
| make image | phase8-launch-normal-image.log | pass, normal debug image restored after serial durability suite |
| make release, twice | phase8-launch-release3.log, phase8-launch-release4.log | both pass; corrected explicit 21-artefact SHA-256 comparison passes |
| make deps | phase8-launch-deps.log | pass; four existing pins checksum-verified, no download |

Intel invocation prepended the installed
C:\Program Files (x86)\Intel\oneAPI\compiler\2026.0\bin directory to PATH
for that shell. It did not change the default toolchain or invalidate normal artefacts.

The corrected reproducibility command used PowerShell ErrorActionPreference=Stop,
required exactly 21 selected files, recorded Get-FileHash -Algorithm SHA256
after the first build and compared every result after the second. Selection:
release/kernel/zizium.efi; release/images/zizium-root.zifs and zizium.img;
and the 18 .exe/.dll/.lib/.sys files directly in release/native.
PDBs and host-tool executables are outside this 21-file comparison.

## 7. Test and analysis commands run

| Command | Log beneath build/ | Result |
| --- | --- | --- |
| make test | phase8-launch-baseline-current.log | baseline pass: 36 groups/3,079 assertions |
| make test | phase8-service-test1.log | fail: incorrect new assertion-counter identifier |
| make test | phase8-service-test2.log | pass: 37 groups/3,175 assertions |
| make analyse | phase8-service-analyse1.log | fail: bool conditional conversion diagnostic |
| make analyse | phase8-service-analyse2.log | fail: new test complexity |
| make analyse | phase8-service-analyse3.log | fail: remaining approved-case complexity |
| make analyse | phase8-service-analyse4.log | pass |
| make boot-test | phase8-service-boot.log | pass |
| make test | phase8-image-test1.log | pass for adapted existing tests |
| make test | phase8-image-test2.log | fail: fixture encoded a zero-mask ACE instead of an empty ACL |
| make analyse | phase8-image-analyse1.log | fail: new test padding/size/complexity, multiplication width and missing parentheses |
| make test | phase8-image-test3.log | fail: corrupt-record fixture expected the wrong failure status |
| make boot-test | phase8-image-boot1.log | pass |
| make test | phase8-image-test4.log | pass: 38 groups/3,249 assertions |
| make analyse | phase8-image-analyse2.log | pass |
| make sanitise | phase8-launch-sanitise.log | pass: 38 groups/3,249 assertions |
| make analyse | phase8-launch-analyse-final.log | pass |
| make boot-test | phase8-launch-boot.log | pass, including both new denial markers |
| make fault-test | phase8-launch-fault.log | pass: invalid-opcode, page-fault, guarded-memory and user-fault containment |
| make storage-test | phase8-launch-storage.log | pass: timeout and corrupt-GPT rejection |
| make zifs-test | phase8-launch-zifs.log | pass across 32 boots; later repeated without overlapping build activity |
| make test | phase8-launch-test-final.log | pass: final 38 groups/3,285 assertions |
| make sanitise | phase8-launch-sanitise-final.log | pass: final 38 groups/3,285 assertions |
| make analyse | phase8-launch-analyse-complete.log | pass for final source |
| make zifs-test | phase8-launch-zifs-serial-final.log | pass: 32 boots, serial run after other gates |
| llvm-readobj --file-headers --coff-imports --coff-basereloc build/release/kernel/zizium.efi | phase8-launch-readobj.log | pass |
| python scripts/check_spelling.py | tool output | pass before final report; repeated after report |

clang-format -i was applied to the changed C/headers; make analyse includes the
repository formatting and Clang-Tidy gates. make test includes self-contained
headers, strict host builds, thirteen read-only inspector fixtures, repair CLI
fixtures, and validation of all fifteen manifests. Sanitisation is the available
AddressSanitizer path, not a claim of UBSan/TSan coverage.

## 8. Results and authoritative evidence

Final host suite: 38/38 groups, 3,285 assertions. Final analysis and ASan passed.
Normal boot, four fault cases, two negative storage cases, optional Intel
validation and all thirty-two serial ZiFS boots passed. No existing acceptance
marker was removed or relaxed.

build/debug/boot-smoke-serial.log contains SERVICE_POLICY_DENIED and
IMAGE_ACCESS_DENIED, followed by LUMA_CHILD_PROCESS and USER_SESSION.
The former uses the real launch provider to reject an unknown SYSTEM service;
the latter rejects an unlisted launch token with no published process and no
remaining kernel-pool allocation. Host tests separately cover main-file and
later-DLL denial, directory traversal, and rollback.

LLVM reports COFF-x86-64, AMD64, PE32+ and Native subsystem for the release
kernel, ImportTableRVA/Size zero and a nonzero relocation directory. pecheck
also runs through the normal build graph. The reproducible PE timestamp is
linker-generated metadata, not the wall-clock work date.

SHA-256 after restoring the normal debug image:

- debug/kernel/zizium.efi:
  2aded8928c72aee1e86d6cb58551f1831d4ad638edda17d3467d9f70dcad4e71
- debug/images/zizium-root.zifs:
  6161ea0c8eb478e01f341076af46c8a8ff3ff7609aa4ea2c4dd88556bf26fc17
- debug/images/zizium.img:
  5bc5f5263a8f28f6d57f918a5823be94e05ede1332092512311b91991ffeaaea
- release/kernel/zizium.efi:
  e3ffdd118072312cc7f6e9cf62bef719f2b6f1c056991a93a31b585cfafed173
- release/images/zizium-root.zifs:
  7a8ea978ca7876525cccb9087b9ddef30fb2b8fd604094d82e9a40a5c0c25ddf
- release/images/zizium.img:
  b885e1b1d37d3dbdb93e7c4f1b453384f932dd4063aa206d1d02d682dcc50eb8

## 9. Errors encountered

All functional/build errors above were corrected and the affected gates rerun.
The new test counter was corrected to the repository's existing counter.
A zero-rights fixture now serialises a genuinely empty DACL, rather than an
invalid ACE. Corrupt descriptor bytes correctly expect CHECKSUM_MISMATCH;
the corruption remains rejected, and no acceptance check was weakened.

The first release comparison named images/root.zifs instead of the actual
images/zizium-root.zifs. PowerShell reported the missing file and compared only
20 files. That partial result was not accepted as the required evidence.
Two further release builds used the correct paths, fail-fast handling and an
explicit count of 21; every hash matched.

Some read-only inspection commands used missing paths or Windows-incompatible
rg glob arguments; corrected discovery/read commands were used. An earlier
baseline log lacked a retained completion handle, so the current baseline was
reproduced after confirming no related process was live.

The first full ZiFS run overlapped later host build/test activity. Although it
passed, all 32 cases were repeated serially after those commands finished.
The serial rerun, not the overlapping run, is the final durability evidence.

## 10. Warnings and style conflicts

No unresolved project compiler/analysis warning remains. Clang/Clang-Tidy
22.1.8 and Python 3.14.5 were confirmed locally. Existing centralised strict
-Weverything -Werror exceptions remain unchanged and documented in docs/build.md.

New fixture diagnostics were addressed by grouping size fields, moving constant
test cases out of function bodies, explicit size_t arithmetic, and parentheses.
Service-token construction now expresses SYSTEM and restricted memberships
explicitly. Service tests were separated by responsibility. One narrow test-only
cognitive-complexity annotation keeps the linear image fixture assertions and
success cleanup together; it suppresses no memory, bounds, conversion or
security diagnostic. No style configuration was weakened.

## 11. Missing dependencies

None for these verified development gates. Secure entropy, secret-memory
services, a reviewed native credential-library adapter, durable identities and
protected credential input remain engineering prerequisites, not installed
or implemented dependencies.

## 12. Dependencies downloaded

None. make deps reused the verified external/deps material:

- Limine 12.5.2:
  a4b4539e4229c25f5ceba93ada8a71b8a2c57d7b7900ea5f86c588e1b7afe621
- Limine protocol 630686a3dd3ce40f9e510a7dd9fea6b4c60d952e:
  4de542d1c232b230ca4af04c5b89a78f51c9bdacb928a94ac44fc88377208a63
- Spleen 2.2.0:
  ec42925c6b56d2138c862b2f97147c872e472f674bf03423417d827a08d69a89
- Unicode UCD 17.0.0:
  2066d1909b2ea93916ce092da1c0ee4808ea3ef8407c94b4f14f5b7eb263d28e

## 13. Downloads not completed

None attempted unsuccessfully. No password library was downloaded or approved.

## 14. Implemented

Approved bootstrap service-token resolution, restricted memberships,
token-bound directory/EXE/DLL authorisation, transactional source cleanup,
per-process DLL checks, exact-case policy binding and real denied-launch probes.
The old FNV-1a collision is reproduced: SvcbPEvTBVorR and SvcJJdsVevOgL both
hashed to 807251377; neither can obtain an approved bootstrap token now.

## 15. Scaffolded, not implemented

Durable NIDs/database, account provisioning, authentication, broker-issued
tokens, ACL propagation/mutation, privilege semantics, elevation, capabilities,
revocation and audit persistence remain incomplete. The compiled bootstrap
table is not a permanent identity service or service enrolment database.

## 16. Intentionally absent

No custom cryptography, passwords, permissive security recovery, silent NID
migration, alternate root filesystem, user-mode token minting or production
driver claim. Networking, GUI/audio, installer/packages/updates, SMP and the
full runtime/development platform remain later roadmap work.

## 17. Remaining implementation sequence

1. Freeze the bounded versioned authority-bound NID and identity database
   contract, preserving current eight-byte IDs through explicit migration only.
2. Implement validated issuance, non-reuse/high-water state, disabled provisioning
   and ZiFS-backed transactional persistence with adversarial/crash tests.
3. Establish native secret-memory, secure entropy, protected broker/input and
   credential resource limits; evaluate/pin a reviewed password library.
4. Deliver two credential-backed local users, owned tokens, isolated profiles,
   persistent ownership/default ACL inheritance, audit and explicit elevation.
5. Continue through the full roadmap; none of these prerequisites completes Phase 8.

## 18. Boot status

Real AMD64 PE kernel boots via UEFI/Limine in QEMU/EDK2. Serial, framebuffer,
interrupt/pre-emption, protected memory, Ring 3, storage, services and Luma
acceptance paths remain live. Both new denial markers are mandatory.
Installed firmware templates remain unchanged. Normal debug image restored.

## 19. ZiFS status

The direct NVMe ZiFS root remains genuinely writable and journalled, with
checksummed security records, old-or-new recovery, inspection and narrow
offline repair. All 32 durability boots pass. Authorised lookup now shares the
raw traversal implementation and checks directory Execute before reading entries.
Raw lookup remains a trusted mounting/maintenance primitive.

Limits remain one synchronous writer, bounded staging/extents/directories,
regular-file deletion and shrink-only truncate. No production data-safety or
general salvage claim; never store irreplaceable data on these development images.

## 20. Scheduler status

32 priorities and live single-CPU kernel-thread pre-emption remain verified.
SMP and concurrent scheduled user threads remain future. No scheduler redesign
or weakened timing/fault gate was introduced.

## 21. ACL/security status

Default-deny evaluation, token bounds/roles, inheritance-only filtering,
owned tokens, secured handles/IPC and durable descriptors remain.
Bootstrap Administrators grants and service hashing are removed. Every actual
filesystem-backed user EXE/DLL path now checks the launch token. SYSTEM has no
implicit evaluator bypass.

The current serialised bootstrap keeps token/path/volume state stable across
lookup and payload reads. Concurrent mutation and revocation require future
file-object/locking contracts. CRCs do not authenticate hostile boot/disk
replacement or solve cross-reboot rollback. Privilege fields remain opaque.

## 22. Terminal/Luma status

Framebuffer/serial, Unicode cells, history/scrollback and the bounded user-mode
Luma child-launch demonstration remain working. Luma is USER:21 with Users
membership and inherited-token image checks. This is not credential-verified
logon, a complete interactive user console, or a GUI.

## 23. Unicode status

UTF-8/UTF-16 primitives, exact-case paths, spaces and existing width foundations
remain. No case folding or normalisation was introduced. Full shaping,
bidirectional text, grapheme handling, IME and localisation remain future.

## 24. Driver status

ACPI/PCIe, DMA/MMIO, IRP lifecycle, GPT and polling QEMU NVMe remain verified.
Dynamic .sys loading, broad PnP/USB, interrupt-driven NVMe and physical-hardware
qualification remain incomplete. No additional driver support was claimed.

## 25. PE/COFF status

Native PE kernel/programmes/DLLs, bounded parsing/relocation/import/export and
W^X mappings remain. ZiFsImageSourceAccess now binds volume and token explicitly;
null/invalid contexts fail. Source payloads require Read/Execute; every process
checks its own core DLL set. No ELF or native format change.

## 26. ZCC/ZiCRT status

Ordinary main, arguments/environment and the minimal runtime continue to
execute. ZCC remains a host Clang-driver scaffold and ZiCRT an incomplete C
library. No compiler/runtime completion claim.

## 27. ZIA/Zx status

The existing process/debug/channel/wait/close slice remains working. Public
children inherit the parent's owned token; new checks are inside the kernel
launch provider, not a bypassable user wrapper. No public identity issuance,
authentication, privilege or elevation API was added.

## 28. Documentation status

All three project READMEs and affected accounts, architecture, boot, identity,
process, PE, security, service, terminal, ZiFS, roadmap and continuation docs
were updated. The previous progress report is archived without changing its
historical body. This current report was written last.

## 29. Known limitations

Zizium is still experimental, not a secure multi-user or daily-use release.
The fixed service table approves only the five bootstrap programmes, not
arbitrary installed services. Their hand-off processes are not resident
production services. Manifest Permissions text conveys no rights. Old
SessionBootstrap manifests declaring NID:SYSTEM must be rebuilt and are rejected.

## 30. Technical debt

- Durable issuer binding and migration for the existing authority/value pairs.
- Explicit non-reuse of reserved SERVICE:1/2/3; never reinterpret old hash IDs.
- Concurrent file/security locking, revocation and general file-object APIs.
- Secret memory, entropy, credential budgets, broker/input protection and audit.
- Persistent ACL update/inheritance and transactional account/profile provisioning.
- Hermetic toolchain pin enforcement and broader real-hardware qualification.
- No VCS metadata; preserve unrelated changes using explicit inventories.

## 31. Suggested next prompt

Continue Phase 8 from the verified 38-group/3,285-assertion launch-authorisation
checkpoint. Read AGENTS, roadmap, this report, continuation, identity_security,
accounts, security, services and ZiFS contracts. Implement the bounded,
authority-bound NID/identity-database and issuance/persistence prerequisite,
with explicit migration, non-reuse, fail-closed disabled provisioning and
adversarial/crash tests. Then build the protected credential/logon path toward
two isolated users; do not mistake a wire codec for authentication. Preserve
the new service/image denial markers and every existing gate. Update all
affected documents and this report last.

## 32. Continuation instructions

The global goal remains ACTIVE. No implementation, authentication, or daily-use
completion was inferred from this checkpoint. All reported validation handles
reached terminal success; no QEMU/build process needs resuming from this work.
Recheck actual live state before restarting any later process.

The shared image-loader signature changed from a bare volume to a versioned
ZiFsImageSourceAccess. Never add a null-token fallback. Keep the authorised and
raw ZiFS path walkers shared. SYSTEM service policy is exact name/path/identity/
policy matching, not a trusted manifest prefix. SessionHost uses SERVICE:3;
Luma USER:21 is only a boot fixture. Old hash-generated principals are not
durable database entries. No credentials or default password exist.

## 33. Frozen decisions

Preserve product names, GPL-3.0-or-later ownership and third-party licences;
x64 first, UEFI/Limine behind ZiBootContext; PE/COFF native; Microsoft x64 C
and RAX/R10/RDX/R8/R9 syscall ABI; C17 and minimal assembly; ZiFS-only root with
GPT type 9ef9e22a-3719-44d4-89af-de9cc7b6b255, FAT32 ESP only; exact validated
UTF-8 paths with spaces; ordinary main and optional ZIA/zizium.h; default-deny
ACLs/tokens without implicit privileged bypass; priorities 0/1–15/16–31;
rational per-output scaling; British English and calm #6496e6/#d1ecfc identity;
write-ahead/checkpoint-gated recovery and fail-closed offline repair. Preserve
strict compiler diagnostics, all denial/corruption gates and truthful reports.
