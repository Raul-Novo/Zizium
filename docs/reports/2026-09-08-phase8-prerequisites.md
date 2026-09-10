# Historical report — first Phase 8 prerequisites

Preserved from the preceding checkpoint; use the root progress report for current state.

# Zizium verified progress report

This is the current implementation ledger. Phases 0–7 retain their completed
milestone status; Phase 8 remains ACTIVE and incomplete. The preceding Phase 7
report is preserved unchanged in [the historical report](docs/reports/2026-09-04-phase7.md).
Do not interpret passing prerequisite tests as secure logon or a daily-use OS.

## 1. Date and time

Work resumed on 2026-09-05, with implementation and verification on
2026-09-07–08. Final evidence collection: 2026-09-08, approximately 15:44–15:48
Europe/Madrid (UTC+02:00). The active objective attachment was read at
C:\Users\rauln\.codex\attachments\8cb9e105-c97a-49d4-833b-3c4276102cfc\goal-objective.md;
its additional strict compiler policy is now implemented.

## 2. Summary

Completed the first Phase 8 prerequisite correction and strict diagnostic
migration, not Phase 8 itself:

- Token validation rejects more than 16 groups before traversing storage,
  restricts principals to SYSTEM/USER/SERVICE, restricts memberships to GROUP,
  and retains duplicate/invalid-ID rejection.
- Current-object ACL evaluation validates but skips inheritance-only ACEs.
- All C compilation paths inherit -Weverything -Werror and an explicit,
  reviewed exception inventory. Existing /W4 /WX alone was insufficient.
- Diagnostic findings were fixed in flag-mask signedness, allocator alignment
  contracts, process-object recovery, boot/CRT declarations, framebuffer pixel
  storage, and host-tool constness/standard integer types.
- NVMe validates the alignment, size, overflow, stride, and last-doorbell bounds
  of its MMIO window through a host-testable shared contract.
- PowerShell entry points discover/load the installed x64 Visual Studio
  environment when needed; optional Intel validation resolves the runtime
  belonging to the selected compiler.
- The identity/credential threat model and dependency evaluation exist.
  No credential library, account database, logon, or elevation was implemented.

## 3. Exact files created

- docs/identity_security.md
- docs/reports/2026-09-04-phase7.md
- kernel/include/zi/freestanding.h
- kernel/include/zi/nvme_registers.h
- kernel/io/storage/nvme_registers.c
- scripts/enter_toolchain.ps1
- tests/host/phase8_security_test.c
- tests/host/phase8_tests.h

## 4. Exact files modified

- AGENTS.md
- README.md
- ZIZIUM_PLAN.md
- ZIZIUM_PROGRESS.md
- boot/limine/adapter.c
- docs/README.md
- docs/architecture.md
- docs/boot.md
- docs/build.md
- docs/continuation.md
- docs/drivers.md
- docs/memory.md
- docs/processes.md
- docs/security.md
- docs/services.md
- docs/terminal.md
- docs/zcrt.md
- docs/zifs_repair.md
- kernel/executive/handle/handle.c
- kernel/executive/ipc/ipc.c
- kernel/executive/process/process.c
- kernel/executive/security/access_check.c
- kernel/include/zi/boot.h
- kernel/include/zi/font.h
- kernel/include/zi/security.h
- kernel/include/zi/user_process.h
- kernel/io/storage/bootstrap.c
- kernel/io/storage/gpt.c
- kernel/io/storage/nvme.c
- kernel/mm/pool/pool.c
- kernel/runtime/freestanding.c
- kernel/terminal/font.c
- kernel/terminal/framebuffer_console.c
- scripts/build.ps1
- scripts/build_driver.py
- scripts/generate_font.py
- scripts/test.ps1
- sdk/crt/memory.c
- sdk/crt/start.c
- tests/host/header_probe.c
- tests/host/test_main.c
- tools/pecheck/main.c
- tools/zifsinspect/main.c
- tools/zifsrepair/main.c
- tools/zifsrepair/source.c

No Git metadata is available. This is the known edit inventory, not an inferred
Git diff. Existing later timestamps on .clang-tidy and kernel/pe/pe.c were
observed and preserved; those edits are not attributed to this step. The five
root style files were read and were not edited by this work. Generated objects,
images, logs, Python caches and editor indexes are not source changes.

## 5. Files deleted

None. Unused local macro definitions were removed, not files. No user data was
deleted. The previous progress report remains recoverable in the archive above.

## 6. Build commands and results

Final commands completed successfully:

- make all — build/phase8-final-all.log.
- make image — build/phase8-final-image.log.
- make release, twice — build/phase8-release1.log and phase8-release2.log.
  SHA-256 comparison in the same verified shell invocation matched all 21
  selected kernel/native PE/library/root-volume/disk artefacts across both builds.
- make intel — build/phase8-intel2.log, after correcting runtime discovery.
- make deps — build/phase8-deps.log; existing pinned downloads verified.
- make image — build/phase8-normal-image.log, restoring the normal image after
  fixture-producing regression gates.
- clang-format -i on the affected C/header files; make analyse subsequently
  performed the repository-wide dry-run format gate.

The actual installed compiler, formatter, and Clang-Tidy version is 22.1.8
(ca7933e47d3a3451d81e72ac174dcb5aa28b59d1), not the previous report's 22.1.6.
This work did not install or replace LLVM. The version transition is documented
in docs/build.md and covered by the complete gates. Python is 3.14.5; NASM is
3.01. The installed Visual Studio 2026 x64 tools, QEMU/EDK2, and Intel oneAPI
2026.0 installation were used.

## 7. Test commands and results

- make test baseline in an unconfigured terminal failed on missing errno.h:
  build/phase8-20260907-baseline.log.
- The same baseline after loading the installed Visual Studio environment
  passed 34 groups/3,045 assertions: phase8-20260907-baseline-vs.log.
- make test after implementation passed 36/36 groups and 3,079 assertions:
  build/phase8-test.log and build/phase8-final-test.log.
- make analyse passed after the listed corrections: build/phase8-analyse6.log.
  Includes format, Clang-Tidy/analyser checks and strict host compilation.
- make sanitise passed the same 36 groups/3,079 assertions under AddressSanitizer:
  build/phase8-final-sanitise.log. This is not a UBSan or TSan claim.
- make boot-test passed: build/phase8-final-boot-test.log.
- make fault-test passed: build/phase8-final-fault-test.log.
- make storage-test passed: build/phase8-final-storage-test.log.
- make zifs-test passed all 32 persistent boots: build/phase8-final-zifs-test.log.
- make intel passed 36/36 groups and 3,079 assertions after runtime discovery:
  build/phase8-intel2.log.
- python scripts/check_spelling.py passed after documentation changes.

Host gates also passed the 13 non-mutating inspector fixtures, repair CLI
acceptance (clean ASCII/UTF-16 paths, four repairable states, stale/wrong tokens,
and refusal cases), self-contained headers, and 15 service manifests.
The build independently ran pecheck on the kernel and native PE artefacts.
No separate llvm-readobj invocation is claimed for this step.

## 8. Evidence and artefact snapshot

QEMU smoke output contains ENTRY, FRAMEBUFFER, ZIFS_DIRECT, ZIFS_MOUNT,
PREEMPTION and USER_SESSION, plus the gate's other required markers.
The fault/storage gates contain their expected failures. The ZiFS matrix
passed create/growth/directory expansion/wrap/rename/move/truncate/delete,
checkpoint-gated reuse, offline repair, security corruption, rollback and replay.

After restoring the normal debug image, SHA-256 values are:

- build/debug/kernel/zizium.efi:
  8f14702fc6cc4457ed02964fd02b6152fc6d329cc475533afca77d2697b12e2d
- build/debug/images/zizium-root.zifs:
  d0c83639933c15849d74a574c29c788474c5df8ae4c3ea0a604d1e3a6824f060
- build/debug/images/zizium.img:
  53d501df3b6b51dcbeA9dfc6de57c95c98b448173908296a6754462fd356d1cd
- build/release/kernel/zizium.efi:
  7632cbefb3a7a0aa5c077474ac50e52282bf9a2832b8a1e3b452fb94e15fc3b3
- build/release/images/zizium-root.zifs:
  ed39616a61ebfe3498c5c6866b74a09796e0cb8188ca8f348e5e5fbe00ca6740
- build/release/images/zizium.img:
  0b8d898cb3526abaf48f864e8fc57d74935bc0c445ebfcaa7829fd2516130f2d

Fixture gates can replace the loose root-volume file; use make image before
treating build/debug/images as normal distribution input. None is a signed release.

## 9. Errors encountered and resolved

- Missing SDK environment caused errno.h/string.h failures. One retry used a
  missing session-cached shell prefix and printed an undefined-command error;
  its failed analysis was not accepted as evidence. The shared PowerShell
  toolchain loader now establishes the installed environment.
- Initial make host diagnostic passes failed on C/C++ compatibility, natural
  padding, raw-buffer migration diagnostics, and real alignment findings:
  phase8-strict-initial.log, phase8-strict-c17.log, phase8-strict-layout.log.
- Read-only syntax audit over 89 sources found 16 failing sources, then two
  after corrections: phase8-strict-audit.log and phase8-strict-audit2.log.
- Strict make attempts failed successively on the generated font declaration,
  freestanding memory prototypes, ZiCrtStartC prototype, and unused CRT macro:
  phase8-strict-build.log through phase8-strict-build4.log. The fifth passed;
  subsequent final gates include the later NVMe tests and all final source.
- Clang-Tidy initially found the relocation anchor's implicit multilevel
  conversion, assembly-entry linkage, test-matrix complexity, and duplicate
  enum fallback branches. These were corrected without reducing test coverage:
  phase8-analyse.log through phase8-analyse5.log; phase8-analyse6.log passed.
- The first make intel linked without its runtime and failed on libircmt.lib:
  phase8-intel.log. The runtime exists beside the selected compiler; explicit
  discovery fixed this, and phase8-intel2.log passed.
- Several diagnostic reads used nonexistent guessed paths; corrected discovery
  used rg. Two multi-file patches failed context validation and made no changes;
  corrected patches were then applied.

No unresolved build/test error remains in this prerequisite correction.

## 10. Warnings and exceptions

Project compilation uses -Weverything -Werror. Six individually documented
exceptions exist: five C-only compatibility/layout/raw-buffer-model exceptions
and one pecheck-only defensive enum-fallback exception. Their exact flags,
scope, rationale, and limits are in docs/build.md beside the central graph.
No alignment, conversion, aliasing, lifetime, or actual bounds warning is disabled.
No root style policy was weakened. C17 source compatibility is not C++ source
compatibility; those exceptions must not migrate to future C++ targets.

Assembler relocation exceptions and existing justified local Clang-Tidy
annotations remain. New external assembly-entry/probe declarations retain
narrow internal-linkage annotations. Test matrices were split/table-driven
instead of disabling their complexity checks. Analysis printed suppressed
third-party/system-header counts; those are not unsuppressed project warnings.

## 11. Missing dependencies

None for the verified development gates. Initial Visual Studio/Intel failures
were environment/discovery defects with installed dependencies, now resolved.
Native secret memory, trusted entropy, an approved credential dependency,
physical-hardware qualification and production security infrastructure remain
engineering prerequisites, not silently installed components.

## 12. Dependencies downloaded

None. make deps reused checksum-verified files under external/deps:

- Limine 12.5.2:
  a4b4539e4229c25f5ceba93ada8a71b8a2c57d7b7900ea5f86c588e1b7afe621
- Limine protocol 630686a3dd3ce40f9e510a7dd9fea6b4c60d952e:
  4de542d1c232b230ca4af04c5b89a78f51c9bdacb928a94ac44fc88377208a63
- Spleen 2.2.0:
  ec42925c6b56d2138c862b2f97147c872e472f674bf03423417d827a08d69a89
- Unicode UCD 17.0.0:
  2066d1909b2ea93916ce092da1c0ee4808ea3ef8407c94b4f14f5b7eb263d28e

## 13. Downloads not completed

None attempted unsuccessfully. Credential-library candidates were researched
in the threat model, not fetched, pinned, approved, or integrated.

## 14. Implemented

All previously booted slices remain working under the new gates. This step
adds bounded token-role validation, inheritance-only ACE filtering, a tested
NVMe register-window contract, stricter diagnostics across compilation paths,
explicit compiler/assembly declarations, checked ownership-based process-object
resolution, standard host integer boundaries, immutable review-token input at
BCrypt, and toolchain environment/runtime discovery.

## 15. Scaffolded, not implemented

Durable NIDs/database, authentication, broker-issued tokens, ACL propagation
and mutation, privilege semantics, elevation, capabilities, revocation and
audit storage are not implemented. Existing service/session bootstrap policy
is not a secure multi-user boundary.

## 16. Intentionally absent

No custom cryptography, default passwords, silent identity migration, permissive
security recovery, alternate root filesystem, or production-driver claim was
introduced. SMP, concurrent user scheduling, general desktop, network/audio,
installer/updates/packages and a complete C runtime/compiler remain later work.

## 17. Remaining implementation sequence

1. Remove Administrators membership from non-elevated bootstrap tokens.
2. Replace service-name hashing with explicit non-colliding identity resolution
   and bind declared identity/token policy to approved service launch policy.
3. Enforce ACL checks for directory traversal and Read/Execute on every main
   executable and DLL before publishing an executable process.
4. Add collision, denied-image/dependency, group-grant and cleanup boot/host tests.
5. Then implement the versioned authority-bound NID/database, reviewed
   credential adapter, two-user logon/profile isolation, persistent inherited
   ownership/ACLs, auditable privileges and explicit elevation.

## 18. Boot status

Verified UEFI/EDK2 -> Limine -> AMD64 PE kernel -> direct NVMe/GPT ZiFS ->
filesystem-backed services/session/Luma remains working. The linker bridge,
volatile request roots, framebuffer and serial markers, timer/pre-emption,
Ring-3 isolation and fault containment pass. Recovery module use remains explicit.

## 19. ZiFS status

Real bounded writable, checksummed, journalled ZiFS with direct read/write/flush,
redundancy, old-or-new recovery, persistent descriptors, inspector and narrow
offline repair. All 32 boots pass. Still one synchronous writer, bounded
staging/extent/directory capacities, regular-file-only deletion and shrink-only
truncate; no production data-safety or general salvage claim.

## 20. Scheduler status

32-priority queues, real single-CPU kernel-thread pre-emption and timer ticks
remain verified. SMP, concurrent scheduled user threads and mature realtime/
starvation policies remain future work.

## 21. ACL/security status

Host-tested token role/count limits, ordered default-deny ACLs, inheritance-only
filtering, owned token copies, secured handles/IPC, and durable ZiFS descriptors
work. No implicit administrator/SYSTEM bypass exists in the evaluator.

IMPORTANT: explicit bootstrap Administrators membership currently grants broad
rights through the default DACL. Service-name hashes can collide and image-source
loading does not yet authorise files under the launch token. These are real
remaining Phase 8 prerequisites, not solved by the evaluator fixes.

## 22. Terminal/Luma status

Framebuffer/serial output, Unicode terminal/history/scrollback primitives and
the bounded filesystem-backed user-mode Luma acceptance process remain verified.
Pixel writes no longer assume C word alignment. This is not yet a general
interactive user-mode console, pipeline engine or GUI.

## 23. Unicode status

Strict UTF-8/UTF-16 primitives, exact names, spaces and existing terminal width
foundations remain. No normalisation/case folding was added. Full shaping,
bidirectional text, grapheme segmentation, IME and localisation remain future.

## 24. Driver status

ACPI/PCIe, DMA/MMIO, IRP lifecycle, GPT and polling QEMU NVMe remain working.
New window checks prevent unaligned or out-of-window register access for the
owned queue set. Dynamic .sys loading, general PnP/USB, interrupt-driven NVMe
and real-hardware qualification remain incomplete.

## 25. PE/COFF status

Native PE kernel/programmes/DLLs, bounded parsing/relocation/import/export,
protected mappings, and pecheck remain working. Process handle resolution
now checks owned objects before recovering a process. No ELF or format change.
Per-image filesystem authorisation is the next missing boundary.

## 26. ZCC/ZiCRT status

Ordinary main and minimal runtime/arguments/environment execute. Strict
compilation now checks explicit start-up and compiler-support declarations.
ZCC is still a host Clang driver scaffold; ZiCRT is not a complete C library.

## 27. ZIA/Zx status

The existing bounded process/debug/channel/wait/close syscall slice remains
working. No public identity issuance, authentication, privilege, or elevation
API was added; the full native catalogue is neither complete nor ABI-stable.

## 28. Documentation status

Affected README, build, boot, architecture, memory, process, storage-driver,
security, service, terminal, CRT, repair, roadmap and continuation documents
were updated. Identity/credential threats, rollback limitations, and candidate
crypto dependencies are documented without claiming implementation.
All required foundation documents remain. The historical Phase 7 report is
preserved; this report was updated last.

## 29. Known limitations

This is an experimental OS, not a daily-use or secure multi-user release.
Never put irreplaceable data on ZiFS. Bootstrap rights and missing image ACL
enforcement must be corrected before authentication. CRCs/generations do not
provide authenticity or cross-reboot anti-rollback. No cryptographic candidate
is approved merely because the threat-model document recommends evaluation.

## 30. Technical debt

- Durable authority binding/migration for the current eight-byte security IDs.
- End-to-end service/image/file authorisation and restricted token construction.
- Protected secret input, entropy, secret-memory cleanup and credential budgets.
- General file objects/I/O, SMP/concurrent user scheduling and broader drivers.
- Hermetic toolchain pin enforcement remains future; the installed LLVM update
  was recorded and tested, not silently treated as the previous version.
- C pointer/length safety still relies on checked contracts plus compiler,
  analyser and adversarial evidence; the warning exception is not a proof.
- No VCS metadata: preserve unrelated edits and use explicit file inventories.

## 31. Suggested next prompt

Continue Phase 8 from the verified 36-group/3,079-assertion strict-build
baseline. Read AGENTS, the roadmap, this report, continuation, security,
identity_security, services, processes, PE and ZiFS documents. Remove bootstrap
Administrators membership, replace service-name hashing with explicit
non-colliding approved identity resolution, and enforce directory plus
Read/Execute ACLs for each EXE and DLL under the launch token. Test collisions,
denials and allocation/handle cleanup in host and QEMU paths. Keep all gates,
including 32 ZiFS boots and -Weverything -Werror, and update documentation and
this report last. Then resume durable NIDs and credential-backed logon.

## 32. Continuation instructions

The global goal remains active; do not mark it complete or blocked.
No build process from this correction needs to be restarted. Check any newly
reported live handle before acting. Read repository state rather than relying
on conversational history. The normal make/test wrappers now load Visual Studio;
direct Python calls still require the developer environment. To reproduce
Intel validation, expose the installed compiler bin directory; its matching
runtime is discovered by the graph. Do not fetch during normal builds.

The security review produced an explicit FNV-1a collision candidate:
SvcbPEvTBVorR and SvcJJdsVevOgL both map to 807251377 in the current service hash.
Reproduce it from source before using it as regression evidence; a wider hash
alone is not durable identity allocation. Do not reintroduce guessed or cloned
identities, treat a manifest string as authority, or silently strip issuer IDs.

## 33. Frozen decisions

Preserve names, GPL-3.0-or-later ownership and third-party licences; x64 first,
UEFI/Limine behind ZiBootContext; PE/COFF native; Microsoft x64 C ABI and
RAX/R10/RDX/R8/R9 syscall convention; C17 with tiny assembly boundaries;
ZiFS-only root with GPT type 9ef9e22a-3719-44d4-89af-de9cc7b6b255 and FAT32
ESP only; exact case-sensitive UTF-8 native paths with spaces; ordinary main
and optional ZIA/zizium.h; ACL/token default deny without implicit bypass;
0/1–15/16–31 priorities; rational per-output scaling; British English and calm
#6496e6/#d1ecfc identity; write-ahead/checkpoint-gated ZiFS recovery; non-mutating
inspection and separate fail-closed reviewed repair. Strict compiler
diagnostics and truthful milestone evidence are mandatory.
