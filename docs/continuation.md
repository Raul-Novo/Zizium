# Continuation contract

## Current vertical slice

The x86-64 PE kernel boots through Limine under QEMU/EDK2, establishes the
Microsoft x64 C environment, logs through COM1, renders a framebuffer terminal,
discovers QEMU hardware through ACPI/PCIe, mounts ZiFS directly from an NVMe
GPT partition, proves exact-case lookup, and reaches a filesystem-backed
user-mode Luma session. The kernel-integrated serial shell is an explicit
recovery facility only.

The kernel owns its GDT, TSS, IDT, exception entry, 100 Hz local-APIC timer, and
live uniprocessor pre-emption. It owns and accounts for physical memory,
installs a protected four-level kernel CR3, enforces NX and W^X, derives kernel
permissions from PE sections, provides guarded stacks, and runs leak-neutral
memory stress before storage or Luma starts.

Phase 3 is complete. A bounded manager creates three explicit process records
before execution. Each receives a private lower-half CR3 with supervisor-only
kernel mappings, a guarded kernel stack, user stack, read-only versioned UTF-8
parameters, and an owned validated token. The loader deliberately relocates
each main PE, resolves an exact-case dependency graph through `zx.dll`,
`zicrt.dll`, and optional `zia.dll`, and applies final W^X protections.

The three processes run synchronously at Ring 3 and prove ordinary
`main(void)`, `main(argc, argv)` with spaces and exact-case environment lookup,
and optional ZIA use. They return statuses 21, 22, and 23 through checked
`ZxExitProcess`; every image, parameter, stack, page-table, and token allocation
is reclaimed. A deliberate user page fault terminates only that process and the
kernel continues through pre-emption to Luma.

Phase 4 is complete. The executive has locked object-type registration,
bounded exact-case namespace directories, single-destruction lifetime rules,
and private generation-safe handle tables for every Seed process. ACL checks
occur on open and target-process duplication; lookup enforces granted masks and
exact types.

Events, mutexes, semaphores, timers, process termination, ports, and channels
are real dispatcher objects. Wait-any/wait-all, finite/infinite deadlines,
explicit expiry, cancellation, scheduler wake-up, and bounded mutex priority
inheritance are host-tested. Bounded IPC validates every message field,
publishes queue readiness atomically, transfers handles through receiver-token
checks, enforces shared-section maximum access, and breaks endpoint reference
cycles on process death. QEMU proves the namespace, handles, waits, two-process
exchange, transferred section, and cleanup before Ring-3 execution.

Phase 5 is complete. Version-three `ZiBootContext` supplies a physical RSDP;
checksummed ACPI root/MCFG parsing drives bounded PCIe ECAM enumeration and
exact driver matching. The kernel publishes PCI device objects, owns uncached
MMIO slots and below-limit DMA pages, and runs real IRP submission,
exactly-once completion, cancellation, deadline expiry, owner teardown, and
device-stack traversal.

The built-in polling NVMe function driver creates DMA-backed admin/I/O queues,
identifies one QEMU namespace, and exports read/write/flush block operations.
Normal boot validates primary or backup GPT, selects the frozen ZiFS GUID,
performs 128 repeatability reads through the hardware path, and mounts the
clipped partition. Injected controller timeout and dual-GPT-corruption boots fail closed
and use the Limine ZiFS module only as an explicit, logged recovery path.

Phase 6 is complete. ZiFS reads bounded regular-file extents and the image
builder populates the real partition with DLLs, programmes, representative
drivers, all service manifests, and a standard-C image beneath `Program Files`.
No native PE is supplied as a Limine module. An allocator-driven source
provider performs exact-case path lookup, enforces per-file and aggregate
limits, and releases raw data after the PE mapper owns its mappings.

The version-one `.zsvc` parser is adversarially host-tested, and the dependency
resolver emits a deterministic acyclic start order. The supervisor implements
bounded `Never`, `OnFailure`, and `Always` policies. Normal QEMU boot launches
filesystem-backed ServiceHost, SecurityHost, LogHost, and MountHost processes
with explicit bootstrap tokens. A real ServiceHost probe fails three times and
proves a two-restart limit without leaking processes.

SessionHost and Luma are real PE processes with distinct tokens and endpoints
of one ACL-protected channel. SessionHost queues a versioned ready record and
quoted command. User-mode Luma consumes them, rejects a wrong-case path,
creates `C:\Program Files\Zizium\Hello Seed.exe`, proves zero-timeout polling,
runs and waits for exit status 21 through the nested Ring-3 boundary, closes
the process handle, and proves stale-handle rejection. Normal boot requires
complete process/channel cleanup through `USER_SESSION`.

The current Phase 7 writable slice is implemented without marking the phase
complete. Version-three block devices and IRPs carry bounded writes and flush
barriers through the partition adapter and polling QEMU NVMe driver. ZiFS has
scalable allocation maps, redundant version-one journal headers, full-block
redo records, dirty/clean superblock generations, staged creation of one
bounded regular file, exact-case no-replacement same-directory rename and
cross-directory move, bounded non-sparse overwrite/growth, shrink-only
regular-file truncation, regular-file deletion, ordered commit, and automatic
single-transaction rollback/replay/redundancy repair. Caller-owned transaction
workspaces provide 1–28 home-block image slots; create accepts up to 24
contiguous data blocks and each write accepts at most 24 data blocks. The
32-record journal reserves one slot, advances modulo its declared capacity,
and reclaims the validated transaction cursor at checkpoint or recovery.

Incompatible feature `ZI_FS_FEATURE_INCOMPAT_DIRECTORY_EXTENTS_V1` freezes the
multi-block directory contract. The directory-table block remains logical
block 0; inline extents map logical blocks 1 onwards, `file_size` stays zero,
and `allocated_size` counts only continuation bytes. Mount, exact-case lookup,
transactions, the formatter, and the inspector validate all blocks, reject
duplicates across blocks, and cap a directory at 256 blocks. Create and move
allocate one continuation block atomically when every existing block is full.

Rename/move validates directory ownership and complete directory blocks,
rejects exact collisions, duplicate names, malformed entry-to-record linkage,
and directory ancestry cycles, and preserves file identity, security reference,
extents, and content. Case-only and canonically distinct names remain valid.
The operation updates the moved record's parent/change time and each affected
parent's modified/change times. A target-directory expansion may add its
directory record, allocation map, and continuation block to the redo set.

Truncate preserves file/security identity, updates size/timestamps, zeroes a
partial retained tail, and releases only a globally validated suffix of inline
extents. Delete removes one exact regular-file entry, updates its parent,
clears the record, and releases every validated inline extent. Released ranges
remain only in staged bitmap images until commit; serial-writer generation and
recovery gates prevent reuse before checkpoint and reject stale speculative
transactions. Write preserves identity, stages all touched blocks, prefers to
extend the final physical extent, and may add another inline extent when that
range is occupied. Offsets beyond end-of-file, sparse allocation, a fifth
extent, and directory deletion remain unsupported.

Host tests fail every one of the 29 write/flush operations in the original
commit, all 23 in a wrapped transaction, all 23 in rename, all 25 in move, and
all 25 in each truncate/delete transaction, requiring an exact old-or-new
namespace, file-data, and allocation state after every restart. A successful
27-image transaction proves all 24 create data blocks. Separate exhaustive
campaigns fail every write-growth operation and every operation in the first
directory expansion, requiring exactly the old or new size/content, path,
extent, allocation, and generation state after recovery. Host acceptance is
now 33 groups and 2,923 assertions. `make zifs-test` proves clean create,
write growth, multi-block directory persistence, rename/move, truncate/delete,
both crash outcomes, slot-31-to-slot-0 wrap, post-wrap persistence, and
checkpoint-delayed reuse across twenty-seven real QEMU/EDK2 boots of writable
NVMe image copies. The final boot corrupts a durable ACE on the direct
partition, proves fail-closed rejection with `ZIFS_SECURITY_CORRUPTION_SAFE`,
and uses only the explicit clean recovery module. The version-one `ZISD`
region stores checksummed owner/group/DACL/ACE data, mount validates every live
reference, and normal boot exercises allow, deny, and default-deny policy.
Phase 7 remains active because clean-unmount/flush semantics, bounded repair
policy/tooling, and its complete exit criteria are not yet finished.

The Windows-host `zifsinspect.exe` is now a real, strictly read-only inspector
for raw volumes and frozen-GUID GPT images. It validates both superblocks and
journal headers, committed in-flight journal state, security records, all live
file and directory relationships, extents/cross-links, and allocation maps.
Committed pre-checkpoint state is evaluated through a heap-owned replay overlay;
the image is never repaired or recovered in place. Eleven fixtures (including
a valid formatter-created multi-block directory) and three real QEMU
checkpoints compare SHA-256 before and after inspection.

The authoritative command results, image hashes, limitations, and exact file
lists are in `ZIZIUM_PROGRESS.md`. Detailed contracts are in `memory.md`,
`processes.md`, `syscalls.md`, `pe_coff.md`, and `zcrt.md`.

## Do not change

- PE/COFF native images, ZiFS root, exact-case UTF-8 names, Windows-style paths,
  British project English, and standard C `main` are frozen invariants.
- The x64 C ABI is Microsoft x64 and the syscall ABI uses RAX/R10/RDX/R8/R9.
- The 48-bit initial user range begins at `0x0000000000010000` and ends before
  `0x0000800000000000`; the upper PML4 half remains supervisor-only.
- Limine stays behind `ZiBootContext`; a custom boot manager must provide that
  contract instead of leaking new protocol types.
- FAT32 remains limited to firmware boot media.
- ACL evaluation remains default deny with no implicit administrator bypass.
- Public ABI prefixes remain `Zi`, `Zx`, `Zk`, and `ZiFs`.
- The ZiFS GPT type GUID remains `9ef9e22a-3719-44d4-89af-de9cc7b6b255`.
- Phase 1 exception/pre-emption, Phase 2 ownership/protection, Phase 3 user-
  fault/teardown, Phase 4 executive/IPC, and Phase 5 direct-storage acceptance
  markers must stay live while services and user-mode shell support grow. Both
  negative storage gates remain mandatory. Phase 6 filesystem PE, service
  supervision, user Luma, nested child, and session-cleanup markers must also
  remain live.

## Exact next task

Extend Phase 7 from its verified durable transaction and security-descriptor
foundation in this dependency order:

1. Define and verify clean-unmount/flush semantics before broadening writer
   concurrency or repair policy.
2. Specify a bounded repair policy which consumes inspector evidence without
   converting unknown corruption into apparent success.
3. Finish the remaining Phase 7 exit-criteria audit, including directory
   deletion/reclamation only if the documented milestone requires it.

Do not mark Phase 7 complete until create/write/read/rename/delete and security
descriptors persist across reboot and all exit criteria pass. Do not introduce
another root filesystem or bypass ZiFS security-record references.

## Later sequence

After Phase 7: implement the Phase 8 durable identity, ACL inheritance, logon,
and elevation boundary before expanding user-facing administration.
