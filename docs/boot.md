# Boot architecture

## Implemented in Seed

The verified path is:

```text
EDK2 x86-64 firmware
Limine v12.5.2 from the EFI System Partition
zizium.efi through the Limine protocol
minimal x64 ABI bridge
kernel GDT, TSS, IST, and IDT ownership
ZkKernelMain with ZiBootContext
validated memory inventory and physical page ownership
kernel-owned x64 page tables, guarded stacks, and kernel pool
COM1 and framebuffer discovery
ACPI root and MCFG validation
PCIe ECAM enumeration and device publication
DMA/MMIO and polling NVMe controller bring-up
primary-or-backup GPT validation and ZiFS partition selection
writable ZiFS mount, journal validation, and automatic recovery
bounded ZiFS file reads, alternate-base PE mapping, and core DLL resolution
object namespace, secured handles, dispatcher waits, and two-process IPC proof
Ring-3 ZiCRT/main/ZIA/Zx execution and process-set teardown
calibrated local-APIC timer and pre-emption proof
filesystem-backed core-service supervision and failure-policy proof
SessionHost-to-Luma channel bootstrap
user-mode Luma child launch, wait, close, and session teardown
```

`boot/limine/adapter.c` uses Limine base revision 6 and requests bootloader
information, command line, memory map, HHDM, framebuffer, modules, RSDP, and the
EFI system table. Limine-owned structures are translated into version-three
`ZiBootContext`; its physical RSDP address is the firmware-discovery root and no
shared kernel manager consumes Limine types directly.

Limine enters x86-64 code using the System V convention. `entry.asm` is the
single bridge to Microsoft x64: it establishes a private bootstrap stack,
reserves the required 32-byte shadow space, aligns the stack, and invokes C.
Revision 6 leaves the SIMD operating-system bits disabled. The bridge therefore
sets CR0.MP, clears CR0.EM, and enables CR4.OSFXSR and CR4.OSXMMEXCPT before
calling compiler-generated C, because Microsoft x64 code may use SSE2.

COM1 is brought up first. Framebuffer discovery accepts supported 32-bit XRGB
layouts and otherwise retains serial-only operation. Normal storage bring-up
validates RSDP, XSDT/RSDT, and MCFG checksums and ranges, enumerates PCIe through
bounded ECAM mappings, attaches the built-in NVMe function driver, identifies
one namespace, validates both GPT headers and entry arrays, and selects the
frozen ZiFS partition type. A partition `ZiBlockDevice` then supplies bounded
reads, writes, and flush barriers to the real ZiFS mount. Mount compares both
superblocks and both journal headers; a recoverable dirty or redundant state is
rolled back, replayed, or repaired before normal use.

The module named `zizium-root.zifs` remains a genuine ZiFS volume, never a RAM
filesystem. It is accepted only for the explicit `zi.storage=module`
development/recovery option and the two injected storage-failure gates. Every
fallback emits `STORAGE_MODULE_FALLBACK`; normal smoke boot rejects that marker.

The ZiFS partition contains all native programmes and DLLs. The kernel reads
them through validated regular-file extents and an allocator-bounded PE source
provider; Limine supplies no `.exe`, `.dll`, or `.sys` modules. The first
acceptance set creates all three process records before execution, deliberately
relocates each main image, resolves the bounded DLL graphs, maps read-only
process parameters, binds validated tokens, and releases every address space.
The programmes prove `main(void)`, `main(argc, argv)`, exact-case environment
lookup, and optional ZIA use with statuses 21, 22, and 23.

After the APIC pre-emption proof, the kernel reads five `.zsvc` manifests from
ZiFS, validates their dependency order, and starts ServiceHost, SecurityHost,
LogHost, and MountHost. A real ServiceHost failure probe exhausts exactly two
restarts. SessionHost and Luma then receive separate tokens and endpoints of an
ACL-protected channel. SessionHost queues a ready record and quoted command;
Luma rejects the wrong-case target, launches the exact standard-C PE beneath
`C:\Program Files`, waits for status 21, and closes it. Normal boot halts after
all process and channel ownership is reclaimed. The kernel-integrated shell is
entered only for explicit recovery options.

The normal smoke test requires `ENTRY`, `SERIAL`, `CPU_TABLES`,
`EXCEPTION_READY`, `BOOT_CONTEXT`, `MEMORY_INVENTORY`, `PMM_READY`,
`VMM_READY`, `TEMPORARY_MAPPING`, `HEAP_READY`, `GUARDED_STACKS`,
`MEMORY_STRESS`, `FRAMEBUFFER` or `FRAMEBUFFER_FALLBACK`, `IO_MANAGER`,
`DMA_READY`, `ACPI_READY`, `PCIE_ENUMERATED`, `PCI_DEVICES`, `NVME_READY`,
`GPT_ZIFS`, `ZIFS_PARTITION`, `STORAGE_READ_STRESS`, `ZIFS_DIRECT`, `ZIFS_MOUNT`,
`CASE_SENSITIVE`, `ZIFS_FILE_READ`, `SERVICE_MANIFESTS`,
`SERVICE_DEPENDENCIES`, `FILESYSTEM_PE_SOURCE`, `USER_ADDRESS_SPACE`, `USER_PE_LOADED`,
`USER_PE_RELOCATED`, `USER_IMPORTS_RESOLVED`, `USER_PARAMETERS`,
`USER_TOKEN_BOUND`, `USER_PROCESS_SET`, `SYSCALL_READY`, `RING3_ENTER`,
`OBJECT_NAMESPACE`, `HANDLE_ACCESS`, `WAIT_OBJECTS`, `IPC_EXCHANGE`,
`IPC_HANDLE_TRANSFER`, `SYSCALL_ENTRY`, all three exact programme messages,
`USER_PROCESS_EXIT`,
three `USER_PROCESS_CLEAN` markers, `USER_PROCESS_SET_CLEAN`,
`IPC_PROCESS_CLEAN`, `STANDARD_C_MAIN`, `STANDARD_C_ARGUMENTS`, `ZIA_LIBRARY`, `APIC_TIMER`,
`SCHEDULER_TICKS`, `PREEMPTION`, all four core service markers,
`SERVICE_FAILURE_DETECTED`, `SERVICE_RESTART_LIMIT`, `SESSION_CHANNEL`,
`SESSION_HOST`, `USER_CREATE_PROCESS`, `USER_WAIT_PROCESS`,
`LUMA_CHILD_PROCESS`, `USER_LUMA_READY`, and `USER_SESSION`. It rejects `PANIC`,
`STORAGE_MODULE_FALLBACK`, `STORAGE_TIMEOUT_SAFE`, and `GPT_CORRUPTION_SAFE`.

`make fault-test` generates separate Limine configurations for deliberate
kernel invalid-opcode, ordinary kernel page-fault, active stack-guard, and user
page-fault boots. The three kernel faults must reach exact diagnostics and halt
through `PANIC`. The Ring-3 fault must emit `USER_FAULT_CONTAINED`, reclaim the
process, avoid the fatal exception path, and continue through APIC pre-emption
to the filesystem-backed user session.

`make storage-test` runs two separate negative boots. One forces the NVMe
initialisation timeout and requires `STORAGE_TIMEOUT_SAFE`; the other corrupts
both GPT header CRCs on the NVMe image and requires `GPT_CORRUPTION_SAFE`.
Neither case may emit a direct-mount marker. Both must use the separately
provided, explicitly logged recovery module, complete the user-session proof,
and then reach the explicit early recovery shell without `PANIC`.

`make zifs-test` uses writable copies of the real GPT/NVMe image across
twenty-five boots. The first eight prove clean create/reboot, pre-commit
rollback, post-commit replay, slot-31-to-slot-0 journal wrap, and post-wrap
persistence. Six further boots case-only rename and then move the populated PE from
`C:\Program Files\Zizium\Hello Seed.exe` to
`C:\Temp\First Light Seed.exe`, verify a clean reboot, cut power on each side
of the move commit boundary, and verify the required rollback or replay state.
The kernel checks exact old/intermediate/new paths, parent linkage, record and
security identity, extents, and PE bytes. Ten final boots perform clean
shrink/delete plus reboot, then independently cut power before and after the
truncate and delete commit boundaries and verify rollback/replay. They require
exact old/new bytes or presence, coherent allocation bits, tail zeroing, and
reuse only after checkpoint. Internal test tokens, the acceptance-only
three-block fixture, and the fault-injection block wrapper are not exposed as a
normal filesystem API or included in the ordinary system image. A final boot
corrupts an ACE byte in the direct partition's checksummed `ZISD` table. It
must emit `ZIFS_SECURITY_CORRUPTION_SAFE`, must not emit `ZIFS_DIRECT`, and may
complete only through the explicitly enabled, uncorrupted recovery module.

## Disk image

The deterministic 128 MiB GPT image has a 64 MiB FAT32 EFI System Partition and
a 32 MiB ZiFS partition. The ZiFS partition type GUID is frozen as
`9ef9e22a-3719-44d4-89af-de9cc7b6b255`. The ESP contains Limine,
`zizium.efi`, configuration, and an exact copy of the ZiFS partition image as a
recovery boot module. It contains no separately copied native programme,
library, or driver. FAT32 is firmware media only.

QEMU uses an installed EDK2 code image read-only and exposes the normal image
as an NVMe namespace. The variable-store template is copied beneath `build/`
for each run and is never modified in place. The headless smoke test uses a
temporary QEMU snapshot overlay, so guest firmware writes cannot change the
verified base disk image. Negative storage boots may expose a distinct IDE
recovery medium solely so EDK2 can boot after the deliberately damaged NVMe
GPT has been rejected.

The ZiFS write gate deliberately does not use QEMU snapshots. It copies each
fixture beneath `build/`, boots that copy, and replaces only the copied EFI
System Partition between stages so the modified ZiFS partition survives the
reboot. Each boot receives a fresh copied EDK2 variable store.

## Scaffolded

The verified NVMe path is polling, single-controller, single-namespace, and
uniprocessor. It is not a general storage/PnP implementation. ZiFS writing is a
bounded single-writer create, no-replacement rename/move, shrink-only truncate,
and regular-file delete slice, not a complete writable filesystem.
The EFI system table address remains reserved for later firmware services.
Programme files are read eagerly rather than through file objects or demand
paging. Process execution remains synchronous; only one nested parent/child
path is verified.

## Future

Interrupt-driven NVMe completion, MSI/MSI-X and IOAPIC routing, multiple
controllers/namespaces, AHCI, physical-device validation, full ZiFS mutation
operations, and a user-selectable recovery manager remain future work. A
custom Zizium UEFI boot manager, Secure Boot, and optional BIOS compatibility
follow later.

Limine configuration and protocol references are maintained at:

- https://github.com/limine-bootloader/limine/blob/v12.x/CONFIG.md
- https://raw.githubusercontent.com/Limine-Bootloader/limine-protocol/630686a3dd3ce40f9e510a7dd9fea6b4c60d952e/PROTOCOL.md
