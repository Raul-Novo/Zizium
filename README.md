# Zizium

Zizium is an experimental operating system which is native to PE/COFF and is case sensitive.
It was designed to be UEFI-first and non-POSIX, and makes use of a modular monolithic kernel.
The present milestone is **Zizium 0.2 "Luma"**.

This repository serves as a foundation and is not a daily-use operating system. As for the boot
slice, host tests, and implemented algorithms are identified separately from
Interfaces that merely set aside a future architecture.

## Current vertical slice

- x86-64 PE32+ kernel loaded by Limine;
- Microsoft x64 kernel ABI behind a minimal Limine entry bridge;
- COM1 diagnostics and an early framebuffer terminal;
- kernel-owned x64 descriptor/interrupt tables and bounded exception reports;
- a calibrated 100 Hz x2APIC timer with repeated kernel-thread pre-emption;
- a range-aware physical page allocator with explicit ownership;
- kernel-owned four-level page tables with NX, W^X, and PE-section protections;
- guarded boot, exception, idle, and worker stacks;
- a corruption-checked kernel pool, object cache, and boot-time memory stress;
- checksummed ACPI root/MCFG discovery and bounded PCIe enumeration;
- uncached MMIO mappings, owned DMA pages, real device-stack and IRP lifecycle
  foundations, and a polling QEMU NVMe function driver;
- defensive primary/backup GPT discovery and a genuine ZiFS root mounted
  directly from the frozen ZiFS partition type; the Limine module path is an
  explicit read-only recovery/development fallback only;
- bounded NVMe/partition writes and flushes, scalable ZiFS allocation maps,
  full-block write-ahead records, caller-owned staging for up to 28 home-block
  images, one atomic regular-file create operation with up to 24 data blocks,
  atomic no-replacement same-directory rename/cross-directory move,
  shrink-only regular-file truncation, and regular-file deletion with
  checkpoint-gated extent reuse; circular-journal reclamation and automatic
  rollback/replay/repair are validated at every host write/flush boundary and
  across twenty-five QEMU boots;
- versioned, checksummed ZiFS security descriptors with durable owner, primary
  group, ordered DACL, and ACE data; mount validates every live security
  reference and a negative QEMU boot proves corrupted policy cannot be used;
- populated ZiFS regular files with bounded extent reads; core DLLs,
  programmes, drivers, and manifests come from ZiFS rather than Limine PE
  modules;
- a bounded early process manager with private CR3s, guarded kernel stacks,
  user stacks, W^X image mappings, checked user copies, validated access
  tokens, pollable termination, and deterministic teardown;
- a real `SYSCALL`/`SYSRETQ` boundary with trusted-stack entry, return-state
  validation, process exit, debug output, and contained user exceptions;
- alternate-base PE relocation and bounded, exact-case import/export resolution
  for the initial Zx, ZiCRT, and ZIA DLL dependency graph;
- three Native-subsystem PE programmes created before execution: ordinary
  `main(void)`, `main(argc, argv)` with UTF-8 parameters and environment, and an
  optional-ZIA example; all return through Zx and leave no allocated pages;
- exact-case executive object-type and namespace directories with locked,
  single-destruction lifetime rules;
- per-process generation-safe handle tables with ACL-checked granted access,
  non-amplifying duplication, deterministic close, and process-death cleanup;
- dispatcher events, mutexes, semaphores, timers, process termination,
  wait-any/wait-all operations, timeout, cancellation, and bounded priority
  inheritance hooks;
- waitable IPC ports and channels with bounded validated messages, secured
  handle transfer, shared-section objects, and close-safe peer ownership;
- a strict `.zsvc` parser, fixed order for dependencies, limited restart
  supervision, explicit service tokens, and a real ServiceHost failure probe;
- filesystem-backed ServiceHost, SecurityHost, LogHost, MountHost, SessionHost,
  and user-mode Luma PE execution;
- an ACL-protected SessionHost-to-Luma channel and public process
  create/poll/wait/close calls; Luma launches a standard C programme from an
  exact path containing spaces and verifies exit code 21;
- strict UTF-8 and case-sensitive Windows-style paths;
- tested ACL, scheduler queue, object, PE, terminal, and display primitives;
- an early, deliberately limited Luma command loop retained only for explicit
  Recovery is achieved through the bounded user-mode Luma slice, which is the standard boot interface.

The exact verified state is given in [ZIZIUM_PROGRESS.md].
The index of the documentation for the architecture and subsystem
documents.

## Build

The primary supported host is Windows 11 x64 with PowerShell 7, GNU Make,
The linkers included are Clang/LLVM, the Microsoft linker, together with NASM, Python, QEMU, and EDK2 firmware.

```powershell
make deps
make
make test
make analyse
make sanitise
make release
make image
make boot-test
make storage-test
make zifs-test
make fault-test
make run
```

`make intel` builds an optional Intel-compiler validation variant when `icx`
It is installed; however, it is not the default build and provides no hardware-vendor
endorsement.

The dependency fetch is explicit, unlike normal compilation, which never downloads files.

## Design invariants

- PE/COFF is the native executable format; ELF is not one of Zizium's formats.
- ZiFS is the native root filesystem; FAT32 is used only for the EFI System
  Partition.
- When it comes to paths and object names, case sensitivity is observed.
main is the usual entry point for a C program; zizium.h and ZIA are optional.
Where it is natural, the English language and identifiers owned by the project use British spelling.

## Licence

The work owned by Zizium is under GPL-3.0 or later, and third-party notices are recorded in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
