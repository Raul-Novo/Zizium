# Zizium architecture

## Scope

Zizium 0.2 “Luma” is an x86-64, UEFI-first, PE/COFF-native operating-system
foundation. It is non-POSIX by design. Its kernel is modular monolithic: core
executive, memory, I/O, filesystem, security, and loader components share one
privileged address space, while their interfaces remain separately owned and
versioned.

The architectural layers are:

```text
standard C / ZiCRT or native application / ZIA
Zx native interface
dedicated syscall ABI
kernel executive and managers
HAL and architecture-specific code
hardware
```

PE32+ is the native executable container. ZiFS is the native system volume.
FAT32 is permitted only on the firmware-required EFI System Partition. Native
paths use drive letters and backslashes, preserve spaces, and compare validated
UTF-8 byte sequences exactly.

## Implemented in Seed

- A relocatable, import-free AMD64 PE32+ kernel and Limine revision-six boot
  adapter.
- An internal `ZiBootContext` which isolates the kernel from Limine types.
- COM1 diagnostics, a calm framebuffer console, a filesystem-backed user-mode
  Luma process, and an early serial loop retained only for explicit recovery.
- Checksummed ACPI RSDP/root-table/MCFG discovery, bounded PCIe ECAM
  enumeration, BAR probing, exact function-driver matching, and publication of
  discovered devices through real driver/device objects.
- Owned below-limit DMA allocation, explicit DMA barriers, a bounded uncached
  kernel MMIO arena, real IRP dispatch/completion/cancellation/expiry, and
  device-stack traversal.
- A polling QEMU NVMe controller with admin and I/O queues, namespace
  discovery, bounded timeouts, block reads, writes, and flushes, followed by
  defensive primary/backup GPT parsing and direct ZiFS partition mounting.
  Limine's ZiFS module is used only when an explicit recovery/development
  option requests it or an injected storage-failure test selects it.
- Scalable ZiFS allocation maps, redundant version-one journal headers,
  full-block redo records, one bounded regular-file create operation with up
  to 28 staged home-block images and 24 contiguous data blocks, bounded
  non-sparse overwrite/growth with up to 24 data blocks per request, plus
  atomic exact-case no-replacement same-directory rename/cross-directory move,
  shrink-only regular-file truncation, and regular-file deletion. The
  directory-extents incompatible feature preserves each fixed directory block
  as logical block 0 and maps up to 255 continuation blocks through inline
  extents. Released extents are validated globally and remain unavailable to a
  new valid writer until checkpoint. The serial writer reserves one ring slot,
  wraps record addressing, reclaims through each checkpoint, and automatically
  rolls back or replays. Host tests cover every relevant ordinary, wrapped,
  write-growth, first-directory-expansion, rename, move, truncate, and delete
  write/flush boundary; twenty-seven QEMU boots prove persistence, both crash
  outcomes, multi-block directory lookup, durable security-descriptor
  enforcement, and fail-closed rejection of a corrupted security table on the
  real partition path.
- A non-mutating host inspector for raw ZiFS volumes and GPT images validates
  both redundant metadata copies, active journal state, the durable security
  table, namespace and extent ownership, and allocation accounting. Committed
  pre-checkpoint metadata is checked through a memory-only replay overlay.
- A kernel-owned GDT, 64-bit TSS, dedicated catastrophic-exception IST stacks,
  a complete IDT, and a single 176-byte C interrupt-frame contract.
- Bounded exception diagnostics with automated invalid-opcode, ordinary
  page-fault, and active stack-guard QEMU tests.
- An x2APIC timer calibrated against PIT channel 2, uniprocessor interrupt
  levels, EOI handling, and 100 Hz scheduler ticks.
- Repeated quantum-driven pre-emption between two kernel workers, including
  separate stacks, general registers, and `FXSAVE` state.
- A validated, range-aware physical-memory inventory and deterministic page
  allocator with explicit state, ownership, reservations, and accounting.
- Kernel-owned four-level x64 page tables with 4 KiB map/unmap/protect/query,
  NX/W^X policy, PE-derived section permissions, an owned HHDM, an uncached
  APIC page, and a single temporary mapping window.
- Guarded boot, IST, idle, and worker stacks; a corruption-checked 256 KiB
  kernel pool; a fixed-size object cache; and leak-neutral live memory stress.
- A bounded early process manager with private lower-half CR3s, shared
  supervisor-only kernel mappings, owned user stacks, guarded kernel stacks,
  checked user copies, validated token ownership, pollable termination, and
  deterministic page-table teardown.
- Bounds-checked PE section mapping with final W^X permissions, deterministic
  alternate-base selection, checked DIR64 relocation, exact-case dependency
  lookup, bounded name/ordinal import/export resolution, and cycle detection.
- A Microsoft x64 Ring-3 transition, trusted-stack `SYSCALL` boundary, safe-
  return validation, and contained user exceptions.
- Three genuinely executed programmes created before running: ordinary
  `main(void)`, ordinary `main(argc, argv)` with versioned UTF-8 parameters and
  exact-case environment, and an optional ZIA call. They dynamically use
  `zx.dll`, `zicrt.dll`, and `zia.dll`, return statuses 21, 22, and 23, and
  reclaim all process pages.
- Bounded ZiFS regular-file reads and an allocator-driven image source provider.
  The system image contains core DLLs, programmes, drivers, and `.zsvc`
  manifests; native PE artefacts are not supplied as Limine modules.
- A strict version-one service-manifest parser, deterministic dependency DAG,
  bounded restart supervisor, and real ServiceHost failure/restart-limit proof.
- Filesystem-backed ServiceHost, SecurityHost, LogHost, and MountHost bootstrap
  processes with explicit service tokens, followed by SessionHost and Luma with
  distinct tokens and an ACL-protected channel.
- Public child create, poll/wait, and close calls. User-mode Luma rejects a
  wrong-case path and runs the ordinary-C programme at
  `C:\Program Files\Zizium\Hello Seed.exe` as a nested Ring-3 child.
- Locked object-type registration, bounded exact-case namespace directories,
  single-destruction lifetime management, and per-process generation-safe
  handles with ACL-enforced access and non-amplifying duplication.
- Dispatcher events, mutexes, semaphores, timers, process termination,
  wait-any/wait-all, timeout, cancellation, and bounded priority inheritance.
- Waitable bounded IPC ports/channels, validated inline messages, secured
  handle transfer, shared-section objects, and process-death endpoint cleanup.
- Host-tested Unicode, path, ZiFS, ACL, object-lifetime, scheduling-queue,
  PE-parsing, terminal, command-line, and display-scale primitives.
- Explicit public fixed-width types, native status values, colours, ZIA and Zx
  headers, plus minimal PE start-up objects that call ordinary C `main`.

## Scaffolded

- General object/handle/wait/port/shared-memory calls, input translation,
  persistent resident services, general PnP/resource arbitration, and loadable
  driver policy. The current public process and channel calls are narrow
  bootstrap contracts, not a complete executive API.
- RuntimeHost, keyboard, and framebuffer PE placeholders are not executed or
  dynamically loaded. The built-in NVMe path uses the real driver/device/I/O
  contracts but is statically linked into the kernel.
- Per-CPU scheduler data, scheduled user threads, automatic timer expiry,
  affinity migration, and priority policy beyond the current single-CPU
  timer-driven and bounded-wait slice.
- User processes run synchronously and are not placed on scheduler queues.
  One nested child path is verified through ZIA/Zx; this is not concurrent
  process scheduling. Bootstrap tokens are trusted kernel policy inputs, not
  products of a logon service or durable identity database.
- ZiFS mutation remains single-writer and bounded to one create, one
  non-sparse write/growth of at most 24 data blocks, one no-replacement
  rename/move, one shrink-only truncate, or one regular-file delete.
  Directories are limited to 256 blocks and four inline continuation extents;
  directory deletion/reclamation, sparse writes, overflow extents, ACL
  mutation/inheritance, clean unmount, repair tooling, and general file I/O
  APIs are not implemented. Durable ACL records themselves are implemented and
  checked at mount.

## Future

Concurrent processes, user-thread scheduling, cached/demand PE loading, shared
DLL mappings and unload, SMP-safe memory and scheduler locking,
TLB shootdown, demand paging, IOAPIC device routing, MSI/MSI-X, interrupt-driven
storage completion, AHCI, general ZiFS mutation, physical-hardware storage
validation, networking, audio, power management, the Aura
compositor, ZiUI, packages, updates, and additional architectures are not
implemented.

## Frozen invariants

- Native executables remain PE/COFF; ELF is not introduced as a native format.
- The root filesystem remains ZiFS and path matching remains case-sensitive.
- The x64 C ABI remains Microsoft x64; the syscall ABI remains distinct.
- Ordinary C `main` remains supported without `zizium.h`, ZIA, or `ZiMain`.
- Public native symbols use `Zi`, `Zx`, `Zk`, and `ZiFs`; private helpers use
  `snake_case`.
- ACL checks have default-deny semantics and no implicit administrator bypass.
- Architecture-specific assembly remains small and isolated.

ARM64 and RISC-V ports must provide the same internal boot, object, I/O, and
security contracts rather than exposing their boot protocols to shared code.
