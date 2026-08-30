# Physical and virtual memory

## Scope

This document records the Phase 2 kernel-memory contract, the verified Phase 3
user-process extension, and the Phase 5 MMIO/DMA boundary. The current code
owns and accounts for physical pages, installs four-level kernel and process
page tables, enforces page protections, provides bounded kernel stacks and
allocation pools, and can
create and tear down a bounded set of isolated lower-half process address
spaces with one active at a time. It is not a general working-set or virtual-
address manager.

## Implemented

### Boot inventory and physical pages

`ZiBootContext` version 3 carries the Limine memory map, HHDM offset, kernel
physical and virtual bases, mapped image size, paging mode, and physical RSDP
address. The kernel copies this information into its own bounded storage before
using it as the physical-memory inventory.

Inventory construction:

- rejects unknown memory types, zero-sized entries, non-4 KiB-aligned entries,
  arithmetic overflow, overlapping ranges, and an excessive range count;
- sorts ranges by physical address and merges adjacent ranges of the same type;
- retains discontiguous high ranges without allocating metadata up to the
  highest page-frame number;
- records the maximum described address and separate managed and initially
  usable page counts.

The PMM stores two bytes of metadata for every described page. Metadata is
indexed across the validated ranges, so a sparse framebuffer range does not
create an enormous empty metadata array. Each page records a state and an
owner. Current owners distinguish firmware, bootloader, kernel, boot module,
framebuffer, allocator metadata, page table, kernel stack, kernel pool,
temporary mapping, test allocation, process image, user stack, process data,
the physical page-zero guard, and DMA allocations.

The metadata array is itself placed in an aligned usable run and immediately
reserved as allocator metadata. Page zero is never returned by the allocator.
Kernel-and-module boot ranges begin reserved; known module pages are reassigned
to the module owner. Firmware, reserved, bad, kernel, module, framebuffer, and
allocator pages cannot satisfy an allocation request.

The physical allocator provides deterministic first-fit allocation over usable
ranges, power-of-two page alignment, explicit ownership, exact owner checks on
free, range queries, reservations, reserved-owner reassignment, and aggregate
managed/free/reserved/allocated counts. It rejects partial intervals, wrong
owners, double frees, invalid alignment, and arithmetic overflow.

### Kernel page tables

The x64 mapper owns a four-level, 4 KiB page-table hierarchy. Allocation and
physical access are callbacks, allowing host tests to exercise the mapper
without privileged instructions. It supports map, unmap, protect, and query
operations for pages and ranges. Operations validate canonical addresses,
alignment, range overflow, the architectural 52-bit physical-address bound,
and protection flags.

NX support is mandatory for this slice. Boot fails safely if CPUID or EFER
cannot establish it. Writable-and-executable mappings are rejected, as are
executable device mappings. CR0.WP and CR4.PGE are enabled before the owned CR3
is loaded. The new CR3 value and the kernel base mapping are read back and
verified.

Page-table creation rolls back newly allocated intermediate tables on failure.
Range mapping removes earlier leaves if a later page fails. Range unmap and
protection first validate that every leaf exists. Empty subordinate tables are
returned to the PMM. The kernel wrapper invalidates affected TLB entries after
successful changes and treats a failed page-table release as memory
corruption.

The kernel image is parsed as PE/COFF before remapping. Headers are read-only
and non-executable. Each section derives its permissions from PE section
characteristics; a writable-and-executable section is rejected as a malformed
kernel image. The current release image therefore has executable/read-only
text, read-only data, writable/non-executable data and Limine-request sections,
and a read-only relocation section.

The HHDM is rebuilt from validated boot ranges:

| Boot range | HHDM policy |
| --- | --- |
| Usable | read/write, non-executable, global |
| ACPI reclaimable or NVS | read-only, non-executable, global |
| Boot reclaimable | read-only, non-executable, global |
| Kernel and modules | read-only, non-executable, global |
| Framebuffer | read/write, non-executable, uncached, global |
| Reserved or bad | not mapped |

The local APIC has a dedicated uncached page. A separate single-page temporary
window has exclusive map/unmap state and is verified by writing through it and
reading the same owned physical page through the HHDM.

Phase 5 adds a bounded uncached MMIO arena at `0xffffe10000000000`. It contains
64 independent 2 MiB slots, maps only validated physical ranges, rejects
overflow and executable device mappings, and releases slots after unmapping.
PCIe ECAM uses one temporary 1 MiB bus mapping at a time; the NVMe controller
uses a persistent bounded BAR mapping. Firmware table reads use a read-only
temporary physical mapping rather than writable aliases.

The kernel DMA adapter allocates explicitly owned, aligned PMM pages below the
caller's physical-address limit and exposes physical/virtual pairs only after
owner and size validation. Buffers are zeroed on allocation and use explicit
architecture barriers for device-direction synchronisation. There is no IOMMU
or scatter/gather mapping yet; unsafe controller shutdown deliberately
quarantines pages rather than returning memory that the device may still own.

### Current kernel virtual regions

These fixed regions are Phase 2 policy, not a complete kernel virtual-address
allocator:

| Virtual base | Current use |
| --- | --- |
| `0xffffb00000000000` | Eight-page mapping stress window |
| `0xffffc00000000000` | 256 KiB kernel pool |
| `0xffffd00000000000` | Guarded kernel-stack slots |
| `0xffffe00000000000` | Local-APIC device page |
| `0xffffe00000001000` | Single temporary physical-page window |
| `0xffffe10000000000` | 128 MiB bounded MMIO arena in 2 MiB slots |
| `0xffffffff80000000` | Preferred PE kernel image base |

The Limine-provided HHDM base is kept in `ZiBootContext` and used for physical
page-table and allocation access.

### Seed process address space

The 48-bit virtual-address policy is now frozen for the initial x64 process
slice:

| Range | Policy |
| --- | --- |
| below `0x0000000000010000` | unmapped user null/low guard |
| `0x0000000000010000`–`0x00007fffffffffff` | validated lower-half user range |
| `0x00007ffffff00000` | exclusive top of the bootstrap stack policy |
| PML4 slots 256–511 | shared supervisor-only kernel mappings |

`zi_address_space_initialise` creates a private PML4 and copies only the upper
kernel half from the trusted template. User mappings require read permission,
the user bit, lower-half page alignment, explicit physical ownership, and no
global or device flags. Writable-and-executable mappings are rejected.

Owned map, protect, unmap, query, deterministic aligned free-range search,
copy-to-user, copy-from-user, and destroy operations are implemented. Copy
operations validate overflow and permissions for every page crossed.
Destruction releases mapped image/stack/data pages, walks and returns private
lower-half page tables, checks the shared upper half, and terminates the
address-space descriptor. The live boot path compares PMM free/allocated counts
before process-set creation and after complete cleanup.

Each PE is staged writable/non-executable, copied, relocated if required, then
protected as read-only headers and per-section read/write/execute mappings
without W^X. The main programme's preferred base is
`0x0000000140000000`, but the acceptance path forces deterministic alternate-
base placement. A separate 64 KiB writable, non-executable user stack ends
below `ZI_USER_STACK_TOP`; the active thread also owns a guarded 64 KiB kernel
stack. The free-range search is deterministic and does not claim ASLR entropy
or a general allocation policy.

### Guarded stacks

The stack allocator owns sixteen 128 KiB virtual slots. Every active stack has
an unmapped lower guard page, a page-aligned writable/non-executable usable
region, and an unmapped upper guard page. Physical pages have the kernel-stack
owner and are zeroed before use and release. Descriptor version, slot identity,
mapping bounds, physical owner, and release order are checked.

After the VMM becomes active, the boot continuation moves to a guarded 64 KiB
stack. TSS RSP0 and the double-fault, non-maskable-interrupt, and machine-check
IST entries move to guarded stacks as well. RSP0 is temporarily changed to the
active process's guarded kernel stack while Ring 3 is active and is restored
before that stack is released. The scheduler's idle and smoke-test workers use
separate guarded 32 KiB stacks. Static entry and IST arrays remain only as
pre-VMM bootstrap/emergency storage.

A page fault whose CR2 lies in an active stack guard emits
`MEMORY_GUARD_FAULT` and a specific stack-boundary diagnostic before the normal
bounded panic path. It remains fatal; automatic stack growth is not present.

### Pool and object cache

The reusable pool core manages a caller-supplied 16-byte-aligned arena. Every
block has a magic value, keyed descriptor checksum, state, previous/current
span, requested size, and generation. Allocations have a canary immediately
after the requested byte range; aligned padding is checked. Freed payload is
zeroed and must remain zero, allowing stale writes to be detected during later
validation. Adjacent free blocks coalesce, and statistics report capacity,
allocated/free bytes, largest free payload, block count, active allocations,
peak use, and generation.

The fixed-size object cache obtains one slab from a pool. Per-slot checksums,
generation, state, immediate tail canaries, zero-on-free, capacity limits,
exhaustion handling, and destroy-with-live-object rejection are implemented.

The live kernel pool owns 64 physical pages mapped at
`0xffffc00000000000`. It also owns a genuine 64-entry memory-descriptor cache.
Kernel wrappers use an interrupt guard for current uniprocessor serialisation.
`HEAP_READY` means this bounded pool/cache foundation passed its self-test; it
does not mean a complete general-purpose C heap or pageable allocator exists.

### Verification

Host tests cover malformed and sparse memory maps, owner-safe physical
allocation, page zero, mapping rollback, canonical and alignment failures,
W^X rejection, private CR3 cloning, cross-page user copies, hostile/null user
ranges, protection changes, deterministic process teardown, pool fragmentation
and coalescing, canary/padding/free-payload corruption, double-free rejection,
object-cache exhaustion, and single-slab lifecycle. Both ordinary and
AddressSanitizer builds run these tests.

The boot stress path performs:

- sixteen PMM rounds with eight varying allocations and 1/2/4-page alignment;
- an eight-page virtual alias check, read-only protection change, W^X rejection,
  unmap, and absent-mapping query;
- four pool-fragmentation rounds plus repeated descriptor-cache self-tests;
- eight rounds of four guarded-stack allocations and releases;
- an exact before/after PMM accounting comparison.

The `MEMORY_STRESS` marker is emitted only after every operation succeeds and
the final counts match. `make fault-test` separately verifies invalid opcode,
an ordinary unmapped access, and a real write to an active lower guard page.

## Scaffolded

- The address-space record has a bounded region table, deterministic free-range
  search, and process-data owner, but no section object, mapped file, working
  set, or copy-on-write policy exists.
- The early manager has four process slots and the acceptance path creates and
  tears down three private spaces. Execution is synchronous; general public
  process creation and scheduler address-space switching are not connected.
- Executive objects and dispatcher domains use atomic spin locks, while the
  interrupt guard remains a uniprocessor logical-level mechanism. No complete
  SMP/pre-emption lock protocol exists.
- Fixed virtual regions preserve separation between kernel facilities, but a
  general kernel virtual-address allocator is absent.

## Future

Shared-section objects now have secured handles, maximum access, transfer, and
process-death cleanup, but they do not map their backing into user address
spaces. Later work must add SMP locks and TLB shootdown, PCID where justified,
page-table sharing rules, copy-on-write, demand paging, memory-mapped files,
working sets, memory pressure and reclamation, quotas, NUMA policy, IOMMU and
scatter/gather integration, boot-reclaimable release, pool growth/reclaim, and
measured allocation tagging/leak diagnostics.

Large pages and five-level paging are intentionally absent. The current pool
validates the complete arena on operations as a hardening-first policy; its
cost must be measured before selecting any release-mode validation reduction.
