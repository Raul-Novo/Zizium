# x64 CPU ownership, exceptions, and interrupts

## Implemented in the current Seed slice

Zizium replaces the loader's execution tables before consuming the general
boot context. The bootstrap entry disables interrupts, enables the mandatory
x86-64 SSE state, moves to a private 64 KiB stack, and then enters Microsoft
x64 C code.

The kernel-owned GDT uses these selectors:

| Selector | Purpose |
| --- | --- |
| `0x08` | Ring-zero 64-bit code |
| `0x10` | Ring-zero data and stack |
| `0x1b` | Ring-three data and stack |
| `0x23` | Ring-three 64-bit code |
| `0x28` | 64-bit TSS |

The 104-byte TSS has `RSP0` and three interrupt-stack-table entries. IST1 is
assigned to double fault, IST2 to non-maskable interrupt, and IST3 to machine
check. Static 32 KiB arrays provide only the pre-VMM emergency state. Once the
owned page tables are active, RSP0 uses a guarded 64 KiB boot stack and each IST
uses a separately owned guarded 32 KiB stack. The active Seed user thread
updates RSP0 to its guarded 64 KiB kernel stack and restores the earlier value
before teardown.

The IDT has all 256 entries. Breakpoint and overflow gates have DPL 3 for their
architectural software forms; the remaining gates have DPL 0. Timer vector
`0xd0`, local-APIC error vector `0xfe`, and spurious vector `0xff` are reserved.

## Interrupt-frame contract

Each generated vector stub supplies a vector number and a normalised error-code
slot, then the shared stub saves all general-purpose registers. The resulting
`ZiX64InterruptFrame` is exactly 176 bytes:

| Offset | Field |
| ---: | --- |
| `0`–`112` | R15 through RAX |
| `120` | Vector |
| `128` | Error code, or zero |
| `136` | RIP |
| `144` | CS |
| `152` | RFLAGS |
| `160` | RSP |
| `168` | SS |

Vectors 8, 10–14, 17, 21, 29, and 30 use the hardware error code. All other
vectors receive an explicit zero. The common assembly path aligns the stack,
provides the 32-byte Microsoft x64 shadow area, calls one C dispatcher, and
returns with `IRETQ`. A dispatcher may select a different validated frame to
perform a kernel-thread context switch.

Each live thread owns a 16-byte-aligned 512-byte `FXSAVE` area. The interrupt
boundary saves the interrupted floating-point/SIMD state before calling C and
restores the selected thread's state before return. This is sufficient for the
current homogeneous scheduled ring-zero threads. Seed user processes run
synchronously, one at a time, before the APIC timer is enabled and are not yet
schedulable user threads. This is not an extended-state policy for AVX,
protection keys,
debug registers, TLS bases, or process switching.

## Exceptions and fault tests

Fatal exceptions disable the framebuffer sink and use bounded COM1 output.
Diagnostics include vector, error code, RIP, CS, RFLAGS, RSP, SS, all general
registers, and CR2 plus access-bit decoding for page faults. A recursive fault
emits one emergency marker and halts. Fatal faults end in the existing bounded
panic path.

`make fault-test` builds four generated smoke images. One executes `UD2`, one
reads an intentionally unmapped canonical kernel address, one writes to the
lower guard page of the active boot stack, and one enters a non-executable user
page. The first three must report vectors 6 or 14 as appropriate, exact fault
data, a separate guard classification for the third case, and `PANIC`, while
never reaching Luma or the recursive-exception marker.

The user case takes a different containment path. A Ring-3 exception owned by
the active Seed process marks that process terminating, changes the
interrupt frame to a private assembly sentinel, and returns directly to a
trusted kernel continuation. It restores kernel CR3/RSP, reclaims the user
address space, emits `USER_FAULT_CONTAINED` and `USER_PROCESS_CLEAN`, then
continues through APIC pre-emption to Luma without `PANIC`.

## Local APIC and interrupt levels

The current QEMU path discovers APIC and x2APIC support through CPUID, enables
x2APIC through `IA32_APIC_BASE`, masks both legacy PICs, configures the local
vector table, and acknowledges timer interrupts with EOI. PIT channel 2 supplies
a bounded 10 ms one-shot reference interval. The local APIC timer is calibrated
with divide-by-16 and then runs periodically at 100 Hz.

The uniprocessor interrupt-level contract is:

| Level | Meaning |
| ---: | --- |
| 0 | Passive work |
| 2 | Dispatcher-critical work |
| 13 | Clock/timer dispatch |
| 15 | Exception and high-level work |

An interrupt guard saves RFLAGS, disables maskable interrupts, raises the
logical level, and restores both on exit. This is not an SMP spin-lock or a
complete interrupt-priority controller.

The memory manager reserves a dedicated uncached virtual page for legacy xAPIC
MMIO instead of depending on a loader HHDM device mapping. The current QEMU
smoke path continues to select x2APIC through MSRs, so the legacy MMIO path is
architecturally mapped but has not yet received equivalent automated coverage.

## Timer-driven scheduling proof

The timer dispatcher performs quantum accounting and may return another
thread's frame. The boot thread and two equal-priority worker threads use
guarded stacks and separate floating-point states. Each worker and the idle
representation has a 32 KiB usable stack bounded by unmapped pages. Acceptance
requires at least six hardware ticks, three context switches, and observed
execution by both workers. The workers are removed under the dispatcher guard
after proof, while the timer and boot thread remain active through the Luma
prompt.

## Future

Dispatcher waits, explicit timeout expiry, and waitable timers now exist.
Phase 5 added bounded I/O request expiry and a polling NVMe timeout path, but it
does not claim controller-interrupt completion. Later process work needs
scheduled user threads and recoverable user exception delivery. Hardware
phases must add ACPI interrupt topology, per-CPU TSS and interrupt state,
IOAPIC routing, MSI/MSI-X, interrupt/DPC I/O completion, extended processor
state, SMP-safe locks, nested-interrupt policy, and recovery or debugger
decisions for faults that need not be fatal.
