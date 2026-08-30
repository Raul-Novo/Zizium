# x64 application binary interface

## Implemented in Seed

Zizium x64 C code uses the Microsoft x64 ABI to match PE/COFF tooling.

| Property | Contract |
| --- | --- |
| Integer arguments 1–4 | RCX, RDX, R8, R9 |
| Floating arguments 1–4 | XMM0–XMM3 |
| Integer return | RAX |
| Floating return | XMM0 |
| Caller home area | 32 bytes of shadow space |
| Stack alignment | 16 bytes at a call boundary |
| Volatile | RAX, RCX, RDX, R8–R11, XMM0–XMM5 |
| Non-volatile | RBX, RBP, RSI, RDI, R12–R15, XMM6–XMM15, RSP |

Public ABI structures begin with `struct_size` and `version` where they are
expected to cross component boundaries. Public scalar types are fixed width.
`ZiHandle` is opaque and `ZiStatus` is signed 32-bit. Negative status values
indicate failure; `ZiSucceeded` and `ZiFailed` are the required tests.

The Limine entry is the only current System V boundary. Its assembly bridge
converts execution into the Microsoft x64 environment before shared C runs.
ZiCRT's `ZiCrtStart` also follows the Microsoft x64 ABI and receives a process-
parameter pointer in RCX. It supports both ordinary `int main(void)` and
`int main(int argc, char *argv[])`; neither `zizium.h` nor `ZiMain` is required.

`ZiProcessParameters` version 1 is a 72-byte fixed-width record containing
counts, user pointers, and explicit byte lengths. Its argument and environment
vectors contain 64-bit user pointers and terminate with a null pointer. Strings
are UTF-8 with a trailing NUL for C consumption, while explicit lengths remain
the authority at the kernel/ZiCRT boundary. The mapped block is read-only
before Ring-3 entry.

The initial DLL boundary is also Microsoft x64. The build and QEMU gates prove
calls through `zx.dll`, `zicrt.dll`, and `zia.dll`, including import-address
table resolution and ordinary non-volatile-register rules. Public DLL ABI
versioning beyond the current symbol set is not frozen by Seed.

The architecture interrupt boundary is separately frozen inside the kernel.
Generated stubs normalise vector/error-code entry, preserve all general
registers, and call C with Microsoft x64 alignment and shadow space. The
176-byte `ZiX64InterruptFrame` ends with RIP, CS, RFLAGS, RSP, and SS at offsets
136, 144, 152, 160, and 168. Kernel-thread contexts additionally hold a
16-byte-aligned 512-byte `FXSAVE` area. These layouts have compile-time and
host-test assertions.

The freestanding kernel supplies a minimal Microsoft x64 `__chkstk` helper for
compiler-generated large stack frames. It preserves the requested allocation
size in RAX, uses only volatile R10/R11 scratch registers, and probes every
crossed 4 KiB page plus the final byte before the function prologue adjusts
RSP. This is ABI support, not a substitute for the kernel's guarded-stack
allocator; a guard hit still follows the ordinary page-fault policy.

The active Ring-3 selectors are user data `0x1b` and user code `0x23`; kernel
code/data remain `0x08` and `0x10`, and the TSS is `0x28`. The bootstrap
transition uses `IRETQ` with an interrupt-enabled user RFLAGS value. Each user
thread has a guarded kernel stack selected through TSS RSP0 and the syscall
per-CPU record.

The syscall boundary is a separate ABI. Its version-one `ZiSyscallFrame` is
exactly 208 bytes and captures every general register plus the syscall number,
four arguments, user RIP/RSP/RFLAGS, action, and result. Assembly and C layout
assertions protect the offsets. Safe returns require lower-half addresses and a
restricted, interrupt-enabled RFLAGS state before `SYSRETQ` is permitted.

## Scaffolded

Thread-local state and user exception-delivery records are scaffolded only.
Luma executes in the bounded Phase 6 user-session path and RuntimeHost proves
its entry symbol and core DLL imports link, but RuntimeHost is not executed.
Driver PE artefacts remain unloaded placeholders. Concurrent user-thread ABI
details are not defined; the current process wait is synchronous and bounded.

## Future

Unwind metadata, recoverable user-mode exception delivery, thread-local
storage, XSAVE-based extended-state policy, vector extensions,
structure-return edge cases, varargs conformance, and DLL versioning require
dedicated ABI tests before being frozen.

ARM64 and RISC-V will have architecture-specific ABI documents. They must not
alter x64 layouts already published by a stable release.
