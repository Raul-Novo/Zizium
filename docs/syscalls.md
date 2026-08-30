# Native syscall contract

## Register convention

The dedicated x86-64 syscall ABI is distinct from the C ABI:

| Purpose | Register |
| --- | --- |
| Syscall number | RAX |
| Argument 1 | R10 |
| Argument 2 | RDX |
| Argument 3 | R8 |
| Argument 4 | R9 |
| Return status/value | RAX |
| Hardware-clobbered | RCX, R11 |

The user wrapper moves Microsoft x64 argument one from RCX to R10 before the
`SYSCALL` instruction. Calls requiring more than four scalar inputs will use a
versioned, probed user structure; no untrusted stack argument is consumed by
the Seed dispatcher.

## Number groups

- `0x0000`: objects, handles, and waits;
- `0x0100`: processes and threads;
- `0x0200`: virtual memory;
- `0x0300`: files and volumes;
- `0x0400`: devices and I/O;
- `0x0500`: IPC channels;
- `0x0600`: time and timers;
- `0x0700`: security;
- `0x0800`: system information;
- `0x0900`: debugging;
- later groups: display, input, and networking.

Named Seed reservations include `CloseHandle`, `WaitForObject`, `ExitProcess`,
`CreateProcess`, `CreateThread`, virtual-memory allocation and release, file
create/read/write, device control, time query, access check, system-information
query, and debug write. Reservation does not imply implementation.

## Implemented in Seed

The bootstrap x64 process configures EFER.SCE, STAR, LSTAR, FMASK, GS base, and
kernel GS base and verifies every MSR read-back before entering Ring 3.
`ZkX64SyscallEntry` then:

1. executes `SWAPGS` and captures the untrusted RSP before reusing it;
2. switches to the active thread's trusted guarded kernel stack;
3. builds the exact version-one, 208-byte `ZiSyscallFrame` with Microsoft x64
   shadow space;
4. calls the C dispatcher;
5. either validates lower-half RIP/RSP and restricted RFLAGS before `SYSRETQ`,
   or restores kernel CR3/RSP and terminates the process without returning to
   untrusted state.

The following calls are active for the bounded user-process and session slice:

| Number | Call | Current contract |
| ---: | --- | --- |
| `0x0000` | `ZxCloseHandle` | Closes a generation-safe process or channel handle; a stale second close fails. A non-running child process is released after its last parent handle closes. |
| `0x0001` | `ZxWaitForObject` | Polls a child process at timeout zero or synchronously runs and waits for it when timeout is non-zero, then copies its signed exit code to checked user memory. |
| `0x0100` | `ZxExitProcess` | Terminates the process and returns its signed 32-bit status to the kernel continuation. |
| `0x0101` | `ZxCreateProcess` | Copies and validates a bounded exact-case UTF-8 absolute path, loads the PE/DLL graph from ZiFS, creates a child with the parent token, and returns an ACL-checked process handle. |
| `0x0500` | `ZxSendChannel` | Copies and validates one version-one inline channel message and requires Write access to the assigned endpoint. Handle transfer is rejected in this public slice. |
| `0x0501` | `ZxReceiveChannel` | Receives one queued inline message through a Read handle and copies the zeroed public record to writable user memory. |
| `0x0502` | `ZxGetBootstrapChannel` | Returns the process's kernel-assigned session channel handle or `ZI_STATUS_NOT_FOUND`. |
| `0x0900` | `ZxDebugWrite` | Copies at most 512 bytes from a readable user range, requires valid UTF-8, and writes to COM1 and the framebuffer sink. |

Every user range is checked for lower-half bounds, overflow, page presence,
user accessibility, and required read/write permission. Unsupported numbers
return `ZI_STATUS_NOT_IMPLEMENTED`. Invalid frame or return state terminates the
process with `ZI_STATUS_PRIVILEGE_VIOLATION`.

The normal QEMU test proves debug output and exit from several separate C
programmes. It also proves SessionHost-to-Luma send/receive, wrong-case process
rejection, create, zero-timeout poll, nested child execution, wait, exit-code
copy, close, and stale-handle rejection. The child transition uses one isolated
assembly wrapper to preserve the parent's kernel GS/syscall record while the
child executes with user GS; the manager restores the parent record, active
process, CR3 continuation, and TSS RSP0 after the child terminates.

A separate QEMU test enters a non-executable user page,
contains the resulting exception, reclaims the address space, and continues to
the filesystem-backed session. Host tests cover frame offsets, null and hostile pointers, non-canonical/
lower-half violations, unsafe flags, W^X, cross-page copies, and teardown
accounting.

## Scaffolded

The remaining versioned number groups, ZIA-to-Zx declarations, and user-memory
contracts are reservations. General dispatcher-object waits, threads, file and
device I/O, shared sections, ports, handle duplication/transfer, virtual-memory
release, cancellation, asynchronous completion, and syscall tracing are not
publicly implemented. The non-zero process wait is synchronous nested
execution, not scheduler-driven blocking. The single per-CPU record and single
active parent/child chain are bootstrap uniprocessor implementations, not SMP
or concurrent-process facilities.

## Future

Later work needs general reviewed object/handle/wait/IPC contracts, per-CPU
syscall state, scheduled user threads,
SMP switching, asynchronous cancellation, tracing, compatibility/version
negotiation, security auditing, and a reviewed contract for every reserved
call.
