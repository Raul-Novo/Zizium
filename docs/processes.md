# Processes and Ring 3

## Scope

Seed implements a bounded, synchronously executed early process manager to
prove the x64 privilege boundary and native programme start-up contract end to
end. It is intentionally smaller than the future executive process manager,
but it uses the permanent address-space, image, syscall, token, parameter,
stack, termination, and teardown contracts rather than simulated calls.

## Implemented

The manager owns four explicit process slots and monotonic process and thread
identifiers. A process owns versioned `ZxProcess`, `ZxThread`,
`ZiAddressSpace`, `ZiUserImageSet`, and `ZiUserProcess` records together with:

- a private four-level CR3 containing only lower-half user mappings and the
  trusted supervisor-only kernel half;
- owned PE image and DLL pages at safe lower-half bases;
- a 64 KiB writable/non-executable user stack;
- a separately guarded 64 KiB kernel stack;
- a read-only, versioned process-parameter mapping;
- a validated access token and an owned copy of up to 16 group identities;
- a private 32-entry generation-safe handle table with granted-access masks;
- an active TSS RSP0 value and a versioned 64-byte syscall CPU record;
- explicit Initialised, Running, Terminating, and Terminated states and a
  signed exit status.

The AMD64 Native-subsystem PE and its bounded DLL dependency graph are read
from exact-case ZiFS regular files through a size-limited allocator provider.
The loader validates and maps them,
forces the main image away from its preferred base in the acceptance path,
applies DIR64 relocations, resolves named or ordinal imports, and applies final
header and section W^X permissions before entry through `IRETQ` at Ring 3 with
interrupts enabled.

`ZiProcessParameters` is a versioned 72-byte user ABI record. Kernel-side
serialisation validates strict UTF-8, rejects embedded NUL bytes and malformed
environment entries, limits arguments and environment entries to 32 each, and
places the image path, command line, pointer vectors, and strings in one
bounded read-only mapping. Argument zero is the image path. Environment names
are compared exactly, so `Mode` and `MODE` are distinct.

The boot acceptance path creates three process records before running any of
them. It then executes them synchronously and verifies:

- ordinary `int main(void)` returns 21;
- `int main(int argc, char *argv[])` receives spaces, UTF-8 parameters, and an
  exact-case environment and returns 22;
- an application that optionally includes `zizium.h` calls ZIA through
  `zia.dll` and returns 23.

The manager also supports one synchronous parent/child chain. A registered
launch provider receives a checked absolute `ZiStringView`, performs exact-case
ZiFS lookup, derives the PE module name from the final component, reads the
main image and core DLLs within 64 KiB per-file and 128 KiB aggregate limits,
and creates the child with an owned copy of the parent token. Raw file buffers
are released once the mapper has copied every image.

`ZxCreateProcess` returns a Read/Execute process handle in the parent table.
A zero-timeout `ZxWaitForObject` polls without starting the child; a non-zero
timeout starts it synchronously and returns its signed status. Nested Ring-3
entry isolates the required GS transition in `syscall.asm`, preserves the
parent syscall CPU record, and restores the parent as active when the child
terminates. Closing the process handle releases the child exactly once.

Normal boot proves this from user-mode Luma. A wrong-case path beneath
`C:\Program Files` fails without creating a process. The exact path containing
spaces launches an ordinary `main(void)` programme, polls it, waits for exit
code 21, closes the handle, and verifies that the stale handle is rejected.

Termination signals the process dispatcher header and preserves the signed
exit status. The kernel-internal wait remains a zero-timeout poll. The public
child wait adds synchronous nested execution for non-zero timeouts; it is not
a scheduler-blocking wait and does not provide concurrent process execution.

Before Ring-3 execution, the Phase 4 acceptance slice uses two of the distinct
process records, their separately owned tokens, and their real handle tables
to exchange a bounded channel message and transfer a read-only shared-section
handle. It also arms ordinary handles which process release must close. The
post-release check proves zero remaining handles and exactly one destruction.

Normal exit and user-exception termination both restore the trusted kernel CR3
and continuation stack. Cleanup restores the earlier TSS RSP0, unloads the
complete image set, destroys the private address space, releases every user and
page-table page, releases the guarded kernel stack and owned token data, zeros
the process slot, and verifies PMM allocation counts exactly match their
starting values. The normal smoke test proves this independently for all three
programmes and for the complete process set.

User faults are distinguished from kernel faults by the active process and the
interrupted CS privilege level. A contained user exception records its vector,
selects a private assembly termination sentinel, and never rewrites an
untrusted return frame into a kernel return. Kernel exceptions retain the fatal
bounded diagnostic policy.

## Scaffolded

`ZxProcess` and `ZxThread` reserve affinity, priority, scheduler, wait, and
architecture links. Execution remains uniprocessor and synchronous; the only
verified nesting is one active top-level process and one child. Capacity limits are four
processes, eight images per process, 32 arguments, and 32 environment entries.
The filesystem provider reads complete bounded files eagerly rather than using
file objects, demand paging, or shared DLL mappings.

There is no general process namespace, inherited-handle list, command-line
parser in the kernel, job object, scheduled user thread, concurrent process
execution, or arbitrary token selection. The public create/wait/close path is
deliberately limited to a child which inherits its parent's token.

## Future

Later work adds scheduled and concurrent user threads, richer process and
handle calls, parent/child policy, jobs, debugging, quotas, capabilities,
durable service identities, demand loading, shared images, and SMP-safe
lifecycle coordination.
