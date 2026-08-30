# Object and handle manager

The object manager owns Zizium's case-sensitive internal namespace. Its root
uses paths such as `\System\Devices`, `\System\Drivers`, `\System\Sessions`,
and `\Volumes\C`. A later volume manager will translate user path
`C:\Users\Raul\File.txt` to `\Volumes\C\Users\Raul\File.txt` without changing
case or normalising Unicode.

Object types include processes, threads, files, directories, devices, drivers,
volumes, events, mutexes, semaphores, timers, sections, tokens, ports, channels,
displays, input devices, and power objects.

## Implemented in Seed

`ZiObjectHeader` records a registered type and versioned operations table,
exact UTF-8 name, parent, security descriptor, debug name, reference count,
handle count, flags, and single-destruction state. An atomic executive lock
serialises every lifetime transition. Reference and handle overflow, underflow,
use after destruction, and double destruction fail explicitly. Destructors run
outside the object lock and exactly once.

Object operations include an optional last-handle callback. An endpoint which
uses it rejects new handles as soon as its final handle starts closing. IPC
ports and channels use this rule to sever peer references and drain queued
resources during process teardown, avoiding a reference cycle or destructor
re-entry.

`ZiObjectTypeRegistry` uses caller-supplied bounded storage. Registration
rejects duplicate numeric IDs and duplicate exact-case names. Lookup by ID and
validated UTF-8 name is locked and bounded.

`ZiObjectDirectory` also uses caller-supplied bounded storage. Insert takes a
reference and assigns one parent; lookup returns a referenced object; remove
either transfers the directory reference to the caller or releases it. Exact
names are distinct, so `Temp` and `temp` can coexist. Absolute namespace lookup
requires a leading backslash, rejects empty, `.` and `..` components, forward
slashes, embedded NUL bytes, malformed UTF-8, and traversal through a
non-directory object.

Every Seed user process owns a 32-entry `ZiHandleTable`. A 64-bit opaque handle
encodes a non-zero generation and slot, so a closed slot cannot be reused
through a stale value. A slot is retired permanently instead of wrapping after
generation `UINT32_MAX`, preserving that guarantee even at the generation
boundary. Open evaluates the object's ACL against the process token and stores
only the granted mask. Lookup enforces desired access and an optional exact
object type while returning a temporary object reference. Duplication cannot
amplify the source mask and repeats the ACL check against the target token.
Close invalidates the slot before releasing its object reference. Process
teardown closes all entries, prevents later lookup/open, and runs endpoint
cleanup before process storage is cleared.

Host tests cover exact-case registration and namespace traversal, namespace
malformation, access denial, stale generations, wrong types, table exhaustion,
duplication, process teardown, underflow, one destructor call, and automatic
IPC endpoint destruction. The normal QEMU path additionally requires
`OBJECT_NAMESPACE`, `HANDLE_ACCESS`, and `IPC_PROCESS_CLEAN` markers.

Each live user process is now itself a typed, ACL-secured object. A child
created by a parent receives the parent's explicit token, and the resulting
process handle grants only Read and Execute. `ZxCloseHandle` performs a checked
lookup, invalidates the generational slot, drops the lookup reference, and
releases a non-running child exactly once. Session IPC endpoints are ordinary
ACL-checked handles and are closed by process teardown.

## Scaffolded

The mechanism is real, but Zizium does not install a persistent system-wide
namespace for general user calls. The boot acceptance tree is deliberately
bounded and private. Processes are exposed through the narrow create/wait/close
slice, but they are not named in a global object directory. Threads, files, and
general objects do not yet have public create/open/duplicate calls.

Object symbolic links, inherited handles, kernel-only handles, per-handle
audit context, quotas, and a general allocation policy remain unspecified.

## Future

Later phases connect every device, driver, volume, file, and service object to
a persistent namespace, complete the handle boundary, add namespace policy and
auditing, and replace fixed capacities where a measured dynamic policy is
appropriate. Phase 16 must harden locking for SMP contention and define
processor-level lock ordering without changing exact-case name semantics.
