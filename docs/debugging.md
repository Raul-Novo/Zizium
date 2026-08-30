# Debugging and crash analysis

The debugging architecture reserves serial diagnostics, structured kernel
events, crash dumps, symbols, stack traces, PE debug information, driver
verification, syscall tracing, and user-facing crash inspection.

## Implemented in Seed

COM1 is initialised at boot and supports bounded polling input/output. The
kernel log records severity, subsystem, message, and sequence in a fixed ring,
mirrors text to serial and framebuffer, emits machine-checkable boot markers,
and has a non-returning panic path. Reproducible links retain a PDB. `pecheck`
inspects bounded PE metadata.

All architectural exceptions enter one C frame contract. Fatal diagnostics
switch to bounded serial-only output and include vector, error code, RIP, CS,
RFLAGS, RSP, SS, every general register, and page-fault CR2/access decoding.
Page faults in an active kernel-stack guard receive a separate
`MEMORY_GUARD_FAULT` classification. Recursive exceptions emit one emergency
marker and halt. Automated QEMU tests exercise invalid opcode, an ordinary
unmapped read, and a real guard-page write without triple-faulting.

Physical and virtual memory bring-up emits stage markers and, in debug builds,
the new CR3 and kernel mapping addresses. The ordinary boot test requires PMM,
VMM, temporary mapping, pool/cache, guarded-stack, and leak-neutral memory
stress evidence before accepting Luma readiness.

Storage smoke evidence now distinguishes direct NVMe/GPT mounting from module
recovery. A dedicated negative gate injects a bounded controller timeout and a
second corrupts both GPT header CRCs. Each must reject direct mounting, emit an
exact reason marker, enter only the explicit recovery path, and still reach
Luma without a panic.

## Scaffolded

Reserved tools are `zdbg`, `symdump`, Trace Viewer, and Crash Viewer. CrashHost
and symbol/log directories exist in ZiFS. None consumes a live crash yet.

## Future

Stack walking, symbol-server format, kernel breakpoints, remote protocol,
minidumps/full dumps, unwinding, source mapping, recoverable exception policy,
driver verifier, syscall tracing, crash triage, and debugger security are
unimplemented.
