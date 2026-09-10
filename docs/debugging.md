# Debugging and crash analysis

The debugging architecture reserves serial diagnostics, structured kernel
events, crash dumps, symbols, stack traces, PE debug information, driver
verification, syscall tracing, and user-facing crash inspection.

## Implemented in Seed

COM1 is initialised at boot and supports bounded polling input/output. The
kernel log records severity, subsystem, message, and sequence in a fixed ring,
mirrors text to serial and framebuffer, emits machine-checkable boot markers,
and has a non-returning panic path. Reproducible links retain a PDB. `pecheck`
inspects bounded PE metadata. `zifsinspect` reads raw ZiFS volumes or their GPT
partition without write capability and reports redundant superblocks, journal
headers and records, security descriptors, namespace/linkage, extents, and
allocation accounting. The separate `zifsrepair` tool consumes the same
full-volume evidence but writes only reviewed, uniquely provable redundancy
or lifecycle repairs. It recomputes the plan before apply and never treats a
refused state as repaired.

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

ZiFS inspection has five real checkpoints in `make zifs-test`: a cleanly
unmounted volume, an interrupted unmount, a clean post-create volume, a
committed transaction stopped before checkpoint, and a clean grown file plus
multi-block directory. The interrupted-unmount report identifies the valid
mounted state without inventing an active transaction. The committed
checkpoint is validated through a memory-only journal replay overlay and must
report recovery required. Thirteen host fixtures cover a valid ordinary volume,
a valid formatter-created multi-block directory, a valid unclean mount,
redundant-copy degradation, checksums, namespace metadata, and allocation
corruption; every fixture is hashed before and after inspection to enforce the
read-only contract.

Repair acceptance exercises raw and GPT containers, clean fixed points, four
repairable metadata combinations, wrong and stale review tokens, three refused
corruption classes, UTF-16 paths, and every write/barrier boundary of a
combined three-action plan. A persistent QEMU image is repaired offline and
then boots through the direct ZiFS partition without recovery markers.

## Scaffolded

Reserved tools are `zdbg`, `symdump`, Trace Viewer, and Crash Viewer. CrashHost
and symbol/log directories exist in ZiFS. None consumes a live crash yet.

## Future

Stack walking, symbol-server format, kernel breakpoints, remote protocol,
minidumps/full dumps, unwinding, source mapping, recoverable exception policy,
driver verifier, syscall tracing, crash triage, and debugger security are
unimplemented.
