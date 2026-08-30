# Logging

Logs are structured records with time, sequence, severity, subsystem, event
identifier, process/thread context, and typed fields. Human text is a rendering,
not the sole durable representation.

Reserved destinations are:

```text
C:\Zizium\Logs\System
C:\Zizium\Logs\Security
C:\Zizium\Logs\Boot
C:\Zizium\Logs\Crash
```

## Implemented in Seed

The early kernel has a fixed in-memory ring and COM1/framebuffer rendering.
Boot-stage markers cover CPU-table ownership, exception readiness, physical and
virtual memory ownership, temporary mapping, pool/cache readiness, guarded
stacks, memory stress, APIC timer start, real scheduler ticks, pre-emption,
ZiFS, framebuffer state, and Luma. Phase 4 adds exact markers for object
namespace lookup, granted handle access, dispatcher waits, two-process IPC,
secured handle transfer, and process-release cleanup. Fault-test markers
separately identify the requested fault, selected handler, stack-guard
classification, recursive-fault emergency path, and bounded panic. Phase 5
adds exact markers for I/O/DMA readiness, ACPI/PCIe discovery, NVMe, GPT,
partition binding, repeated storage reads, direct ZiFS mount, injected timeout,
corrupt-GPT rejection, and explicit module recovery. There is no clocked
timestamp or persistent writer.

Phase 6 adds markers for filesystem PE sourcing, manifest/DAG validation,
each core service hand-off, bounded service failure and restart exhaustion,
session-channel creation, SessionHost completion, user process create/wait,
Luma child completion, user-mode Luma readiness, and leak-free session
teardown. QEMU requires the corresponding user-visible service, session, and
Luma messages as evidence rather than accepting markers alone.

Phase 7 adds distinct markers for a clean durable create, persisted reboot
verification, injected rollback and replay boundaries, redundant-superblock
repair, rollback, replay, and exact present/absent verification. The QEMU gate
also rejects recovery markers during the clean reboot, so recovery cannot hide
a normal-commit defect. `ZIFS_JOURNAL_WRAPPED` identifies a successful
slot-31-to-slot-0 commit on the direct NVMe partition;
`ZIFS_WRAP_PERSISTED` is emitted only after a separate boot has re-read the
96 KiB and empty-file fixtures and validated the clean ring cursor.

The rename/move extension emits `ZIFS_RENAME_MOVE_COMMIT` only after the
case-only rename and cross-directory move commit, and
`ZIFS_RENAME_MOVE_PERSISTED` only after a separate boot validates the final
exact path, parent linkage, identity, extents, and content. Move crash boots
emit `ZIFS_MOVE_CRASH_ROLLBACK_BOUNDARY` or
`ZIFS_MOVE_CRASH_REPLAY_BOUNDARY`; recovery boots require the corresponding
`ZIFS_RECOVERY_ROLLBACK` plus `ZIFS_MOVE_OLD_STATE`, or
`ZIFS_RECOVERY_REPLAY` plus `ZIFS_MOVE_PERSISTED`.

The truncate/delete extension emits `ZIFS_TRUNCATE_COMMIT`,
`ZIFS_DELETE_COMMIT`, and `ZIFS_RECLAIM_COMMIT` only after the clean mutation
sequence. `ZIFS_RECLAIM_AFTER_CHECKPOINT` proves that a released block becomes
selectable by a fresh transaction only after checkpoint. A separate reboot
requires `ZIFS_TRUNCATE_DELETE_PERSISTED`. Four crash-boundary markers identify
pre-/post-commit power loss for truncate and delete; recovery boots pair
`ZIFS_RECOVERY_ROLLBACK` or `ZIFS_RECOVERY_REPLAY` with exact
`ZIFS_TRUNCATE_OLD_STATE`, `ZIFS_TRUNCATE_NEW_STATE`,
`ZIFS_DELETE_OLD_STATE`, or `ZIFS_DELETE_NEW_STATE` evidence.

Durable security activation emits `ZIFS_SECURITY` only after the root
descriptor has been loaded and its allow, deny, and default-deny policy has
been exercised. The negative security-table boot requires
`ZIFS_SECURITY_CORRUPTION_SAFE` before `STORAGE_MODULE_FALLBACK` and forbids
`ZIFS_DIRECT`, proving corrupted policy was rejected before root-volume use.

## Scaffolded

LogHost and per-service log paths reserve routing. `Show-Log` exposes the early
ring through Luma.

## Future

Persistent event files, schema registry, timestamps, rotation, quotas, ACLs,
security audit separation, subscriptions, filtering, correlation, forwarding,
crash-safe writes, privacy controls, and Trace Viewer remain unimplemented.
