# Scheduler

The target scheduler is pre-emptive, thread-based, priority-driven, SMP-aware,
quantum-based, affinity-aware, wait-object integrated, and capable of dynamic
and real-time policy.

Priority 0 is idle, 1–15 are dynamic, and 16–31 are real-time. Thread states
are Initialised, Ready, Running, Waiting, Transition, and Terminated. Policy
classes reserve Realtime, High, AboveNormal, Normal, BelowNormal, Background,
and Idle.

## Implemented in Seed

`ZxScheduler` owns 32 FIFO ready queues and a 32-bit ready bitmap. Enqueue and
remove validate state, queue membership, priority, and affinity. Selection
finds the highest runnable priority and preserves FIFO order within that level.
Structures retain process/thread IDs, state, base/current priority, affinity,
quantum, wait block, current thread, idle thread, and CPU index.

Priority boost is capped below the real-time band for dynamic threads;
priority decay returns towards the base priority. Tests cover priority
selection, FIFO order, empty queues, invalid affinity, removal, hooks, quantum
decrement and expiry, higher-priority pre-emption, and dispatch counters.

The current single-CPU live slice connects a calibrated 100 Hz local-APIC timer
to `zi_scheduler_on_tick`. It tracks tick, quantum-expiry, and context-switch
counts. A quantum-expired running thread returns to the tail of its priority
queue; the next highest runnable thread is selected. A newly ready higher
priority also requests immediate dispatch.

The x64 interrupt dispatcher can return a different 176-byte interrupt frame.
The common assembly path then restores the selected thread's general registers,
`FXSAVE` state, stack, and instruction pointer with `IRETQ`. Boot acceptance
requires at least six real timer ticks, three switches, and execution by both of
two equal-priority kernel workers on separate guarded 32 KiB stacks. The idle
representation also owns a guarded 32 KiB stack.

`ZxProcess` and `ZxThread` also carry early user-process state, address-space,
token, affinity, priorities, kernel-stack link, and exit status. The bounded
manager creates three acceptance processes, then enters and tears them down
synchronously before the APIC timer starts. They are not queued or pre-empted
as user threads.

The dispatcher layer now implements notification and synchronisation events,
recursive mutexes, bounded semaphores, one-shot and periodic timers, process
termination, ports, and channels. A caller-supplied `ZiWaitOperation` and wait-
block array support exact wait-any and atomic wait-all semantics without busy
waiting. Immediate checks, finite or infinite deadlines, explicit expiry,
cancellation, and completion queries have distinct native status results.
Completing a pending wait moves the thread through Transition to the scheduler
ready queue. Duplicate wait objects, cross-domain waits, deadline overflow,
invalid states, and malformed counts are rejected.

Each dispatcher domain has an atomic executive lock. Signal state, wait lists,
and IPC queue readiness are updated under that one lock. This is sufficient for
the current bounded uniprocessor slice and provides the lock boundary that the
later per-CPU design must preserve.

Mutex contention invokes a priority-inheritance hook. A dynamic-priority owner
temporarily inherits the highest waiter priority, clamped below the realtime
band, while preserving ready-queue membership. Release restores the base
priority and transfers ownership through the ordinary wait completion path.
This Seed policy is deliberately limited to one mutex's current waiter set; a
future ownership graph must aggregate multiple held mutexes and chained
dependencies.

## Scaffolded

A global timer queue which expires all operations automatically is not present;
the owner must call the bounded expiry or timer-tick interface. Public handle-
based waits, schedulable user threads, general thread creation, and user-mode
wait cancellation are not exposed. The early process wrapper retains a zero-
timeout poll API even though its embedded termination header is now a real
dispatcher object.

The scheduler ready queues themselves remain a single-CPU implementation. The
dispatcher lock is an atomic spin lock, but there is no interrupt-priority/
pre-emption protocol suitable for arbitrary runtime callers or SMP. The
guarded stack allocator has a fixed sixteen-slot kernel region and is not a
general process stack manager.

## Future

Phase 5 connects dispatcher completion to real I/O requests and device
timeouts. Later work adds a timer wheel, scheduled concurrent user threads,
wait syscalls, process address-space switching, and general stack policy.
Phase 16 owns per-CPU state, scalable SMP locks, processor groups, cross-CPU
rescheduling, affinity migration, chained priority inheritance, I/O-driven
dynamic boosts, realtime admission, load balancing, and CPU hotplug. The
current proof is a safe uniprocessor vertical slice, not a complete NT-class
scheduler.
