# Service management

Zizium services use exact-case, versioned `.zsvc` manifests. A manifest records
its name, executable path, identity, token policy, start mode and order,
dependencies, restart policy and bound, permissions, log path, and
implementation status. Manifest status describes the current bootstrap
component only; it is not a claim that the long-term service is complete.

## Implemented

The version-one parser reads at most 4 KiB, validates strict UTF-8 and absolute
native paths, bounds every field and dependency array, rejects embedded NULs,
duplicates and unknown keys, and requires every mandatory key exactly once.
Service names and dependency matching are exact-case. The dependency resolver
rejects unknown dependencies, duplicate manifests, self-dependencies and
cycles, then emits a deterministic order by `StartOrder` and name.

The bounded supervisor calls a launch provider and records attempts, restarts,
launch status, and signed exit status. `Never`, `OnFailure`, and `Always` are
implemented. A service can be restarted no more than `MaximumRestarts`; an
exhausted policy returns `ZI_STATUS_SERVICE_RESTART_LIMIT`. There is no
unbounded retry loop or false successful status.

Normal QEMU boot reads five core manifests from ZiFS, resolves this order, and
loads each PE and its core DLLs from exact-case ZiFS paths:

1. `ServiceHost.exe`;
2. `SecurityHost.exe`;
3. `LogHost.exe`;
4. `MountHost.exe`;
5. `SessionHost.exe`.

The first four are short-lived Phase 6 bootstrap hand-off programmes. They run
with explicit SYSTEM or service tokens and must exit successfully. They are not
resident production service implementations. A real `ServiceHost.exe` failure
probe exits with status 21; the supervisor launches it three times under an
`OnFailure`, two-restart policy and proves bounded exhaustion through
`SERVICE_FAILURE_DETECTED` and `SERVICE_RESTART_LIMIT`.

`SessionHost.exe` and `luma.exe` are created together. The kernel gives them
different narrow tokens and an ACL-protected channel. SessionHost publishes a
versioned ready message and one bounded quoted command, then exits. Luma owns
the peer endpoint and consumes the queued messages after peer closure. Process
and channel teardown is verified before `USER_SESSION` is emitted.

`zsvccheck.exe` validates all fifteen repository manifests and prints their
resolved dependency order. Host tests cover malformed input, bounds, duplicate
fields and names, unknown and exact-case dependencies, cycles, ordering, every
restart policy, launch failures, non-zero exits, and restart exhaustion.

## Scaffolded

Only the five core manifests have executable Phase 6 bootstrap paths. The
remaining manifests reserve future components and remain `Status=Scaffolded`.
The four core hand-off processes do not stay resident, accept control requests,
write persistent logs, or provide their long-term service functionality.

There is no general service namespace, asynchronous process monitoring,
service-control IPC, health protocol, delayed start, per-user service host,
resource quota, capability derivation from `Permissions`, or durable state.
The service-token IDs are deterministic bootstrap identities, not durable NIDs
issued by an identity database.

## Future

Later phases add resident supervision, dependency readiness rather than
one-shot exit, stop/pause/control operations, timeouts, failure backoff,
structured LogHost routing, crash reports, per-user services, audited policy,
durable identities, package ownership, updates, and administrative tools.
