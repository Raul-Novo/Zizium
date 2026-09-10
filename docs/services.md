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
different bootstrap tokens and an ACL-protected channel. SessionHost publishes a
versioned ready message and one bounded quoted command, then exits. Luma owns
the peer endpoint and consumes the queued messages after peer closure. Process
and channel teardown is verified before `USER_SESSION` is emitted.

`zsvccheck.exe` validates all fifteen repository manifests and prints their
resolved dependency order. It checks syntax/dependencies, not the kernel's
restricted bootstrap launch approval. Host tests cover malformed input, bounds, duplicate
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
The service-token IDs are reserved bootstrap identities, not durable NIDs
issued by an identity database.

Phase 8 must replace those trusted bootstrap identity inputs with bounded
database-backed service identities and auditable token construction before any
service is treated as a persistent security boundary.

## Implemented bootstrap launch policy

`zi_service_bootstrap_token_create` is kernel-internal trusted policy, not a
public token-issuance operation. It first validates the manifest, then requires
an exact match of name, executable path, declared identity and token policy.
Only System-kind, non-disabled manifests may match. Unknown or substituted
policies return AccessDenied without changing output storage. The approved
executable for each entry is `C:\Zizium\System\<Name>.exe`.

| Name | Declared identity | Token policy | Effective principal | Groups |
| --- | --- | --- | --- | --- |
| ServiceHost | NID:SYSTEM | System | SYSTEM:1 | none |
| SecurityHost | NID:SYSTEM | System | SYSTEM:1 | none |
| LogHost | NID:SERVICE:LogHost | Service | SERVICE:1 | Users:2 |
| MountHost | NID:SERVICE:MountHost | Service | SERVICE:2 | Users:2 |
| SessionHost | NID:SERVICE:SessionHost | SessionBootstrap | SERVICE:3 | Users:2 |

All privileges are zero. Luma's trusted demonstration USER:21 receives Users:2,
not Administrators:1. Its identity is not an authenticated account. SessionHost
no longer uses the synthetic SYSTEM:2 pair or declares NID:SYSTEM. Old manifests
using that SessionBootstrap declaration now fail validation; rebuild the image.
This is an explicit development-policy correction, not a durable NID migration.
Do not reinterpret old name-hash values or reuse the reserved service pairs for
later accounts. The two SYSTEM services intentionally share the well-known
SYSTEM identity; the three restricted service principals are distinct.

`Permissions` does not confer rights. The compiled table approves bootstrap
launch policy only; it does not authenticate substituted boot media or provide
a service enrolment database. File ACLs separately authorise directory traversal
and each EXE/DLL read and execution request under the resolved token.

Host regressions prove policy substitution fails and reproduce two colliding
names from the removed hash scheme. Normal boot requires `SERVICE_POLICY_DENIED`
for an unknown service declaring SYSTEM and `IMAGE_ACCESS_DENIED` for an
unlisted principal, in addition to every existing service/session marker.

## Future

Later phases add resident supervision, dependency readiness rather than
one-shot exit, stop/pause/control operations, timeouts, failure backoff,
structured LogHost routing, crash reports, per-user services, audited policy,
durable identities, package ownership, updates, and administrative tools.
