# Inter-process communication

Zizium's native IPC model uses named ports, connected channels, messages,
shared sections, and dispatcher waits. RPC is a later protocol above these
primitives, not a replacement for them.

## Implemented in Seed

`ZiPort`, `ZiChannel`, and `ZiSharedSection` are real executive objects with
security descriptors and reference-counted lifetimes. Ports and channels also
embed dispatcher headers, so connection and message arrival can satisfy the
same wait operations as events and process termination.

A port owns a bounded FIFO of pending server endpoints. Connect creates a
paired client/server channel and adds one referenced server endpoint to the
port; accept transfers that reference to the caller. Port close wakes waiters,
closes every unaccepted pair, and releases the queue references.

Each channel owns a bounded FIFO of at most eight messages. Capacity is chosen
at pair creation and cannot exceed the compiled maximum. `ZiMessage` version 1
contains IDs, type, flags, an explicit payload length, 192 inline payload
bytes, and at most one transferred handle. Send validates structure size,
version, flag bits, reserved fields, length, handle state, and access bits. It
copies fields into a zeroed queue record instead of copying caller padding or
unused payload bytes. Queue state and dispatcher readiness change atomically
under one domain lock, avoiding stale readiness publication.

Handle transfer duplicates from the sender table into the receiver table. The
requested mask must be a subset of the source handle, then the receiver token
must independently pass the target object's ACL. Queue-full and peer-close
races roll the duplicate back. A received handle is already owned by the
receiver process.

Shared sections use caller-owned backing storage, an explicit size, an ACL,
and a maximum access mask. Opening a section enforces both that maximum and the
ordinary handle ACL. The current primitive proves object ownership and secured
transfer; it does not yet map the backing into user address spaces.

Channel peers hold references while connected. Close atomically severs both
links, marks peer closure, wakes both sides, drains queued transferred handles,
and releases the cross-references. The object last-handle callback performs
the same work when a process dies or closes its table, so peer cycles cannot
leak. Repeated close is harmless.

Host tests cover bounded FIFO behaviour, wait wake-up, malformed versions,
oversized payloads, unknown flags, non-zero reserved fields, invalid access
bits, source and target access denial, queue rollback, transferred-handle
drain, peer closure, abandoned port connections, and process-death cleanup.
The QEMU acceptance path uses two distinct process records and tokens to send
a bounded message, transfer a read-only section handle, wait for arrival, and
prove handle cleanup through `IPC_EXCHANGE`, `IPC_HANDLE_TRANSFER`, and
`IPC_PROCESS_CLEAN` markers.

Phase 6 exposes a deliberately narrow public channel ABI. The version-one,
248-byte `ZiChannelMessage` contains the same identifiers, type, flags,
explicit length, transfer metadata, and 192-byte inline payload bound as the
kernel message. `ZxSendChannel`, `ZxReceiveChannel`, and
`ZxGetBootstrapChannel` cross the checked syscall boundary. The public adapter
copies fields rather than ABI padding and currently rejects handle-transfer
flags explicitly; user-mode transfer is not falsely reported as supported.

Normal boot creates an ACL-protected channel whose endpoints belong to
SessionHost and Luma handle tables. SessionHost sends a ready record and quoted
command. It then exits, closing its endpoint; Luma may still drain already-
queued records before receiving `ZI_STATUS_PEER_CLOSED`. Releasing Luma closes
the other endpoint and the kernel releases both initial object references.
`SESSION_CHANNEL` and `USER_SESSION` bracket this live user-mode proof.

## Scaffolded

Ports are not yet published in a persistent global namespace. There are no
public port-create/connect/accept calls, shared-section mapping syscalls,
blocking channel receive, or ZIA IPC convenience wrappers. The Phase 6 public
channel calls operate only on bootstrap handles assigned by the kernel.

Shared-section mapping, message quotas beyond fixed Seed bounds, asynchronous
I/O integration, cancellation tokens, impersonation, and RPC negotiation are
not implemented. Caller-provided object and queue storage is suitable for the
bounded bootstrap slice, not a general allocation service.

## Future

Later work exposes secured named ports, general service/session connections,
and continuous console routing. It also adds mapped shared memory, RPC interface
discovery/versioning, auditing, capability policy, per-process quotas, and
high-throughput transport without weakening message validation.
