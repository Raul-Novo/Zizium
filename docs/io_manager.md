# I/O manager

The I/O manager connects devices and drivers and reserves the boundary for file
objects, volume objects, and asynchronous completion through IRP-like request
packets. Requests carry a
major operation, status, access context, input/output buffers, byte counts,
offset, completion routine, and stack location.

## Implemented in Seed

Versioned request and dispatch structures, operation numbers, completion state,
device-stack links, and a generic version-three `ZiBlockDevice`
read/write/flush contract exist. Capability flags and callback presence must
agree, and read-only devices reject writes explicitly. A bounded exact-case
device catalogue publishes and finds real
device objects. Submission traverses to the top of a validated device stack,
selects the typed dispatch routine, tracks active requests, and supports both
synchronous completion and explicit pending state. Exactly-once completion is
atomic and rejects invalid state transitions or double completion.

Cancellation, deadline expiry, and owner-wide teardown are implemented with
bounded active-request storage. Version-two IRP initialisers carry distinct
mutable output and constant input buffers. Unsupported operations return
`ZI_STATUS_NOT_IMPLEMENTED`. The built-in NVMe driver services read, write, and
flush IRPs; a checked partition adapter translates and clips both read and
write ranges to the selected GPT extent and forwards barriers only when the
parent advertises them. Normal boot mounts writable ZiFS through this NVMe/GPT
block stack. The Limine block adapter remains an explicitly selected read-only
recovery path.

Host tests cover exact translation, parent-boundary rejection, input-size
checks, read-only enforcement, write failure propagation, and flush capability
validation. The ZiFS crash gate exercises real NVMe writes and flushes under
QEMU. ZiFS create, write-growth, directory-expansion, rename/move,
truncate/delete, and recovery paths all use the same block/flush contract.
Released allocation bits exist only in journalled home-block images; the
current single-writer/recovery gate prevents a new allocator from observing
those blocks until checkpoint publication.

## Scaffolded

Create, close, device-control, PnP, and power operations are reserved. Block
writes exist, but there is no public file-object write request path.
Pending requests have lifecycle and cancellation semantics but no general
interrupt-driven queueing engine, dispatcher-completion object, completion
port, or user-visible file/volume request path.

## Future

File and volume objects, access checks at public I/O boundaries, completion
ports, scatter/gather I/O, cache integration, interrupt/DPC completion,
per-request DMA mapping, broader asynchronous policy, and SMP-safe elevated-
interrupt completion remain future work. No unsupported path may report false
success.
