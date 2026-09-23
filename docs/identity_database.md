# Bound identity database and private storage

## Implemented

The C codec and kernel-only storage wrapper implement a bounded version-one
database, disabled-record issuance and tombstone deletion. Host tests exercise
the real ZiFS transaction/recovery engine using a fault-injected block device.
Six dedicated QEMU boots exercise the same store on the real NVMe partition,
including reboot persistence, tombstones, non-reuse and access denials.
This is not yet integrated into normal boot or SecurityHost. No credential,
enabled account, user profile or logon token is created. Consult the current
progress report for gate results; identity and access management remains active.

The contracts are in `zi/identity_database.h` and `zi/identity_store.h`.
All integers on disk are little-endian, UUIDs use canonical octet order, and
encoding is explicit rather than an overlay of a C structure. The complete
file is exactly 36,864 bytes: one 4 KiB header and 64 slots of 512 bytes.
It fits within one existing ZiFS bounded-write transaction.

## Header wire format

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 4 | `ZIDB` magic |
| 4 | 2 | Version 1 |
| 6 | 2 | Header size 4096 |
| 8 | 4 | Complete file size 36864 |
| 12 | 2 | Record size 512 |
| 14 | 2 | Capacity 64 |
| 16 | 4 | Dense occupied-slot count, including tombstones |
| 20 | 4 | Flags, zero |
| 24 | 8 | Nonzero database generation |
| 32 | 16 | Nonzero issuer UUID |
| 48 | 16 | Nonzero system-volume UUID |
| 64 | 16 | Nonzero database UUID |
| 80 | 4 | GROUP high-water value |
| 84 | 4 | USER high-water value |
| 88 | 4 | SERVICE high-water value |
| 92 | 4000 | Reserved zero bytes |
| 4092 | 4 | CRC32C of the entire file, with this field zeroed |

An empty initial database has generation 1, count zero and each high-water
value 255. Every unused record slot is zero. High-water values never decrease;
dynamic values start at 256. SYSTEM allocation is forbidden. Counter or
generation exhaustion fails without wrapping or changing candidate bytes.

## Record wire format

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 4 | `ZIAR` magic |
| 4 | 2 | Version 1 |
| 6 | 2 | Record size 512 |
| 8 | 4 | State: 1 disabled, 2 tombstone |
| 12 | 4 | Flags, zero |
| 16 | 32 | Issuer-bound `ZNID` identity |
| 48 | 2 | Name byte count, 1–128 |
| 50 | 2 | Membership count, 0–16 |
| 52 | 4 | Reserved zero |
| 56 | 8 | Last record mutation generation |
| 64 | 128 | Exact validated UTF-8 name, unused bytes zero |
| 192 | 64 | Up to 16 little-endian GROUP values, unused bytes zero |
| 256 | 252 | Reserved zero; no credential fields |
| 508 | 4 | CRC32C over bytes 0–507 |

Names reject C0/C1 controls and slash, backslash and colon. Spaces, case and
canonically distinct Unicode sequences are preserved. Names are account
attributes, not paths: a future profile allocator must not concatenate them
unchecked into filesystem paths (including `.` or `..`). Names are unique
within an authority among non-tombstone records. Every NID, including a
tombstone NID, is unique across all occupied slots.

Memberships are strictly increasing dynamic GROUP values in the same issuer.
Every reference must resolve to a non-tombstone group record. Group nesting
is unsupported. A referenced group cannot be removed. Removal preserves its
NID and name, clears memberships, sets tombstone state and advances generation.
Reusing a deleted name allocates a new slot and a new NID; it cannot recover
old ACL grants. Tombstone slots are never reclaimed in version one. The
64-slot lifetime issuance limit fails explicitly rather than recycling IDs.

All records must belong to the bound issuer and their high-water range.
Record generations must be nonzero and no greater than the header generation.
Unknown states, versions, flags, reserved data, malformed Unicode, duplicate
records and broken group references fail closed. Neither state permits logon.

## Trusted binding and access checks

`ZiIdentityDatabaseAuthority` must come from independent trusted provisioning,
never from the file it is meant to authenticate. `ZiIdentityStore` additionally
binds the mounted volume, record index, expected file ID and minimum accepted
generation. Caller-owned arguments and workspaces remain stable and disjoint
throughout each operation. A trusted owner serialises the entire store and
volume operation; there is not yet a concurrent locking or revocation API.

Loading validates the volume UUID, exact regular-file identity, zero file flags
and exact size. It loads the actual descriptor referenced by that file and
requires owner SYSTEM:1, a present DACL, zero control flags and precisely one
explicit SYSTEM:1 FullControl allow ACE. It then evaluates the supplied token
through the ordinary ACL evaluator. There is no administrator or SYSTEM bypass.
The descriptor number and path spelling do not establish privacy. A host
fixture deliberately uses descriptor ID 7, not the formatter's ID 2.

Policy and token checks precede database payload reads. The payload must match
the separately supplied issuer, volume and database UUIDs and satisfy the
accepted generation floor. Validation publishes outputs only on success.
The load workspace may have been overwritten on failure; it is not an account
snapshot until validation succeeds.

## Atomic issuance, deletion and recovery

Codec append/remove operations produce unpublished candidate bytes only.
The storage wrapper loads and validates a fresh snapshot, applies the candidate
mutation, and stages the complete nine-block database plus its ZiFS file record.
Only successful commit publishes an issued ID and advances the store's floor.
The caller supplies 163,840 bytes: database, one scratch block and the existing
30-block transaction workspace. No user-mode account syscall is exposed.

A commit error marks the store as needing recovery. The operation may already
be durable even though it returned failure; no ID is returned and the caller
must not retry an old reservation blindly. Trusted recovery/reopening must
inspect the recovered state before choosing the next operation. A timestamp
provider is not wired in yet; these writes currently use timestamp zero.

Host fault tests interrupt every write/flush in issuance and tombstone commit,
then require a coherent old or new generation, record, high-water value and
state after recovery, plus a byte-for-byte match against the complete old or
new database snapshot. Each mutation has 39 write/flush boundaries. This
exposed a ZiFS prerequisite defect: a durable
CHECKPOINT before final empty-header publication was rejected. Recovery now
accepts it only after validating the complete redo set, matching COMMIT,
contiguous sequence, image count and transaction checksum. Replaying the set
again is idempotent. Six recomputed-checksum malformed-checkpoint/commit cases
must fail before recovery writes; see [ZiFS](zifs.md).

## Security limits and future work

CRCs detect corruption, not deliberate replacement. UUID comparison establishes
consistency with caller-supplied trust, not provenance by itself. One canonical
store rejects generations older than those accepted in that running instance;
copying or resetting it defeats that floor. Whole-volume rollback across reboot
is not detectable with the current platform. Trusted recovery must not resume
issuance under an old issuer when a reliable high-water value is unavailable.

Production enrolment, secure entropy, a durable trusted-binding source,
installed-volume migration, credentials,
profiles, enabled states, authentication IPC, token creation, membership edits,
revocation and audit remain to be implemented. Fixed UUIDs and provisioning
in host tests are fixtures only. Normal images contain no identity database.
Read [the identity security contract](identity_security.md) before extending
this format or making issuance available to a service.

## Native acceptance contract

`make identity-test` creates disposable images containing an independently encoded
empty database. The trusted host fixture establishes volume, issuer and database
UUIDs, record index and file ID before guest execution. Fixed UUIDs are test-only;
the boot argument `zi.identity=<stage>:<record_index>:<file_id>` supplies the
remaining binding. The kernel never adopts trust from the database being tested.
The parser rejects duplicate arguments, overflow, unsupported stages, missing
fields and command lines not terminated within its 1,024-byte bound.

The six stages issue disabled USER:256, verify after reboot, tombstone that
record, verify after reboot, issue USER:257 under the same name, then verify both
records after another reboot. Generations advance from 1 to 4. Only the ESP is
replaced between stages; the NVMe ZiFS partition retains all writes. Each stage
requires direct-storage, private-policy, identity and clean-unmount markers,
rejects recovery/module fallback, runs the read-only volume inspector and compares
all 36,864 database bytes against an independently encoded expected snapshot.

Wrong issuer, volume, database and file bindings fail. A non-SYSTEM user with
Administrators and Users membership cannot load or issue records. Failed calls
must preserve unpublished outputs. Each kernel run releases its 163,840-byte
workspace before continuing the existing boot acceptance sequence.

Normal images omit the argument and database. This acceptance path validates the
storage boundary, not installed-system trust, credentials or logon. Run
`make image` afterwards to restore the normal debug image. The exhaustive host
crash campaign remains required in addition to these clean-reboot tests.
