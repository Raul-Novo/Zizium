# ZiFS offline repair policy

This document defines the bounded repair boundary for ZiFS 0.1. It does not
authorise general reconstruction, best-effort salvage, or silent conversion of
unknown corruption into apparent success.

The normal kernel mount/recovery path remains responsible for validated
single-transaction rollback and replay. The read-only `zifsinspect.exe` remains
non-mutating. Offline repair belongs to a separate Windows-host tool,
`zifsrepair.exe`, with an explicit plan/apply boundary.

## Repairable states

A repair plan may contain only these actions:

1. Recreate one invalid or stale superblock copy from the uniquely selected,
   fully validated authoritative copy.
2. Recreate one invalid or stale journal-header copy from the uniquely
   selected, fully validated authoritative copy.
3. Clear the feature-bit-3 `MOUNTED` marker when the journal is empty and
   checkpointed at the selected generation and transaction identifier.
4. Combine the preceding actions when every prerequisite remains independently
   provable.

The selected metadata view must have valid security descriptors, namespace
linkage, extent ownership, allocation accounting, and exact UTF-8 names. The
journal must contain no occupied record. The selected superblock state may be
only cleanly unmounted or transaction-free mounted. A plan may address at most
four 4 KiB metadata blocks.

## Mandatory refusal cases

The tool must refuse to plan or apply when any of the following is true:

- both superblocks or both journal headers are invalid;
- valid superblocks disagree on volume identity or geometry;
- equal-sequence journal headers disagree on logical state;
- a transaction-dirty state or any occupied journal record exists;
- recovery requires rollback, replay, or interpretation of a torn journal
  record;
- security, namespace, extent, required-allocation, padding, or other metadata
  validation fails;
- allocated-but-unreferenced blocks exist;
- an unknown feature, format, checksum, bound, or state is present;
- the target lacks reliable read, write, and flush/barrier operations; or
- the final proposed overlay does not pass a complete read-only inspection as
  a clean, non-recovery volume.

Refusal is a safe result. The tool must never clear checksums, discard unknown
records, regenerate ACLs, infer missing names, or rebuild allocation merely to
make a mount succeed.

## Plan boundary

`zifsrepair.exe plan [--raw|--gpt] <image>` opens the container without write
access and emits:

- the selected volume identity, generation, and state;
- every bounded action in durability order;
- whether the plan repairs superblock redundancy, journal redundancy, an
  interrupted mount, or a combination; and
- a SHA-256 review token derived from the versioned plan fields and the exact
  expected/replacement block images.

The token detects a stale or different plan. It is not a digital signature,
an authorisation decision, or proof that the image came from a trusted source.
Normal plan operation must leave the complete input byte-for-byte unchanged.

## Apply boundary

`zifsrepair.exe apply [--raw|--gpt] <image> <review-token>` opens the container
for exclusive read/write access, derives a fresh plan, and requires an exact
token match before the first write. Immediately before each action it requires
the target block to equal either the planned old image or the planned
replacement image. Any third state aborts the operation.

Journal redundancy is repaired first. Superblock actions then write the
non-authoritative copy before the authoritative copy. Clearing an interrupted
mount therefore follows the same backup-first order when the primary is the
survivor, but reverses the order when the backup is the only survivor. Each
block write is followed by a device barrier.

After the final barrier, the tool repeats full inspection and requires no
remaining action. A failed write or barrier reports failure and never reports
repair success. Replanning any durable prefix must remain safe, and replanning
the completed image must produce an empty plan without modifying it.

## Container and exit contract

Raw ZiFS volumes and frozen-GUID ZiFS partitions inside GPT images are
supported. FAT32 is not treated as a ZiFS volume and remains firmware media
only.

Exit code zero means a valid plan, no repair needed, an applied repair, or an
already-valid fixed point. Exit code one means metadata failure, an explicitly
refused state, or an I/O failure during repair. Exit code two means invalid
invocation, source opening/configuration failure, or review-token mismatch.

## Implemented in ZiFS milestone

`zifsrepair.exe` implements this contract for raw volumes and the frozen-GUID
ZiFS partition inside GPT images. Windows paths enter through the UTF-16 CRT
boundary, so names containing spaces and non-ASCII text do not depend on the
active code page. Diagnostics receive a separately validated UTF-8 rendering.

Planning opens the source read-only. Apply opens it exclusively, derives the
plan again, checks the SHA-256 review token through Windows CNG, and verifies
the expected bytes immediately before each write. The common repair engine
uses a `ZiBlockDevice`, writes one 4 KiB block at a time, follows every write
with a flush, and requires the complete read-only inspector to report a clean
fixed point afterwards.

Host tests cover clean non-mutation, each permitted redundancy repair, an
interrupted mount, a stale journal-header copy, a three-action combined repair,
tampered plans, all six write/flush boundaries in that combined case, and the
mandatory refusal states. Command-line acceptance covers clean, repairable,
wrong-token, stale-token, refused, spaced, and non-ASCII Windows paths. The
thirty-two-boot ZiFS matrix performs a three-action repair against a persistent
GPT image, replans to an empty fixed point, and boots the repaired direct
partition without a kernel recovery action.

## Deliberately limited

The tool does not replay or roll back journal transactions, reconstruct lost
metadata, rewrite security descriptors, reclaim leaks, salvage files, or
select between ambiguous states. It is an offline Windows-host maintenance
tool, not a kernel or user-mode repair service. Its review token detects a
changed plan but is neither an authorisation mechanism nor a digital
signature.

The Windows review-token implementation hashes bounded mutable copies at the
BCrypt boundary, preserving constness of the reviewed plan bytes. This does not
change the SHA-256 token format or permit additional repair classes. Strict
compiler and CLI regression gates cover the same immutable plan/apply contract.

## Future

Any broader repair or salvage operation requires a separately versioned policy,
new adversarial evidence, and an explicit representation of uncertainty. It
must not weaken this tool's fail-closed boundary.
