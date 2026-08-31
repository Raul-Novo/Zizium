# ZiFS 0.1 on-disk format

ZiFS is the only native Zizium root filesystem. Version 0.1 is little-endian,
uses fixed 4 KiB blocks, exact validated UTF-8 names, explicit byte encoding,
and CRC32C metadata checksums. Native paths are case-sensitive and apply no
implicit Unicode normalisation or case folding.

The frozen GPT partition type GUID is
`9ef9e22a-3719-44d4-89af-de9cc7b6b255`.

## Superblocks

The primary superblock occupies block 0 and the backup occupies the final
block. The encoded header is 256 bytes; the rest of its 4 KiB block is zero.
Mount reads and validates both copies. It selects the higher generation, or a
clean copy over a dirty copy at equal generation, and records any redundancy
disagreement as requiring repair.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | `ZiFS 0D 0A 1A 0A` magic bytes |
| 8 | 2 + 2 | major and minor format |
| 12 | 2 | header size, 256 |
| 14 | 1 + 1 | block shift and checksum type |
| 16 | 8 | compatible feature bits |
| 24 | 8 | read-only-compatible feature bits |
| 32 | 8 | incompatible feature bits |
| 40 | 16 | volume UUID bytes |
| 56 | 8 | generation |
| 64 | 8 | total blocks |
| 72 | 8 | root record index |
| 80 | 8 + 8 | record-table start and block count |
| 96 | 8 + 8 | directory-table start and block count |
| 112 | 8 + 8 | allocation-bitmap start and block count |
| 128 | 8 + 8 | journal start and block count |
| 144 | 8 + 8 | security-table start and block count |
| 160 | 8 | backup-superblock block number |
| 168 | 2 | UTF-8 volume-name byte count |
| 172 | 64 | volume-name bytes |
| 236 | 8 | last committed transaction ID |
| 244 | 4 | state flags; bit 0 means dirty |
| 252 | 4 | CRC32C over bytes 0–251 |

Unknown compatible features may be ignored. Unknown read-only-compatible
features require a read-only mount. Unknown incompatible features reject the
mount. Incompatible bit 0 identifies the version-one journal contract, bit 1
identifies the version-one durable security-table contract, and bit 2
(`ZI_FS_FEATURE_INCOMPAT_DIRECTORY_EXTENTS_V1`) identifies the directory
continuation contract below. All three bits are required by newly formatted
Seed volumes. All metadata regions must fit, must not overlap, and must exclude
both superblocks.

## File records, extents, and directories

Each file record is 256 bytes with `ZIFR` magic, version, file type, file and
parent IDs, flags, logical and allocated sizes, security-record ID, and extent
count. Four inline 32-byte extents contain logical block, physical block, block
count, flags, and reserved data. Four 64-bit timestamps and a directory block
follow. CRC32C is stored at offset 252.

A directory block begins with a 64-byte header: `ZIDR`, version 1, header size,
directory file ID, entry count, used byte count, generation, and a CRC32C at
offset 60 calculated over the entire block with that field zeroed. Variable
entries have a 24-byte header containing aligned entry size, name byte count,
file type, flags, file ID, and record index. The validated UTF-8 name follows
and the entry is padded to eight bytes.

Every directory retains its fixed directory-table block as logical block 0.
When incompatible feature bit 2 is present, the directory record's inline
extents map continuation blocks beginning at logical block 1. Directory
`file_size` remains zero; `allocated_size` is the byte capacity of continuation
blocks only. Extents must be logically contiguous, physically valid,
non-overlapping, outside metadata, and represented by at most four inline
records. The current reader, formatter, inspector, and transaction writer
accept at most 256 directory blocks in total. A directory without continuation
extents remains wire-compatible with the earlier one-block representation.

Lookup compares the exact encoded sequence. `Temp` and `temp`, and precomposed
and decomposed spellings, therefore remain distinct.

## Security table

The security region is a versioned table identified by `ZISD`. It occupies
1–16 contiguous blocks and contains one 256-byte header followed by sorted,
fixed-size 256-byte `ZISE` records. Because the header consumes the first
record-sized slot, capacities range from 15 records in one block to 255 records
in 16 blocks. Security ID zero is invalid. Records use strictly increasing IDs,
and every unused byte through the end of the declared region must be zero.

The table header layout is:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | `ZISD` magic |
| 4 | 2 + 2 | version 1 and header size 256 |
| 8 | 2 + 2 | descriptor-record size 256 and ACE size 16 |
| 12 | 4 | table block count |
| 16 | 4 | record count |
| 20 | 4 | record capacity derived from block count |
| 24 | 8 | security-table generation |
| 32 | 8 | used byte count |
| 40 | 8 | table flags; zero in version 1 |
| 48 | 204 | reserved zero bytes |
| 252 | 4 | CRC32C over the entire table region with this field zeroed |

Each descriptor record stores:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | `ZISE` magic |
| 4 | 2 + 2 | version 1 and record size 256 |
| 8 | 8 | nonzero security ID |
| 16 | 4 | descriptor flags; bit 0 means DACL present |
| 20 | 4 | security-descriptor control flags |
| 24 | 8 | owner authority and value |
| 32 | 8 | primary-group authority and value |
| 40 | 2 + 2 | ACE count and ACE size 16 |
| 44 | 4 | reserved zero bytes |
| 48 | 192 | up to 12 ACEs |
| 240 | 12 | reserved zero bytes |
| 252 | 4 | CRC32C over record bytes 0–251 |

An ACE encodes type, inheritance flags, a zero reserved field, access mask,
and trustee authority/value. Mount validates the table geometry, both checksum
layers, versions, known flags, identities, access masks, ACE order as stored,
strict record-ID ordering, zeroed spare records, and every nonempty file
record's security reference before making the volume available. Missing or
unknown references fail closed.

`mkzifs.exe` currently emits descriptor ID 1 for every formatted file record.
Its ordered DACL denies Guests mutation rights, grants SYSTEM and
Administrators full control, and grants Users Read, Execute, and List. There is
no implicit administrator bypass in the evaluator. Inheritance flags are
stored and validated, but applying inherited ACLs during creation is Phase 8
work.

The current no-replacement rename/move transaction accepts exact source and
target names plus indexed parent records. An already-present exact target, or
an exactly identical source and target, returns `ZI_STATUS_ALREADY_EXISTS` and
prepares no transaction. A case-only target and a canonically distinct UTF-8
target are different names and may be committed. A bounded record-table walk
rejects moving a directory beneath itself or one of its descendants.

Same-directory rename stages the source directory block and the changed record
blocks. Cross-directory move stages the source and target directory blocks and
their changed records. If the target has no room, insertion atomically allocates
a continuation block and updates its directory record and allocation bitmap.
The operation preserves the file ID, record index, file type, security
reference, extents, and data; it changes the parent file ID and change time,
updates the affected parent records' modified/change times, and advances each
affected directory-block generation. Path-record lookup scans every directory
block and validates each entry against the referenced file record, including
parent, type, and unique file-ID linkage.

Shrink-only truncation operates on a regular-file record by index. It preserves
the file ID, record index, parent, security reference, and retained extent
prefix; updates logical/allocated size and timestamps; zeroes the unused tail
of a retained partial block; and stages released allocation bits in the same
transaction.

`ZiFsTransactionPrepareWrite` performs a bounded non-sparse overwrite or
growth of a regular file by record index. The offset may not exceed the old
file size and each request carries at most 24 data blocks. Every touched data
block, the file record, and any changed allocation-map block are one redo set.
Growth allocates one contiguous suffix run, preferring physical adjacency so
it can merge with the final extent; otherwise it consumes another of the four
inline extents. A fifth extent is rejected rather than silently introducing an
unsupported overflow structure. The operation preserves file and security
identity, updates logical/allocated size plus modified/change times, and leaves
newly allocated unwritten bytes zero. Sparse writes are not implemented.

Regular-file deletion removes one exact directory entry, advances the directory
generation, updates the parent record timestamps, clears the removed 256-byte
file-record slot, and stages every inline extent for release. Directory deletion
is deliberately rejected with `ZI_STATUS_NOT_IMPLEMENTED`. Before either
operation can release an allocation bit, a bounded global record-table walk
proves that the extent belongs only to the target record and that every data
block is allocated, in range, outside metadata, and free of cross-links.

## Allocation bitmap

One bit represents one volume block. Bit zero of byte zero represents block
zero. The map length is `ceil(total_blocks / 32768)` blocks and is validated
against the volume size. The formatter writes every bitmap block and currently
accepts 8–2048 MiB volumes, bounded to at most 16 allocation-map blocks.

The transaction allocator scans the complete map, excludes all metadata and
superblock ranges, and stages the affected map block rather than modifying the
mounted volume in place. Create requires one contiguous extent of at most 24
blocks. Write growth and directory expansion prefer to extend the final
physical extent; if that range is unavailable they allocate one new contiguous
suffix extent within the inline limit.

Truncate/delete release bits only in staged bitmap home-block images and record
each released range as a deferred extent. The current serial writer admits no
second transaction while commit or recovery is incomplete. A transaction
prepared speculatively against the old generation is rejected after the first
transaction commits. Consequently, a released block cannot be selected by a
new valid allocation until `CHECKPOINT` publication (or mount recovery has
finished and checkpointed the recovered state).

## Journal headers

The formatter reserves 66 journal blocks: two redundant 4 KiB headers followed
by 32 fixed record slots of two blocks each. A header uses `ZIJR` magic and the
first 128 bytes below; the remainder of its block is zero.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | `ZIJR` magic |
| 4 | 2 + 2 | version 1 and header size 128 |
| 8 | 8 | monotonically increasing header sequence |
| 16 | 8 | volume generation |
| 24 | 4 | blocks per record, currently 2 |
| 28 | 4 | flags |
| 32 | 8 | record capacity |
| 40 | 8 | head record |
| 48 | 8 | tail record |
| 56 | 8 | next record sequence |
| 64 | 8 | next transaction ID |
| 72 | 8 | last committed transaction ID |
| 80 | 8 | last checkpoint transaction ID |
| 124 | 4 | CRC32C over bytes 0–123 |

Readers validate both copies and select the valid header with the highest
header sequence. A clean mounted volume requires its selected header generation
and checkpoint transaction to match the selected superblock. One record is
always reserved so `head == tail` has the single meaning "empty". The current
32-slot ring therefore exposes at most 31 occupied records. A committed but
not checkpointed transaction must have exactly one generation gap between its
commit and checkpoint identifiers and at least three occupied records.

## Journal records

Each 8 KiB `ZIJE` record has a 128-byte header and space for one complete 4 KiB
home-block image. Record types are `BEGIN`, `BLOCK_IMAGE`, `COMMIT`, and
`CHECKPOINT`.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | `ZIJE` magic |
| 4 | 2 + 2 | version 1 and header size 128 |
| 8 | 2 + 2 | record type and flags |
| 12 | 4 | payload bytes |
| 16 | 8 | transaction ID |
| 24 | 8 | record sequence |
| 32 | 8 | target home block, or all-ones for non-image records |
| 40 | 8 | source generation |
| 48 | 8 | target generation |
| 56 | 4 | expected image count for `BEGIN` |
| 60 | 4 | transaction checksum for `COMMIT` |
| 64 | 4 | payload CRC32C |
| 124 | 4 | record-header and payload CRC32C |
| 128 | up to 4096 | complete target-block image |

The transaction checksum covers each ordered image descriptor and payload
checksum. Recovery rejects duplicate targets, impossible sequences, wrong
generations, unsafe targets, inconsistent counts, or a committed checksum that
does not match the validated image set. Record addressing advances modulo the
declared capacity. Recovery scans all slots, orders the selected transaction by
its monotonically increasing sequence, and reclaims through the last validated
record even when the sequence crosses slot 31 to slot 0.

## Commit and recovery ordering

The implemented single-writer transactions use this durable order:

1. Write `BEGIN` and every redo block image, then flush.
2. Write backup and primary dirty superblocks, flushing each copy.
3. Write `COMMIT`, then flush.
4. Publish the committed redundant journal header, then flush.
5. Write every home block, then flush.
6. Write clean backup and primary superblocks, flushing each copy.
7. Write `CHECKPOINT`, then flush.
8. Publish the second clean journal header with `tail == head`, then flush.

No home block is written before a durable commit record. Consequently, a dirty
transaction without a valid commit is rolled back by restoring the source
generation. A dirty transaction with a valid commit replays all validated
block images before publishing clean superblocks. Clean redundancy mismatches
are repaired separately. Any unrecoverable checksum or shape error fails
closed; it is not converted to apparent success.

Checkpoint publication reclaims the transaction immediately by advancing both
ring cursors to the slot after `CHECKPOINT`. The next serial transaction starts
at that cursor and may wrap. This is bounded single-writer reclamation; there
is no concurrent writer, retained multi-transaction history, or background
checkpoint worker.

## Implemented

- `mkzifs.exe` creates deterministic 8–2048 MiB volumes, 75 required
  directories, optional bounded host files, scalable allocation maps,
  multi-block directory continuation extents where needed, both superblocks,
  both valid journal headers, and the version-one default security descriptor.
- The kernel mounts primary or backup metadata through a checked
  `ZiBlockDevice`, validates redundant state, reads files, and performs
  exact-case path lookup. Mount also validates the complete security table and
  every live file-record reference before access checks can load a descriptor.
- The NVMe/GPT partition path supports bounded reads, writes, and flushes. The
  Limine module adapter remains explicitly read-only and is recovery media,
  not another root filesystem.
- A caller-owned in-memory transaction derives capacity from whole workspace
  blocks after two scratch blocks. It supports 1–28 home-block images and
  stages one new regular file, its file record, directory entry, parent record,
  allocation bits, and up to 24 contiguous data blocks without publishing
  partial home metadata.
- Bounded regular-file write stages non-sparse overwrite or growth through the
  same transaction engine. It supports up to 24 data blocks per request,
  contiguous-preferred suffix allocation, and at most four inline extents.
- Checked directory mutation scans and validates every fixed or continuation
  block, rejects duplicate exact names across the complete directory, compacts
  removed entries, clears vacated bytes, advances the generation, and
  recomputes CRC32C. Create and move can allocate a new continuation block and
  update the parent record atomically when all existing blocks are full.
- Atomic same-directory rename and cross-directory move use the same journal
  commit/recovery engine. They enforce exact-case no-replacement semantics,
  reject ancestry cycles and malformed entry/record linkage, and preserve file
  identity, security reference, extents, and content.
- Shrink-only regular-file truncation and exact-name regular-file deletion use
  the same engine. Truncation handles whole-block release and partial-block tail
  zeroing; deletion removes the directory link and clears the record. Both
  validate global extent ownership before staging allocation-map release and
  expose bounded deferred-extent descriptors.
- The write-ahead commit and single-transaction mount recovery paths implement
  rollback, replay, redundant-superblock repair, root validation, circular
  record addressing, and checkpoint reclamation.
- `zifsinspect.exe` opens either a raw ZiFS volume or the frozen-GUID partition
  in a GPT image through a read-only block device. It reports each superblock
  and journal-header copy, selects valid redundant state, validates journal
  record order and targets, security records, the complete namespace, extents,
  cross-links, required allocation bits, padding bits, and leaked allocation.
  A valid committed transaction is applied only to a heap-owned replay overlay
  so the prospective recovered metadata can be checked without changing the
  inspected image. The tool performs neither recovery writes nor repair.
- Host tests inject failure before every write or flush in a 29-operation
  five-image commit and every one of the 23 operations in a transaction that
  begins at slot 30 and crosses slot 31 to slot 0. Every restart must expose
  exactly the old or new state. A successful 27-image transaction also proves
  all 24 data blocks and the enlarged caller-owned staging capacity.
- Rename tests fail each of 23 durable operations; cross-directory move tests
  fail each of 25. Recovery must expose exactly the old or new namespace and
  must retain the original file ID, security reference, extents, and bytes.
- Truncate and delete tests fail each of their 25 durable operations. Every
  restart exposes exactly one coherent old/new file and allocation-map state;
  corrupt, unallocated, cross-linked, or metadata extents fail closed. Tests
  also prove that stale speculative work cannot reuse a released block before
  checkpoint and that the first valid post-checkpoint allocation can reuse it.
- Write-growth tests fail every write/flush operation and require exact old or
  new content, size, extent, allocation, and generation after recovery. The
  first one-block-to-two-block directory expansion receives the same exhaustive
  fault campaign; rollback must leave its name and allocation absent, while
  replay/commit must expose the second block and exact path together.
- `make zifs-test` boots the real NVMe partition twenty-seven times: the original
  clean create/reboot, rollback, replay, wrap, and post-wrap cases; clean
  case-only rename plus cross-directory move and reboot; a clean regular-file
  growth plus 18 long-name creates that force directory expansion and a reboot
  which revalidates every exact path and byte; move rollback/replay;
  clean truncate/delete plus reboot; and independent pre-/post-commit crash and
  recovery boots for truncate and delete. The rename/move final path is
  `C:\Temp\First Light Seed.exe`; its old and intermediate exact paths must
  be absent after the clean and replay outcomes. Truncate recovery validates
  exact old/new size and bytes, while delete recovery validates exact
  presence/absence and allocation reuse. The final negative boot corrupts a
  durable ACE byte on the direct partition, requires
  `ZIFS_SECURITY_CORRUPTION_SAFE`, forbids `ZIFS_DIRECT`, and permits only the
  explicitly requested uncorrupted recovery module.
- Inspector acceptance covers one valid image, one valid formatter-created
  multi-block directory image, and nine independent corruption or redundancy
  cases: primary superblock, one journal header, both journal headers,
  security-record checksum, directory checksum, file-record checksum, a
  cleared required allocation bit, an allocated but unreferenced block, and an
  allocation-padding bit. SHA-256 is compared before and after every case.
  The QEMU suite also inspects the GPT partition after clean creation, at a
  committed pre-checkpoint crash boundary, and after file/directory growth;
  the crash case must require recovery while validating the memory-only replay
  view, while both clean cases must validate on-disk home blocks.

## Scaffolded or limited

- Transactions are single-writer, bounded to 28 home-block images, and expose
  one regular-file create, bounded write, no-replacement rename/move,
  shrink-only truncation, or deletion of one regular file per transaction.
- Files and directory continuations use at most four inline extents. Directories
  are bounded to 256 blocks; empty continuation blocks are not compacted or
  reclaimed, and there is no overflow-extent structure.
- Truncate remains shrink-only and delete does not accept directories. There is
  no sparse write, open-handle delete-pending state, sharing policy, link count,
  or public file-object mutation API.
- Recovery handles the one in-flight transaction guaranteed by the current
  writer. Mid-device-write tearing is detected by CRC32C and fails closed but
  has no redundant-record reconstruction.
- The security table is bounded to 16 blocks, 255 descriptors, and 12 inline
  ACEs per descriptor. Descriptor mutation, deduplication, inheritance
  application, and journalled ACL updates are not implemented.
- There is no public clean-unmount operation, cache, or repair utility. The
  inspector is deliberately read-only and cannot make a volume mountable.

## Future

Directory deletion, continuation compaction/reclamation, replacement moves,
multiple/concurrent writers, sparse writes, overflow extents, retained
multi-transaction journal history, background checkpointing, torn-record
redundancy, snapshots, compression, encryption, quotas, checksummed trees,
clean-unmount semantics, and repair policy/tooling remain unimplemented.
ZiFS 0.1 is experimental and must not hold irreplaceable data.
