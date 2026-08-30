// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/block.h"
#include "zi/byte_order.h"
#include "zi/zifs.h"
#include "zi/zifs_journal.h"
#include "zi/zifs_recovery.h"
#include "zizium/status.h"

typedef struct RecoveryImage {
  uint64_t record_index;
  uint64_t sequence;
  uint64_t target_block;
} RecoveryImage;

typedef struct RecoveryScan {
  uint64_t record_capacity;
  uint64_t transaction_id;
  uint64_t source_generation;
  uint64_t target_generation;
  uint64_t begin_sequence;
  uint64_t commit_sequence;
  uint64_t maximum_sequence;
  uint64_t maximum_sequence_record;
  uint32_t expected_image_count;
  uint32_t image_count;
  uint32_t commit_checksum;
  bool found_begin;
  bool found_commit;
  RecoveryImage images[ZI_FS_RECOVERY_MAXIMUM_IMAGES];
} RecoveryScan;

static ZiStatus scan_transaction(const ZiFsVolume* volume,
                                 uint64_t transaction_id,
                                 uint64_t source_generation,
                                 uint64_t target_generation,
                                 void* workspace,
                                 RecoveryScan* out_scan);
static ZiStatus accumulate_recovery_record(const ZiFsSuperblock* superblock,
                                           uint64_t source_generation,
                                           uint64_t target_generation,
                                           uint64_t record_index,
                                           const ZiFsJournalRecord* record,
                                           RecoveryScan* scan);
static ZiStatus
validate_recovery_scan(const ZiFsVolume* volume, void* workspace, RecoveryScan* scan);
static void sort_recovery_images(RecoveryScan* scan);
static bool recovery_targets_are_unique(const RecoveryScan* scan);
static ZiStatus validate_recovery_image(const ZiFsVolume* volume,
                                        void* workspace,
                                        uint64_t capacity,
                                        const RecoveryImage* image,
                                        uint64_t* previous_sequence,
                                        uint32_t* checksum);
static ZiStatus replay_images(ZiFsVolume* volume, void* workspace, const RecoveryScan* scan);
static ZiStatus
write_clean_superblocks(ZiFsVolume* volume, const ZiFsSuperblock* superblock, void* block_buffer);
static ZiStatus reset_journal_headers(ZiFsVolume* volume,
                                      const ZiFsSuperblock* superblock,
                                      uint64_t minimum_next_sequence,
                                      uint64_t reclaimed_head,
                                      void* block_buffer);
static bool recovery_target_is_valid(const ZiFsSuperblock* superblock, uint64_t target_block);
static bool block_is_in_range(uint64_t block_number, uint64_t start, uint64_t count);
static uint32_t finalise_transaction_checksum(uint32_t checksum);

// Recovery is deliberately single-transaction until concurrent ZiFS writers are introduced.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
ZiStatus ZiFsRecoverVolume(ZiFsVolume* volume,
                           void* workspace,
                           size_t workspace_size,
                           ZiFsRecoveryReport* out_report) {
  if (volume == NULL || workspace == NULL || workspace_size < ZI_FS_RECOVERY_WORKSPACE_SIZE ||
      out_report == NULL ||
      (volume->superblock.incompatible_features & ZI_FS_FEATURE_INCOMPAT_JOURNAL_V1) == 0 ||
      (volume->device.flags &
       (ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED)) !=
          (ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED) ||
      volume->device.write_blocks == NULL || volume->device.flush == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_memory_zero(out_report, sizeof *out_report);
  out_report->struct_size = sizeof *out_report;
  out_report->version = ZI_FS_RECOVERY_REPORT_VERSION;

  ZiFsSuperblock recovered = volume->superblock;
  if (recovered.state_flags == ZI_FS_SUPERBLOCK_STATE_NONE) {
    ZiStatus status = write_clean_superblocks(volume, &recovered, workspace);
    if (ZiSucceeded(status)) {
      status = reset_journal_headers(volume, &recovered, 1, UINT64_MAX, workspace);
    }
    if (ZiFailed(status)) {
      return status;
    }
    out_report->action = ZI_FS_RECOVERY_ACTION_REPAIRED_REDUNDANCY;
  } else {
    if (recovered.generation < 2 || recovered.last_committed_transaction == 0) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    uint64_t transaction_id = recovered.last_committed_transaction;
    uint64_t source_generation = recovered.generation - 1u;
    RecoveryScan scan = {0};
    ZiStatus status = scan_transaction(volume,
                                       transaction_id,
                                       source_generation,
                                       recovered.generation,
                                       workspace,
                                       &scan);
    if (ZiFailed(status)) {
      return status;
    }
    status = validate_recovery_scan(volume, workspace, &scan);
    if (ZiFailed(status)) {
      return status;
    }
    if (scan.found_commit) {
      status = replay_images(volume, workspace, &scan);
      out_report->action = ZI_FS_RECOVERY_ACTION_REPLAYED;
    } else {
      recovered.generation = source_generation;
      --recovered.last_committed_transaction;
      out_report->action = ZI_FS_RECOVERY_ACTION_ROLLED_BACK;
    }
    if (ZiFailed(status)) {
      return status;
    }
    recovered.state_flags = ZI_FS_SUPERBLOCK_STATE_NONE;
    if (scan.maximum_sequence == UINT64_MAX) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    uint64_t reclaimed_head = 0;
    status = ZiFsJournalAdvanceRecord(scan.record_capacity,
                                      scan.maximum_sequence_record,
                                      1u,
                                      &reclaimed_head);
    if (ZiFailed(status)) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    status = write_clean_superblocks(volume, &recovered, workspace);
    if (ZiSucceeded(status)) {
      status = reset_journal_headers(volume,
                                     &recovered,
                                     scan.maximum_sequence + 1u,
                                     reclaimed_head,
                                     workspace);
    }
    if (ZiFailed(status)) {
      return status;
    }
    out_report->transaction_id = transaction_id;
    out_report->source_generation = source_generation;
    out_report->target_generation = scan.target_generation;
    out_report->image_count = scan.image_count;
  }

  volume->superblock = recovered;
  volume->mounted_from_backup = 0;
  volume->needs_recovery = 0;
  volume->journal_header_valid = 1;
  volume->is_read_only = 0;
  ZiFsFileRecord root = {0};
  ZiStatus status =
      ZiFsReadFileRecord(volume, recovered.root_record_index, workspace, ZI_FS_BLOCK_SIZE, &root);
  if (ZiFailed(status) || root.file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
    volume->is_read_only = 1;
    volume->needs_recovery = 1;
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus scan_transaction(const ZiFsVolume* volume,
                                 uint64_t transaction_id,
                                 uint64_t source_generation,
                                 uint64_t target_generation,
                                 void* workspace,
                                 RecoveryScan* out_scan) {
  uint64_t capacity = 0;
  ZiStatus status = ZiFsJournalRecordCapacity(volume->superblock.journal_blocks, &capacity);
  if (ZiFailed(status) || capacity < ZI_FS_JOURNAL_MINIMUM_RECORD_CAPACITY) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  RecoveryScan scan = {0};
  scan.record_capacity = capacity;
  scan.transaction_id = transaction_id;
  scan.source_generation = source_generation;
  scan.target_generation = target_generation;
  for (uint64_t record_index = 0; record_index < capacity; ++record_index) {
    uint64_t block = 0;
    status =
        ZiFsJournalRecordBlock(volume->superblock.journal_start, capacity, record_index, &block);
    if (ZiFailed(status)) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    status = volume->device.read_blocks(volume->device.context,
                                        block,
                                        (uint32_t)ZI_FS_JOURNAL_RECORD_BLOCKS,
                                        workspace,
                                        ZI_FS_JOURNAL_RECORD_SIZE);
    if (ZiFailed(status)) {
      return status;
    }
    const unsigned char* bytes = workspace;
    if (zi_memory_compare(bytes, "ZIJE", 4) != 0) {
      continue;
    }
    ZiFsJournalRecord record = {0};
    status = ZiFsDecodeJournalRecord(workspace, ZI_FS_JOURNAL_RECORD_SIZE, &record);
    if (ZiFailed(status)) {
      if (zi_read_u64_le(bytes + 16) == transaction_id) {
        return status;
      }
      continue;
    }
    if (record.transaction_id != transaction_id) {
      continue;
    }
    status = accumulate_recovery_record(&volume->superblock,
                                        source_generation,
                                        target_generation,
                                        record_index,
                                        &record,
                                        &scan);
    if (ZiFailed(status)) {
      return status;
    }
  }
  *out_scan = scan;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus accumulate_recovery_record(const ZiFsSuperblock* superblock,
                                           uint64_t source_generation,
                                           uint64_t target_generation,
                                           uint64_t record_index,
                                           const ZiFsJournalRecord* record,
                                           RecoveryScan* scan) {
  if (record->source_generation != source_generation ||
      record->target_generation != target_generation) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  if (record->sequence > scan->maximum_sequence) {
    scan->maximum_sequence = record->sequence;
    scan->maximum_sequence_record = record_index;
  }
  if (record->record_type == ZI_FS_JOURNAL_RECORD_BEGIN) {
    uint64_t ring_image_limit = scan->record_capacity - ZI_FS_JOURNAL_RESERVED_RECORDS - 3u;
    if (scan->found_begin || record->image_count > ZI_FS_RECOVERY_MAXIMUM_IMAGES ||
        record->image_count > ring_image_limit) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    scan->found_begin = true;
    scan->begin_sequence = record->sequence;
    scan->expected_image_count = record->image_count;
  } else if (record->record_type == ZI_FS_JOURNAL_RECORD_BLOCK_IMAGE) {
    if (scan->image_count >= ZI_FS_RECOVERY_MAXIMUM_IMAGES ||
        !recovery_target_is_valid(superblock, record->target_block)) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    RecoveryImage* image = &scan->images[scan->image_count++];
    image->record_index = record_index;
    image->sequence = record->sequence;
    image->target_block = record->target_block;
  } else if (record->record_type == ZI_FS_JOURNAL_RECORD_COMMIT) {
    if (scan->found_commit) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    scan->found_commit = true;
    scan->commit_sequence = record->sequence;
    scan->commit_checksum = record->transaction_checksum;
  } else if (record->record_type == ZI_FS_JOURNAL_RECORD_CHECKPOINT) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus
validate_recovery_scan(const ZiFsVolume* volume, void* workspace, RecoveryScan* scan) {
  if (!scan->found_begin || scan->expected_image_count != scan->image_count ||
      scan->image_count == 0) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  sort_recovery_images(scan);
  if (!recovery_targets_are_unique(scan)) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  uint64_t capacity = 0;
  if (ZiFailed(ZiFsJournalRecordCapacity(volume->superblock.journal_blocks, &capacity))) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  uint32_t checksum = 0;
  uint64_t previous_sequence = scan->begin_sequence;
  for (size_t index = 0; index < scan->image_count; ++index) {
    ZiStatus status = validate_recovery_image(volume,
                                              workspace,
                                              capacity,
                                              &scan->images[index],
                                              &previous_sequence,
                                              &checksum);
    if (ZiFailed(status)) {
      return status;
    }
  }
  checksum = finalise_transaction_checksum(checksum);
  if (scan->found_commit &&
      (previous_sequence == UINT64_MAX || scan->commit_sequence != previous_sequence + 1u ||
       scan->commit_checksum != checksum)) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  return ZI_STATUS_SUCCESS;
}

static void sort_recovery_images(RecoveryScan* scan) {
  for (size_t index = 1; index < scan->image_count; ++index) {
    RecoveryImage moving = scan->images[index];
    size_t position = index;
    while (position > 0 && scan->images[position - 1u].sequence > moving.sequence) {
      scan->images[position] = scan->images[position - 1u];
      --position;
    }
    scan->images[position] = moving;
  }
}

static bool recovery_targets_are_unique(const RecoveryScan* scan) {
  for (size_t index = 0; index < scan->image_count; ++index) {
    for (size_t other = 0; other < index; ++other) {
      if (scan->images[other].target_block == scan->images[index].target_block) {
        return false;
      }
    }
  }
  return true;
}

static ZiStatus validate_recovery_image(const ZiFsVolume* volume,
                                        void* workspace,
                                        uint64_t capacity,
                                        const RecoveryImage* image,
                                        uint64_t* previous_sequence,
                                        uint32_t* checksum) {
  if (*previous_sequence == UINT64_MAX || image->sequence != *previous_sequence + 1u) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  uint64_t block = 0;
  ZiStatus status = ZiFsJournalRecordBlock(volume->superblock.journal_start,
                                           capacity,
                                           image->record_index,
                                           &block);
  if (ZiFailed(status)) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  status = volume->device.read_blocks(volume->device.context,
                                      block,
                                      (uint32_t)ZI_FS_JOURNAL_RECORD_BLOCKS,
                                      workspace,
                                      ZI_FS_JOURNAL_RECORD_SIZE);
  ZiFsJournalRecord record = {0};
  if (ZiSucceeded(status)) {
    status = ZiFsDecodeJournalRecord(workspace, ZI_FS_JOURNAL_RECORD_SIZE, &record);
  }
  if (ZiFailed(status) || record.sequence != image->sequence ||
      record.target_block != image->target_block) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  status = ZiFsJournalExtendTransactionChecksum(*checksum, &record, checksum);
  if (ZiFailed(status)) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  *previous_sequence = image->sequence;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus replay_images(ZiFsVolume* volume, void* workspace, const RecoveryScan* scan) {
  uint64_t capacity = 0;
  ZiStatus status = ZiFsJournalRecordCapacity(volume->superblock.journal_blocks, &capacity);
  if (ZiFailed(status)) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  for (size_t index = 0; index < scan->image_count; ++index) {
    uint64_t block = 0;
    status = ZiFsJournalRecordBlock(volume->superblock.journal_start,
                                    capacity,
                                    scan->images[index].record_index,
                                    &block);
    if (ZiFailed(status)) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    status = volume->device.read_blocks(volume->device.context,
                                        block,
                                        (uint32_t)ZI_FS_JOURNAL_RECORD_BLOCKS,
                                        workspace,
                                        ZI_FS_JOURNAL_RECORD_SIZE);
    ZiFsJournalRecord record = {0};
    if (ZiSucceeded(status)) {
      status = ZiFsDecodeJournalRecord(workspace, ZI_FS_JOURNAL_RECORD_SIZE, &record);
    }
    if (ZiFailed(status)) {
      return status;
    }
    status = zi_block_write(&volume->device,
                            record.target_block,
                            1,
                            record.payload.data,
                            ZI_FS_BLOCK_SIZE);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return zi_block_barrier(&volume->device);
}

static ZiStatus
write_clean_superblocks(ZiFsVolume* volume, const ZiFsSuperblock* superblock, void* block_buffer) {
  ZiStatus status = ZiFsEncodeSuperblock(superblock, block_buffer, ZI_FS_BLOCK_SIZE);
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_block_write(&volume->device,
                          superblock->backup_superblock,
                          1,
                          block_buffer,
                          ZI_FS_BLOCK_SIZE);
  if (ZiSucceeded(status)) {
    status = zi_block_barrier(&volume->device);
  }
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_block_write(&volume->device, 0, 1, block_buffer, ZI_FS_BLOCK_SIZE);
  if (ZiSucceeded(status)) {
    status = zi_block_barrier(&volume->device);
  }
  return status;
}

static ZiStatus reset_journal_headers(ZiFsVolume* volume,
                                      const ZiFsSuperblock* superblock,
                                      uint64_t minimum_next_sequence,
                                      uint64_t reclaimed_head,
                                      void* block_buffer) {
  uint64_t capacity = 0;
  ZiStatus status = ZiFsJournalRecordCapacity(superblock->journal_blocks, &capacity);
  if (ZiFailed(status) || capacity < ZI_FS_JOURNAL_MINIMUM_RECORD_CAPACITY ||
      superblock->last_committed_transaction == UINT64_MAX ||
      (reclaimed_head != UINT64_MAX && reclaimed_head >= capacity)) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  ZiFsJournalHeader previous = {0};
  uint32_t previous_copy = 0;
  uint64_t header_sequence = 0;
  uint64_t head_record = reclaimed_head == UINT64_MAX ? 0 : reclaimed_head;
  uint64_t next_sequence = minimum_next_sequence == 0 ? 1 : minimum_next_sequence;
  status = ZiFsLoadJournalHeader(&volume->device,
                                 superblock->journal_start,
                                 block_buffer,
                                 ZI_FS_BLOCK_SIZE,
                                 &previous,
                                 &previous_copy);
  if (ZiSucceeded(status) && previous.record_capacity == capacity) {
    header_sequence = previous.header_sequence;
    if (reclaimed_head == UINT64_MAX) {
      head_record = previous.head_record;
    }
    if (previous.next_sequence > next_sequence) {
      next_sequence = previous.next_sequence;
    }
  }
  if (header_sequence > UINT64_MAX - 2u) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  ZiFsJournalHeader header = {0};
  header.volume_generation = superblock->generation;
  header.record_capacity = capacity;
  header.head_record = head_record;
  header.tail_record = head_record;
  header.next_sequence = next_sequence;
  header.next_transaction_id = superblock->last_committed_transaction + 1u;
  header.last_committed_transaction = superblock->last_committed_transaction;
  header.last_checkpoint_transaction = superblock->last_committed_transaction;
  for (uint32_t copy_index = 0; copy_index < ZI_FS_JOURNAL_HEADER_COPIES; ++copy_index) {
    header.header_sequence = header_sequence + copy_index + 1u;
    status = ZiFsStoreJournalHeader(&volume->device,
                                    superblock->journal_start,
                                    copy_index,
                                    &header,
                                    block_buffer,
                                    ZI_FS_BLOCK_SIZE);
    if (ZiSucceeded(status)) {
      status = zi_block_barrier(&volume->device);
    }
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static bool recovery_target_is_valid(const ZiFsSuperblock* superblock, uint64_t target_block) {
  return (bool)(target_block < superblock->total_blocks && target_block != 0 &&
                target_block != superblock->backup_superblock &&
                !block_is_in_range(target_block,
                                   superblock->journal_start,
                                   superblock->journal_blocks));
}

static bool block_is_in_range(uint64_t block_number, uint64_t start, uint64_t count) {
  return (bool)(block_number >= start && block_number - start < count);
}

static uint32_t finalise_transaction_checksum(uint32_t checksum) {
  return checksum == 0 ? UINT32_MAX : checksum;
}
