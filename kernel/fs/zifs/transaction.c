// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/block.h"
#include "zi/byte_order.h"
#include "zi/unicode.h"
#include "zi/zifs.h"
#include "zi/zifs_journal.h"
#include "zi/zifs_security.h"
#include "zi/zifs_transaction.h"
#include "zizium/status.h"
#include "zizium/types.h"

static bool transaction_is_valid(const ZiFsTransaction* transaction);
static uint32_t transaction_image_capacity(size_t workspace_size);
static void transaction_discard_images(ZiFsTransaction* transaction);
static ZiStatus transaction_fail(ZiFsTransaction* transaction, ZiStatus status);
static unsigned char* transaction_scratch(const ZiFsTransaction* transaction);
static unsigned char* transaction_image_data(const ZiFsTransaction* transaction,
                                             size_t image_index);
static ZiStatus transaction_stage_existing_block(ZiFsTransaction* transaction,
                                                 uint64_t target_block,
                                                 unsigned char** out_data);
static ZiStatus transaction_stage_empty_block(ZiFsTransaction* transaction,
                                              uint64_t target_block,
                                              unsigned char** out_data);
static ZiStatus validate_create_request(const ZiFsCreateRequest* request);
static ZiStatus validate_move_request(const ZiFsMoveRequest* request);
static ZiStatus validate_truncate_request(const ZiFsTruncateRequest* request);
static ZiStatus validate_delete_request(const ZiFsDeleteRequest* request);
static ZiStatus validate_transaction_name(ZiStringView name);
static ZiStatus find_record_by_file_id(const ZiFsVolume* volume,
                                       uint64_t file_id,
                                       void* scratch,
                                       size_t scratch_size,
                                       uint64_t* out_record_index,
                                       ZiFsFileRecord* out_record);
static ZiStatus validate_move_destination(const ZiFsVolume* volume,
                                          const ZiFsFileRecord* moved_record,
                                          const ZiFsFileRecord* target_parent,
                                          void* scratch,
                                          size_t scratch_size);
static ZiStatus stage_changed_file_record(ZiFsTransaction* transaction,
                                          uint64_t record_index,
                                          const ZiFsFileRecord* record);
static void
remember_first_free_record(uint64_t record_index, bool* found_free, uint64_t* free_record);
static ZiStatus find_free_record(const ZiFsVolume* volume,
                                 void* scratch,
                                 size_t scratch_size,
                                 uint64_t* out_record_index,
                                 uint64_t* out_file_id);
static ZiStatus find_free_extent(const ZiFsVolume* volume,
                                 uint64_t requested_blocks,
                                 void* scratch,
                                 size_t scratch_size,
                                 uint64_t* out_first_block);
static ZiStatus
stage_extent_allocation(ZiFsTransaction* transaction, uint64_t first_block, uint64_t block_count);
static ZiStatus
stage_extent_release(ZiFsTransaction* transaction, uint64_t first_block, uint64_t block_count);
static ZiStatus validate_extent_ownership(const ZiFsVolume* volume,
                                          uint64_t owner_record_index,
                                          const ZiFsFileRecord* owner_record,
                                          void* scratch,
                                          size_t scratch_size);
static ZiStatus validate_extent_non_overlap(const ZiFsFileRecord* record);
static ZiStatus validate_owner_record_candidate(uint64_t owner_record_index,
                                                const ZiFsFileRecord* owner_record,
                                                uint64_t candidate_index,
                                                const ZiFsFileRecord* candidate,
                                                bool* owner_seen);
static ZiStatus validate_record_table_block(const ZiFsVolume* volume,
                                            uint64_t block_offset,
                                            uint64_t owner_record_index,
                                            const ZiFsFileRecord* owner_record,
                                            void* scratch,
                                            size_t scratch_size,
                                            bool* owner_seen);
static ZiStatus validate_allocated_extents(const ZiFsVolume* volume,
                                           const ZiFsFileRecord* record,
                                           void* scratch,
                                           size_t scratch_size);
static ZiStatus validate_allocated_extent(const ZiFsVolume* volume,
                                          const ZiFsExtent* extent,
                                          void* scratch,
                                          size_t scratch_size,
                                          uint64_t* loaded_bitmap_block);
static bool block_is_metadata(const ZiFsSuperblock* superblock, uint64_t block_number);
static bool block_is_in_range(uint64_t block_number, uint64_t start, uint64_t count);
static bool block_ranges_overlap(uint64_t first_start,
                                 uint64_t first_count,
                                 uint64_t second_start,
                                 uint64_t second_count);
static bool bytes_are_zero(const unsigned char* bytes, size_t size);
static ZiStatus write_journal_record(const ZiFsTransaction* transaction,
                                     uint64_t record_index,
                                     const ZiFsJournalRecord* record);
static ZiStatus write_transaction_superblocks(ZiFsTransaction* transaction, uint32_t state_flags);
static uint32_t finalise_transaction_checksum(uint32_t checksum);

ZiStatus ZiFsTransactionInitialise(ZiFsTransaction* transaction,
                                   ZiFsVolume* volume,
                                   void* workspace,
                                   size_t workspace_size) {
  uint32_t image_capacity = transaction_image_capacity(workspace_size);
  if (transaction == NULL || volume == NULL || workspace == NULL ||
      image_capacity < ZI_FS_TRANSACTION_MINIMUM_BLOCK_IMAGES ||
      volume->superblock.generation == UINT64_MAX ||
      volume->superblock.last_committed_transaction >= UINT64_MAX - 1u ||
      (volume->superblock.incompatible_features & ZI_FS_FEATURE_INCOMPAT_JOURNAL_V1) == 0 ||
      volume->device.read_blocks == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (volume->superblock.state_flags != ZI_FS_SUPERBLOCK_STATE_NONE ||
      volume->needs_recovery != 0) {
    return ZI_STATUS_RECOVERY_REQUIRED;
  }

  zi_memory_zero(transaction, sizeof *transaction);
  transaction->struct_size = sizeof *transaction;
  transaction->version = ZI_FS_TRANSACTION_VERSION;
  transaction->volume = volume;
  transaction->workspace = workspace;
  transaction->workspace_size =
      ((size_t)image_capacity + ZI_FS_TRANSACTION_SCRATCH_BLOCKS) * (size_t)ZI_FS_BLOCK_SIZE;
  transaction->source_generation = volume->superblock.generation;
  transaction->target_generation = volume->superblock.generation + 1u;
  transaction->transaction_id = volume->superblock.last_committed_transaction + 1u;
  transaction->state = ZI_FS_TRANSACTION_STATE_READY;
  transaction->block_image_capacity = image_capacity;
  zi_memory_zero(workspace, transaction->workspace_size);
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsTransactionReset(ZiFsTransaction* transaction) {
  if (!transaction_is_valid(transaction)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (transaction->state == ZI_FS_TRANSACTION_STATE_FAILED ||
      transaction->volume->needs_recovery != 0) {
    return ZI_STATUS_RECOVERY_REQUIRED;
  }
  transaction_discard_images(transaction);
  transaction->source_generation = transaction->volume->superblock.generation;
  if (transaction->source_generation == UINT64_MAX ||
      transaction->volume->superblock.last_committed_transaction == UINT64_MAX) {
    return ZI_STATUS_INVALID_STATE;
  }
  transaction->target_generation = transaction->source_generation + 1u;
  transaction->transaction_id = transaction->volume->superblock.last_committed_transaction + 1u;
  return ZI_STATUS_SUCCESS;
}

// Barriers enforce redo images, dirty marker, commit, home images, then clean marker.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
ZiStatus ZiFsTransactionCommit(ZiFsTransaction* transaction) {
  if (!transaction_is_valid(transaction)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (transaction->state != ZI_FS_TRANSACTION_STATE_PREPARED ||
      transaction->block_image_count == 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  if (transaction->volume->is_read_only != 0 || transaction->volume->needs_recovery != 0 ||
      (transaction->volume->device.flags &
       (ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED)) !=
          (ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED)) {
    return ZI_STATUS_READ_ONLY_FILESYSTEM;
  }

  unsigned char* journal_buffer = transaction_scratch(transaction);
  ZiFsJournalHeader header = {0};
  uint32_t header_copy = 0;
  ZiStatus status = ZiFsLoadJournalHeader(&transaction->volume->device,
                                          transaction->volume->superblock.journal_start,
                                          journal_buffer,
                                          ZI_FS_BLOCK_SIZE,
                                          &header,
                                          &header_copy);
  uint64_t expected_capacity = 0;
  if (ZiFailed(status) ||
      ZiFailed(ZiFsJournalRecordCapacity(transaction->volume->superblock.journal_blocks,
                                         &expected_capacity)) ||
      header.record_capacity != expected_capacity ||
      header.volume_generation != transaction->source_generation ||
      header.last_committed_transaction !=
          transaction->volume->superblock.last_committed_transaction ||
      header.last_checkpoint_transaction != header.last_committed_transaction ||
      header.head_record != header.tail_record || header.header_sequence == UINT64_MAX ||
      header.next_transaction_id != transaction->transaction_id) {
    return ZI_STATUS_RECOVERY_REQUIRED;
  }
  if (header.next_sequence > UINT64_MAX - transaction->block_image_count - 3u ||
      transaction->transaction_id == UINT64_MAX) {
    return ZI_STATUS_JOURNAL_FULL;
  }
  uint64_t occupied_records = 0;
  uint64_t available_records = 0;
  uint64_t required_records = (uint64_t)transaction->block_image_count + 3u;
  if (ZiFailed(ZiFsJournalQuerySpace(&header, &occupied_records, &available_records)) ||
      occupied_records != 0 || required_records > available_records) {
    return ZI_STATUS_JOURNAL_FULL;
  }

  uint64_t record_index = header.head_record;
  uint64_t sequence = header.next_sequence;
  ZiFsJournalRecord record = {0};
  record.record_type = ZI_FS_JOURNAL_RECORD_BEGIN;
  record.transaction_id = transaction->transaction_id;
  record.sequence = sequence++;
  record.target_block = ZI_FS_JOURNAL_TARGET_NONE;
  record.source_generation = transaction->source_generation;
  record.target_generation = transaction->target_generation;
  record.image_count = transaction->block_image_count;
  status = write_journal_record(transaction, record_index, &record);
  if (ZiFailed(status)) {
    goto commit_failed;
  }
  status = ZiFsJournalAdvanceRecord(header.record_capacity, record_index, 1u, &record_index);
  if (ZiFailed(status)) {
    goto commit_failed;
  }

  uint32_t transaction_checksum = 0;
  for (size_t image_index = 0; image_index < transaction->block_image_count; ++image_index) {
    ZiFsJournalRecord image_record = {0};
    image_record.record_type = ZI_FS_JOURNAL_RECORD_BLOCK_IMAGE;
    image_record.transaction_id = transaction->transaction_id;
    image_record.sequence = sequence++;
    image_record.target_block = transaction->block_images[image_index].target_block;
    image_record.source_generation = transaction->source_generation;
    image_record.target_generation = transaction->target_generation;
    image_record.payload =
        (ZiConstBuffer){transaction_image_data(transaction, image_index), ZI_FS_BLOCK_SIZE};
    status = write_journal_record(transaction, record_index, &image_record);
    if (ZiFailed(status)) {
      goto commit_failed;
    }
    status = ZiFsJournalExtendTransactionChecksum(transaction_checksum,
                                                  &image_record,
                                                  &transaction_checksum);
    if (ZiFailed(status)) {
      goto commit_failed;
    }
    status = ZiFsJournalAdvanceRecord(header.record_capacity, record_index, 1u, &record_index);
    if (ZiFailed(status)) {
      goto commit_failed;
    }
  }
  transaction_checksum = finalise_transaction_checksum(transaction_checksum);
  status = zi_block_barrier(&transaction->volume->device);
  if (ZiFailed(status)) {
    goto commit_failed;
  }

  status = write_transaction_superblocks(transaction, ZI_FS_SUPERBLOCK_STATE_DIRTY);
  if (ZiFailed(status)) {
    goto commit_failed;
  }

  record.record_type = ZI_FS_JOURNAL_RECORD_COMMIT;
  record.sequence = sequence++;
  record.transaction_checksum = transaction_checksum;
  status = write_journal_record(transaction, record_index, &record);
  if (ZiSucceeded(status)) {
    status = zi_block_barrier(&transaction->volume->device);
  }
  if (ZiFailed(status)) {
    goto commit_failed;
  }
  status = ZiFsJournalAdvanceRecord(header.record_capacity, record_index, 1u, &record_index);
  if (ZiFailed(status)) {
    goto commit_failed;
  }

  ++header.header_sequence;
  header.volume_generation = transaction->target_generation;
  header.head_record = record_index;
  header.next_sequence = sequence;
  header.next_transaction_id = transaction->transaction_id + 1u;
  header.last_committed_transaction = transaction->transaction_id;
  uint32_t committed_header_copy = (uint32_t)((header_copy + 1u) % ZI_FS_JOURNAL_HEADER_COPIES);
  status = ZiFsStoreJournalHeader(&transaction->volume->device,
                                  transaction->volume->superblock.journal_start,
                                  committed_header_copy,
                                  &header,
                                  journal_buffer,
                                  ZI_FS_BLOCK_SIZE);
  if (ZiSucceeded(status)) {
    status = zi_block_barrier(&transaction->volume->device);
  }
  if (ZiFailed(status)) {
    goto commit_failed;
  }

  for (size_t image_index = 0; image_index < transaction->block_image_count; ++image_index) {
    status = zi_block_write(&transaction->volume->device,
                            transaction->block_images[image_index].target_block,
                            1,
                            transaction_image_data(transaction, image_index),
                            ZI_FS_BLOCK_SIZE);
    if (ZiFailed(status)) {
      goto commit_failed;
    }
  }
  status = zi_block_barrier(&transaction->volume->device);
  if (ZiFailed(status)) {
    goto commit_failed;
  }

  status = write_transaction_superblocks(transaction, ZI_FS_SUPERBLOCK_STATE_NONE);
  if (ZiFailed(status)) {
    goto commit_failed;
  }

  record.record_type = ZI_FS_JOURNAL_RECORD_CHECKPOINT;
  record.sequence = sequence++;
  status = write_journal_record(transaction, record_index, &record);
  if (ZiSucceeded(status)) {
    status = zi_block_barrier(&transaction->volume->device);
  }
  if (ZiFailed(status)) {
    goto commit_failed;
  }
  status = ZiFsJournalAdvanceRecord(header.record_capacity, record_index, 1u, &record_index);
  if (ZiFailed(status)) {
    goto commit_failed;
  }
  ++header.header_sequence;
  header.head_record = record_index;
  header.tail_record = record_index;
  header.next_sequence = sequence;
  header.last_checkpoint_transaction = transaction->transaction_id;
  status = ZiFsStoreJournalHeader(&transaction->volume->device,
                                  transaction->volume->superblock.journal_start,
                                  header_copy,
                                  &header,
                                  journal_buffer,
                                  ZI_FS_BLOCK_SIZE);
  if (ZiSucceeded(status)) {
    status = zi_block_barrier(&transaction->volume->device);
  }
  if (ZiFailed(status)) {
    goto commit_failed;
  }

  transaction->volume->superblock.generation = transaction->target_generation;
  transaction->volume->superblock.last_committed_transaction = transaction->transaction_id;
  transaction->volume->superblock.state_flags = ZI_FS_SUPERBLOCK_STATE_NONE;
  transaction->volume->needs_recovery = 0;
  transaction->volume->journal_header_valid = 1;
  return ZiFsTransactionReset(transaction);

commit_failed:
  transaction->state = ZI_FS_TRANSACTION_STATE_FAILED;
  transaction->volume->is_read_only = 1;
  transaction->volume->needs_recovery = 1;
  return status;
}

// Preparation keeps all derived metadata in caller-owned staging storage until commit.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
ZiStatus ZiFsTransactionPrepareCreateFile(ZiFsTransaction* transaction,
                                          const ZiFsCreateRequest* request,
                                          ZiFsCreateResult* out_result) {
  if (!transaction_is_valid(transaction) || request == NULL || out_result == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_memory_zero(out_result, sizeof *out_result);
  if (transaction->state != ZI_FS_TRANSACTION_STATE_READY || transaction->block_image_count != 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiStatus status = validate_create_request(request);
  if (ZiFailed(status)) {
    return status;
  }

  unsigned char* scratch = transaction_scratch(transaction);
  ZiFsSecurityDescriptorStorage security = {0};
  status = ZiFsLoadSecurityDescriptor(transaction->volume,
                                      request->security_id,
                                      scratch,
                                      ZI_FS_BLOCK_SIZE,
                                      &security);
  if (ZiFailed(status)) {
    return status;
  }
  ZiFsFileRecord parent = {0};
  status = ZiFsReadFileRecord(transaction->volume,
                              request->parent_record_index,
                              scratch,
                              ZI_FS_BLOCK_SIZE,
                              &parent);
  if (ZiFailed(status)) {
    return status;
  }
  if (parent.file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  status = transaction->volume->device.read_blocks(transaction->volume->device.context,
                                                   parent.directory_block,
                                                   1,
                                                   scratch,
                                                   ZI_FS_BLOCK_SIZE);
  if (ZiFailed(status)) {
    return status;
  }
  ZiFsDirectoryEntry existing_entry = {0};
  status = ZiFsFindDirectoryEntry(scratch, ZI_FS_BLOCK_SIZE, request->name, &existing_entry);
  if (ZiSucceeded(status)) {
    return ZI_STATUS_ALREADY_EXISTS;
  }
  if (status != ZI_STATUS_NOT_FOUND) {
    return status;
  }

  uint64_t record_index = 0;
  uint64_t file_id = 0;
  status =
      find_free_record(transaction->volume, scratch, ZI_FS_BLOCK_SIZE, &record_index, &file_id);
  if (ZiFailed(status)) {
    return status;
  }

  uint64_t data_block_count =
      request->data.size == 0
          ? 0
          : 1u + (((uint64_t)request->data.size - 1u) / (uint64_t)ZI_FS_BLOCK_SIZE);
  uint64_t first_data_block = 0;
  if (data_block_count != 0) {
    status = find_free_extent(transaction->volume,
                              data_block_count,
                              scratch,
                              ZI_FS_BLOCK_SIZE,
                              &first_data_block);
    if (ZiFailed(status)) {
      return status;
    }
    status = stage_extent_allocation(transaction, first_data_block, data_block_count);
    if (ZiFailed(status)) {
      return transaction_fail(transaction, status);
    }
  }

  const uint64_t records_per_block = ZI_FS_BLOCK_SIZE / ZI_FS_FILE_RECORD_SIZE;
  uint64_t record_block =
      transaction->volume->superblock.record_table_start + (record_index / records_per_block);
  unsigned char* record_block_data = NULL;
  status = transaction_stage_existing_block(transaction, record_block, &record_block_data);
  if (ZiFailed(status)) {
    return transaction_fail(transaction, status);
  }
  ZiFsFileRecord record = {0};
  record.file_id = file_id;
  record.parent_file_id = parent.file_id;
  record.file_type = ZI_FS_FILE_TYPE_REGULAR;
  record.file_size = request->data.size;
  record.security_id = request->security_id;
  record.created_time = request->timestamp;
  record.modified_time = request->timestamp;
  record.changed_time = request->timestamp;
  record.accessed_time = request->timestamp;
  if (data_block_count != 0) {
    record.allocated_size = data_block_count * ZI_FS_BLOCK_SIZE;
    record.extent_count = 1;
    record.extents[0].physical_block = first_data_block;
    record.extents[0].block_count = data_block_count;
  }
  size_t record_offset = (size_t)(record_index % records_per_block) * ZI_FS_FILE_RECORD_SIZE;
  status = ZiFsEncodeFileRecord(&record, record_block_data + record_offset, ZI_FS_FILE_RECORD_SIZE);
  if (ZiFailed(status)) {
    return transaction_fail(transaction, status);
  }

  unsigned char* directory_data = NULL;
  status = transaction_stage_existing_block(transaction, parent.directory_block, &directory_data);
  if (ZiFailed(status)) {
    return transaction_fail(transaction, status);
  }
  ZiFsDirectoryEntry new_entry = {0};
  new_entry.file_id = file_id;
  new_entry.record_index = record_index;
  new_entry.file_type = ZI_FS_FILE_TYPE_REGULAR;
  new_entry.name = request->name;
  status = ZiFsAddDirectoryEntry(directory_data, ZI_FS_BLOCK_SIZE, &new_entry);
  if (ZiFailed(status)) {
    return transaction_fail(transaction, status);
  }
  status =
      ZiFsSetDirectoryGeneration(directory_data, ZI_FS_BLOCK_SIZE, transaction->target_generation);
  if (ZiFailed(status)) {
    return transaction_fail(transaction, status);
  }

  size_t copied = 0;
  for (uint64_t block_offset = 0; block_offset < data_block_count; ++block_offset) {
    unsigned char* data_block = NULL;
    status =
        transaction_stage_empty_block(transaction, first_data_block + block_offset, &data_block);
    if (ZiFailed(status)) {
      return transaction_fail(transaction, status);
    }
    size_t copy_size = request->data.size - copied;
    if (copy_size > ZI_FS_BLOCK_SIZE) {
      copy_size = ZI_FS_BLOCK_SIZE;
    }
    zi_memory_copy(data_block, (const unsigned char*)request->data.data + copied, copy_size);
    copied += copy_size;
  }

  transaction->state = ZI_FS_TRANSACTION_STATE_PREPARED;
  out_result->struct_size = sizeof *out_result;
  out_result->version = ZI_FS_CREATE_RESULT_VERSION;
  out_result->file_id = file_id;
  out_result->record_index = record_index;
  out_result->first_data_block = first_data_block;
  out_result->data_block_count = data_block_count;
  return ZI_STATUS_SUCCESS;
}

// Rename and cross-directory move share one no-replacement atomic transaction.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
ZiStatus ZiFsTransactionPrepareMove(ZiFsTransaction* transaction,
                                    const ZiFsMoveRequest* request,
                                    ZiFsMoveResult* out_result) {
  if (!transaction_is_valid(transaction) || request == NULL || out_result == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_memory_zero(out_result, sizeof *out_result);
  if (transaction->state != ZI_FS_TRANSACTION_STATE_READY || transaction->block_image_count != 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiStatus status = validate_move_request(request);
  if (ZiFailed(status)) {
    return status;
  }

  unsigned char* scratch = transaction_scratch(transaction);
  ZiFsFileRecord source_parent = {0};
  status = ZiFsReadFileRecord(transaction->volume,
                              request->source_parent_record_index,
                              scratch,
                              ZI_FS_BLOCK_SIZE,
                              &source_parent);
  if (ZiFailed(status)) {
    return status;
  }
  if (source_parent.file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  status = transaction->volume->device.read_blocks(transaction->volume->device.context,
                                                   source_parent.directory_block,
                                                   1,
                                                   scratch,
                                                   ZI_FS_BLOCK_SIZE);
  if (ZiSucceeded(status)) {
    status = ZiFsValidateDirectoryBlock(scratch, ZI_FS_BLOCK_SIZE, source_parent.file_id);
  }
  ZiFsDirectoryEntry source_entry = {0};
  if (ZiSucceeded(status)) {
    status = ZiFsFindDirectoryEntry(scratch, ZI_FS_BLOCK_SIZE, request->source_name, &source_entry);
  }
  if (ZiFailed(status)) {
    return status;
  }

  bool same_parent = request->source_parent_record_index == request->target_parent_record_index;
  if (same_parent && request->source_name.size == request->target_name.size &&
      zi_memory_compare(request->source_name.data,
                        request->target_name.data,
                        request->source_name.size) == 0) {
    return ZI_STATUS_ALREADY_EXISTS;
  }

  ZiFsFileRecord target_parent = source_parent;
  if (!same_parent) {
    status = ZiFsReadFileRecord(transaction->volume,
                                request->target_parent_record_index,
                                scratch,
                                ZI_FS_BLOCK_SIZE,
                                &target_parent);
    if (ZiFailed(status)) {
      return status;
    }
    if (target_parent.file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
      return ZI_STATUS_INVALID_ARGUMENT;
    }
    if (source_parent.file_id == target_parent.file_id ||
        source_parent.directory_block == target_parent.directory_block) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    status = transaction->volume->device.read_blocks(transaction->volume->device.context,
                                                     target_parent.directory_block,
                                                     1,
                                                     scratch,
                                                     ZI_FS_BLOCK_SIZE);
    if (ZiSucceeded(status)) {
      status = ZiFsValidateDirectoryBlock(scratch, ZI_FS_BLOCK_SIZE, target_parent.file_id);
    }
    if (ZiFailed(status)) {
      return status;
    }
  }

  ZiFsDirectoryEntry collision = {0};
  status = ZiFsFindDirectoryEntry(scratch, ZI_FS_BLOCK_SIZE, request->target_name, &collision);
  if (ZiSucceeded(status)) {
    return ZI_STATUS_ALREADY_EXISTS;
  }
  if (status != ZI_STATUS_NOT_FOUND) {
    return status;
  }

  ZiFsFileRecord moved_record = {0};
  status = ZiFsReadFileRecord(transaction->volume,
                              source_entry.record_index,
                              scratch,
                              ZI_FS_BLOCK_SIZE,
                              &moved_record);
  if (ZiFailed(status)) {
    return status;
  }
  if (source_entry.record_index == transaction->volume->superblock.root_record_index ||
      moved_record.file_id != source_entry.file_id ||
      moved_record.file_type != source_entry.file_type ||
      moved_record.parent_file_id != source_parent.file_id) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  if (!same_parent) {
    status = validate_move_destination(transaction->volume,
                                       &moved_record,
                                       &target_parent,
                                       scratch,
                                       ZI_FS_BLOCK_SIZE);
    if (ZiFailed(status)) {
      return status;
    }
  }

  unsigned char* source_directory = NULL;
  status = transaction_stage_existing_block(transaction,
                                            source_parent.directory_block,
                                            &source_directory);
  if (ZiSucceeded(status)) {
    status = ZiFsValidateDirectoryBlock(source_directory, ZI_FS_BLOCK_SIZE, source_parent.file_id);
  }
  ZiFsDirectoryEntry removed_entry = {0};
  if (ZiSucceeded(status)) {
    status = ZiFsRemoveDirectoryEntry(source_directory,
                                      ZI_FS_BLOCK_SIZE,
                                      request->source_name,
                                      &removed_entry);
  }
  if (ZiFailed(status)) {
    return transaction_fail(transaction, status);
  }
  if (removed_entry.file_id != source_entry.file_id ||
      removed_entry.record_index != source_entry.record_index ||
      removed_entry.file_type != source_entry.file_type ||
      removed_entry.flags != source_entry.flags) {
    return transaction_fail(transaction, ZI_STATUS_CORRUPT_FILESYSTEM);
  }

  ZiFsDirectoryEntry target_entry = removed_entry;
  target_entry.name = request->target_name;
  unsigned char* target_directory = source_directory;
  if (!same_parent) {
    status = transaction_stage_existing_block(transaction,
                                              target_parent.directory_block,
                                              &target_directory);
    if (ZiSucceeded(status)) {
      status =
          ZiFsValidateDirectoryBlock(target_directory, ZI_FS_BLOCK_SIZE, target_parent.file_id);
    }
  }
  if (ZiSucceeded(status)) {
    status = ZiFsAddDirectoryEntry(target_directory, ZI_FS_BLOCK_SIZE, &target_entry);
  }
  if (ZiSucceeded(status)) {
    status = ZiFsSetDirectoryGeneration(source_directory,
                                        ZI_FS_BLOCK_SIZE,
                                        transaction->target_generation);
  }
  if (ZiSucceeded(status) && !same_parent) {
    status = ZiFsSetDirectoryGeneration(target_directory,
                                        ZI_FS_BLOCK_SIZE,
                                        transaction->target_generation);
  }
  if (ZiFailed(status)) {
    return transaction_fail(transaction, status);
  }

  moved_record.parent_file_id = target_parent.file_id;
  moved_record.changed_time = request->timestamp;
  status = stage_changed_file_record(transaction, source_entry.record_index, &moved_record);
  if (ZiFailed(status)) {
    return transaction_fail(transaction, status);
  }

  transaction->state = ZI_FS_TRANSACTION_STATE_PREPARED;
  out_result->struct_size = sizeof *out_result;
  out_result->version = ZI_FS_MOVE_RESULT_VERSION;
  out_result->file_id = moved_record.file_id;
  out_result->record_index = source_entry.record_index;
  out_result->source_parent_file_id = source_parent.file_id;
  out_result->target_parent_file_id = target_parent.file_id;
  out_result->file_type = moved_record.file_type;
  return ZI_STATUS_SUCCESS;
}

// Shrinking preserves file identity and defers released allocation bits to the checkpointed image.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
ZiStatus ZiFsTransactionPrepareTruncate(ZiFsTransaction* transaction,
                                        const ZiFsTruncateRequest* request,
                                        ZiFsTruncateResult* out_result) {
  if (!transaction_is_valid(transaction) || request == NULL || out_result == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_memory_zero(out_result, sizeof *out_result);
  if (transaction->state != ZI_FS_TRANSACTION_STATE_READY || transaction->block_image_count != 0 ||
      transaction->deferred_extent_count != 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiStatus status = validate_truncate_request(request);
  if (ZiFailed(status)) {
    return status;
  }

  unsigned char* scratch = transaction_scratch(transaction);
  ZiFsFileRecord record = {0};
  status = ZiFsReadFileRecord(transaction->volume,
                              request->record_index,
                              scratch,
                              ZI_FS_BLOCK_SIZE,
                              &record);
  if (ZiFailed(status)) {
    return status;
  }
  if (request->record_index == transaction->volume->superblock.root_record_index ||
      record.file_type != ZI_FS_FILE_TYPE_REGULAR) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (request->new_size > record.file_size) {
    return ZI_STATUS_NOT_IMPLEMENTED;
  }
  status = validate_extent_ownership(transaction->volume,
                                     request->record_index,
                                     &record,
                                     scratch,
                                     ZI_FS_BLOCK_SIZE);
  if (ZiFailed(status)) {
    return status;
  }

  uint64_t retained_blocks =
      request->new_size == 0 ? 0 : 1u + ((request->new_size - 1u) >> ZI_FS_BLOCK_SHIFT);
  uint64_t remaining_blocks = retained_blocks;
  uint64_t released_blocks = 0;
  uint32_t release_count = 0;
  ZiFsDeferredExtent releases[ZI_FS_TRANSACTION_MAXIMUM_DEFERRED_EXTENTS] = {0};
  ZiFsFileRecord changed = record;
  zi_memory_zero(changed.extents, sizeof changed.extents);
  changed.extent_count = 0;
  for (size_t index = 0; index < record.extent_count; ++index) {
    const ZiFsExtent* extent = &record.extents[index];
    uint64_t keep_blocks = extent->block_count;
    if (keep_blocks > remaining_blocks) {
      keep_blocks = remaining_blocks;
    }
    if (keep_blocks != 0) {
      changed.extents[changed.extent_count] = *extent;
      changed.extents[changed.extent_count].block_count = keep_blocks;
      ++changed.extent_count;
      remaining_blocks -= keep_blocks;
    }
    if (keep_blocks < extent->block_count) {
      if (release_count >= ZI_FS_TRANSACTION_MAXIMUM_DEFERRED_EXTENTS) {
        return ZI_STATUS_CORRUPT_FILESYSTEM;
      }
      releases[release_count].first_block = extent->physical_block + keep_blocks;
      releases[release_count].block_count = extent->block_count - keep_blocks;
      released_blocks += releases[release_count].block_count;
      ++release_count;
    }
  }
  if (remaining_blocks != 0 || retained_blocks > (UINT64_MAX >> ZI_FS_BLOCK_SHIFT)) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  changed.file_size = request->new_size;
  changed.allocated_size = retained_blocks << ZI_FS_BLOCK_SHIFT;
  changed.modified_time = request->timestamp;
  changed.changed_time = request->timestamp;
  status = stage_changed_file_record(transaction, request->record_index, &changed);
  if (ZiFailed(status)) {
    return transaction_fail(transaction, status);
  }

  size_t tail_offset = (size_t)(request->new_size & (ZI_FS_BLOCK_SIZE - 1u));
  if (retained_blocks != 0 && tail_offset != 0) {
    const ZiFsExtent* final_extent = &changed.extents[changed.extent_count - 1u];
    uint64_t final_block = final_extent->physical_block + final_extent->block_count - 1u;
    unsigned char* tail_data = NULL;
    status = transaction_stage_existing_block(transaction, final_block, &tail_data);
    if (ZiSucceeded(status)) {
      zi_memory_zero(tail_data + tail_offset, ZI_FS_BLOCK_SIZE - tail_offset);
    }
    if (ZiFailed(status)) {
      return transaction_fail(transaction, status);
    }
  }

  for (size_t index = 0; index < release_count; ++index) {
    status =
        stage_extent_release(transaction, releases[index].first_block, releases[index].block_count);
    if (ZiFailed(status)) {
      return transaction_fail(transaction, status);
    }
  }

  transaction->state = ZI_FS_TRANSACTION_STATE_PREPARED;
  out_result->struct_size = sizeof *out_result;
  out_result->version = ZI_FS_TRUNCATE_RESULT_VERSION;
  out_result->file_id = record.file_id;
  out_result->record_index = request->record_index;
  out_result->previous_size = record.file_size;
  out_result->new_size = request->new_size;
  out_result->retained_block_count = retained_blocks;
  out_result->released_block_count = released_blocks;
  return ZI_STATUS_SUCCESS;
}

// Deletion removes the exact directory link and record before staging allocation release.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
ZiStatus ZiFsTransactionPrepareDelete(ZiFsTransaction* transaction,
                                      const ZiFsDeleteRequest* request,
                                      ZiFsDeleteResult* out_result) {
  if (!transaction_is_valid(transaction) || request == NULL || out_result == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_memory_zero(out_result, sizeof *out_result);
  if (transaction->state != ZI_FS_TRANSACTION_STATE_READY || transaction->block_image_count != 0 ||
      transaction->deferred_extent_count != 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiStatus status = validate_delete_request(request);
  if (ZiFailed(status)) {
    return status;
  }

  unsigned char* scratch = transaction_scratch(transaction);
  ZiFsFileRecord parent = {0};
  status = ZiFsReadFileRecord(transaction->volume,
                              request->parent_record_index,
                              scratch,
                              ZI_FS_BLOCK_SIZE,
                              &parent);
  if (ZiFailed(status)) {
    return status;
  }
  if (parent.file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  status = transaction->volume->device.read_blocks(transaction->volume->device.context,
                                                   parent.directory_block,
                                                   1,
                                                   scratch,
                                                   ZI_FS_BLOCK_SIZE);
  if (ZiSucceeded(status)) {
    status = ZiFsValidateDirectoryBlock(scratch, ZI_FS_BLOCK_SIZE, parent.file_id);
  }
  ZiFsDirectoryEntry entry = {0};
  if (ZiSucceeded(status)) {
    status = ZiFsFindDirectoryEntry(scratch, ZI_FS_BLOCK_SIZE, request->name, &entry);
  }
  if (ZiFailed(status)) {
    return status;
  }
  if (entry.record_index == transaction->volume->superblock.root_record_index ||
      entry.record_index == request->parent_record_index) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }

  ZiFsFileRecord record = {0};
  status = ZiFsReadFileRecord(transaction->volume,
                              entry.record_index,
                              scratch,
                              ZI_FS_BLOCK_SIZE,
                              &record);
  if (ZiFailed(status)) {
    return status;
  }
  if (record.file_id != entry.file_id || record.file_type != entry.file_type ||
      record.parent_file_id != parent.file_id) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  if (record.file_type != ZI_FS_FILE_TYPE_REGULAR) {
    return ZI_STATUS_NOT_IMPLEMENTED;
  }
  status = validate_extent_ownership(transaction->volume,
                                     entry.record_index,
                                     &record,
                                     scratch,
                                     ZI_FS_BLOCK_SIZE);
  if (ZiFailed(status)) {
    return status;
  }

  unsigned char* directory_data = NULL;
  status = transaction_stage_existing_block(transaction, parent.directory_block, &directory_data);
  if (ZiSucceeded(status)) {
    status = ZiFsValidateDirectoryBlock(directory_data, ZI_FS_BLOCK_SIZE, parent.file_id);
  }
  ZiFsDirectoryEntry removed = {0};
  if (ZiSucceeded(status)) {
    status = ZiFsRemoveDirectoryEntry(directory_data, ZI_FS_BLOCK_SIZE, request->name, &removed);
  }
  if (ZiSucceeded(status)) {
    status = ZiFsSetDirectoryGeneration(directory_data,
                                        ZI_FS_BLOCK_SIZE,
                                        transaction->target_generation);
  }
  if (ZiFailed(status)) {
    return transaction_fail(transaction, status);
  }
  if (removed.file_id != entry.file_id || removed.record_index != entry.record_index ||
      removed.file_type != entry.file_type || removed.flags != entry.flags) {
    return transaction_fail(transaction, ZI_STATUS_CORRUPT_FILESYSTEM);
  }

  parent.modified_time = request->timestamp;
  parent.changed_time = request->timestamp;
  status = stage_changed_file_record(transaction, request->parent_record_index, &parent);
  if (ZiFailed(status)) {
    return transaction_fail(transaction, status);
  }
  const uint64_t records_per_block = ZI_FS_BLOCK_SIZE / ZI_FS_FILE_RECORD_SIZE;
  uint64_t record_block =
      transaction->volume->superblock.record_table_start + (entry.record_index / records_per_block);
  unsigned char* record_data = NULL;
  status = transaction_stage_existing_block(transaction, record_block, &record_data);
  if (ZiFailed(status)) {
    return transaction_fail(transaction, status);
  }
  size_t record_offset = (size_t)(entry.record_index % records_per_block) * ZI_FS_FILE_RECORD_SIZE;
  zi_memory_zero(record_data + record_offset, ZI_FS_FILE_RECORD_SIZE);

  uint64_t released_blocks = 0;
  for (size_t index = 0; index < record.extent_count; ++index) {
    status = stage_extent_release(transaction,
                                  record.extents[index].physical_block,
                                  record.extents[index].block_count);
    if (ZiFailed(status)) {
      return transaction_fail(transaction, status);
    }
    released_blocks += record.extents[index].block_count;
  }

  transaction->state = ZI_FS_TRANSACTION_STATE_PREPARED;
  out_result->struct_size = sizeof *out_result;
  out_result->version = ZI_FS_DELETE_RESULT_VERSION;
  out_result->file_id = record.file_id;
  out_result->record_index = entry.record_index;
  out_result->parent_file_id = parent.file_id;
  out_result->released_block_count = released_blocks;
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsTransactionGetBlockImage(const ZiFsTransaction* transaction,
                                      size_t image_index,
                                      uint64_t* out_target_block,
                                      ZiConstBuffer* out_image) {
  if (!transaction_is_valid(transaction) || out_target_block == NULL || out_image == NULL ||
      transaction->state != ZI_FS_TRANSACTION_STATE_PREPARED ||
      image_index >= transaction->block_image_count) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_target_block = transaction->block_images[image_index].target_block;
  *out_image = (ZiConstBuffer){transaction_image_data(transaction, image_index), ZI_FS_BLOCK_SIZE};
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsTransactionGetDeferredExtent(const ZiFsTransaction* transaction,
                                          size_t extent_index,
                                          ZiFsDeferredExtent* out_extent) {
  if (!transaction_is_valid(transaction) || out_extent == NULL ||
      transaction->state != ZI_FS_TRANSACTION_STATE_PREPARED ||
      extent_index >= transaction->deferred_extent_count) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_extent = transaction->deferred_extents[extent_index];
  return ZI_STATUS_SUCCESS;
}

static bool transaction_is_valid(const ZiFsTransaction* transaction) {
  return (bool)((transaction != NULL && transaction->struct_size == sizeof *transaction &&
                 transaction->version == ZI_FS_TRANSACTION_VERSION && transaction->volume != NULL &&
                 transaction->workspace != NULL &&
                 transaction->block_image_capacity >= ZI_FS_TRANSACTION_MINIMUM_BLOCK_IMAGES &&
                 transaction->block_image_capacity <= ZI_FS_TRANSACTION_MAXIMUM_BLOCK_IMAGES &&
                 transaction->workspace_size == ((size_t)transaction->block_image_capacity +
                                                 ZI_FS_TRANSACTION_SCRATCH_BLOCKS) *
                                                    (size_t)ZI_FS_BLOCK_SIZE &&
                 transaction->state >= ZI_FS_TRANSACTION_STATE_READY &&
                 transaction->state <= ZI_FS_TRANSACTION_STATE_FAILED &&
                 transaction->block_image_count <= transaction->block_image_capacity &&
                 transaction->deferred_extent_count <=
                     ZI_FS_TRANSACTION_MAXIMUM_DEFERRED_EXTENTS) != 0);
}

static uint32_t transaction_image_capacity(size_t workspace_size) {
  size_t workspace_blocks = workspace_size / (size_t)ZI_FS_BLOCK_SIZE;
  if (workspace_blocks < ZI_FS_TRANSACTION_MINIMUM_WORKSPACE_BLOCKS) {
    return 0;
  }
  size_t image_capacity = workspace_blocks - ZI_FS_TRANSACTION_SCRATCH_BLOCKS;
  if (image_capacity > ZI_FS_TRANSACTION_MAXIMUM_BLOCK_IMAGES) {
    image_capacity = ZI_FS_TRANSACTION_MAXIMUM_BLOCK_IMAGES;
  }
  return (uint32_t)image_capacity;
}

static void transaction_discard_images(ZiFsTransaction* transaction) {
  zi_memory_zero(transaction->workspace, transaction->workspace_size);
  zi_memory_zero(transaction->block_images, sizeof transaction->block_images);
  zi_memory_zero(transaction->deferred_extents, sizeof transaction->deferred_extents);
  transaction->block_image_count = 0;
  transaction->deferred_extent_count = 0;
  transaction->state = ZI_FS_TRANSACTION_STATE_READY;
}

static ZiStatus transaction_fail(ZiFsTransaction* transaction, ZiStatus status) {
  transaction_discard_images(transaction);
  return status;
}

static unsigned char* transaction_scratch(const ZiFsTransaction* transaction) {
  return transaction->workspace;
}

static unsigned char* transaction_image_data(const ZiFsTransaction* transaction,
                                             size_t image_index) {
  return (unsigned char*)transaction->workspace +
         ((image_index + ZI_FS_TRANSACTION_SCRATCH_BLOCKS) * (size_t)ZI_FS_BLOCK_SIZE);
}

static ZiStatus transaction_stage_existing_block(ZiFsTransaction* transaction,
                                                 uint64_t target_block,
                                                 unsigned char** out_data) {
  if (target_block >= transaction->volume->superblock.total_blocks || out_data == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  for (size_t index = 0; index < transaction->block_image_count; ++index) {
    if (transaction->block_images[index].target_block == target_block) {
      *out_data = transaction_image_data(transaction, index);
      return ZI_STATUS_SUCCESS;
    }
  }
  if (transaction->block_image_count >= transaction->block_image_capacity) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  size_t image_index = transaction->block_image_count;
  unsigned char* data = transaction_image_data(transaction, image_index);
  ZiStatus status = transaction->volume->device.read_blocks(transaction->volume->device.context,
                                                            target_block,
                                                            1,
                                                            data,
                                                            ZI_FS_BLOCK_SIZE);
  if (ZiFailed(status)) {
    zi_memory_zero(data, ZI_FS_BLOCK_SIZE);
    return status;
  }
  transaction->block_images[image_index].target_block = target_block;
  ++transaction->block_image_count;
  *out_data = data;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus transaction_stage_empty_block(ZiFsTransaction* transaction,
                                              uint64_t target_block,
                                              unsigned char** out_data) {
  if (target_block >= transaction->volume->superblock.total_blocks || out_data == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  for (size_t index = 0; index < transaction->block_image_count; ++index) {
    if (transaction->block_images[index].target_block == target_block) {
      return ZI_STATUS_INVALID_STATE;
    }
  }
  if (transaction->block_image_count >= transaction->block_image_capacity) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  size_t image_index = transaction->block_image_count;
  unsigned char* data = transaction_image_data(transaction, image_index);
  zi_memory_zero(data, ZI_FS_BLOCK_SIZE);
  transaction->block_images[image_index].target_block = target_block;
  ++transaction->block_image_count;
  *out_data = data;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_create_request(const ZiFsCreateRequest* request) {
  if (request->struct_size < sizeof *request || request->version != ZI_FS_CREATE_REQUEST_VERSION ||
      request->security_id == 0 || request->name.data == NULL || request->name.size == 0 ||
      request->name.size > ZI_FS_MAX_DIRECTORY_NAME_BYTES ||
      (request->data.data == NULL && request->data.size != 0) ||
      request->data.size >
          (size_t)ZI_FS_TRANSACTION_MAXIMUM_DATA_BLOCKS * (size_t)ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return validate_transaction_name(request->name);
}

static ZiStatus validate_move_request(const ZiFsMoveRequest* request) {
  if (request->struct_size < sizeof *request || request->version != ZI_FS_MOVE_REQUEST_VERSION ||
      request->flags != ZI_FS_MOVE_FLAG_NONE || request->reserved != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_transaction_name(request->source_name);
  if (ZiFailed(status)) {
    return status;
  }
  return validate_transaction_name(request->target_name);
}

static ZiStatus validate_truncate_request(const ZiFsTruncateRequest* request) {
  if (request->struct_size < sizeof *request ||
      request->version != ZI_FS_TRUNCATE_REQUEST_VERSION ||
      request->flags != ZI_FS_TRUNCATE_FLAG_NONE || request->reserved != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_delete_request(const ZiFsDeleteRequest* request) {
  if (request->struct_size < sizeof *request || request->version != ZI_FS_DELETE_REQUEST_VERSION ||
      request->flags != ZI_FS_DELETE_FLAG_NONE || request->reserved != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return validate_transaction_name(request->name);
}

static ZiStatus validate_transaction_name(ZiStringView name) {
  if (name.data == NULL || name.size == 0 || name.size > ZI_FS_MAX_DIRECTORY_NAME_BYTES) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_utf8_validate(name.data, name.size);
  if (ZiFailed(status)) {
    return status;
  }
  if ((name.size == 1 && name.data[0] == '.') ||
      (name.size == 2 && name.data[0] == '.' && name.data[1] == '.')) {
    return ZI_STATUS_INVALID_PATH;
  }
  for (size_t index = 0; index < name.size; ++index) {
    if (name.data[index] == '\0' || name.data[index] == '\\' || name.data[index] == '/') {
      return ZI_STATUS_INVALID_PATH;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus find_record_by_file_id(const ZiFsVolume* volume,
                                       uint64_t file_id,
                                       void* scratch,
                                       size_t scratch_size,
                                       uint64_t* out_record_index,
                                       ZiFsFileRecord* out_record) {
  const uint64_t records_per_block = ZI_FS_BLOCK_SIZE / ZI_FS_FILE_RECORD_SIZE;
  if (volume == NULL || file_id == 0 || scratch == NULL || scratch_size < ZI_FS_BLOCK_SIZE ||
      out_record_index == NULL || out_record == NULL ||
      volume->superblock.record_table_blocks > UINT64_MAX / records_per_block) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  bool found = false;
  for (uint64_t block_offset = 0; block_offset < volume->superblock.record_table_blocks;
       ++block_offset) {
    ZiStatus status =
        volume->device.read_blocks(volume->device.context,
                                   volume->superblock.record_table_start + block_offset,
                                   1,
                                   scratch,
                                   scratch_size);
    if (ZiFailed(status)) {
      return status;
    }
    for (uint64_t slot = 0; slot < records_per_block; ++slot) {
      const unsigned char* encoded =
          (const unsigned char*)scratch + ((size_t)slot * ZI_FS_FILE_RECORD_SIZE);
      if (bytes_are_zero(encoded, ZI_FS_FILE_RECORD_SIZE)) {
        continue;
      }
      ZiFsFileRecord candidate = {0};
      status = ZiFsDecodeFileRecord(encoded, ZI_FS_FILE_RECORD_SIZE, &candidate);
      if (ZiFailed(status) || ZiFailed(ZiFsValidateFileRecord(volume, &candidate))) {
        return ZI_STATUS_CORRUPT_FILESYSTEM;
      }
      if (candidate.file_id != file_id) {
        continue;
      }
      if (found) {
        return ZI_STATUS_CORRUPT_FILESYSTEM;
      }
      found = true;
      *out_record_index = (block_offset * records_per_block) + slot;
      *out_record = candidate;
    }
  }
  if (!found) {
    return ZI_STATUS_NOT_FOUND;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_move_destination(const ZiFsVolume* volume,
                                          const ZiFsFileRecord* moved_record,
                                          const ZiFsFileRecord* target_parent,
                                          void* scratch,
                                          size_t scratch_size) {
  if (volume == NULL || moved_record == NULL || target_parent == NULL || scratch == NULL ||
      scratch_size < ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (moved_record->file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
    return ZI_STATUS_SUCCESS;
  }

  const uint64_t records_per_block = ZI_FS_BLOCK_SIZE / ZI_FS_FILE_RECORD_SIZE;
  if (volume->superblock.record_table_blocks > UINT64_MAX / records_per_block) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  uint64_t maximum_hops = volume->superblock.record_table_blocks * records_per_block;
  ZiFsFileRecord ancestor = *target_parent;
  for (uint64_t hop = 0; hop < maximum_hops; ++hop) {
    if (ancestor.file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    if (ancestor.file_id == moved_record->file_id) {
      return ZI_STATUS_INVALID_PATH;
    }
    if (ancestor.parent_file_id == ancestor.file_id) {
      return ZI_STATUS_SUCCESS;
    }
    uint64_t ancestor_record_index = 0;
    ZiStatus status = find_record_by_file_id(volume,
                                             ancestor.parent_file_id,
                                             scratch,
                                             scratch_size,
                                             &ancestor_record_index,
                                             &ancestor);
    if (status == ZI_STATUS_NOT_FOUND) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_CORRUPT_FILESYSTEM;
}

static ZiStatus stage_changed_file_record(ZiFsTransaction* transaction,
                                          uint64_t record_index,
                                          const ZiFsFileRecord* record) {
  const uint64_t records_per_block = ZI_FS_BLOCK_SIZE / ZI_FS_FILE_RECORD_SIZE;
  if (transaction == NULL || transaction->volume == NULL || record == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t table_block_offset = record_index / records_per_block;
  if (table_block_offset >= transaction->volume->superblock.record_table_blocks) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char* record_block_data = NULL;
  ZiStatus status = transaction_stage_existing_block(
      transaction,
      transaction->volume->superblock.record_table_start + table_block_offset,
      &record_block_data);
  if (ZiFailed(status)) {
    return status;
  }
  size_t record_offset = (size_t)(record_index % records_per_block) * ZI_FS_FILE_RECORD_SIZE;
  return ZiFsEncodeFileRecord(record, record_block_data + record_offset, ZI_FS_FILE_RECORD_SIZE);
}

static void
remember_first_free_record(uint64_t record_index, bool* found_free, uint64_t* free_record) {
  if (!*found_free) {
    *found_free = true;
    *free_record = record_index;
  }
}

static ZiStatus find_free_record(const ZiFsVolume* volume,
                                 void* scratch,
                                 size_t scratch_size,
                                 uint64_t* out_record_index,
                                 uint64_t* out_file_id) {
  const uint64_t records_per_block = ZI_FS_BLOCK_SIZE / ZI_FS_FILE_RECORD_SIZE;
  if (volume == NULL || scratch == NULL || scratch_size < ZI_FS_BLOCK_SIZE ||
      out_record_index == NULL || out_file_id == NULL ||
      volume->superblock.record_table_blocks > UINT64_MAX / records_per_block) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  bool found_free = false;
  uint64_t free_record = 0;
  uint64_t maximum_file_id = 0;
  for (uint64_t block_offset = 0; block_offset < volume->superblock.record_table_blocks;
       ++block_offset) {
    ZiStatus status =
        volume->device.read_blocks(volume->device.context,
                                   volume->superblock.record_table_start + block_offset,
                                   1,
                                   scratch,
                                   scratch_size);
    if (ZiFailed(status)) {
      return status;
    }
    for (uint64_t slot = 0; slot < records_per_block; ++slot) {
      const unsigned char* encoded =
          (const unsigned char*)scratch + ((size_t)slot * ZI_FS_FILE_RECORD_SIZE);
      uint64_t record_index = (block_offset * records_per_block) + slot;
      if (bytes_are_zero(encoded, ZI_FS_FILE_RECORD_SIZE)) {
        remember_first_free_record(record_index, &found_free, &free_record);
        continue;
      }
      ZiFsFileRecord record = {0};
      status = ZiFsDecodeFileRecord(encoded, ZI_FS_FILE_RECORD_SIZE, &record);
      if (ZiFailed(status) || ZiFailed(ZiFsValidateFileRecord(volume, &record))) {
        return ZI_STATUS_CORRUPT_FILESYSTEM;
      }
      if (record.file_id > maximum_file_id) {
        maximum_file_id = record.file_id;
      }
    }
  }
  if (!found_free || maximum_file_id == UINT64_MAX) {
    return ZI_STATUS_VOLUME_FULL;
  }
  *out_record_index = free_record;
  *out_file_id = maximum_file_id + 1u;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus find_free_extent(const ZiFsVolume* volume,
                                 uint64_t requested_blocks,
                                 void* scratch,
                                 size_t scratch_size,
                                 uint64_t* out_first_block) {
  if (volume == NULL || requested_blocks == 0 || scratch == NULL ||
      scratch_size < ZI_FS_BLOCK_SIZE || out_first_block == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const uint64_t bits_per_bitmap_block = (uint64_t)ZI_FS_BLOCK_SIZE * 8u;
  uint64_t loaded_bitmap_block = UINT64_MAX;
  uint64_t run_start = 0;
  uint64_t run_size = 0;
  for (uint64_t block = 0; block < volume->superblock.total_blocks; ++block) {
    if (block_is_metadata(&volume->superblock, block)) {
      run_size = 0;
      continue;
    }
    uint64_t bitmap_block = block / bits_per_bitmap_block;
    if (bitmap_block >= volume->superblock.allocation_bitmap_blocks) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    if (bitmap_block != loaded_bitmap_block) {
      ZiStatus status =
          volume->device.read_blocks(volume->device.context,
                                     volume->superblock.allocation_bitmap_start + bitmap_block,
                                     1,
                                     scratch,
                                     scratch_size);
      if (ZiFailed(status)) {
        return status;
      }
      loaded_bitmap_block = bitmap_block;
    }
    bool allocated = false;
    ZiStatus status = ZiFsAllocationBitQuery(scratch,
                                             ZI_FS_BLOCK_SIZE,
                                             block % bits_per_bitmap_block,
                                             &allocated);
    if (ZiFailed(status)) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    if (allocated) {
      run_size = 0;
      continue;
    }
    if (run_size == 0) {
      run_start = block;
    }
    ++run_size;
    if (run_size == requested_blocks) {
      *out_first_block = run_start;
      return ZI_STATUS_SUCCESS;
    }
  }
  return ZI_STATUS_VOLUME_FULL;
}

static ZiStatus
stage_extent_allocation(ZiFsTransaction* transaction, uint64_t first_block, uint64_t block_count) {
  const uint64_t bits_per_bitmap_block = (uint64_t)ZI_FS_BLOCK_SIZE * 8u;
  for (uint64_t offset = 0; offset < block_count; ++offset) {
    uint64_t block = first_block + offset;
    uint64_t bitmap_block = block / bits_per_bitmap_block;
    unsigned char* bitmap_data = NULL;
    ZiStatus status = transaction_stage_existing_block(
        transaction,
        transaction->volume->superblock.allocation_bitmap_start + bitmap_block,
        &bitmap_data);
    if (ZiFailed(status)) {
      return status;
    }
    bool allocated = false;
    status = ZiFsAllocationBitQuery(bitmap_data,
                                    ZI_FS_BLOCK_SIZE,
                                    block % bits_per_bitmap_block,
                                    &allocated);
    if (ZiFailed(status) || allocated) {
      return ZI_STATUS_INVALID_STATE;
    }
    status =
        ZiFsAllocationBitSet(bitmap_data, ZI_FS_BLOCK_SIZE, block % bits_per_bitmap_block, true);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus
stage_extent_release(ZiFsTransaction* transaction, uint64_t first_block, uint64_t block_count) {
  if (transaction == NULL || transaction->volume == NULL || block_count == 0 ||
      first_block >= transaction->volume->superblock.total_blocks ||
      block_count > transaction->volume->superblock.total_blocks - first_block ||
      transaction->deferred_extent_count >= ZI_FS_TRANSACTION_MAXIMUM_DEFERRED_EXTENTS) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  for (size_t index = 0; index < transaction->deferred_extent_count; ++index) {
    if (block_ranges_overlap(first_block,
                             block_count,
                             transaction->deferred_extents[index].first_block,
                             transaction->deferred_extents[index].block_count)) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
  }

  const uint64_t bits_per_bitmap_block = (uint64_t)ZI_FS_BLOCK_SIZE * 8u;
  for (uint64_t offset = 0; offset < block_count; ++offset) {
    uint64_t block = first_block + offset;
    if (block_is_metadata(&transaction->volume->superblock, block)) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    uint64_t bitmap_block = block / bits_per_bitmap_block;
    if (bitmap_block >= transaction->volume->superblock.allocation_bitmap_blocks) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    unsigned char* bitmap_data = NULL;
    ZiStatus status = transaction_stage_existing_block(
        transaction,
        transaction->volume->superblock.allocation_bitmap_start + bitmap_block,
        &bitmap_data);
    if (ZiFailed(status)) {
      return status;
    }
    bool allocated = false;
    status = ZiFsAllocationBitQuery(bitmap_data,
                                    ZI_FS_BLOCK_SIZE,
                                    block % bits_per_bitmap_block,
                                    &allocated);
    if (ZiFailed(status) || !allocated) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    status =
        ZiFsAllocationBitSet(bitmap_data, ZI_FS_BLOCK_SIZE, block % bits_per_bitmap_block, false);
    if (ZiFailed(status)) {
      return status;
    }
  }
  transaction->deferred_extents[transaction->deferred_extent_count] =
      (ZiFsDeferredExtent){first_block, block_count};
  ++transaction->deferred_extent_count;
  return ZI_STATUS_SUCCESS;
}

// Extent ownership is checked globally before any allocation bit may be released.
static ZiStatus validate_extent_ownership(const ZiFsVolume* volume,
                                          uint64_t owner_record_index,
                                          const ZiFsFileRecord* owner_record,
                                          void* scratch,
                                          size_t scratch_size) {
  const uint64_t records_per_block = ZI_FS_BLOCK_SIZE / ZI_FS_FILE_RECORD_SIZE;
  if (volume == NULL || owner_record == NULL || scratch == NULL ||
      scratch_size < ZI_FS_BLOCK_SIZE || owner_record->file_type != ZI_FS_FILE_TYPE_REGULAR ||
      volume->superblock.record_table_blocks > UINT64_MAX / records_per_block ||
      owner_record_index >= volume->superblock.record_table_blocks * records_per_block) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_extent_non_overlap(owner_record);
  if (ZiFailed(status)) {
    return status;
  }

  bool owner_seen = false;
  for (uint64_t block_offset = 0; block_offset < volume->superblock.record_table_blocks;
       ++block_offset) {
    status = validate_record_table_block(volume,
                                         block_offset,
                                         owner_record_index,
                                         owner_record,
                                         scratch,
                                         scratch_size,
                                         &owner_seen);
    if (ZiFailed(status)) {
      return status;
    }
  }
  if (!owner_seen) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  return validate_allocated_extents(volume, owner_record, scratch, scratch_size);
}

static ZiStatus validate_extent_non_overlap(const ZiFsFileRecord* record) {
  if (record == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  for (size_t index = 0; index < record->extent_count; ++index) {
    for (size_t other = index + 1u; other < record->extent_count; ++other) {
      if (block_ranges_overlap(record->extents[index].physical_block,
                               record->extents[index].block_count,
                               record->extents[other].physical_block,
                               record->extents[other].block_count)) {
        return ZI_STATUS_CORRUPT_FILESYSTEM;
      }
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_owner_record_candidate(uint64_t owner_record_index,
                                                const ZiFsFileRecord* owner_record,
                                                uint64_t candidate_index,
                                                const ZiFsFileRecord* candidate,
                                                bool* owner_seen) {
  if (owner_record == NULL || candidate == NULL || owner_seen == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (candidate_index == owner_record_index) {
    if (*owner_seen || candidate->file_id != owner_record->file_id ||
        candidate->file_type != owner_record->file_type) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    *owner_seen = true;
    return ZI_STATUS_SUCCESS;
  }
  if (candidate->file_id == owner_record->file_id) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  if (candidate->file_type != ZI_FS_FILE_TYPE_REGULAR) {
    return ZI_STATUS_SUCCESS;
  }
  for (size_t owner_extent = 0; owner_extent < owner_record->extent_count; ++owner_extent) {
    for (size_t candidate_extent = 0; candidate_extent < candidate->extent_count;
         ++candidate_extent) {
      if (block_ranges_overlap(owner_record->extents[owner_extent].physical_block,
                               owner_record->extents[owner_extent].block_count,
                               candidate->extents[candidate_extent].physical_block,
                               candidate->extents[candidate_extent].block_count)) {
        return ZI_STATUS_CORRUPT_FILESYSTEM;
      }
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_record_table_block(const ZiFsVolume* volume,
                                            uint64_t block_offset,
                                            uint64_t owner_record_index,
                                            const ZiFsFileRecord* owner_record,
                                            void* scratch,
                                            size_t scratch_size,
                                            bool* owner_seen) {
  if (volume == NULL || owner_record == NULL || scratch == NULL || owner_seen == NULL ||
      scratch_size < ZI_FS_BLOCK_SIZE || block_offset >= volume->superblock.record_table_blocks) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = volume->device.read_blocks(volume->device.context,
                                               volume->superblock.record_table_start + block_offset,
                                               1,
                                               scratch,
                                               scratch_size);
  if (ZiFailed(status)) {
    return status;
  }

  const uint64_t records_per_block = ZI_FS_BLOCK_SIZE / ZI_FS_FILE_RECORD_SIZE;
  for (uint64_t slot = 0; slot < records_per_block; ++slot) {
    const unsigned char* encoded =
        (const unsigned char*)scratch + ((size_t)slot * ZI_FS_FILE_RECORD_SIZE);
    if (bytes_are_zero(encoded, ZI_FS_FILE_RECORD_SIZE)) {
      continue;
    }
    ZiFsFileRecord candidate = {0};
    status = ZiFsDecodeFileRecord(encoded, ZI_FS_FILE_RECORD_SIZE, &candidate);
    if (ZiFailed(status) || ZiFailed(ZiFsValidateFileRecord(volume, &candidate))) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    status = validate_owner_record_candidate(owner_record_index,
                                             owner_record,
                                             (block_offset * records_per_block) + slot,
                                             &candidate,
                                             owner_seen);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_allocated_extents(const ZiFsVolume* volume,
                                           const ZiFsFileRecord* record,
                                           void* scratch,
                                           size_t scratch_size) {
  if (volume == NULL || record == NULL || scratch == NULL || scratch_size < ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t loaded_bitmap_block = UINT64_MAX;
  for (size_t extent_index = 0; extent_index < record->extent_count; ++extent_index) {
    ZiStatus status = validate_allocated_extent(volume,
                                                &record->extents[extent_index],
                                                scratch,
                                                scratch_size,
                                                &loaded_bitmap_block);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_allocated_extent(const ZiFsVolume* volume,
                                          const ZiFsExtent* extent,
                                          void* scratch,
                                          size_t scratch_size,
                                          uint64_t* loaded_bitmap_block) {
  if (volume == NULL || extent == NULL || scratch == NULL || loaded_bitmap_block == NULL ||
      scratch_size < ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const uint64_t bits_per_bitmap_block = (uint64_t)ZI_FS_BLOCK_SIZE * 8u;
  for (uint64_t offset = 0; offset < extent->block_count; ++offset) {
    uint64_t block = extent->physical_block + offset;
    uint64_t bitmap_block = block / bits_per_bitmap_block;
    if (bitmap_block >= volume->superblock.allocation_bitmap_blocks) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    if (bitmap_block != *loaded_bitmap_block) {
      ZiStatus status =
          volume->device.read_blocks(volume->device.context,
                                     volume->superblock.allocation_bitmap_start + bitmap_block,
                                     1,
                                     scratch,
                                     scratch_size);
      if (ZiFailed(status)) {
        return status;
      }
      *loaded_bitmap_block = bitmap_block;
    }
    bool allocated = false;
    ZiStatus status =
        ZiFsAllocationBitQuery(scratch, scratch_size, block % bits_per_bitmap_block, &allocated);
    if (ZiFailed(status) || !allocated) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static bool block_is_metadata(const ZiFsSuperblock* superblock, uint64_t block_number) {
  return (bool)(block_number == 0 || block_number == superblock->backup_superblock ||
                block_is_in_range(block_number,
                                  superblock->record_table_start,
                                  superblock->record_table_blocks) ||
                block_is_in_range(block_number,
                                  superblock->directory_table_start,
                                  superblock->directory_table_blocks) ||
                block_is_in_range(block_number,
                                  superblock->allocation_bitmap_start,
                                  superblock->allocation_bitmap_blocks) ||
                block_is_in_range(block_number,
                                  superblock->journal_start,
                                  superblock->journal_blocks) ||
                block_is_in_range(block_number,
                                  superblock->security_table_start,
                                  superblock->security_table_blocks));
}

static bool block_is_in_range(uint64_t block_number, uint64_t start, uint64_t count) {
  return (bool)(block_number >= start && block_number - start < count);
}

static bool block_ranges_overlap(uint64_t first_start,
                                 uint64_t first_count,
                                 uint64_t second_start,
                                 uint64_t second_count) {
  if (first_count == 0 || second_count == 0) {
    return false;
  }
  if (first_start <= second_start) {
    return first_count > second_start - first_start;
  }
  return second_count > first_start - second_start;
}

static bool bytes_are_zero(const unsigned char* bytes, size_t size) {
  for (size_t index = 0; index < size; ++index) {
    if (bytes[index] != 0) {
      return false;
    }
  }
  return true;
}

static ZiStatus write_journal_record(const ZiFsTransaction* transaction,
                                     uint64_t record_index,
                                     const ZiFsJournalRecord* record) {
  uint64_t capacity = 0;
  ZiStatus status =
      ZiFsJournalRecordCapacity(transaction->volume->superblock.journal_blocks, &capacity);
  uint64_t target_block = 0;
  if (ZiSucceeded(status)) {
    status = ZiFsJournalRecordBlock(transaction->volume->superblock.journal_start,
                                    capacity,
                                    record_index,
                                    &target_block);
  }
  if (ZiFailed(status)) {
    return status;
  }
  unsigned char* buffer = transaction_scratch(transaction);
  status = ZiFsEncodeJournalRecord(record, buffer, ZI_FS_JOURNAL_RECORD_SIZE);
  if (ZiFailed(status)) {
    return status;
  }
  return zi_block_write(&transaction->volume->device,
                        target_block,
                        (uint32_t)ZI_FS_JOURNAL_RECORD_BLOCKS,
                        buffer,
                        ZI_FS_JOURNAL_RECORD_SIZE);
}

static ZiStatus write_transaction_superblocks(ZiFsTransaction* transaction, uint32_t state_flags) {
  ZiFsSuperblock superblock = transaction->volume->superblock;
  superblock.generation = transaction->target_generation;
  superblock.last_committed_transaction = transaction->transaction_id;
  superblock.state_flags = state_flags;
  unsigned char* buffer = transaction_scratch(transaction);
  ZiStatus status = ZiFsEncodeSuperblock(&superblock, buffer, ZI_FS_BLOCK_SIZE);
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_block_write(&transaction->volume->device,
                          superblock.backup_superblock,
                          1,
                          buffer,
                          ZI_FS_BLOCK_SIZE);
  if (ZiSucceeded(status)) {
    status = zi_block_barrier(&transaction->volume->device);
  }
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_block_write(&transaction->volume->device, 0, 1, buffer, ZI_FS_BLOCK_SIZE);
  if (ZiSucceeded(status)) {
    status = zi_block_barrier(&transaction->volume->device);
  }
  return status;
}

static uint32_t finalise_transaction_checksum(uint32_t checksum) {
  return checksum == 0 ? UINT32_MAX : checksum;
}
