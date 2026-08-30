// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/block.h"
#include "zi/byte_order.h"
#include "zi/crc32c.h"
#include "zi/zifs.h"
#include "zi/zifs_journal.h"
#include "zizium/status.h"
#include "zizium/types.h"

enum {
  ZIFS_JOURNAL_HEADER_MAGIC_OFFSET = 0,
  ZIFS_JOURNAL_HEADER_VERSION_OFFSET = 4,
  ZIFS_JOURNAL_HEADER_SIZE_OFFSET = 6,
  ZIFS_JOURNAL_HEADER_SEQUENCE_OFFSET = 8,
  ZIFS_JOURNAL_HEADER_VOLUME_GENERATION_OFFSET = 16,
  ZIFS_JOURNAL_HEADER_RECORD_BLOCKS_OFFSET = 24,
  ZIFS_JOURNAL_HEADER_FLAGS_OFFSET = 28,
  ZIFS_JOURNAL_HEADER_RECORD_CAPACITY_OFFSET = 32,
  ZIFS_JOURNAL_HEADER_HEAD_RECORD_OFFSET = 40,
  ZIFS_JOURNAL_HEADER_TAIL_RECORD_OFFSET = 48,
  ZIFS_JOURNAL_HEADER_NEXT_SEQUENCE_OFFSET = 56,
  ZIFS_JOURNAL_HEADER_NEXT_TRANSACTION_OFFSET = 64,
  ZIFS_JOURNAL_HEADER_LAST_COMMITTED_OFFSET = 72,
  ZIFS_JOURNAL_HEADER_LAST_CHECKPOINT_OFFSET = 80,
  ZIFS_JOURNAL_HEADER_CHECKSUM_OFFSET = 124,
  ZIFS_JOURNAL_RECORD_MAGIC_OFFSET = 0,
  ZIFS_JOURNAL_RECORD_VERSION_OFFSET = 4,
  ZIFS_JOURNAL_RECORD_HEADER_SIZE_OFFSET = 6,
  ZIFS_JOURNAL_RECORD_TYPE_OFFSET = 8,
  ZIFS_JOURNAL_RECORD_FLAGS_OFFSET = 10,
  ZIFS_JOURNAL_RECORD_PAYLOAD_SIZE_OFFSET = 12,
  ZIFS_JOURNAL_RECORD_TRANSACTION_OFFSET = 16,
  ZIFS_JOURNAL_RECORD_SEQUENCE_OFFSET = 24,
  ZIFS_JOURNAL_RECORD_TARGET_BLOCK_OFFSET = 32,
  ZIFS_JOURNAL_RECORD_SOURCE_GENERATION_OFFSET = 40,
  ZIFS_JOURNAL_RECORD_TARGET_GENERATION_OFFSET = 48,
  ZIFS_JOURNAL_RECORD_IMAGE_COUNT_OFFSET = 56,
  ZIFS_JOURNAL_RECORD_TRANSACTION_CHECKSUM_OFFSET = 60,
  ZIFS_JOURNAL_RECORD_PAYLOAD_CHECKSUM_OFFSET = 64,
  ZIFS_JOURNAL_RECORD_CHECKSUM_OFFSET = 124,
};

static const unsigned char k_journal_header_magic[4] = {'Z', 'I', 'J', 'R'};
static const unsigned char k_journal_record_magic[4] = {'Z', 'I', 'J', 'E'};

static bool journal_header_is_valid(const ZiFsJournalHeader* header);
static bool journal_record_is_valid(const ZiFsJournalRecord* record);
static bool journal_ring_space(uint64_t record_capacity,
                               uint64_t head_record,
                               uint64_t tail_record,
                               uint64_t* out_occupied_records,
                               uint64_t* out_available_records);

ZiStatus ZiFsAllocationBitmapBlockCount(uint64_t total_blocks, uint64_t* out_bitmap_blocks) {
  if (total_blocks == 0 || out_bitmap_blocks == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const uint64_t bits_per_block = (uint64_t)ZI_FS_BLOCK_SIZE * 8u;
  *out_bitmap_blocks = 1u + ((total_blocks - 1u) / bits_per_block);
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsAllocationBitQuery(const void* bitmap,
                                size_t bitmap_size,
                                uint64_t block_number,
                                bool* out_is_allocated) {
  if (bitmap == NULL || bitmap_size == 0 || out_is_allocated == NULL ||
      block_number / 8u >= bitmap_size) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const unsigned char* bytes = bitmap;
  unsigned char mask = (unsigned char)(1u << (block_number % 8u));
  *out_is_allocated = (bool)(((bytes[block_number / 8u] & mask) != 0) != 0);
  return ZI_STATUS_SUCCESS;
}

ZiStatus
ZiFsAllocationBitSet(void* bitmap, size_t bitmap_size, uint64_t block_number, bool is_allocated) {
  if (bitmap == NULL || bitmap_size == 0 || block_number / 8u >= bitmap_size) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char* bytes = bitmap;
  unsigned char mask = (unsigned char)(1u << (block_number % 8u));
  if (is_allocated) {
    bytes[block_number / 8u] |= mask;
  } else {
    bytes[block_number / 8u] &= (unsigned char)~mask;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsJournalRecordCapacity(uint64_t journal_blocks, uint64_t* out_record_capacity) {
  if (out_record_capacity == NULL || journal_blocks <= ZI_FS_JOURNAL_HEADER_COPIES ||
      (journal_blocks - ZI_FS_JOURNAL_HEADER_COPIES) % ZI_FS_JOURNAL_RECORD_BLOCKS != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t capacity = (journal_blocks - ZI_FS_JOURNAL_HEADER_COPIES) / ZI_FS_JOURNAL_RECORD_BLOCKS;
  if (capacity == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_record_capacity = capacity;
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsJournalRecordBlock(uint64_t journal_start,
                                uint64_t record_capacity,
                                uint64_t record_index,
                                uint64_t* out_block_number) {
  if (record_capacity == 0 || record_index >= record_capacity || out_block_number == NULL ||
      record_index > (UINT64_MAX - ZI_FS_JOURNAL_HEADER_COPIES) / ZI_FS_JOURNAL_RECORD_BLOCKS) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t relative = ZI_FS_JOURNAL_HEADER_COPIES + (record_index * ZI_FS_JOURNAL_RECORD_BLOCKS);
  if (journal_start > UINT64_MAX - relative) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  *out_block_number = journal_start + relative;
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsJournalAdvanceRecord(uint64_t record_capacity,
                                  uint64_t record_index,
                                  uint64_t record_count,
                                  uint64_t* out_record_index) {
  if (record_capacity == 0 || record_index >= record_capacity || out_record_index == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t remaining = record_count % record_capacity;
  if (remaining >= record_capacity - record_index) {
    *out_record_index = remaining - (record_capacity - record_index);
  } else {
    *out_record_index = record_index + remaining;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsJournalQuerySpace(const ZiFsJournalHeader* header,
                               uint64_t* out_occupied_records,
                               uint64_t* out_available_records) {
  if (!journal_header_is_valid(header) || out_occupied_records == NULL ||
      out_available_records == NULL ||
      !journal_ring_space(header->record_capacity,
                          header->head_record,
                          header->tail_record,
                          out_occupied_records,
                          out_available_records)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus
ZiFsEncodeJournalHeader(const ZiFsJournalHeader* header, void* output, size_t output_size) {
  if (!journal_header_is_valid(header) || output == NULL || output_size < ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char* bytes = output;
  zi_memory_zero(bytes, ZI_FS_BLOCK_SIZE);
  zi_memory_copy(bytes, k_journal_header_magic, sizeof k_journal_header_magic);
  zi_write_u16_le(bytes + ZIFS_JOURNAL_HEADER_VERSION_OFFSET, ZI_FS_JOURNAL_VERSION);
  zi_write_u16_le(bytes + ZIFS_JOURNAL_HEADER_SIZE_OFFSET, ZI_FS_JOURNAL_HEADER_SIZE);
  zi_write_u64_le(bytes + ZIFS_JOURNAL_HEADER_SEQUENCE_OFFSET, header->header_sequence);
  zi_write_u64_le(bytes + ZIFS_JOURNAL_HEADER_VOLUME_GENERATION_OFFSET, header->volume_generation);
  zi_write_u32_le(bytes + ZIFS_JOURNAL_HEADER_RECORD_BLOCKS_OFFSET,
                  (uint32_t)ZI_FS_JOURNAL_RECORD_BLOCKS);
  zi_write_u32_le(bytes + ZIFS_JOURNAL_HEADER_FLAGS_OFFSET, header->flags);
  zi_write_u64_le(bytes + ZIFS_JOURNAL_HEADER_RECORD_CAPACITY_OFFSET, header->record_capacity);
  zi_write_u64_le(bytes + ZIFS_JOURNAL_HEADER_HEAD_RECORD_OFFSET, header->head_record);
  zi_write_u64_le(bytes + ZIFS_JOURNAL_HEADER_TAIL_RECORD_OFFSET, header->tail_record);
  zi_write_u64_le(bytes + ZIFS_JOURNAL_HEADER_NEXT_SEQUENCE_OFFSET, header->next_sequence);
  zi_write_u64_le(bytes + ZIFS_JOURNAL_HEADER_NEXT_TRANSACTION_OFFSET, header->next_transaction_id);
  zi_write_u64_le(bytes + ZIFS_JOURNAL_HEADER_LAST_COMMITTED_OFFSET,
                  header->last_committed_transaction);
  zi_write_u64_le(bytes + ZIFS_JOURNAL_HEADER_LAST_CHECKPOINT_OFFSET,
                  header->last_checkpoint_transaction);
  zi_write_u32_le(bytes + ZIFS_JOURNAL_HEADER_CHECKSUM_OFFSET,
                  zi_crc32c(0, bytes, ZIFS_JOURNAL_HEADER_CHECKSUM_OFFSET));
  return ZI_STATUS_SUCCESS;
}

ZiStatus
ZiFsDecodeJournalHeader(const void* data, size_t data_size, ZiFsJournalHeader* out_header) {
  if (data == NULL || data_size < ZI_FS_BLOCK_SIZE || out_header == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const unsigned char* bytes = data;
  if (zi_memory_compare(bytes, k_journal_header_magic, sizeof k_journal_header_magic) != 0 ||
      zi_read_u16_le(bytes + ZIFS_JOURNAL_HEADER_VERSION_OFFSET) != ZI_FS_JOURNAL_VERSION ||
      zi_read_u16_le(bytes + ZIFS_JOURNAL_HEADER_SIZE_OFFSET) != ZI_FS_JOURNAL_HEADER_SIZE ||
      zi_read_u32_le(bytes + ZIFS_JOURNAL_HEADER_RECORD_BLOCKS_OFFSET) !=
          ZI_FS_JOURNAL_RECORD_BLOCKS) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  if (zi_read_u32_le(bytes + ZIFS_JOURNAL_HEADER_CHECKSUM_OFFSET) !=
      zi_crc32c(0, bytes, ZIFS_JOURNAL_HEADER_CHECKSUM_OFFSET)) {
    return ZI_STATUS_CHECKSUM_MISMATCH;
  }
  ZiFsJournalHeader header = {0};
  header.header_sequence = zi_read_u64_le(bytes + ZIFS_JOURNAL_HEADER_SEQUENCE_OFFSET);
  header.volume_generation = zi_read_u64_le(bytes + ZIFS_JOURNAL_HEADER_VOLUME_GENERATION_OFFSET);
  header.flags = zi_read_u32_le(bytes + ZIFS_JOURNAL_HEADER_FLAGS_OFFSET);
  header.record_capacity = zi_read_u64_le(bytes + ZIFS_JOURNAL_HEADER_RECORD_CAPACITY_OFFSET);
  header.head_record = zi_read_u64_le(bytes + ZIFS_JOURNAL_HEADER_HEAD_RECORD_OFFSET);
  header.tail_record = zi_read_u64_le(bytes + ZIFS_JOURNAL_HEADER_TAIL_RECORD_OFFSET);
  header.next_sequence = zi_read_u64_le(bytes + ZIFS_JOURNAL_HEADER_NEXT_SEQUENCE_OFFSET);
  header.next_transaction_id = zi_read_u64_le(bytes + ZIFS_JOURNAL_HEADER_NEXT_TRANSACTION_OFFSET);
  header.last_committed_transaction =
      zi_read_u64_le(bytes + ZIFS_JOURNAL_HEADER_LAST_COMMITTED_OFFSET);
  header.last_checkpoint_transaction =
      zi_read_u64_le(bytes + ZIFS_JOURNAL_HEADER_LAST_CHECKPOINT_OFFSET);
  if (!journal_header_is_valid(&header)) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  *out_header = header;
  return ZI_STATUS_SUCCESS;
}

ZiStatus
ZiFsEncodeJournalRecord(const ZiFsJournalRecord* record, void* output, size_t output_size) {
  if (!journal_record_is_valid(record) || output == NULL ||
      output_size < ZI_FS_JOURNAL_RECORD_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char* bytes = output;
  zi_memory_zero(bytes, ZI_FS_JOURNAL_RECORD_SIZE);
  zi_memory_copy(bytes, k_journal_record_magic, sizeof k_journal_record_magic);
  zi_write_u16_le(bytes + ZIFS_JOURNAL_RECORD_VERSION_OFFSET, ZI_FS_JOURNAL_VERSION);
  zi_write_u16_le(bytes + ZIFS_JOURNAL_RECORD_HEADER_SIZE_OFFSET, ZI_FS_JOURNAL_RECORD_HEADER_SIZE);
  zi_write_u16_le(bytes + ZIFS_JOURNAL_RECORD_TYPE_OFFSET, record->record_type);
  zi_write_u16_le(bytes + ZIFS_JOURNAL_RECORD_FLAGS_OFFSET, record->flags);
  zi_write_u32_le(bytes + ZIFS_JOURNAL_RECORD_PAYLOAD_SIZE_OFFSET, (uint32_t)record->payload.size);
  zi_write_u64_le(bytes + ZIFS_JOURNAL_RECORD_TRANSACTION_OFFSET, record->transaction_id);
  zi_write_u64_le(bytes + ZIFS_JOURNAL_RECORD_SEQUENCE_OFFSET, record->sequence);
  zi_write_u64_le(bytes + ZIFS_JOURNAL_RECORD_TARGET_BLOCK_OFFSET, record->target_block);
  zi_write_u64_le(bytes + ZIFS_JOURNAL_RECORD_SOURCE_GENERATION_OFFSET, record->source_generation);
  zi_write_u64_le(bytes + ZIFS_JOURNAL_RECORD_TARGET_GENERATION_OFFSET, record->target_generation);
  zi_write_u32_le(bytes + ZIFS_JOURNAL_RECORD_IMAGE_COUNT_OFFSET, record->image_count);
  zi_write_u32_le(bytes + ZIFS_JOURNAL_RECORD_TRANSACTION_CHECKSUM_OFFSET,
                  record->transaction_checksum);
  uint32_t payload_checksum = zi_crc32c(0, record->payload.data, record->payload.size);
  zi_write_u32_le(bytes + ZIFS_JOURNAL_RECORD_PAYLOAD_CHECKSUM_OFFSET, payload_checksum);
  zi_memory_copy(bytes + ZI_FS_JOURNAL_RECORD_HEADER_SIZE,
                 record->payload.data,
                 record->payload.size);
  uint32_t record_checksum = zi_crc32c(0, bytes, ZIFS_JOURNAL_RECORD_CHECKSUM_OFFSET);
  record_checksum =
      zi_crc32c(record_checksum, bytes + ZI_FS_JOURNAL_RECORD_HEADER_SIZE, record->payload.size);
  zi_write_u32_le(bytes + ZIFS_JOURNAL_RECORD_CHECKSUM_OFFSET, record_checksum);
  return ZI_STATUS_SUCCESS;
}

ZiStatus
ZiFsDecodeJournalRecord(const void* data, size_t data_size, ZiFsJournalRecord* out_record) {
  if (data == NULL || data_size < ZI_FS_JOURNAL_RECORD_SIZE || out_record == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const unsigned char* bytes = data;
  if (zi_memory_compare(bytes, k_journal_record_magic, sizeof k_journal_record_magic) != 0 ||
      zi_read_u16_le(bytes + ZIFS_JOURNAL_RECORD_VERSION_OFFSET) != ZI_FS_JOURNAL_VERSION ||
      zi_read_u16_le(bytes + ZIFS_JOURNAL_RECORD_HEADER_SIZE_OFFSET) !=
          ZI_FS_JOURNAL_RECORD_HEADER_SIZE) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  uint32_t payload_size = zi_read_u32_le(bytes + ZIFS_JOURNAL_RECORD_PAYLOAD_SIZE_OFFSET);
  if (payload_size > ZI_FS_JOURNAL_MAXIMUM_PAYLOAD_SIZE) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  uint32_t payload_checksum = zi_crc32c(0, bytes + ZI_FS_JOURNAL_RECORD_HEADER_SIZE, payload_size);
  if (payload_checksum != zi_read_u32_le(bytes + ZIFS_JOURNAL_RECORD_PAYLOAD_CHECKSUM_OFFSET)) {
    return ZI_STATUS_CHECKSUM_MISMATCH;
  }
  uint32_t record_checksum = zi_crc32c(0, bytes, ZIFS_JOURNAL_RECORD_CHECKSUM_OFFSET);
  record_checksum =
      zi_crc32c(record_checksum, bytes + ZI_FS_JOURNAL_RECORD_HEADER_SIZE, payload_size);
  if (record_checksum != zi_read_u32_le(bytes + ZIFS_JOURNAL_RECORD_CHECKSUM_OFFSET)) {
    return ZI_STATUS_CHECKSUM_MISMATCH;
  }
  ZiFsJournalRecord record = {0};
  record.record_type = zi_read_u16_le(bytes + ZIFS_JOURNAL_RECORD_TYPE_OFFSET);
  record.flags = zi_read_u16_le(bytes + ZIFS_JOURNAL_RECORD_FLAGS_OFFSET);
  record.transaction_id = zi_read_u64_le(bytes + ZIFS_JOURNAL_RECORD_TRANSACTION_OFFSET);
  record.sequence = zi_read_u64_le(bytes + ZIFS_JOURNAL_RECORD_SEQUENCE_OFFSET);
  record.target_block = zi_read_u64_le(bytes + ZIFS_JOURNAL_RECORD_TARGET_BLOCK_OFFSET);
  record.source_generation = zi_read_u64_le(bytes + ZIFS_JOURNAL_RECORD_SOURCE_GENERATION_OFFSET);
  record.target_generation = zi_read_u64_le(bytes + ZIFS_JOURNAL_RECORD_TARGET_GENERATION_OFFSET);
  record.image_count = zi_read_u32_le(bytes + ZIFS_JOURNAL_RECORD_IMAGE_COUNT_OFFSET);
  record.transaction_checksum =
      zi_read_u32_le(bytes + ZIFS_JOURNAL_RECORD_TRANSACTION_CHECKSUM_OFFSET);
  record.payload = (ZiConstBuffer){bytes + ZI_FS_JOURNAL_RECORD_HEADER_SIZE, payload_size};
  if (!journal_record_is_valid(&record)) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  *out_record = record;
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsJournalExtendTransactionChecksum(uint32_t checksum,
                                              const ZiFsJournalRecord* block_image,
                                              uint32_t* out_checksum) {
  if (block_image == NULL || out_checksum == NULL ||
      block_image->record_type != ZI_FS_JOURNAL_RECORD_BLOCK_IMAGE ||
      !journal_record_is_valid(block_image)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char descriptor[32] = {0};
  zi_write_u64_le(descriptor, block_image->transaction_id);
  zi_write_u64_le(descriptor + 8, block_image->sequence);
  zi_write_u64_le(descriptor + 16, block_image->target_block);
  zi_write_u32_le(descriptor + 24,
                  zi_crc32c(0, block_image->payload.data, block_image->payload.size));
  *out_checksum = zi_crc32c(checksum, descriptor, sizeof descriptor);
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsLoadJournalHeader(const ZiBlockDevice* device,
                               uint64_t journal_start,
                               void* block_buffer,
                               size_t block_buffer_size,
                               ZiFsJournalHeader* out_header,
                               uint32_t* out_copy_index) {
  if (device == NULL || device->read_blocks == NULL || block_buffer == NULL ||
      block_buffer_size < ZI_FS_BLOCK_SIZE || out_header == NULL || out_copy_index == NULL ||
      journal_start > device->block_count ||
      ZI_FS_JOURNAL_HEADER_COPIES > device->block_count - journal_start) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  bool found = false;
  ZiFsJournalHeader selected = {0};
  uint32_t selected_copy = 0;
  ZiStatus last_status = ZI_STATUS_CORRUPT_FILESYSTEM;
  for (uint32_t copy_index = 0; copy_index < ZI_FS_JOURNAL_HEADER_COPIES; ++copy_index) {
    ZiStatus status = device->read_blocks(device->context,
                                          journal_start + copy_index,
                                          1,
                                          block_buffer,
                                          block_buffer_size);
    if (ZiFailed(status)) {
      last_status = status;
      continue;
    }
    ZiFsJournalHeader candidate = {0};
    status = ZiFsDecodeJournalHeader(block_buffer, block_buffer_size, &candidate);
    if (ZiFailed(status)) {
      last_status = status;
      continue;
    }
    if (!found || candidate.header_sequence > selected.header_sequence) {
      found = true;
      selected = candidate;
      selected_copy = copy_index;
    }
  }
  if (!found) {
    return last_status;
  }
  *out_header = selected;
  *out_copy_index = selected_copy;
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsStoreJournalHeader(const ZiBlockDevice* device,
                                uint64_t journal_start,
                                uint32_t copy_index,
                                const ZiFsJournalHeader* header,
                                void* block_buffer,
                                size_t block_buffer_size) {
  if (device == NULL || copy_index >= ZI_FS_JOURNAL_HEADER_COPIES || header == NULL ||
      block_buffer == NULL || block_buffer_size < ZI_FS_BLOCK_SIZE ||
      journal_start > device->block_count ||
      ZI_FS_JOURNAL_HEADER_COPIES > device->block_count - journal_start) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = ZiFsEncodeJournalHeader(header, block_buffer, block_buffer_size);
  if (ZiFailed(status)) {
    return status;
  }
  return zi_block_write(device, journal_start + copy_index, 1, block_buffer, ZI_FS_BLOCK_SIZE);
}

static bool journal_header_is_valid(const ZiFsJournalHeader* header) {
  if (header == NULL || header->header_sequence == 0 || header->volume_generation == 0 ||
      header->record_capacity < ZI_FS_JOURNAL_MINIMUM_RECORD_CAPACITY ||
      header->head_record >= header->record_capacity ||
      header->tail_record >= header->record_capacity || header->next_sequence == 0 ||
      header->last_committed_transaction == UINT64_MAX ||
      header->next_transaction_id != header->last_committed_transaction + 1u ||
      header->last_checkpoint_transaction > header->last_committed_transaction ||
      header->flags != ZI_FS_JOURNAL_HEADER_FLAGS_NONE) {
    return false;
  }
  uint64_t occupied_records = 0;
  uint64_t available_records = 0;
  if (!journal_ring_space(header->record_capacity,
                          header->head_record,
                          header->tail_record,
                          &occupied_records,
                          &available_records)) {
    return false;
  }
  (void)available_records;
  if (header->last_checkpoint_transaction == header->last_committed_transaction) {
    return occupied_records == 0;
  }
  return (bool)(header->last_committed_transaction - header->last_checkpoint_transaction == 1u &&
                occupied_records >= 3u);
}

static bool journal_record_is_valid(const ZiFsJournalRecord* record) {
  if (record == NULL || record->transaction_id == 0 || record->sequence == 0 ||
      record->source_generation == 0 || record->source_generation == UINT64_MAX ||
      record->target_generation != record->source_generation + 1u ||
      record->flags != ZI_FS_JOURNAL_RECORD_FLAGS_NONE ||
      record->payload.size > ZI_FS_JOURNAL_MAXIMUM_PAYLOAD_SIZE ||
      (record->payload.data == NULL && record->payload.size != 0)) {
    return false;
  }
  if (record->record_type == ZI_FS_JOURNAL_RECORD_BLOCK_IMAGE) {
    return (bool)((record->target_block != ZI_FS_JOURNAL_TARGET_NONE &&
                   record->payload.size == ZI_FS_BLOCK_SIZE && record->image_count == 0 &&
                   record->transaction_checksum == 0) != 0);
  }
  if (record->target_block != ZI_FS_JOURNAL_TARGET_NONE || record->payload.size != 0 ||
      record->image_count == 0) {
    return false;
  }
  if (record->record_type == ZI_FS_JOURNAL_RECORD_BEGIN) {
    return record->transaction_checksum == 0;
  }
  if (record->record_type == ZI_FS_JOURNAL_RECORD_COMMIT ||
      record->record_type == ZI_FS_JOURNAL_RECORD_CHECKPOINT) {
    return record->transaction_checksum != 0;
  }
  return false;
}

static bool journal_ring_space(uint64_t record_capacity,
                               uint64_t head_record,
                               uint64_t tail_record,
                               uint64_t* out_occupied_records,
                               uint64_t* out_available_records) {
  if (record_capacity < ZI_FS_JOURNAL_MINIMUM_RECORD_CAPACITY || head_record >= record_capacity ||
      tail_record >= record_capacity || out_occupied_records == NULL ||
      out_available_records == NULL) {
    return false;
  }
  uint64_t occupied_records = 0;
  if (head_record >= tail_record) {
    occupied_records = head_record - tail_record;
  } else {
    occupied_records = record_capacity - (tail_record - head_record);
  }
  *out_occupied_records = occupied_records;
  *out_available_records = record_capacity - occupied_records - ZI_FS_JOURNAL_RESERVED_RECORDS;
  return true;
}
