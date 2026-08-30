// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/block.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_FS_JOURNAL_VERSION UINT16_C(1)
#define ZI_FS_JOURNAL_HEADER_SIZE 128u
#define ZI_FS_JOURNAL_HEADER_COPIES UINT64_C(2)
#define ZI_FS_JOURNAL_RECORD_HEADER_SIZE 128u
#define ZI_FS_JOURNAL_RECORD_BLOCKS UINT64_C(2)
#define ZI_FS_JOURNAL_RECORD_SIZE 8192u
#define ZI_FS_JOURNAL_MAXIMUM_PAYLOAD_SIZE 4096u
#define ZI_FS_JOURNAL_TARGET_NONE UINT64_MAX
#define ZI_FS_JOURNAL_MINIMUM_RECORD_CAPACITY UINT64_C(5)
#define ZI_FS_JOURNAL_RESERVED_RECORDS UINT64_C(1)
#define ZI_FS_JOURNAL_MAXIMUM_BLOCK_IMAGES 28u

#define ZI_FS_JOURNAL_HEADER_FLAGS_NONE UINT32_C(0)
#define ZI_FS_JOURNAL_RECORD_FLAGS_NONE UINT16_C(0)

enum ZiFsJournalRecordType {
  ZI_FS_JOURNAL_RECORD_BEGIN = 1,
  ZI_FS_JOURNAL_RECORD_BLOCK_IMAGE = 2,
  ZI_FS_JOURNAL_RECORD_COMMIT = 3,
  ZI_FS_JOURNAL_RECORD_CHECKPOINT = 4,
};

typedef struct ZiFsJournalHeader {
  uint64_t header_sequence;
  uint64_t volume_generation;
  uint64_t record_capacity;
  uint64_t head_record;
  uint64_t tail_record;
  uint64_t next_sequence;
  uint64_t next_transaction_id;
  uint64_t last_committed_transaction;
  uint64_t last_checkpoint_transaction;
  uint32_t flags;
} ZiFsJournalHeader;

typedef struct ZiFsJournalRecord {
  uint64_t transaction_id;
  uint64_t sequence;
  uint64_t target_block;
  uint64_t source_generation;
  uint64_t target_generation;
  uint32_t image_count;
  uint32_t transaction_checksum;
  uint16_t record_type;
  uint16_t flags;
  ZiConstBuffer payload;
} ZiFsJournalRecord;

ZiStatus ZiFsAllocationBitmapBlockCount(uint64_t total_blocks, uint64_t* out_bitmap_blocks);
ZiStatus ZiFsAllocationBitQuery(const void* bitmap,
                                size_t bitmap_size,
                                uint64_t block_number,
                                bool* out_is_allocated);
ZiStatus
ZiFsAllocationBitSet(void* bitmap, size_t bitmap_size, uint64_t block_number, bool is_allocated);
ZiStatus ZiFsJournalRecordCapacity(uint64_t journal_blocks, uint64_t* out_record_capacity);
ZiStatus ZiFsJournalRecordBlock(uint64_t journal_start,
                                uint64_t record_capacity,
                                uint64_t record_index,
                                uint64_t* out_block_number);
ZiStatus ZiFsJournalAdvanceRecord(uint64_t record_capacity,
                                  uint64_t record_index,
                                  uint64_t record_count,
                                  uint64_t* out_record_index);
ZiStatus ZiFsJournalQuerySpace(const ZiFsJournalHeader* header,
                               uint64_t* out_occupied_records,
                               uint64_t* out_available_records);
ZiStatus ZiFsEncodeJournalHeader(const ZiFsJournalHeader* header, void* output, size_t output_size);
ZiStatus ZiFsDecodeJournalHeader(const void* data, size_t data_size, ZiFsJournalHeader* out_header);
ZiStatus ZiFsEncodeJournalRecord(const ZiFsJournalRecord* record, void* output, size_t output_size);
ZiStatus ZiFsDecodeJournalRecord(const void* data, size_t data_size, ZiFsJournalRecord* out_record);
ZiStatus ZiFsJournalExtendTransactionChecksum(uint32_t checksum,
                                              const ZiFsJournalRecord* block_image,
                                              uint32_t* out_checksum);
ZiStatus ZiFsLoadJournalHeader(const ZiBlockDevice* device,
                               uint64_t journal_start,
                               void* block_buffer,
                               size_t block_buffer_size,
                               ZiFsJournalHeader* out_header,
                               uint32_t* out_copy_index);
ZiStatus ZiFsStoreJournalHeader(const ZiBlockDevice* device,
                                uint64_t journal_start,
                                uint32_t copy_index,
                                const ZiFsJournalHeader* header,
                                void* block_buffer,
                                size_t block_buffer_size);
