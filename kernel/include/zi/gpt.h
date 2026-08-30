// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/block.h"
#include "zizium/status.h"

#define ZI_GPT_PARTITION_NAME_UNITS 36u
#define ZI_GPT_MINIMUM_ENTRY_SIZE 128u
#define ZI_GPT_MAXIMUM_ENTRY_SIZE 4096u
#define ZI_GPT_MAXIMUM_ENTRY_COUNT 4096u

typedef struct ZiGuid {
  unsigned char bytes[16];
} ZiGuid;

typedef struct ZiGptPartition {
  ZiGuid type_guid;
  ZiGuid unique_guid;
  uint64_t first_lba;
  uint64_t last_lba;
  uint64_t attributes;
  uint16_t name[ZI_GPT_PARTITION_NAME_UNITS];
} ZiGptPartition;

typedef struct ZiGptTable {
  ZiGuid disk_guid;
  uint64_t current_lba;
  uint64_t backup_lba;
  uint64_t first_usable_lba;
  uint64_t last_usable_lba;
  ZiGptPartition* partitions;
  size_t partition_count;
  uint32_t mounted_from_backup;
} ZiGptTable;

extern const ZiGuid ZiGptZiFsTypeGuid;

ZiStatus zi_gpt_read(const ZiBlockDevice* device,
                     void* block_buffer,
                     size_t block_buffer_size,
                     ZiGptPartition* partitions,
                     size_t partition_capacity,
                     ZiGptTable* out_table);
ZiStatus zi_gpt_find_partition_by_type(const ZiGptTable* table,
                                       const ZiGuid* type_guid,
                                       const ZiGptPartition** out_partition);
bool zi_guid_equal(const ZiGuid* left, const ZiGuid* right);
