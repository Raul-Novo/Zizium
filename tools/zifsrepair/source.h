// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

#include "zi/block.h"
#include "zizium/status.h"

enum ZiFsRepairSourceMode {
  ZIFS_REPAIR_SOURCE_AUTO = 0,
  ZIFS_REPAIR_SOURCE_RAW = 1,
  ZIFS_REPAIR_SOURCE_GPT = 2,
};

typedef struct ZiFsRepairFileContext {
  FILE* file;
  uint64_t file_size;
  uint32_t block_size;
} ZiFsRepairFileContext;

typedef struct ZiFsRepairSource {
  FILE* file;
  ZiFsRepairFileContext file_context;
  ZiBlockDevice file_device;
  ZiPartitionBlockContext partition_context;
  ZiBlockDevice volume_device;
  const char* container_name;
  uint64_t partition_first_lba;
  uint64_t partition_lba_count;
  uint32_t gpt_from_backup;
  bool is_writable;
} ZiFsRepairSource;

ZiStatus zifs_repair_source_open(const wchar_t* path,
                                 enum ZiFsRepairSourceMode requested_mode,
                                 bool writable,
                                 ZiFsRepairSource* out_source);
ZiStatus zifs_repair_source_close(ZiFsRepairSource* source);
