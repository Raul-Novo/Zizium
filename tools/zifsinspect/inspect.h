// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

#include "zi/block.h"
#include "zi/zifs.h"
#include "zi/zifs_journal.h"
#include "zizium/status.h"

#define ZIFS_INSPECT_REPORT_VERSION UINT32_C(1)
#define ZIFS_INSPECT_MAXIMUM_RECORD_SLOTS UINT64_C(65536)
#define ZIFS_INSPECT_MAXIMUM_VOLUME_BLOCKS UINT64_C(16777216)

typedef struct ZiFsInspectReport {
  uint32_t struct_size;
  uint32_t version;
  ZiStatus primary_superblock_status;
  ZiStatus backup_superblock_status;
  ZiStatus mount_status;
  ZiStatus journal_status;
  ZiStatus security_status;
  ZiStatus namespace_status;
  ZiStatus allocation_status;
  ZiStatus overall_status;
  ZiFsSuperblock superblock;
  ZiFsJournalHeader journal;
  uint32_t selected_superblock_copy;
  uint32_t selected_journal_copy;
  uint32_t needs_recovery;
  uint32_t reserved;
  uint64_t occupied_journal_records;
  uint64_t journal_begin_records;
  uint64_t journal_block_images;
  uint64_t journal_commit_records;
  uint64_t journal_checkpoint_records;
  uint64_t security_descriptor_count;
  uint64_t security_ace_count;
  uint64_t record_slot_count;
  uint64_t live_file_records;
  uint64_t regular_file_records;
  uint64_t directory_records;
  uint64_t other_file_records;
  uint64_t directory_entries;
  uint64_t allocated_blocks;
  uint64_t free_blocks;
  uint64_t unreferenced_allocated_blocks;
} ZiFsInspectReport;

ZiStatus zifs_inspect_volume(const ZiBlockDevice* device, ZiFsInspectReport* out_report);
