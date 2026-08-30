// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/zifs.h"
#include "zi/zifs_journal.h"
#include "zizium/status.h"

#define ZI_FS_RECOVERY_REPORT_VERSION 1u
#define ZI_FS_RECOVERY_WORKSPACE_SIZE ZI_FS_JOURNAL_RECORD_SIZE
#define ZI_FS_RECOVERY_MAXIMUM_IMAGES ZI_FS_JOURNAL_MAXIMUM_BLOCK_IMAGES

enum ZiFsRecoveryAction {
  ZI_FS_RECOVERY_ACTION_NONE = 0,
  ZI_FS_RECOVERY_ACTION_REPAIRED_REDUNDANCY = 1,
  ZI_FS_RECOVERY_ACTION_ROLLED_BACK = 2,
  ZI_FS_RECOVERY_ACTION_REPLAYED = 3,
};

typedef struct ZiFsRecoveryReport {
  uint32_t struct_size;
  uint32_t version;
  uint32_t action;
  uint32_t image_count;
  uint64_t transaction_id;
  uint64_t source_generation;
  uint64_t target_generation;
} ZiFsRecoveryReport;

ZiStatus ZiFsRecoverVolume(ZiFsVolume* volume,
                           void* workspace,
                           size_t workspace_size,
                           ZiFsRecoveryReport* out_report);
