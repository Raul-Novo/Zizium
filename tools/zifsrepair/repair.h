// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "zi/block.h"
#include "zi/zifs.h"
#include "zizium/status.h"

#define ZIFS_REPAIR_PLAN_VERSION UINT32_C(1)
#define ZIFS_REPAIR_APPLY_REPORT_VERSION UINT32_C(1)
#define ZIFS_REPAIR_MAXIMUM_ACTIONS 4u

#define ZIFS_REPAIR_PLAN_NONE UINT32_C(0)
#define ZIFS_REPAIR_PLAN_SUPERBLOCK_REDUNDANCY (UINT32_C(1) << 0)
#define ZIFS_REPAIR_PLAN_JOURNAL_REDUNDANCY (UINT32_C(1) << 1)
#define ZIFS_REPAIR_PLAN_UNCLEAN_MOUNT (UINT32_C(1) << 2)

enum ZiFsRepairActionKind {
  ZIFS_REPAIR_ACTION_JOURNAL_HEADER = 1,
  ZIFS_REPAIR_ACTION_SUPERBLOCK = 2,
};

typedef struct ZiFsRepairAction {
  uint64_t block_number;
  uint32_t kind;
  uint32_t copy_index;
  unsigned char expected_block[ZI_FS_BLOCK_SIZE];
  unsigned char replacement_block[ZI_FS_BLOCK_SIZE];
} ZiFsRepairAction;

typedef struct ZiFsRepairPlan {
  uint32_t struct_size;
  uint32_t version;
  uint32_t flags;
  uint32_t action_count;
  unsigned char volume_uuid[16];
  uint64_t total_blocks;
  uint64_t generation;
  uint64_t last_committed_transaction;
  uint32_t selected_superblock_copy;
  uint32_t selected_journal_copy;
  ZiFsRepairAction actions[ZIFS_REPAIR_MAXIMUM_ACTIONS];
} ZiFsRepairPlan;

typedef struct ZiFsRepairApplyReport {
  uint32_t struct_size;
  uint32_t version;
  uint32_t applied_actions;
  uint32_t already_present_actions;
} ZiFsRepairApplyReport;

ZiStatus zifs_repair_plan(const ZiBlockDevice* device, ZiFsRepairPlan* out_plan);
ZiStatus zifs_repair_apply(const ZiBlockDevice* device,
                           const ZiFsRepairPlan* plan,
                           ZiFsRepairApplyReport* out_report);
bool zifs_repair_plans_equal(const ZiFsRepairPlan* left, const ZiFsRepairPlan* right);
