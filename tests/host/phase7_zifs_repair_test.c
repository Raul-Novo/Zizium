// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "../../tools/zifsinspect/inspect.h"
#include "../../tools/zifsrepair/repair.h"
#include "phase7_tests.h"
#include "zi/block.h"
#include "zi/byte_order.h"
#include "zi/security.h"
#include "zi/zifs.h"
#include "zi/zifs_journal.h"
#include "zi/zifs_security.h"
#include "zizium/status.h"

#define REPAIR_VOLUME_BLOCKS 128u
#define REPAIR_RECORD_TABLE_START 1u
#define REPAIR_BITMAP_BLOCK 3u
#define REPAIR_JOURNAL_START 4u
#define REPAIR_JOURNAL_BLOCKS 66u
#define REPAIR_SECURITY_BLOCK 70u
#define REPAIR_DIRECTORY_START 71u
#define REPAIR_DIRECTORY_BLOCKS 4u
#define REPAIR_BACKUP_BLOCK (REPAIR_VOLUME_BLOCKS - 1u)

typedef struct RepairMemoryDevice {
  unsigned char* bytes;
  size_t size;
  size_t operation_count;
  size_t fail_operation;
  size_t write_count;
  size_t flush_count;
} RepairMemoryDevice;

static unsigned char s_repair_image[REPAIR_VOLUME_BLOCKS][ZI_FS_BLOCK_SIZE];
static unsigned char s_repair_snapshot[REPAIR_VOLUME_BLOCKS][ZI_FS_BLOCK_SIZE];
static RepairMemoryDevice s_repair_memory;
static size_t s_repair_assertions;

static bool repair_assert(bool condition, const char* expression, int line);
static bool initialise_clean_image(void);
static bool initialise_security_table(void);
static void initialise_device(ZiBlockDevice* out_device, bool writable);
static ZiStatus repair_memory_read(void* context,
                                   uint64_t first_block,
                                   uint32_t block_count,
                                   void* output,
                                   size_t output_size);
static ZiStatus repair_memory_write(void* context,
                                    uint64_t first_block,
                                    uint32_t block_count,
                                    const void* input,
                                    size_t input_size);
static ZiStatus repair_memory_flush(void* context);
static bool set_superblock_state(uint32_t state_flags);
static bool
set_journal_header(uint32_t copy_index, uint64_t header_sequence, uint64_t next_sequence);
static bool plan_is_clean(const ZiBlockDevice* device);
static bool inspect_is_clean(const ZiBlockDevice* device);
static bool test_clean_fixed_point(void);
static bool test_repairable_redundancy(void);
static bool test_unclean_mount_and_stale_header(void);
static bool test_fail_closed_cases(void);
static bool test_review_plan_and_power_boundaries(void);
static bool initialise_combined_repair_case(ZiBlockDevice* out_device);

#define REPAIR_ASSERT(expression)                                                                  \
  do {                                                                                             \
    if (!repair_assert((expression), #expression, __LINE__)) {                                     \
      return false;                                                                                \
    }                                                                                              \
  } while (false)

bool phase7_zifs_repair_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  s_repair_assertions = 0;
  bool result = test_clean_fixed_point();
  if (result) {
    result = test_repairable_redundancy();
  }
  if (result) {
    result = test_unclean_mount_and_stale_header();
  }
  if (result) {
    result = test_fail_closed_cases();
  }
  if (result) {
    result = test_review_plan_and_power_boundaries();
  }
  *out_assertion_count = s_repair_assertions;
  return result;
}

static bool repair_assert(bool condition, const char* expression, int line) {
  ++s_repair_assertions;
  if (!condition) {
    (void)fprintf_s(stderr, "ZiFS repair assertion failed at line %d: %s\n", line, expression);
    return false;
  }
  return true;
}

static bool initialise_clean_image(void) {
  zi_memory_zero(s_repair_image, sizeof s_repair_image);
  ZiFsSuperblock superblock = {0};
  superblock.format_major = ZI_FS_FORMAT_MAJOR;
  superblock.format_minor = ZI_FS_FORMAT_MINOR;
  superblock.block_shift = ZI_FS_BLOCK_SHIFT;
  superblock.checksum_type = 1;
  superblock.incompatible_features = ZI_FS_FEATURE_INCOMPAT_JOURNAL_V1 |
                                     ZI_FS_FEATURE_INCOMPAT_SECURITY_V1 |
                                     ZI_FS_FEATURE_INCOMPAT_CLEAN_UNMOUNT_V1;
  for (size_t index = 0; index < sizeof superblock.volume_uuid; ++index) {
    superblock.volume_uuid[index] = (unsigned char)(UINT8_C(0x21) + index);
  }
  superblock.generation = 1;
  superblock.total_blocks = REPAIR_VOLUME_BLOCKS;
  superblock.root_record_index = 0;
  superblock.record_table_start = REPAIR_RECORD_TABLE_START;
  superblock.record_table_blocks = 2;
  superblock.directory_table_start = REPAIR_DIRECTORY_START;
  superblock.directory_table_blocks = REPAIR_DIRECTORY_BLOCKS;
  superblock.allocation_bitmap_start = REPAIR_BITMAP_BLOCK;
  superblock.allocation_bitmap_blocks = 1;
  superblock.journal_start = REPAIR_JOURNAL_START;
  superblock.journal_blocks = REPAIR_JOURNAL_BLOCKS;
  superblock.security_table_start = REPAIR_SECURITY_BLOCK;
  superblock.security_table_blocks = 1;
  superblock.backup_superblock = REPAIR_BACKUP_BLOCK;
  superblock.volume_name_size = sizeof "Repair Test" - 1u;
  zi_memory_copy(superblock.volume_name, "Repair Test", superblock.volume_name_size);
  if (ZiFailed(ZiFsEncodeSuperblock(&superblock, s_repair_image[0], ZI_FS_BLOCK_SIZE))) {
    return false;
  }
  zi_memory_copy(s_repair_image[REPAIR_BACKUP_BLOCK], s_repair_image[0], ZI_FS_BLOCK_SIZE);

  ZiFsFileRecord root = {0};
  root.file_id = 1;
  root.parent_file_id = 1;
  root.file_type = ZI_FS_FILE_TYPE_DIRECTORY;
  root.security_id = 1;
  root.directory_block = REPAIR_DIRECTORY_START;
  if (ZiFailed(ZiFsEncodeFileRecord(&root,
                                    s_repair_image[REPAIR_RECORD_TABLE_START],
                                    ZI_FS_FILE_RECORD_SIZE)) ||
      ZiFailed(ZiFsInitialiseDirectoryBlock(s_repair_image[REPAIR_DIRECTORY_START],
                                            ZI_FS_BLOCK_SIZE,
                                            root.file_id,
                                            superblock.generation)) ||
      !initialise_security_table()) {
    return false;
  }

  for (uint64_t block = 0; block < REPAIR_DIRECTORY_START + REPAIR_DIRECTORY_BLOCKS; ++block) {
    if (ZiFailed(ZiFsAllocationBitSet(s_repair_image[REPAIR_BITMAP_BLOCK],
                                      ZI_FS_BLOCK_SIZE,
                                      block,
                                      true))) {
      return false;
    }
  }
  if (ZiFailed(ZiFsAllocationBitSet(s_repair_image[REPAIR_BITMAP_BLOCK],
                                    ZI_FS_BLOCK_SIZE,
                                    REPAIR_BACKUP_BLOCK,
                                    true))) {
    return false;
  }

  ZiFsJournalHeader journal = {0};
  journal.volume_generation = superblock.generation;
  journal.record_capacity = 32;
  journal.next_sequence = 1;
  journal.next_transaction_id = 1;
  for (uint32_t copy = 0; copy < ZI_FS_JOURNAL_HEADER_COPIES; ++copy) {
    journal.header_sequence = copy + 1u;
    if (ZiFailed(ZiFsEncodeJournalHeader(&journal,
                                         s_repair_image[REPAIR_JOURNAL_START + copy],
                                         ZI_FS_BLOCK_SIZE))) {
      return false;
    }
  }
  return true;
}

static bool initialise_security_table(void) {
  const ZiSecurityId owner = {ZI_SECURITY_AUTHORITY_USER, 21};
  const ZiSecurityId group = {ZI_SECURITY_AUTHORITY_GROUP, 7};
  const ZiAce entries[] = {{ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_FULL_CONTROL, owner}};
  const ZiAcl dacl = {sizeof(ZiAcl), ZI_ACL_VERSION, entries, 1};
  const ZiSecurityDescriptor descriptor = {
      sizeof(ZiSecurityDescriptor),
      ZI_SECURITY_DESCRIPTOR_VERSION,
      owner,
      group,
      &dacl,
      ZI_SECURITY_DESCRIPTOR_CONTROL_NONE,
  };
  return (
      bool)(ZiSucceeded(ZiFsInitialiseSecurityTable(s_repair_image[REPAIR_SECURITY_BLOCK],
                                                    ZI_FS_BLOCK_SIZE,
                                                    1)) &&
            ZiSucceeded(ZiFsAppendSecurityDescriptor(s_repair_image[REPAIR_SECURITY_BLOCK],
                                                     ZI_FS_BLOCK_SIZE,
                                                     1,
                                                     ZI_FS_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT,
                                                     &descriptor)));
}

static void initialise_device(ZiBlockDevice* out_device, bool writable) {
  s_repair_memory.bytes = &s_repair_image[0][0];
  s_repair_memory.size = sizeof s_repair_image;
  s_repair_memory.operation_count = 0;
  s_repair_memory.fail_operation = 0;
  s_repair_memory.write_count = 0;
  s_repair_memory.flush_count = 0;
  ZiBlockDevice device = {
      sizeof(ZiBlockDevice),
      ZI_BLOCK_DEVICE_VERSION,
      &s_repair_memory,
      ZI_FS_BLOCK_SIZE,
      REPAIR_VOLUME_BLOCKS,
      repair_memory_read,
      NULL,
      ZI_BLOCK_DEVICE_READ_ONLY,
      NULL,
  };
  if (writable) {
    device.flush = repair_memory_flush;
    device.flags = ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED;
    device.write_blocks = repair_memory_write;
  }
  *out_device = device;
}

static ZiStatus repair_memory_read(void* context,
                                   uint64_t first_block,
                                   uint32_t block_count,
                                   void* output,
                                   size_t output_size) {
  if (context == NULL || output == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  RepairMemoryDevice* memory = context;
  if (first_block > SIZE_MAX / ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  size_t offset = (size_t)first_block * ZI_FS_BLOCK_SIZE;
  size_t byte_count = (size_t)block_count * ZI_FS_BLOCK_SIZE;
  if (offset > memory->size || byte_count > memory->size - offset || output_size < byte_count) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  zi_memory_copy(output, memory->bytes + offset, byte_count);
  return ZI_STATUS_SUCCESS;
}

static ZiStatus repair_memory_write(void* context,
                                    uint64_t first_block,
                                    uint32_t block_count,
                                    const void* input,
                                    size_t input_size) {
  if (context == NULL || input == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  RepairMemoryDevice* memory = context;
  ++memory->operation_count;
  if (memory->fail_operation != 0 && memory->operation_count == memory->fail_operation) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  if (first_block > SIZE_MAX / ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  size_t offset = (size_t)first_block * ZI_FS_BLOCK_SIZE;
  size_t byte_count = (size_t)block_count * ZI_FS_BLOCK_SIZE;
  if (offset > memory->size || byte_count > memory->size - offset || input_size < byte_count) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  zi_memory_copy(memory->bytes + offset, input, byte_count);
  ++memory->write_count;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus repair_memory_flush(void* context) {
  if (context == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  RepairMemoryDevice* memory = context;
  ++memory->operation_count;
  if (memory->fail_operation != 0 && memory->operation_count == memory->fail_operation) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  ++memory->flush_count;
  return ZI_STATUS_SUCCESS;
}

static bool set_superblock_state(uint32_t state_flags) {
  const uint64_t blocks[] = {0, REPAIR_BACKUP_BLOCK};
  for (size_t index = 0; index < sizeof blocks / sizeof blocks[0]; ++index) {
    ZiFsSuperblock superblock = {0};
    if (ZiFailed(
            ZiFsDecodeSuperblock(s_repair_image[blocks[index]], ZI_FS_BLOCK_SIZE, &superblock))) {
      return false;
    }
    superblock.state_flags = state_flags;
    if (ZiFailed(
            ZiFsEncodeSuperblock(&superblock, s_repair_image[blocks[index]], ZI_FS_BLOCK_SIZE))) {
      return false;
    }
  }
  return true;
}

static bool
set_journal_header(uint32_t copy_index, uint64_t header_sequence, uint64_t next_sequence) {
  if (copy_index >= ZI_FS_JOURNAL_HEADER_COPIES) {
    return false;
  }
  ZiFsJournalHeader header = {0};
  if (ZiFailed(ZiFsDecodeJournalHeader(s_repair_image[REPAIR_JOURNAL_START + copy_index],
                                       ZI_FS_BLOCK_SIZE,
                                       &header))) {
    return false;
  }
  header.header_sequence = header_sequence;
  header.next_sequence = next_sequence;
  return ZiSucceeded(ZiFsEncodeJournalHeader(&header,
                                             s_repair_image[REPAIR_JOURNAL_START + copy_index],
                                             ZI_FS_BLOCK_SIZE));
}

static bool plan_is_clean(const ZiBlockDevice* device) {
  ZiFsRepairPlan plan = {0};
  return (bool)(ZiSucceeded(zifs_repair_plan(device, &plan)) && plan.action_count == 0 &&
                plan.flags == ZIFS_REPAIR_PLAN_NONE);
}

static bool inspect_is_clean(const ZiBlockDevice* device) {
  ZiFsInspectReport report = {0};
  ZiStatus status = zifs_inspect_volume(device, &report);
  bool clean = (bool)(status == ZI_STATUS_SUCCESS && report.overall_status == ZI_STATUS_SUCCESS &&
                      report.needs_recovery == 0 && report.unclean_mount == 0 &&
                      report.unreferenced_allocated_blocks == 0);
  if (!clean) {
    (void)fprintf_s(stderr,
                    "repair inspection: status=%d overall=%d recovery=%u unclean=%u leak=%llu\n",
                    status,
                    report.overall_status,
                    report.needs_recovery,
                    report.unclean_mount,
                    (unsigned long long)report.unreferenced_allocated_blocks);
  }
  return clean;
}

static bool test_clean_fixed_point(void) {
  REPAIR_ASSERT(initialise_clean_image());
  ZiBlockDevice device = {0};
  initialise_device(&device, false);
  zi_memory_copy(s_repair_snapshot, s_repair_image, sizeof s_repair_snapshot);
  ZiFsRepairPlan plan = {0};
  REPAIR_ASSERT(zifs_repair_plan(&device, &plan) == ZI_STATUS_SUCCESS);
  REPAIR_ASSERT(plan.struct_size == sizeof plan && plan.version == ZIFS_REPAIR_PLAN_VERSION &&
                plan.action_count == 0 && plan.flags == ZIFS_REPAIR_PLAN_NONE);
  REPAIR_ASSERT(zi_memory_compare(s_repair_snapshot, s_repair_image, sizeof s_repair_image) == 0 &&
                s_repair_memory.write_count == 0 && s_repair_memory.flush_count == 0);
  REPAIR_ASSERT(inspect_is_clean(&device));
  ZiFsRepairApplyReport apply_report = {0};
  REPAIR_ASSERT(zifs_repair_apply(&device, &plan, &apply_report) == ZI_STATUS_INVALID_ARGUMENT);

  initialise_device(&device, true);
  zi_memory_copy(s_repair_snapshot, s_repair_image, sizeof s_repair_snapshot);
  REPAIR_ASSERT(inspect_is_clean(&device) && s_repair_memory.write_count == 0 &&
                s_repair_memory.flush_count == 0 &&
                zi_memory_compare(s_repair_snapshot, s_repair_image, sizeof s_repair_image) == 0);
  return true;
}

// Each supported redundancy fault must produce one exact, reviewable block replacement.
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static bool test_repairable_redundancy(void) {
  ZiBlockDevice device = {0};
  ZiFsRepairPlan plan = {0};
  ZiFsRepairApplyReport apply_report = {0};

  REPAIR_ASSERT(initialise_clean_image());
  s_repair_image[0][0] ^= UINT8_C(0xff);
  initialise_device(&device, true);
  REPAIR_ASSERT(ZiSucceeded(zifs_repair_plan(&device, &plan)) && plan.action_count == 1 &&
                plan.flags == ZIFS_REPAIR_PLAN_SUPERBLOCK_REDUNDANCY &&
                plan.selected_superblock_copy == 1 && plan.actions[0].block_number == 0 &&
                plan.actions[0].copy_index == 0);
  REPAIR_ASSERT(ZiSucceeded(zifs_repair_apply(&device, &plan, &apply_report)) &&
                apply_report.applied_actions == 1 && s_repair_memory.write_count == 1 &&
                s_repair_memory.flush_count == 1 && plan_is_clean(&device));

  REPAIR_ASSERT(initialise_clean_image());
  s_repair_image[REPAIR_BACKUP_BLOCK][0] ^= UINT8_C(0xff);
  initialise_device(&device, true);
  REPAIR_ASSERT(ZiSucceeded(zifs_repair_plan(&device, &plan)) && plan.action_count == 1 &&
                plan.selected_superblock_copy == 0 &&
                plan.actions[0].block_number == REPAIR_BACKUP_BLOCK);
  REPAIR_ASSERT(ZiSucceeded(zifs_repair_apply(&device, &plan, &apply_report)));
  REPAIR_ASSERT(inspect_is_clean(&device));

  REPAIR_ASSERT(initialise_clean_image());
  s_repair_image[REPAIR_JOURNAL_START][0] ^= UINT8_C(0xff);
  initialise_device(&device, true);
  REPAIR_ASSERT(ZiSucceeded(zifs_repair_plan(&device, &plan)) && plan.action_count == 1 &&
                plan.flags == ZIFS_REPAIR_PLAN_JOURNAL_REDUNDANCY &&
                plan.selected_journal_copy == 1 &&
                plan.actions[0].kind == ZIFS_REPAIR_ACTION_JOURNAL_HEADER &&
                plan.actions[0].block_number == REPAIR_JOURNAL_START);
  REPAIR_ASSERT(ZiSucceeded(zifs_repair_apply(&device, &plan, &apply_report)) &&
                inspect_is_clean(&device) && plan_is_clean(&device));
  return true;
}

// Clean-up is permitted only for an empty checkpointed journal and an unambiguous survivor.
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static bool test_unclean_mount_and_stale_header(void) {
  ZiBlockDevice device = {0};
  ZiFsRepairPlan plan = {0};
  ZiFsRepairApplyReport apply_report = {0};

  REPAIR_ASSERT(initialise_clean_image() && set_superblock_state(ZI_FS_SUPERBLOCK_STATE_MOUNTED));
  initialise_device(&device, true);
  REPAIR_ASSERT(ZiSucceeded(zifs_repair_plan(&device, &plan)) && plan.action_count == 2 &&
                plan.flags == ZIFS_REPAIR_PLAN_UNCLEAN_MOUNT &&
                plan.actions[0].block_number == REPAIR_BACKUP_BLOCK &&
                plan.actions[1].block_number == 0);
  REPAIR_ASSERT(ZiSucceeded(zifs_repair_apply(&device, &plan, &apply_report)) &&
                apply_report.applied_actions == 2 && inspect_is_clean(&device));

  REPAIR_ASSERT(initialise_clean_image() && set_journal_header(0, 1, 2));
  initialise_device(&device, true);
  REPAIR_ASSERT(ZiSucceeded(zifs_repair_plan(&device, &plan)) && plan.action_count == 1 &&
                plan.flags == ZIFS_REPAIR_PLAN_JOURNAL_REDUNDANCY &&
                plan.actions[0].block_number == REPAIR_JOURNAL_START);
  ZiFsJournalHeader replacement = {0};
  REPAIR_ASSERT(ZiSucceeded(ZiFsDecodeJournalHeader(plan.actions[0].replacement_block,
                                                    ZI_FS_BLOCK_SIZE,
                                                    &replacement)) &&
                replacement.header_sequence == 3 && replacement.next_sequence == 1);
  REPAIR_ASSERT(ZiSucceeded(zifs_repair_apply(&device, &plan, &apply_report)) &&
                plan_is_clean(&device));
  return true;
}

// Unsupported ambiguity or metadata damage must never produce a write plan.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static bool test_fail_closed_cases(void) {
  ZiBlockDevice device = {0};
  ZiFsRepairPlan plan = {0};

  REPAIR_ASSERT(initialise_clean_image());
  s_repair_image[REPAIR_SECURITY_BLOCK][0] ^= UINT8_C(0xff);
  initialise_device(&device, true);
  REPAIR_ASSERT(ZiFailed(zifs_repair_plan(&device, &plan)) && s_repair_memory.write_count == 0);

  REPAIR_ASSERT(initialise_clean_image());
  REPAIR_ASSERT(ZiSucceeded(ZiFsAllocationBitSet(s_repair_image[REPAIR_BITMAP_BLOCK],
                                                 ZI_FS_BLOCK_SIZE,
                                                 REPAIR_DIRECTORY_START + REPAIR_DIRECTORY_BLOCKS,
                                                 true)));
  initialise_device(&device, true);
  REPAIR_ASSERT(ZiFailed(zifs_repair_plan(&device, &plan)) && s_repair_memory.write_count == 0);

  REPAIR_ASSERT(initialise_clean_image());
  s_repair_image[0][0] ^= UINT8_C(0xff);
  s_repair_image[REPAIR_BACKUP_BLOCK][0] ^= UINT8_C(0xff);
  initialise_device(&device, true);
  REPAIR_ASSERT(ZiFailed(zifs_repair_plan(&device, &plan)) && s_repair_memory.write_count == 0);

  REPAIR_ASSERT(initialise_clean_image());
  s_repair_image[REPAIR_JOURNAL_START][0] ^= UINT8_C(0xff);
  s_repair_image[REPAIR_JOURNAL_START + 1u][0] ^= UINT8_C(0xff);
  initialise_device(&device, true);
  REPAIR_ASSERT(ZiFailed(zifs_repair_plan(&device, &plan)) && s_repair_memory.write_count == 0);

  REPAIR_ASSERT(initialise_clean_image() &&
                set_superblock_state(ZI_FS_SUPERBLOCK_STATE_TRANSACTION_DIRTY |
                                     ZI_FS_SUPERBLOCK_STATE_MOUNTED));
  initialise_device(&device, true);
  REPAIR_ASSERT(ZiFailed(zifs_repair_plan(&device, &plan)) && s_repair_memory.write_count == 0);

  REPAIR_ASSERT(initialise_clean_image() && set_journal_header(0, 2, 2));
  initialise_device(&device, true);
  REPAIR_ASSERT(ZiFailed(zifs_repair_plan(&device, &plan)) && s_repair_memory.write_count == 0);

  REPAIR_ASSERT(initialise_clean_image());
  ZiFsSuperblock mismatched = {0};
  REPAIR_ASSERT(ZiSucceeded(
      ZiFsDecodeSuperblock(s_repair_image[REPAIR_BACKUP_BLOCK], ZI_FS_BLOCK_SIZE, &mismatched)));
  mismatched.volume_uuid[0] ^= UINT8_C(0xff);
  REPAIR_ASSERT(ZiSucceeded(
      ZiFsEncodeSuperblock(&mismatched, s_repair_image[REPAIR_BACKUP_BLOCK], ZI_FS_BLOCK_SIZE)));
  initialise_device(&device, true);
  REPAIR_ASSERT(ZiFailed(zifs_repair_plan(&device, &plan)) && s_repair_memory.write_count == 0);
  return true;
}

static bool initialise_combined_repair_case(ZiBlockDevice* out_device) {
  if (out_device == NULL || !initialise_clean_image() ||
      !set_superblock_state(ZI_FS_SUPERBLOCK_STATE_MOUNTED)) {
    return false;
  }
  s_repair_image[0][0] ^= UINT8_C(0xff);
  s_repair_image[REPAIR_JOURNAL_START][0] ^= UINT8_C(0xff);
  initialise_device(out_device, true);
  return true;
}

// Every write/barrier prefix must remain re-plannable, and a stale plan must not mutate media.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static bool test_review_plan_and_power_boundaries(void) {
  ZiBlockDevice device = {0};
  REPAIR_ASSERT(initialise_combined_repair_case(&device));
  ZiFsRepairPlan plan = {0};
  REPAIR_ASSERT(
      ZiSucceeded(zifs_repair_plan(&device, &plan)) && plan.action_count == 3 &&
      plan.flags == (ZIFS_REPAIR_PLAN_SUPERBLOCK_REDUNDANCY | ZIFS_REPAIR_PLAN_JOURNAL_REDUNDANCY |
                     ZIFS_REPAIR_PLAN_UNCLEAN_MOUNT) &&
      plan.actions[0].block_number == REPAIR_JOURNAL_START && plan.actions[1].block_number == 0 &&
      plan.actions[2].block_number == REPAIR_BACKUP_BLOCK);
  zi_memory_copy(s_repair_snapshot, s_repair_image, sizeof s_repair_snapshot);

  ZiFsRepairPlan tampered = plan;
  tampered.actions[0].expected_block[17] ^= UINT8_C(1);
  ZiFsRepairApplyReport apply_report = {0};
  REPAIR_ASSERT(zifs_repair_apply(&device, &tampered, &apply_report) == ZI_STATUS_INVALID_STATE &&
                s_repair_memory.operation_count == 0 &&
                zi_memory_compare(s_repair_snapshot, s_repair_image, sizeof s_repair_image) == 0);

  REPAIR_ASSERT(ZiSucceeded(zifs_repair_apply(&device, &plan, &apply_report)) &&
                apply_report.applied_actions == 3 && s_repair_memory.operation_count == 6 &&
                inspect_is_clean(&device) && plan_is_clean(&device));
  const size_t operation_count = s_repair_memory.operation_count;
  REPAIR_ASSERT(operation_count == 6);

  for (size_t fail_operation = 1; fail_operation <= operation_count; ++fail_operation) {
    zi_memory_copy(s_repair_image, s_repair_snapshot, sizeof s_repair_image);
    initialise_device(&device, true);
    REPAIR_ASSERT(ZiSucceeded(zifs_repair_plan(&device, &plan)) && plan.action_count == 3);
    s_repair_memory.fail_operation = fail_operation;
    REPAIR_ASSERT(zifs_repair_apply(&device, &plan, &apply_report) == ZI_STATUS_DEVICE_ERROR);
    s_repair_memory.fail_operation = 0;
    s_repair_memory.operation_count = 0;
    ZiFsRepairPlan continuation = {0};
    REPAIR_ASSERT(ZiSucceeded(zifs_repair_plan(&device, &continuation)));
    if (continuation.action_count != 0) {
      REPAIR_ASSERT(ZiSucceeded(zifs_repair_apply(&device, &continuation, &apply_report)));
    }
    REPAIR_ASSERT(plan_is_clean(&device) && inspect_is_clean(&device));
  }
  return true;
}
