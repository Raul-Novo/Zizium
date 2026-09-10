// SPDX-License-Identifier: GPL-3.0-or-later

#include "repair.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "../zifsinspect/inspect.h"
#include "zi/block.h"
#include "zi/byte_order.h"
#include "zi/zifs.h"
#include "zi/zifs_journal.h"
#include "zizium/status.h"

typedef struct RepairOverlay {
  const ZiBlockDevice* parent;
  const ZiFsRepairPlan* plan;
} RepairOverlay;

static ZiStatus read_block(const ZiBlockDevice* device, uint64_t block_number, void* output);
static ZiStatus decode_superblock_copy(const ZiBlockDevice* device,
                                       uint64_t block_number,
                                       unsigned char* encoded,
                                       ZiFsSuperblock* out_superblock);
static ZiStatus decode_journal_copy(const ZiBlockDevice* device,
                                    uint64_t block_number,
                                    unsigned char* encoded,
                                    ZiFsJournalHeader* out_header);
static ZiStatus validate_repairable_report(const ZiFsInspectReport* report);
static ZiStatus validate_selected_journal(const ZiFsInspectReport* report,
                                          const ZiFsJournalHeader* header);
static bool journal_states_equal(const ZiFsJournalHeader* left, const ZiFsJournalHeader* right);
static bool superblock_recovery_states_equal(const ZiFsSuperblock* left,
                                             const ZiFsSuperblock* right);
static ZiStatus append_action(ZiFsRepairPlan* plan,
                              uint32_t kind,
                              uint32_t copy_index,
                              uint64_t block_number,
                              const void* expected_block,
                              const void* replacement_block);
static ZiStatus
plan_journal_repair(const ZiFsInspectReport* report,
                    const ZiStatus statuses[ZI_FS_JOURNAL_HEADER_COPIES],
                    const ZiFsJournalHeader headers[ZI_FS_JOURNAL_HEADER_COPIES],
                    const unsigned char encoded[ZI_FS_JOURNAL_HEADER_COPIES][ZI_FS_BLOCK_SIZE],
                    ZiFsRepairPlan* plan);
static ZiStatus plan_superblock_repair(const ZiFsInspectReport* report,
                                       const ZiStatus statuses[2],
                                       const ZiFsSuperblock superblocks[2],
                                       const unsigned char encoded[2][ZI_FS_BLOCK_SIZE],
                                       ZiFsRepairPlan* plan);
static ZiStatus validate_final_overlay(const ZiBlockDevice* device, const ZiFsRepairPlan* plan);
static ZiStatus repair_overlay_read(void* context,
                                    uint64_t first_block,
                                    uint32_t block_count,
                                    void* output,
                                    size_t output_size);
static const unsigned char* find_replacement(const ZiFsRepairPlan* plan, uint64_t block_number);
static bool action_equal(const ZiFsRepairAction* left, const ZiFsRepairAction* right);
static ZiStatus apply_action(const ZiBlockDevice* device,
                             const ZiFsRepairAction* action,
                             unsigned char* block,
                             ZiFsRepairApplyReport* report);
static bool device_is_readable(const ZiBlockDevice* device);
static bool device_is_writable(const ZiBlockDevice* device);

ZiStatus zifs_repair_plan(const ZiBlockDevice* device, ZiFsRepairPlan* out_plan) {
  if (!device_is_readable(device) || out_plan == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  zi_memory_zero(out_plan, sizeof *out_plan);
  out_plan->struct_size = sizeof *out_plan;
  out_plan->version = ZIFS_REPAIR_PLAN_VERSION;

  ZiBlockDevice read_only_device = *device;
  read_only_device.write_blocks = NULL;
  read_only_device.flush = NULL;
  read_only_device.flags = ZI_BLOCK_DEVICE_READ_ONLY;
  ZiFsInspectReport report = {0};
  ZiStatus inspection_status = zifs_inspect_volume(&read_only_device, &report);
  ZiStatus status = validate_repairable_report(&report);
  if (ZiFailed(status)) {
    return status;
  }

  unsigned char superblock_bytes[2][ZI_FS_BLOCK_SIZE] = {0};
  ZiFsSuperblock superblocks[2] = {0};
  ZiStatus superblock_statuses[2] = {0};
  superblock_statuses[0] = decode_superblock_copy(device, 0, superblock_bytes[0], &superblocks[0]);
  superblock_statuses[1] = decode_superblock_copy(device,
                                                  device->block_count - 1u,
                                                  superblock_bytes[1],
                                                  &superblocks[1]);
  if (superblock_statuses[0] != report.primary_superblock_status ||
      superblock_statuses[1] != report.backup_superblock_status ||
      report.selected_superblock_copy > 1 ||
      ZiFailed(superblock_statuses[report.selected_superblock_copy])) {
    return ZI_STATUS_INVALID_STATE;
  }

  unsigned char journal_bytes[ZI_FS_JOURNAL_HEADER_COPIES][ZI_FS_BLOCK_SIZE] = {0};
  ZiFsJournalHeader journal_headers[ZI_FS_JOURNAL_HEADER_COPIES] = {0};
  ZiStatus journal_statuses[ZI_FS_JOURNAL_HEADER_COPIES] = {0};
  for (uint32_t index = 0; index < ZI_FS_JOURNAL_HEADER_COPIES; ++index) {
    journal_statuses[index] = decode_journal_copy(device,
                                                  report.superblock.journal_start + index,
                                                  journal_bytes[index],
                                                  &journal_headers[index]);
    if (journal_statuses[index] != report.journal_header_status[index]) {
      return ZI_STATUS_INVALID_STATE;
    }
  }
  if (report.selected_journal_copy >= ZI_FS_JOURNAL_HEADER_COPIES ||
      ZiFailed(journal_statuses[report.selected_journal_copy])) {
    return ZI_STATUS_INVALID_STATE;
  }
  status = validate_selected_journal(&report, &journal_headers[report.selected_journal_copy]);
  if (ZiFailed(status)) {
    return status;
  }

  zi_memory_copy(out_plan->volume_uuid,
                 report.superblock.volume_uuid,
                 sizeof out_plan->volume_uuid);
  out_plan->total_blocks = report.superblock.total_blocks;
  out_plan->generation = report.superblock.generation;
  out_plan->last_committed_transaction = report.superblock.last_committed_transaction;
  out_plan->selected_superblock_copy = report.selected_superblock_copy;
  out_plan->selected_journal_copy = report.selected_journal_copy;

  status = plan_journal_repair(&report, journal_statuses, journal_headers, journal_bytes, out_plan);
  if (ZiSucceeded(status)) {
    status = plan_superblock_repair(&report,
                                    superblock_statuses,
                                    superblocks,
                                    superblock_bytes,
                                    out_plan);
  }
  if (ZiFailed(status)) {
    zi_memory_zero(out_plan, sizeof *out_plan);
    return status;
  }
  if (inspection_status == ZI_STATUS_RECOVERY_REQUIRED && out_plan->action_count == 0) {
    zi_memory_zero(out_plan, sizeof *out_plan);
    return ZI_STATUS_RECOVERY_REQUIRED;
  }
  status = validate_final_overlay(device, out_plan);
  if (ZiFailed(status)) {
    zi_memory_zero(out_plan, sizeof *out_plan);
    return status;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zifs_repair_apply(const ZiBlockDevice* device,
                           const ZiFsRepairPlan* plan,
                           ZiFsRepairApplyReport* out_report) {
  if (!device_is_writable(device) || plan == NULL || out_report == NULL ||
      plan->struct_size != sizeof *plan || plan->version != ZIFS_REPAIR_PLAN_VERSION ||
      plan->action_count == 0 || plan->action_count > ZIFS_REPAIR_MAXIMUM_ACTIONS) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  ZiFsRepairPlan* current = malloc(sizeof *current);
  ZiFsRepairPlan* final = malloc(sizeof *final);
  if (current == NULL || final == NULL) {
    free(current);
    free(final);
    return ZI_STATUS_NO_MEMORY;
  }
  ZiStatus status = zifs_repair_plan(device, current);
  if (ZiSucceeded(status) && !zifs_repair_plans_equal(plan, current)) {
    status = ZI_STATUS_INVALID_STATE;
  }

  ZiFsRepairApplyReport report = {0};
  report.struct_size = sizeof report;
  report.version = ZIFS_REPAIR_APPLY_REPORT_VERSION;
  unsigned char block[ZI_FS_BLOCK_SIZE] = {0};
  for (uint32_t index = 0; ZiSucceeded(status) && index < plan->action_count; ++index) {
    status = apply_action(device, &plan->actions[index], block, &report);
  }

  if (ZiSucceeded(status)) {
    status = zifs_repair_plan(device, final);
    if (ZiSucceeded(status) && final->action_count != 0) {
      status = ZI_STATUS_INVALID_STATE;
    }
  }
  if (ZiSucceeded(status)) {
    *out_report = report;
  }
  free(current);
  free(final);
  return status;
}

bool zifs_repair_plans_equal(const ZiFsRepairPlan* left, const ZiFsRepairPlan* right) {
  if (left == NULL || right == NULL || left->struct_size != right->struct_size ||
      left->version != right->version || left->flags != right->flags ||
      left->action_count != right->action_count || left->total_blocks != right->total_blocks ||
      left->generation != right->generation ||
      left->last_committed_transaction != right->last_committed_transaction ||
      left->selected_superblock_copy != right->selected_superblock_copy ||
      left->selected_journal_copy != right->selected_journal_copy ||
      zi_memory_compare(left->volume_uuid, right->volume_uuid, sizeof left->volume_uuid) != 0) {
    return false;
  }
  for (uint32_t index = 0; index < left->action_count; ++index) {
    if (!action_equal(&left->actions[index], &right->actions[index])) {
      return false;
    }
  }
  return true;
}

static ZiStatus read_block(const ZiBlockDevice* device, uint64_t block_number, void* output) {
  if (!device_is_readable(device) || output == NULL || block_number >= device->block_count) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return device->read_blocks(device->context, block_number, 1, output, ZI_FS_BLOCK_SIZE);
}

static ZiStatus decode_superblock_copy(const ZiBlockDevice* device,
                                       uint64_t block_number,
                                       unsigned char* encoded,
                                       ZiFsSuperblock* out_superblock) {
  ZiStatus status = read_block(device, block_number, encoded);
  if (ZiSucceeded(status)) {
    status = ZiFsDecodeSuperblock(encoded, ZI_FS_BLOCK_SIZE, out_superblock);
  }
  return status;
}

static ZiStatus decode_journal_copy(const ZiBlockDevice* device,
                                    uint64_t block_number,
                                    unsigned char* encoded,
                                    ZiFsJournalHeader* out_header) {
  ZiStatus status = read_block(device, block_number, encoded);
  if (ZiSucceeded(status)) {
    status = ZiFsDecodeJournalHeader(encoded, ZI_FS_BLOCK_SIZE, out_header);
  }
  return status;
}

static ZiStatus validate_repairable_report(const ZiFsInspectReport* report) {
  if (report == NULL || report->struct_size != sizeof *report ||
      report->version != ZIFS_INSPECT_REPORT_VERSION) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (report->mount_status != ZI_STATUS_SUCCESS &&
      report->mount_status != ZI_STATUS_RECOVERY_REQUIRED) {
    return report->mount_status;
  }
  if (report->journal_status != ZI_STATUS_SUCCESS || report->security_status != ZI_STATUS_SUCCESS ||
      report->namespace_status != ZI_STATUS_SUCCESS ||
      report->allocation_status != ZI_STATUS_SUCCESS) {
    if (report->overall_status == ZI_STATUS_SUCCESS) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    return report->overall_status;
  }
  if ((report->superblock.incompatible_features & ZI_FS_FEATURE_INCOMPAT_CLEAN_UNMOUNT_V1) == 0 ||
      report->occupied_journal_records != 0 || report->inspected_replay_view != 0 ||
      (report->superblock.state_flags != ZI_FS_SUPERBLOCK_STATE_NONE &&
       report->superblock.state_flags != ZI_FS_SUPERBLOCK_STATE_MOUNTED)) {
    return ZI_STATUS_RECOVERY_REQUIRED;
  }
  if (report->superblock.state_flags == ZI_FS_SUPERBLOCK_STATE_MOUNTED &&
      report->unclean_mount == 0) {
    return ZI_STATUS_RECOVERY_REQUIRED;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_selected_journal(const ZiFsInspectReport* report,
                                          const ZiFsJournalHeader* header) {
  uint64_t expected_capacity = 0;
  ZiStatus status =
      ZiFsJournalRecordCapacity(report->superblock.journal_blocks, &expected_capacity);
  if (ZiFailed(status) || header->record_capacity != expected_capacity ||
      header->head_record != header->tail_record ||
      header->volume_generation != report->superblock.generation ||
      header->last_committed_transaction != report->superblock.last_committed_transaction ||
      header->last_checkpoint_transaction != header->last_committed_transaction ||
      header->last_committed_transaction == UINT64_MAX ||
      header->next_transaction_id != header->last_committed_transaction + 1u) {
    return ZI_STATUS_RECOVERY_REQUIRED;
  }
  return ZI_STATUS_SUCCESS;
}

static bool journal_states_equal(const ZiFsJournalHeader* left, const ZiFsJournalHeader* right) {
  return (bool)(left->volume_generation == right->volume_generation &&
                left->record_capacity == right->record_capacity &&
                left->head_record == right->head_record &&
                left->tail_record == right->tail_record &&
                left->next_sequence == right->next_sequence &&
                left->next_transaction_id == right->next_transaction_id &&
                left->last_committed_transaction == right->last_committed_transaction &&
                left->last_checkpoint_transaction == right->last_checkpoint_transaction &&
                left->flags == right->flags);
}

static bool superblock_recovery_states_equal(const ZiFsSuperblock* left,
                                             const ZiFsSuperblock* right) {
  return (bool)(left->generation == right->generation &&
                left->last_committed_transaction == right->last_committed_transaction &&
                left->state_flags == right->state_flags);
}

static ZiStatus append_action(ZiFsRepairPlan* plan,
                              uint32_t kind,
                              uint32_t copy_index,
                              uint64_t block_number,
                              const void* expected_block,
                              const void* replacement_block) {
  if (plan == NULL || expected_block == NULL || replacement_block == NULL ||
      plan->action_count >= ZIFS_REPAIR_MAXIMUM_ACTIONS) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  ZiFsRepairAction* action = &plan->actions[plan->action_count++];
  action->block_number = block_number;
  action->kind = kind;
  action->copy_index = copy_index;
  zi_memory_copy(action->expected_block, expected_block, ZI_FS_BLOCK_SIZE);
  zi_memory_copy(action->replacement_block, replacement_block, ZI_FS_BLOCK_SIZE);
  return ZI_STATUS_SUCCESS;
}

static ZiStatus
plan_journal_repair(const ZiFsInspectReport* report,
                    const ZiStatus statuses[ZI_FS_JOURNAL_HEADER_COPIES],
                    const ZiFsJournalHeader headers[ZI_FS_JOURNAL_HEADER_COPIES],
                    const unsigned char encoded[ZI_FS_JOURNAL_HEADER_COPIES][ZI_FS_BLOCK_SIZE],
                    ZiFsRepairPlan* plan) {
  uint32_t selected = report->selected_journal_copy;
  uint32_t other = selected ^ 1u;
  bool requires_repair = ZiFailed(statuses[other]);
  if (!requires_repair && !journal_states_equal(&headers[selected], &headers[other])) {
    if (headers[selected].header_sequence <= headers[other].header_sequence) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    requires_repair = true;
  }
  if (!requires_repair) {
    return ZI_STATUS_SUCCESS;
  }
  if (headers[selected].header_sequence == UINT64_MAX) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  ZiFsJournalHeader replacement = headers[selected];
  replacement.header_sequence = headers[selected].header_sequence + 1u;
  unsigned char replacement_bytes[ZI_FS_BLOCK_SIZE] = {0};
  ZiStatus status =
      ZiFsEncodeJournalHeader(&replacement, replacement_bytes, sizeof replacement_bytes);
  if (ZiFailed(status)) {
    return status;
  }
  status = append_action(plan,
                         ZIFS_REPAIR_ACTION_JOURNAL_HEADER,
                         other,
                         report->superblock.journal_start + other,
                         encoded[other],
                         replacement_bytes);
  if (ZiSucceeded(status)) {
    plan->flags |= ZIFS_REPAIR_PLAN_JOURNAL_REDUNDANCY;
  }
  return status;
}

static ZiStatus plan_superblock_repair(const ZiFsInspectReport* report,
                                       const ZiStatus statuses[2],
                                       const ZiFsSuperblock superblocks[2],
                                       const unsigned char encoded[2][ZI_FS_BLOCK_SIZE],
                                       ZiFsRepairPlan* plan) {
  ZiFsSuperblock replacement = report->superblock;
  bool unclean_mount = replacement.state_flags == ZI_FS_SUPERBLOCK_STATE_MOUNTED;
  replacement.state_flags = ZI_FS_SUPERBLOCK_STATE_NONE;
  unsigned char replacement_bytes[ZI_FS_BLOCK_SIZE] = {0};
  ZiStatus status = ZiFsEncodeSuperblock(&replacement, replacement_bytes, sizeof replacement_bytes);
  if (ZiFailed(status)) {
    return status;
  }

  uint32_t selected = report->selected_superblock_copy;
  uint32_t other = selected ^ 1u;
  bool redundancy_mismatch = ZiFailed(statuses[other]);
  if (!redundancy_mismatch &&
      !superblock_recovery_states_equal(&superblocks[selected], &superblocks[other])) {
    redundancy_mismatch = true;
  }
  if (redundancy_mismatch) {
    plan->flags |= ZIFS_REPAIR_PLAN_SUPERBLOCK_REDUNDANCY;
  }
  if (unclean_mount) {
    plan->flags |= ZIFS_REPAIR_PLAN_UNCLEAN_MOUNT;
  }

  const uint64_t block_numbers[2] = {0, report->superblock.backup_superblock};
  if (zi_memory_compare(encoded[other], replacement_bytes, ZI_FS_BLOCK_SIZE) != 0) {
    status = append_action(plan,
                           ZIFS_REPAIR_ACTION_SUPERBLOCK,
                           other,
                           block_numbers[other],
                           encoded[other],
                           replacement_bytes);
  }
  if (ZiSucceeded(status) &&
      zi_memory_compare(encoded[selected], replacement_bytes, ZI_FS_BLOCK_SIZE) != 0) {
    status = append_action(plan,
                           ZIFS_REPAIR_ACTION_SUPERBLOCK,
                           selected,
                           block_numbers[selected],
                           encoded[selected],
                           replacement_bytes);
  }
  return status;
}

static ZiStatus validate_final_overlay(const ZiBlockDevice* device, const ZiFsRepairPlan* plan) {
  RepairOverlay overlay = {device, plan};
  ZiBlockDevice overlay_device = *device;
  overlay_device.context = &overlay;
  overlay_device.read_blocks = repair_overlay_read;
  overlay_device.write_blocks = NULL;
  overlay_device.flush = NULL;
  overlay_device.flags = ZI_BLOCK_DEVICE_READ_ONLY;
  ZiFsInspectReport report = {0};
  ZiStatus status = zifs_inspect_volume(&overlay_device, &report);
  if (ZiFailed(status) || report.overall_status != ZI_STATUS_SUCCESS ||
      report.needs_recovery != 0 || report.superblock.state_flags != ZI_FS_SUPERBLOCK_STATE_NONE ||
      report.mount_status != ZI_STATUS_SUCCESS || report.journal_status != ZI_STATUS_SUCCESS ||
      report.security_status != ZI_STATUS_SUCCESS || report.namespace_status != ZI_STATUS_SUCCESS ||
      report.allocation_status != ZI_STATUS_SUCCESS) {
    if (ZiFailed(status)) {
      return status;
    }
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus repair_overlay_read(void* context,
                                    uint64_t first_block,
                                    uint32_t block_count,
                                    void* output,
                                    size_t output_size) {
  RepairOverlay* overlay = context;
  if (overlay == NULL || overlay->parent == NULL || overlay->plan == NULL || output == NULL ||
      block_count == 0 || output_size < (size_t)block_count * ZI_FS_BLOCK_SIZE ||
      first_block >= overlay->parent->block_count ||
      block_count > overlay->parent->block_count - first_block) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char* output_bytes = output;
  for (uint32_t offset = 0; offset < block_count; ++offset) {
    uint64_t block = first_block + offset;
    const unsigned char* replacement = find_replacement(overlay->plan, block);
    if (replacement != NULL) {
      zi_memory_copy(output_bytes + ((size_t)offset * ZI_FS_BLOCK_SIZE),
                     replacement,
                     ZI_FS_BLOCK_SIZE);
      continue;
    }
    ZiStatus status =
        overlay->parent->read_blocks(overlay->parent->context,
                                     block,
                                     1,
                                     output_bytes + ((size_t)offset * ZI_FS_BLOCK_SIZE),
                                     ZI_FS_BLOCK_SIZE);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static const unsigned char* find_replacement(const ZiFsRepairPlan* plan, uint64_t block_number) {
  for (uint32_t index = 0; index < plan->action_count; ++index) {
    if (plan->actions[index].block_number == block_number) {
      return plan->actions[index].replacement_block;
    }
  }
  return NULL;
}

static bool action_equal(const ZiFsRepairAction* left, const ZiFsRepairAction* right) {
  return (bool)(left->block_number == right->block_number && left->kind == right->kind &&
                left->copy_index == right->copy_index &&
                zi_memory_compare(left->expected_block, right->expected_block, ZI_FS_BLOCK_SIZE) ==
                    0 &&
                zi_memory_compare(left->replacement_block,
                                  right->replacement_block,
                                  ZI_FS_BLOCK_SIZE) == 0);
}

static ZiStatus apply_action(const ZiBlockDevice* device,
                             const ZiFsRepairAction* action,
                             unsigned char* block,
                             ZiFsRepairApplyReport* report) {
  ZiStatus status = read_block(device, action->block_number, block);
  if (ZiFailed(status)) {
    return status;
  }
  if (zi_memory_compare(block, action->replacement_block, ZI_FS_BLOCK_SIZE) == 0) {
    status = zi_block_barrier(device);
    if (ZiSucceeded(status)) {
      ++report->already_present_actions;
    }
    return status;
  }
  if (zi_memory_compare(block, action->expected_block, ZI_FS_BLOCK_SIZE) != 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  status =
      zi_block_write(device, action->block_number, 1, action->replacement_block, ZI_FS_BLOCK_SIZE);
  if (ZiSucceeded(status)) {
    status = zi_block_barrier(device);
  }
  if (ZiSucceeded(status)) {
    ++report->applied_actions;
  }
  return status;
}

static bool device_is_readable(const ZiBlockDevice* device) {
  return (bool)(device != NULL && device->struct_size >= sizeof *device &&
                device->version == ZI_BLOCK_DEVICE_VERSION && device->context != NULL &&
                device->block_size == ZI_FS_BLOCK_SIZE && device->block_count >= 2 &&
                device->read_blocks != NULL);
}

static bool device_is_writable(const ZiBlockDevice* device) {
  return (
      bool)(device_is_readable(device) && device->write_blocks != NULL && device->flush != NULL &&
            (device->flags & (ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED)) ==
                (ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED) &&
            (device->flags & ZI_BLOCK_DEVICE_READ_ONLY) == 0);
}
