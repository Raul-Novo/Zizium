// SPDX-License-Identifier: GPL-3.0-or-later

#include "inspect.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "zi/block.h"
#include "zi/byte_order.h"
#include "zi/path.h"
#include "zi/zifs.h"
#include "zi/zifs_journal.h"
#include "zi/zifs_security.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define RECORDS_PER_BLOCK (ZI_FS_BLOCK_SIZE / ZI_FS_FILE_RECORD_SIZE)
#define MAXIMUM_DIRECTORY_ENTRIES (ZI_FS_BLOCK_SIZE / ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE)

enum {
  DIRECTORY_ENTRY_COUNT_OFFSET = 16,
  DIRECTORY_USED_BYTES_OFFSET = 20,
  DIRECTORY_ENTRY_SIZE_OFFSET = 0,
  DIRECTORY_ENTRY_NAME_SIZE_OFFSET = 2,
  DIRECTORY_ENTRY_FILE_TYPE_OFFSET = 4,
  DIRECTORY_ENTRY_FLAGS_OFFSET = 6,
  DIRECTORY_ENTRY_FILE_ID_OFFSET = 8,
  DIRECTORY_ENTRY_RECORD_INDEX_OFFSET = 16,
};

typedef struct RecordSummary {
  ZiFsFileRecord record;
  uint64_t record_index;
  uint32_t link_count;
  uint32_t present;
} RecordSummary;

typedef struct JournalRecordSummary {
  ZiFsJournalRecord record;
  uint64_t record_index;
  unsigned char payload[ZI_FS_JOURNAL_MAXIMUM_PAYLOAD_SIZE];
} JournalRecordSummary;

static ZiStatus inspect_superblocks(const ZiBlockDevice* device,
                                    void* block_buffer,
                                    size_t block_buffer_size,
                                    ZiFsVolume* out_volume,
                                    ZiFsInspectReport* report);
static ZiStatus inspect_journal(const ZiFsVolume* volume,
                                void* block_buffer,
                                size_t block_buffer_size,
                                ZiFsInspectReport* report);
static ZiStatus inspect_active_transaction(const ZiFsVolume* volume,
                                           const ZiFsJournalHeader* header,
                                           void* block_buffer,
                                           size_t block_buffer_size,
                                           ZiFsInspectReport* report);
static ZiStatus inspect_security(const ZiFsVolume* volume,
                                 uint64_t* security_ids,
                                 size_t security_id_capacity,
                                 ZiFsInspectReport* report);
static ZiStatus inspect_namespace(const ZiFsVolume* volume,
                                  const uint64_t* security_ids,
                                  size_t security_id_count,
                                  unsigned char* expected_blocks,
                                  ZiFsInspectReport* report);
static ZiStatus scan_file_records(const ZiFsVolume* volume,
                                  const uint64_t* security_ids,
                                  size_t security_id_count,
                                  unsigned char* expected_blocks,
                                  RecordSummary* records,
                                  uint64_t record_capacity,
                                  ZiFsInspectReport* report);
static ZiStatus inspect_directories(const ZiFsVolume* volume,
                                    RecordSummary* records,
                                    uint64_t record_capacity,
                                    ZiFsInspectReport* report);
static ZiStatus inspect_directory_entries(const ZiFsVolume* volume,
                                          RecordSummary* records,
                                          uint64_t record_capacity,
                                          RecordSummary* directory,
                                          void* block_buffer,
                                          ZiFsInspectReport* report);
static ZiStatus inspect_allocation(const ZiFsVolume* volume,
                                   const unsigned char* expected_blocks,
                                   ZiFsInspectReport* report);
static ZiStatus mark_metadata_blocks(const ZiFsSuperblock* superblock,
                                     unsigned char* expected_blocks);
static ZiStatus mark_expected_range(unsigned char* expected_blocks,
                                    uint64_t total_blocks,
                                    uint64_t first_block,
                                    uint64_t block_count,
                                    unsigned char marker,
                                    bool reject_existing);
static bool
security_id_exists(const uint64_t* security_ids, size_t security_id_count, uint64_t security_id);
static bool bytes_are_zero(const void* data, size_t size);
static int compare_u64(const void* left, const void* right);
static bool journal_header_state_equal(const ZiFsJournalHeader* left,
                                       const ZiFsJournalHeader* right);
static ZiStatus validate_journal_record_sequence(const JournalRecordSummary* records,
                                                 uint64_t record_count,
                                                 const ZiFsJournalHeader* header,
                                                 ZiFsInspectReport* report);
static void preserve_first_failure(ZiStatus candidate, ZiStatus* first_failure);

ZiStatus zifs_inspect_volume(const ZiBlockDevice* device, ZiFsInspectReport* out_report) {
  if (device == NULL || out_report == NULL || device->struct_size < sizeof *device ||
      device->version != ZI_BLOCK_DEVICE_VERSION || device->read_blocks == NULL ||
      device->block_size != ZI_FS_BLOCK_SIZE || device->block_count < 2) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  ZiFsInspectReport report = {0};
  report.struct_size = sizeof report;
  report.version = ZIFS_INSPECT_REPORT_VERSION;
  report.primary_superblock_status = ZI_STATUS_INVALID_STATE;
  report.backup_superblock_status = ZI_STATUS_INVALID_STATE;
  report.mount_status = ZI_STATUS_INVALID_STATE;
  report.journal_status = ZI_STATUS_INVALID_STATE;
  report.security_status = ZI_STATUS_INVALID_STATE;
  report.namespace_status = ZI_STATUS_INVALID_STATE;
  report.allocation_status = ZI_STATUS_INVALID_STATE;

  unsigned char block_buffer[ZI_FS_JOURNAL_RECORD_SIZE] = {0};
  ZiFsVolume volume = {0};
  ZiStatus status =
      inspect_superblocks(device, block_buffer, sizeof block_buffer, &volume, &report);
  if (ZiFailed(status) && volume.superblock.total_blocks == 0) {
    report.overall_status = status;
    *out_report = report;
    return status;
  }

  ZiStatus first_failure = ZI_STATUS_SUCCESS;
  if (ZiFailed(status) && status != ZI_STATUS_RECOVERY_REQUIRED) {
    preserve_first_failure(status, &first_failure);
  }
  if (status == ZI_STATUS_RECOVERY_REQUIRED) {
    report.needs_recovery = 1;
  }
  if (volume.superblock.total_blocks > ZIFS_INSPECT_MAXIMUM_VOLUME_BLOCKS) {
    first_failure = ZI_STATUS_BUFFER_TOO_SMALL;
  }

  report.journal_status = inspect_journal(&volume, block_buffer, sizeof block_buffer, &report);
  preserve_first_failure(report.journal_status, &first_failure);

  uint64_t security_ids[ZI_FS_SECURITY_MAXIMUM_RECORDS] = {0};
  report.security_status =
      inspect_security(&volume, security_ids, ZI_FS_SECURITY_MAXIMUM_RECORDS, &report);
  preserve_first_failure(report.security_status, &first_failure);

  unsigned char* expected_blocks = NULL;
  if (volume.superblock.total_blocks <= ZIFS_INSPECT_MAXIMUM_VOLUME_BLOCKS &&
      ZiSucceeded(report.security_status)) {
    expected_blocks = calloc((size_t)volume.superblock.total_blocks, 1);
    if (expected_blocks == NULL) {
      report.namespace_status = ZI_STATUS_NO_MEMORY;
      preserve_first_failure(report.namespace_status, &first_failure);
    }
  }
  if (expected_blocks != NULL) {
    report.namespace_status = mark_metadata_blocks(&volume.superblock, expected_blocks);
    if (ZiSucceeded(report.namespace_status)) {
      report.namespace_status = inspect_namespace(&volume,
                                                  security_ids,
                                                  (size_t)report.security_descriptor_count,
                                                  expected_blocks,
                                                  &report);
    }
    preserve_first_failure(report.namespace_status, &first_failure);
    if (ZiSucceeded(report.namespace_status)) {
      report.allocation_status = inspect_allocation(&volume, expected_blocks, &report);
      preserve_first_failure(report.allocation_status, &first_failure);
    }
    free(expected_blocks);
  }

  if (ZiSucceeded(first_failure) && report.needs_recovery != 0) {
    first_failure = ZI_STATUS_RECOVERY_REQUIRED;
  }
  report.overall_status = first_failure;
  *out_report = report;
  return first_failure;
}

static ZiStatus inspect_superblocks(const ZiBlockDevice* device,
                                    void* block_buffer,
                                    size_t block_buffer_size,
                                    ZiFsVolume* out_volume,
                                    ZiFsInspectReport* report) {
  ZiFsSuperblock primary = {0};
  ZiFsSuperblock backup = {0};
  report->primary_superblock_status =
      device->read_blocks(device->context, 0, 1, block_buffer, block_buffer_size);
  if (ZiSucceeded(report->primary_superblock_status)) {
    report->primary_superblock_status =
        ZiFsDecodeSuperblock(block_buffer, block_buffer_size, &primary);
  }
  report->backup_superblock_status = device->read_blocks(device->context,
                                                         device->block_count - 1u,
                                                         1,
                                                         block_buffer,
                                                         block_buffer_size);
  if (ZiSucceeded(report->backup_superblock_status)) {
    report->backup_superblock_status =
        ZiFsDecodeSuperblock(block_buffer, block_buffer_size, &backup);
  }

  report->mount_status = ZiFsMountVolume(device, block_buffer, block_buffer_size, out_volume);
  if (out_volume->superblock.total_blocks != 0) {
    report->superblock = out_volume->superblock;
    report->selected_superblock_copy = out_volume->mounted_from_backup;
    report->needs_recovery = out_volume->needs_recovery;
  }
  if (ZiFailed(report->primary_superblock_status) && ZiFailed(report->backup_superblock_status)) {
    return report->mount_status;
  }
  if (ZiFailed(report->primary_superblock_status) || ZiFailed(report->backup_superblock_status)) {
    report->needs_recovery = 1;
  }
  if (report->mount_status == ZI_STATUS_RECOVERY_REQUIRED) {
    report->needs_recovery = 1;
    return ZI_STATUS_RECOVERY_REQUIRED;
  }
  return report->mount_status;
}

static ZiStatus inspect_journal(const ZiFsVolume* volume,
                                void* block_buffer,
                                size_t block_buffer_size,
                                ZiFsInspectReport* report) {
  uint64_t expected_capacity = 0;
  ZiStatus status =
      ZiFsJournalRecordCapacity(volume->superblock.journal_blocks, &expected_capacity);
  if (ZiFailed(status)) {
    return status;
  }

  ZiFsJournalHeader copies[ZI_FS_JOURNAL_HEADER_COPIES] = {0};
  ZiStatus copy_status[ZI_FS_JOURNAL_HEADER_COPIES] = {0};
  for (uint32_t index = 0; index < ZI_FS_JOURNAL_HEADER_COPIES; ++index) {
    copy_status[index] = volume->device.read_blocks(volume->device.context,
                                                    volume->superblock.journal_start + index,
                                                    1,
                                                    block_buffer,
                                                    block_buffer_size);
    if (ZiSucceeded(copy_status[index])) {
      copy_status[index] = ZiFsDecodeJournalHeader(block_buffer, ZI_FS_BLOCK_SIZE, &copies[index]);
    }
  }

  status = ZiFsLoadJournalHeader(&volume->device,
                                 volume->superblock.journal_start,
                                 block_buffer,
                                 block_buffer_size,
                                 &report->journal,
                                 &report->selected_journal_copy);
  if (ZiFailed(status) || report->journal.record_capacity != expected_capacity) {
    if (ZiFailed(status)) {
      return status;
    }
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  if (ZiSucceeded(copy_status[0]) && ZiSucceeded(copy_status[1]) &&
      !journal_header_state_equal(&copies[0], &copies[1])) {
    report->needs_recovery = 1;
  }
  if (report->journal.volume_generation != volume->superblock.generation ||
      report->journal.last_checkpoint_transaction !=
          volume->superblock.last_committed_transaction) {
    report->needs_recovery = 1;
  }
  uint64_t available = 0;
  status = ZiFsJournalQuerySpace(&report->journal, &report->occupied_journal_records, &available);
  if (ZiFailed(status)) {
    return status;
  }
  if (report->occupied_journal_records == 0) {
    return ZI_STATUS_SUCCESS;
  }
  report->needs_recovery = 1;
  return inspect_active_transaction(volume,
                                    &report->journal,
                                    block_buffer,
                                    block_buffer_size,
                                    report);
}

static ZiStatus inspect_active_transaction(const ZiFsVolume* volume,
                                           const ZiFsJournalHeader* header,
                                           void* block_buffer,
                                           size_t block_buffer_size,
                                           ZiFsInspectReport* report) {
  if (report->occupied_journal_records > ZI_FS_JOURNAL_MAXIMUM_BLOCK_IMAGES + 2u) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  JournalRecordSummary records[ZI_FS_JOURNAL_MAXIMUM_BLOCK_IMAGES + 2u] = {0};
  uint64_t record_index = header->tail_record;
  for (uint64_t index = 0; index < report->occupied_journal_records; ++index) {
    uint64_t record_block = 0;
    ZiStatus status = ZiFsJournalRecordBlock(volume->superblock.journal_start,
                                             header->record_capacity,
                                             record_index,
                                             &record_block);
    if (ZiFailed(status)) {
      return status;
    }
    status = volume->device.read_blocks(volume->device.context,
                                        record_block,
                                        (uint32_t)ZI_FS_JOURNAL_RECORD_BLOCKS,
                                        block_buffer,
                                        block_buffer_size);
    if (ZiFailed(status)) {
      return status;
    }
    records[index].record_index = record_index;
    status =
        ZiFsDecodeJournalRecord(block_buffer, ZI_FS_JOURNAL_RECORD_SIZE, &records[index].record);
    if (ZiFailed(status)) {
      return status;
    }
    if (records[index].record.payload.size != 0) {
      zi_memory_copy(records[index].payload,
                     records[index].record.payload.data,
                     records[index].record.payload.size);
      records[index].record.payload.data = records[index].payload;
    }
    status = ZiFsJournalAdvanceRecord(header->record_capacity, record_index, 1, &record_index);
    if (ZiFailed(status)) {
      return status;
    }
  }
  if (record_index != header->head_record) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  return validate_journal_record_sequence(records,
                                          report->occupied_journal_records,
                                          header,
                                          report);
}

static ZiStatus inspect_security(const ZiFsVolume* volume,
                                 uint64_t* security_ids,
                                 size_t security_id_capacity,
                                 ZiFsInspectReport* report) {
  if ((volume->superblock.incompatible_features & ZI_FS_FEATURE_INCOMPAT_SECURITY_V1) == 0 ||
      volume->superblock.security_table_blocks == 0 ||
      volume->superblock.security_table_blocks > ZI_FS_SECURITY_MAXIMUM_TABLE_BLOCKS) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  size_t table_size = (size_t)volume->superblock.security_table_blocks * (size_t)ZI_FS_BLOCK_SIZE;
  unsigned char* table = malloc(table_size);
  if (table == NULL) {
    return ZI_STATUS_NO_MEMORY;
  }
  ZiStatus status = volume->device.read_blocks(volume->device.context,
                                               volume->superblock.security_table_start,
                                               (uint32_t)volume->superblock.security_table_blocks,
                                               table,
                                               table_size);
  ZiFsSecurityTableHeader header = {0};
  if (ZiSucceeded(status)) {
    status = ZiFsValidateSecurityTable(table, table_size, &header);
  }
  if (ZiSucceeded(status) &&
      (header.record_count == 0 || header.record_count > security_id_capacity)) {
    status = ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  for (uint32_t index = 0; ZiSucceeded(status) && index < header.record_count; ++index) {
    size_t offset =
        ZI_FS_SECURITY_TABLE_HEADER_SIZE + ((size_t)index * ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE);
    ZiFsSecurityDescriptorStorage storage = {0};
    status = ZiFsDecodeSecurityDescriptor(table + offset,
                                          ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE,
                                          &storage);
    if (ZiSucceeded(status)) {
      security_ids[index] = storage.security_id;
      report->security_ace_count += storage.dacl.entry_count;
    }
  }
  if (ZiSucceeded(status)) {
    report->security_descriptor_count = header.record_count;
  }
  free(table);
  return status;
}

static ZiStatus inspect_namespace(const ZiFsVolume* volume,
                                  const uint64_t* security_ids,
                                  size_t security_id_count,
                                  unsigned char* expected_blocks,
                                  ZiFsInspectReport* report) {
  if (volume->superblock.record_table_blocks > UINT64_MAX / RECORDS_PER_BLOCK) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  uint64_t record_capacity = volume->superblock.record_table_blocks * RECORDS_PER_BLOCK;
  if (record_capacity == 0 || record_capacity > ZIFS_INSPECT_MAXIMUM_RECORD_SLOTS ||
      volume->superblock.root_record_index >= record_capacity) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  RecordSummary* records = calloc((size_t)record_capacity, sizeof *records);
  if (records == NULL) {
    return ZI_STATUS_NO_MEMORY;
  }
  report->record_slot_count = record_capacity;
  ZiStatus status = scan_file_records(volume,
                                      security_ids,
                                      security_id_count,
                                      expected_blocks,
                                      records,
                                      record_capacity,
                                      report);
  if (ZiSucceeded(status)) {
    const RecordSummary* root = &records[volume->superblock.root_record_index];
    if (root->present == 0 || root->record.file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
      status = ZI_STATUS_CORRUPT_FILESYSTEM;
    }
  }
  if (ZiSucceeded(status)) {
    status = inspect_directories(volume, records, record_capacity, report);
  }
  free(records);
  return status;
}

// The complete record-table scan keeps slot, identity, extent, and security checks together.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static ZiStatus scan_file_records(const ZiFsVolume* volume,
                                  const uint64_t* security_ids,
                                  size_t security_id_count,
                                  unsigned char* expected_blocks,
                                  RecordSummary* records,
                                  uint64_t record_capacity,
                                  ZiFsInspectReport* report) {
  unsigned char block[ZI_FS_BLOCK_SIZE] = {0};
  uint64_t* file_ids = malloc((size_t)record_capacity * sizeof *file_ids);
  uint64_t* directory_blocks = malloc((size_t)record_capacity * sizeof *directory_blocks);
  if (file_ids == NULL || directory_blocks == NULL) {
    free(file_ids);
    free(directory_blocks);
    return ZI_STATUS_NO_MEMORY;
  }
  size_t file_id_count = 0;
  size_t directory_block_count = 0;
  ZiStatus status = ZI_STATUS_SUCCESS;
  for (uint64_t table_block = 0;
       ZiSucceeded(status) && table_block < volume->superblock.record_table_blocks;
       ++table_block) {
    status = volume->device.read_blocks(volume->device.context,
                                        volume->superblock.record_table_start + table_block,
                                        1,
                                        block,
                                        sizeof block);
    for (uint64_t slot = 0; ZiSucceeded(status) && slot < RECORDS_PER_BLOCK; ++slot) {
      uint64_t record_index = (table_block * RECORDS_PER_BLOCK) + slot;
      const unsigned char* encoded = block + (slot * ZI_FS_FILE_RECORD_SIZE);
      if (bytes_are_zero(encoded, ZI_FS_FILE_RECORD_SIZE)) {
        continue;
      }
      RecordSummary* summary = &records[record_index];
      status = ZiFsDecodeFileRecord(encoded, ZI_FS_FILE_RECORD_SIZE, &summary->record);
      if (ZiSucceeded(status)) {
        status = ZiFsValidateFileRecord(volume, &summary->record);
      }
      if (ZiSucceeded(status) &&
          !security_id_exists(security_ids, security_id_count, summary->record.security_id)) {
        status = ZI_STATUS_CORRUPT_FILESYSTEM;
      }
      if (ZiFailed(status)) {
        break;
      }
      summary->record_index = record_index;
      summary->present = 1;
      file_ids[file_id_count++] = summary->record.file_id;
      ++report->live_file_records;
      if (summary->record.file_type == ZI_FS_FILE_TYPE_REGULAR) {
        ++report->regular_file_records;
      } else if (summary->record.file_type == ZI_FS_FILE_TYPE_DIRECTORY) {
        directory_blocks[directory_block_count++] = summary->record.directory_block;
        ++report->directory_records;
      } else {
        ++report->other_file_records;
      }
      for (uint32_t extent = 0; extent < summary->record.extent_count; ++extent) {
        status = mark_expected_range(expected_blocks,
                                     volume->superblock.total_blocks,
                                     summary->record.extents[extent].physical_block,
                                     summary->record.extents[extent].block_count,
                                     2,
                                     true);
        if (ZiFailed(status)) {
          break;
        }
      }
    }
  }
  if (ZiSucceeded(status)) {
    qsort(file_ids, file_id_count, sizeof *file_ids, compare_u64);
    qsort(directory_blocks, directory_block_count, sizeof *directory_blocks, compare_u64);
    for (size_t index = 1; index < file_id_count; ++index) {
      if (file_ids[index - 1u] == file_ids[index]) {
        status = ZI_STATUS_CORRUPT_FILESYSTEM;
        break;
      }
    }
    for (size_t index = 1; ZiSucceeded(status) && index < directory_block_count; ++index) {
      if (directory_blocks[index - 1u] == directory_blocks[index]) {
        status = ZI_STATUS_CORRUPT_FILESYSTEM;
      }
    }
  }
  free(file_ids);
  free(directory_blocks);
  return status;
}

static ZiStatus inspect_directories(const ZiFsVolume* volume,
                                    RecordSummary* records,
                                    uint64_t record_capacity,
                                    ZiFsInspectReport* report) {
  unsigned char block[ZI_FS_BLOCK_SIZE] = {0};
  for (uint64_t index = 0; index < record_capacity; ++index) {
    RecordSummary* summary = &records[index];
    if (summary->present == 0 || summary->record.file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
      continue;
    }
    ZiStatus status =
        inspect_directory_entries(volume, records, record_capacity, summary, block, report);
    if (ZiFailed(status)) {
      return status;
    }
  }
  for (uint64_t index = 0; index < record_capacity; ++index) {
    if (records[index].present == 0) {
      continue;
    }
    uint32_t expected_links = index == volume->superblock.root_record_index ? 0u : 1u;
    if (records[index].link_count != expected_links) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus inspect_directory_entries(const ZiFsVolume* volume,
                                          RecordSummary* records,
                                          uint64_t record_capacity,
                                          RecordSummary* directory,
                                          void* block_buffer,
                                          ZiFsInspectReport* report) {
  ZiStatus status = volume->device.read_blocks(volume->device.context,
                                               directory->record.directory_block,
                                               1,
                                               block_buffer,
                                               ZI_FS_BLOCK_SIZE);
  if (ZiSucceeded(status)) {
    status = ZiFsValidateDirectoryBlock(block_buffer, ZI_FS_BLOCK_SIZE, directory->record.file_id);
  }
  if (ZiFailed(status)) {
    return status;
  }
  const unsigned char* bytes = block_buffer;
  uint32_t entry_count = zi_read_u32_le(bytes + DIRECTORY_ENTRY_COUNT_OFFSET);
  uint32_t used_bytes = zi_read_u32_le(bytes + DIRECTORY_USED_BYTES_OFFSET);
  if (entry_count > MAXIMUM_DIRECTORY_ENTRIES) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  size_t entry_offsets[MAXIMUM_DIRECTORY_ENTRIES] = {0};
  size_t offset = ZI_FS_DIRECTORY_HEADER_SIZE;
  for (uint32_t index = 0; index < entry_count; ++index) {
    const unsigned char* entry = bytes + offset;
    uint16_t entry_size = zi_read_u16_le(entry + DIRECTORY_ENTRY_SIZE_OFFSET);
    uint16_t name_size = zi_read_u16_le(entry + DIRECTORY_ENTRY_NAME_SIZE_OFFSET);
    uint64_t record_index = zi_read_u64_le(entry + DIRECTORY_ENTRY_RECORD_INDEX_OFFSET);
    if (offset >= used_bytes || entry_size > used_bytes - offset ||
        record_index >= record_capacity ||
        zi_read_u16_le(entry + DIRECTORY_ENTRY_FLAGS_OFFSET) != 0 ||
        records[record_index].present == 0 ||
        records[record_index].record.file_id !=
            zi_read_u64_le(entry + DIRECTORY_ENTRY_FILE_ID_OFFSET) ||
        records[record_index].record.file_type !=
            zi_read_u16_le(entry + DIRECTORY_ENTRY_FILE_TYPE_OFFSET) ||
        records[record_index].record.parent_file_id != directory->record.file_id ||
        records[record_index].link_count != 0) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    ZiStringView name = {
        (const char*)entry + ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE,
        name_size,
    };
    for (uint32_t prior = 0; prior < index; ++prior) {
      const unsigned char* prior_entry = bytes + entry_offsets[prior];
      ZiStringView prior_name = {
          (const char*)prior_entry + ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE,
          zi_read_u16_le(prior_entry + DIRECTORY_ENTRY_NAME_SIZE_OFFSET),
      };
      int comparison = 0;
      if (ZiFailed(zi_path_compare_component(name, prior_name, &comparison)) || comparison == 0) {
        return ZI_STATUS_CORRUPT_FILESYSTEM;
      }
    }
    entry_offsets[index] = offset;
    records[record_index].link_count = 1;
    ++report->directory_entries;
    offset += entry_size;
  }
  return offset == used_bytes ? ZI_STATUS_SUCCESS : ZI_STATUS_CORRUPT_FILESYSTEM;
}

static ZiStatus inspect_allocation(const ZiFsVolume* volume,
                                   const unsigned char* expected_blocks,
                                   ZiFsInspectReport* report) {
  uint64_t expected_bitmap_blocks = 0;
  ZiStatus status =
      ZiFsAllocationBitmapBlockCount(volume->superblock.total_blocks, &expected_bitmap_blocks);
  if (ZiFailed(status) || expected_bitmap_blocks != volume->superblock.allocation_bitmap_blocks ||
      expected_bitmap_blocks > SIZE_MAX / ZI_FS_BLOCK_SIZE || expected_bitmap_blocks > UINT32_MAX) {
    if (ZiFailed(status)) {
      return status;
    }
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  size_t bitmap_size = (size_t)expected_bitmap_blocks * ZI_FS_BLOCK_SIZE;
  unsigned char* bitmap = malloc(bitmap_size);
  if (bitmap == NULL) {
    return ZI_STATUS_NO_MEMORY;
  }
  status = volume->device.read_blocks(volume->device.context,
                                      volume->superblock.allocation_bitmap_start,
                                      (uint32_t)expected_bitmap_blocks,
                                      bitmap,
                                      bitmap_size);
  for (uint64_t block = 0; ZiSucceeded(status) && block < volume->superblock.total_blocks;
       ++block) {
    bool allocated = false;
    status = ZiFsAllocationBitQuery(bitmap, bitmap_size, block, &allocated);
    if (ZiFailed(status)) {
      break;
    }
    if (allocated) {
      ++report->allocated_blocks;
      if (expected_blocks[block] == 0) {
        ++report->unreferenced_allocated_blocks;
      }
    } else {
      ++report->free_blocks;
      if (expected_blocks[block] != 0) {
        status = ZI_STATUS_CORRUPT_FILESYSTEM;
      }
    }
  }
  free(bitmap);
  return status;
}

static ZiStatus mark_metadata_blocks(const ZiFsSuperblock* superblock,
                                     unsigned char* expected_blocks) {
  const uint64_t ranges[][2] = {
      {0, 1},
      {superblock->record_table_start, superblock->record_table_blocks},
      {superblock->directory_table_start, superblock->directory_table_blocks},
      {superblock->allocation_bitmap_start, superblock->allocation_bitmap_blocks},
      {superblock->journal_start, superblock->journal_blocks},
      {superblock->security_table_start, superblock->security_table_blocks},
      {superblock->backup_superblock, 1},
  };
  for (size_t index = 0; index < sizeof ranges / sizeof ranges[0]; ++index) {
    ZiStatus status = mark_expected_range(expected_blocks,
                                          superblock->total_blocks,
                                          ranges[index][0],
                                          ranges[index][1],
                                          1,
                                          true);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus mark_expected_range(unsigned char* expected_blocks,
                                    uint64_t total_blocks,
                                    uint64_t first_block,
                                    uint64_t block_count,
                                    unsigned char marker,
                                    bool reject_existing) {
  if (expected_blocks == NULL || marker == 0 || block_count == 0 || first_block >= total_blocks ||
      block_count > total_blocks - first_block) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  for (uint64_t offset = 0; offset < block_count; ++offset) {
    unsigned char* existing = &expected_blocks[first_block + offset];
    if (reject_existing && *existing != 0) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    *existing = marker;
  }
  return ZI_STATUS_SUCCESS;
}

static bool
security_id_exists(const uint64_t* security_ids, size_t security_id_count, uint64_t security_id) {
  for (size_t index = 0; index < security_id_count; ++index) {
    if (security_ids[index] == security_id) {
      return true;
    }
  }
  return false;
}

static bool bytes_are_zero(const void* data, size_t size) {
  const unsigned char* bytes = data;
  for (size_t index = 0; index < size; ++index) {
    if (bytes[index] != 0) {
      return false;
    }
  }
  return true;
}

static int compare_u64(const void* left, const void* right) {
  uint64_t left_value = *(const uint64_t*)left;
  uint64_t right_value = *(const uint64_t*)right;
  if (left_value < right_value) {
    return -1;
  }
  if (left_value > right_value) {
    return 1;
  }
  return 0;
}

static bool journal_header_state_equal(const ZiFsJournalHeader* left,
                                       const ZiFsJournalHeader* right) {
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

// The single-writer journal contract deliberately validates the whole declared transaction.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static ZiStatus validate_journal_record_sequence(const JournalRecordSummary* records,
                                                 uint64_t record_count,
                                                 const ZiFsJournalHeader* header,
                                                 ZiFsInspectReport* report) {
  if (record_count < 3 || records[0].record.record_type != ZI_FS_JOURNAL_RECORD_BEGIN) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  const ZiFsJournalRecord* begin = &records[0].record;
  if (begin->image_count == 0 || begin->image_count > ZI_FS_JOURNAL_MAXIMUM_BLOCK_IMAGES ||
      record_count != (uint64_t)begin->image_count + 2u || begin->source_generation == UINT64_MAX ||
      begin->target_generation != begin->source_generation + 1u) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  ++report->journal_begin_records;
  uint64_t targets[ZI_FS_JOURNAL_MAXIMUM_BLOCK_IMAGES] = {0};
  uint32_t transaction_checksum = 0;
  for (uint32_t index = 0; index < begin->image_count; ++index) {
    const ZiFsJournalRecord* image = &records[index + 1u].record;
    if (image->record_type != ZI_FS_JOURNAL_RECORD_BLOCK_IMAGE ||
        image->transaction_id != begin->transaction_id ||
        image->source_generation != begin->source_generation ||
        image->target_generation != begin->target_generation ||
        image->sequence != begin->sequence + index + 1u) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    for (uint32_t prior = 0; prior < index; ++prior) {
      if (targets[prior] == image->target_block) {
        return ZI_STATUS_CORRUPT_FILESYSTEM;
      }
    }
    targets[index] = image->target_block;
    ZiStatus status =
        ZiFsJournalExtendTransactionChecksum(transaction_checksum, image, &transaction_checksum);
    if (ZiFailed(status)) {
      return status;
    }
    ++report->journal_block_images;
  }
  const ZiFsJournalRecord* commit = &records[record_count - 1u].record;
  if (commit->record_type != ZI_FS_JOURNAL_RECORD_COMMIT ||
      commit->transaction_id != begin->transaction_id ||
      commit->source_generation != begin->source_generation ||
      commit->target_generation != begin->target_generation ||
      commit->sequence != begin->sequence + begin->image_count + 1u ||
      commit->transaction_checksum != transaction_checksum ||
      header->last_committed_transaction != begin->transaction_id ||
      commit->sequence == UINT64_MAX || header->next_sequence != commit->sequence + 1u) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  ++report->journal_commit_records;
  return ZI_STATUS_SUCCESS;
}

static void preserve_first_failure(ZiStatus candidate, ZiStatus* first_failure) {
  if (ZiFailed(candidate) && ZiSucceeded(*first_failure)) {
    *first_failure = candidate;
  }
}
