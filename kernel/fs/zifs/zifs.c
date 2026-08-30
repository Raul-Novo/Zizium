// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/zifs.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/block.h"
#include "zi/byte_order.h"
#include "zi/crc32c.h"
#include "zi/path.h"
#include "zi/unicode.h"
#include "zi/zifs_journal.h"
#include "zi/zifs_security.h"
#include "zizium/status.h"
#include "zizium/types.h"

enum {
  ZIFS_SUPER_MAGIC_OFFSET = 0,
  ZIFS_SUPER_MAJOR_OFFSET = 8,
  ZIFS_SUPER_MINOR_OFFSET = 10,
  ZIFS_SUPER_HEADER_SIZE_OFFSET = 12,
  ZIFS_SUPER_BLOCK_SHIFT_OFFSET = 14,
  ZIFS_SUPER_CHECKSUM_TYPE_OFFSET = 15,
  ZIFS_SUPER_COMPATIBLE_OFFSET = 16,
  ZIFS_SUPER_READ_ONLY_COMPATIBLE_OFFSET = 24,
  ZIFS_SUPER_INCOMPATIBLE_OFFSET = 32,
  ZIFS_SUPER_UUID_OFFSET = 40,
  ZIFS_SUPER_GENERATION_OFFSET = 56,
  ZIFS_SUPER_TOTAL_BLOCKS_OFFSET = 64,
  ZIFS_SUPER_ROOT_RECORD_OFFSET = 72,
  ZIFS_SUPER_RECORD_TABLE_START_OFFSET = 80,
  ZIFS_SUPER_RECORD_TABLE_BLOCKS_OFFSET = 88,
  ZIFS_SUPER_DIRECTORY_TABLE_START_OFFSET = 96,
  ZIFS_SUPER_DIRECTORY_TABLE_BLOCKS_OFFSET = 104,
  ZIFS_SUPER_BITMAP_START_OFFSET = 112,
  ZIFS_SUPER_BITMAP_BLOCKS_OFFSET = 120,
  ZIFS_SUPER_JOURNAL_START_OFFSET = 128,
  ZIFS_SUPER_JOURNAL_BLOCKS_OFFSET = 136,
  ZIFS_SUPER_SECURITY_START_OFFSET = 144,
  ZIFS_SUPER_SECURITY_BLOCKS_OFFSET = 152,
  ZIFS_SUPER_BACKUP_OFFSET = 160,
  ZIFS_SUPER_NAME_SIZE_OFFSET = 168,
  ZIFS_SUPER_NAME_OFFSET = 172,
  ZIFS_SUPER_LAST_COMMITTED_TRANSACTION_OFFSET = 236,
  ZIFS_SUPER_STATE_FLAGS_OFFSET = 244,
  ZIFS_SUPER_CHECKSUM_OFFSET = 252,
  ZIFS_RECORD_MAGIC_OFFSET = 0,
  ZIFS_RECORD_VERSION_OFFSET = 4,
  ZIFS_RECORD_TYPE_OFFSET = 6,
  ZIFS_RECORD_FILE_ID_OFFSET = 8,
  ZIFS_RECORD_PARENT_ID_OFFSET = 16,
  ZIFS_RECORD_FLAGS_OFFSET = 24,
  ZIFS_RECORD_FILE_SIZE_OFFSET = 32,
  ZIFS_RECORD_ALLOCATED_SIZE_OFFSET = 40,
  ZIFS_RECORD_SECURITY_ID_OFFSET = 48,
  ZIFS_RECORD_EXTENT_COUNT_OFFSET = 56,
  ZIFS_RECORD_EXTENTS_OFFSET = 64,
  ZIFS_RECORD_CREATED_TIME_OFFSET = 192,
  ZIFS_RECORD_MODIFIED_TIME_OFFSET = 200,
  ZIFS_RECORD_CHANGED_TIME_OFFSET = 208,
  ZIFS_RECORD_ACCESSED_TIME_OFFSET = 216,
  ZIFS_RECORD_DIRECTORY_BLOCK_OFFSET = 224,
  ZIFS_RECORD_CHECKSUM_OFFSET = 252,
  ZIFS_DIRECTORY_MAGIC_OFFSET = 0,
  ZIFS_DIRECTORY_VERSION_OFFSET = 4,
  ZIFS_DIRECTORY_HEADER_SIZE_OFFSET = 6,
  ZIFS_DIRECTORY_FILE_ID_OFFSET = 8,
  ZIFS_DIRECTORY_ENTRY_COUNT_OFFSET = 16,
  ZIFS_DIRECTORY_USED_BYTES_OFFSET = 20,
  ZIFS_DIRECTORY_GENERATION_OFFSET = 24,
  ZIFS_DIRECTORY_CHECKSUM_OFFSET = 60,
};

static const unsigned char k_superblock_magic[8] = {'Z', 'i', 'F', 'S', '\r', '\n', 0x1a, '\n'};
static const unsigned char k_record_magic[4] = {'Z', 'I', 'F', 'R'};
static const unsigned char k_directory_magic[4] = {'Z', 'I', 'D', 'R'};

typedef struct MountSelection {
  ZiFsSuperblock superblock;
  uint32_t mounted_from_backup;
  bool redundancy_mismatch;
} MountSelection;

static bool superblock_ranges_are_valid(const ZiFsSuperblock* superblock);
static ZiStatus validate_file_record_shape(const ZiFsFileRecord* record);
static bool extent_overlaps_metadata(const ZiFsSuperblock* superblock,
                                     uint64_t first_block,
                                     uint64_t block_count);
static bool ranges_overlap(uint64_t first_start,
                           uint64_t first_count,
                           uint64_t second_start,
                           uint64_t second_count);
static ZiStatus validate_directory_block(const void* block, size_t block_size);
static ZiStatus validate_directory_name(ZiStringView name);
static void update_directory_checksum(unsigned char* bytes);
static size_t align_up_eight(size_t value);
static ZiStatus read_directory_block(const ZiFsVolume* volume,
                                     uint64_t block_number,
                                     void* block_buffer,
                                     size_t block_buffer_size);
static bool superblocks_have_same_identity(const ZiFsSuperblock* left, const ZiFsSuperblock* right);
static bool superblocks_have_same_recovery_state(const ZiFsSuperblock* left,
                                                 const ZiFsSuperblock* right);
static bool mount_device_contract_is_valid(const ZiBlockDevice* device,
                                           const void* block_buffer,
                                           size_t block_buffer_size,
                                           const ZiFsVolume* out_volume);
static ZiStatus read_mount_superblock(const ZiBlockDevice* device,
                                      uint64_t block_number,
                                      void* block_buffer,
                                      size_t block_buffer_size,
                                      ZiFsSuperblock* out_superblock);
static ZiStatus select_mount_superblock(const ZiFsSuperblock* primary,
                                        ZiStatus primary_status,
                                        const ZiFsSuperblock* backup,
                                        ZiStatus backup_status,
                                        MountSelection* out_selection);
static bool device_supports_zifs_writes(const ZiBlockDevice* device);
static bool superblock_uses_journal(const ZiFsSuperblock* superblock);
static void
assess_journal_mount_state(void* block_buffer, size_t block_buffer_size, ZiFsVolume* volume);

ZiStatus ZiFsEncodeSuperblock(const ZiFsSuperblock* superblock, void* output, size_t output_size) {
  if (superblock == NULL || output == NULL || output_size < ZI_FS_BLOCK_SIZE ||
      superblock->volume_name_size > ZI_FS_MAX_VOLUME_NAME_BYTES ||
      !superblock_ranges_are_valid(superblock)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  unsigned char* bytes = output;
  zi_memory_zero(bytes, output_size);
  zi_memory_copy(bytes + ZIFS_SUPER_MAGIC_OFFSET, k_superblock_magic, sizeof k_superblock_magic);
  zi_write_u16_le(bytes + ZIFS_SUPER_MAJOR_OFFSET, superblock->format_major);
  zi_write_u16_le(bytes + ZIFS_SUPER_MINOR_OFFSET, superblock->format_minor);
  zi_write_u16_le(bytes + ZIFS_SUPER_HEADER_SIZE_OFFSET, ZI_FS_SUPERBLOCK_SIZE);
  bytes[ZIFS_SUPER_BLOCK_SHIFT_OFFSET] = superblock->block_shift;
  bytes[ZIFS_SUPER_CHECKSUM_TYPE_OFFSET] = superblock->checksum_type;
  zi_write_u64_le(bytes + ZIFS_SUPER_COMPATIBLE_OFFSET, superblock->compatible_features);
  zi_write_u64_le(bytes + ZIFS_SUPER_READ_ONLY_COMPATIBLE_OFFSET,
                  superblock->read_only_compatible_features);
  zi_write_u64_le(bytes + ZIFS_SUPER_INCOMPATIBLE_OFFSET, superblock->incompatible_features);
  zi_memory_copy(bytes + ZIFS_SUPER_UUID_OFFSET,
                 superblock->volume_uuid,
                 sizeof superblock->volume_uuid);
  zi_write_u64_le(bytes + ZIFS_SUPER_GENERATION_OFFSET, superblock->generation);
  zi_write_u64_le(bytes + ZIFS_SUPER_TOTAL_BLOCKS_OFFSET, superblock->total_blocks);
  zi_write_u64_le(bytes + ZIFS_SUPER_ROOT_RECORD_OFFSET, superblock->root_record_index);
  zi_write_u64_le(bytes + ZIFS_SUPER_RECORD_TABLE_START_OFFSET, superblock->record_table_start);
  zi_write_u64_le(bytes + ZIFS_SUPER_RECORD_TABLE_BLOCKS_OFFSET, superblock->record_table_blocks);
  zi_write_u64_le(bytes + ZIFS_SUPER_DIRECTORY_TABLE_START_OFFSET,
                  superblock->directory_table_start);
  zi_write_u64_le(bytes + ZIFS_SUPER_DIRECTORY_TABLE_BLOCKS_OFFSET,
                  superblock->directory_table_blocks);
  zi_write_u64_le(bytes + ZIFS_SUPER_BITMAP_START_OFFSET, superblock->allocation_bitmap_start);
  zi_write_u64_le(bytes + ZIFS_SUPER_BITMAP_BLOCKS_OFFSET, superblock->allocation_bitmap_blocks);
  zi_write_u64_le(bytes + ZIFS_SUPER_JOURNAL_START_OFFSET, superblock->journal_start);
  zi_write_u64_le(bytes + ZIFS_SUPER_JOURNAL_BLOCKS_OFFSET, superblock->journal_blocks);
  zi_write_u64_le(bytes + ZIFS_SUPER_SECURITY_START_OFFSET, superblock->security_table_start);
  zi_write_u64_le(bytes + ZIFS_SUPER_SECURITY_BLOCKS_OFFSET, superblock->security_table_blocks);
  zi_write_u64_le(bytes + ZIFS_SUPER_BACKUP_OFFSET, superblock->backup_superblock);
  zi_write_u16_le(bytes + ZIFS_SUPER_NAME_SIZE_OFFSET, superblock->volume_name_size);
  zi_memory_copy(bytes + ZIFS_SUPER_NAME_OFFSET,
                 superblock->volume_name,
                 superblock->volume_name_size);
  zi_write_u64_le(bytes + ZIFS_SUPER_LAST_COMMITTED_TRANSACTION_OFFSET,
                  superblock->last_committed_transaction);
  zi_write_u32_le(bytes + ZIFS_SUPER_STATE_FLAGS_OFFSET, superblock->state_flags);
  uint32_t checksum = zi_crc32c(0, bytes, ZIFS_SUPER_CHECKSUM_OFFSET);
  zi_write_u32_le(bytes + ZIFS_SUPER_CHECKSUM_OFFSET, checksum);
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsDecodeSuperblock(const void* data, size_t data_size, ZiFsSuperblock* out_superblock) {
  if (data == NULL || out_superblock == NULL || data_size < ZI_FS_SUPERBLOCK_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const unsigned char* bytes = data;
  if (zi_memory_compare(bytes + ZIFS_SUPER_MAGIC_OFFSET,
                        k_superblock_magic,
                        sizeof k_superblock_magic) != 0) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  if (zi_read_u16_le(bytes + ZIFS_SUPER_HEADER_SIZE_OFFSET) != ZI_FS_SUPERBLOCK_SIZE) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  uint32_t stored_checksum = zi_read_u32_le(bytes + ZIFS_SUPER_CHECKSUM_OFFSET);
  uint32_t calculated_checksum = zi_crc32c(0, bytes, ZIFS_SUPER_CHECKSUM_OFFSET);
  if (stored_checksum != calculated_checksum) {
    return ZI_STATUS_CHECKSUM_MISMATCH;
  }

  zi_memory_zero(out_superblock, sizeof *out_superblock);
  out_superblock->format_major = zi_read_u16_le(bytes + ZIFS_SUPER_MAJOR_OFFSET);
  out_superblock->format_minor = zi_read_u16_le(bytes + ZIFS_SUPER_MINOR_OFFSET);
  out_superblock->block_shift = bytes[ZIFS_SUPER_BLOCK_SHIFT_OFFSET];
  out_superblock->checksum_type = bytes[ZIFS_SUPER_CHECKSUM_TYPE_OFFSET];
  out_superblock->compatible_features = zi_read_u64_le(bytes + ZIFS_SUPER_COMPATIBLE_OFFSET);
  out_superblock->read_only_compatible_features =
      zi_read_u64_le(bytes + ZIFS_SUPER_READ_ONLY_COMPATIBLE_OFFSET);
  out_superblock->incompatible_features = zi_read_u64_le(bytes + ZIFS_SUPER_INCOMPATIBLE_OFFSET);
  zi_memory_copy(out_superblock->volume_uuid,
                 bytes + ZIFS_SUPER_UUID_OFFSET,
                 sizeof out_superblock->volume_uuid);
  out_superblock->generation = zi_read_u64_le(bytes + ZIFS_SUPER_GENERATION_OFFSET);
  out_superblock->total_blocks = zi_read_u64_le(bytes + ZIFS_SUPER_TOTAL_BLOCKS_OFFSET);
  out_superblock->root_record_index = zi_read_u64_le(bytes + ZIFS_SUPER_ROOT_RECORD_OFFSET);
  out_superblock->record_table_start = zi_read_u64_le(bytes + ZIFS_SUPER_RECORD_TABLE_START_OFFSET);
  out_superblock->record_table_blocks =
      zi_read_u64_le(bytes + ZIFS_SUPER_RECORD_TABLE_BLOCKS_OFFSET);
  out_superblock->directory_table_start =
      zi_read_u64_le(bytes + ZIFS_SUPER_DIRECTORY_TABLE_START_OFFSET);
  out_superblock->directory_table_blocks =
      zi_read_u64_le(bytes + ZIFS_SUPER_DIRECTORY_TABLE_BLOCKS_OFFSET);
  out_superblock->allocation_bitmap_start = zi_read_u64_le(bytes + ZIFS_SUPER_BITMAP_START_OFFSET);
  out_superblock->allocation_bitmap_blocks =
      zi_read_u64_le(bytes + ZIFS_SUPER_BITMAP_BLOCKS_OFFSET);
  out_superblock->journal_start = zi_read_u64_le(bytes + ZIFS_SUPER_JOURNAL_START_OFFSET);
  out_superblock->journal_blocks = zi_read_u64_le(bytes + ZIFS_SUPER_JOURNAL_BLOCKS_OFFSET);
  out_superblock->security_table_start = zi_read_u64_le(bytes + ZIFS_SUPER_SECURITY_START_OFFSET);
  out_superblock->security_table_blocks = zi_read_u64_le(bytes + ZIFS_SUPER_SECURITY_BLOCKS_OFFSET);
  out_superblock->backup_superblock = zi_read_u64_le(bytes + ZIFS_SUPER_BACKUP_OFFSET);
  out_superblock->last_committed_transaction =
      zi_read_u64_le(bytes + ZIFS_SUPER_LAST_COMMITTED_TRANSACTION_OFFSET);
  out_superblock->state_flags = zi_read_u32_le(bytes + ZIFS_SUPER_STATE_FLAGS_OFFSET);
  out_superblock->volume_name_size = zi_read_u16_le(bytes + ZIFS_SUPER_NAME_SIZE_OFFSET);
  if (out_superblock->volume_name_size > ZI_FS_MAX_VOLUME_NAME_BYTES) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  zi_memory_copy(out_superblock->volume_name,
                 bytes + ZIFS_SUPER_NAME_OFFSET,
                 out_superblock->volume_name_size);
  out_superblock->volume_name[out_superblock->volume_name_size] = '\0';

  if (out_superblock->format_major != ZI_FS_FORMAT_MAJOR ||
      out_superblock->format_minor > ZI_FS_FORMAT_MINOR ||
      out_superblock->block_shift != ZI_FS_BLOCK_SHIFT || out_superblock->checksum_type != 1 ||
      out_superblock->generation == 0 ||
      (out_superblock->state_flags & ~ZI_FS_SUPERBLOCK_STATE_SUPPORTED) != 0 ||
      !superblock_ranges_are_valid(out_superblock)) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  return zi_utf8_validate(out_superblock->volume_name, out_superblock->volume_name_size);
}

ZiStatus ZiFsEncodeFileRecord(const ZiFsFileRecord* record, void* output, size_t output_size) {
  if (record == NULL || output == NULL || output_size < ZI_FS_FILE_RECORD_SIZE ||
      ZiFailed(validate_file_record_shape(record))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  unsigned char* bytes = output;
  zi_memory_zero(bytes, ZI_FS_FILE_RECORD_SIZE);
  zi_memory_copy(bytes + ZIFS_RECORD_MAGIC_OFFSET, k_record_magic, sizeof k_record_magic);
  zi_write_u16_le(bytes + ZIFS_RECORD_VERSION_OFFSET, 1);
  zi_write_u16_le(bytes + ZIFS_RECORD_TYPE_OFFSET, record->file_type);
  zi_write_u64_le(bytes + ZIFS_RECORD_FILE_ID_OFFSET, record->file_id);
  zi_write_u64_le(bytes + ZIFS_RECORD_PARENT_ID_OFFSET, record->parent_file_id);
  zi_write_u64_le(bytes + ZIFS_RECORD_FLAGS_OFFSET, record->flags);
  zi_write_u64_le(bytes + ZIFS_RECORD_FILE_SIZE_OFFSET, record->file_size);
  zi_write_u64_le(bytes + ZIFS_RECORD_ALLOCATED_SIZE_OFFSET, record->allocated_size);
  zi_write_u64_le(bytes + ZIFS_RECORD_SECURITY_ID_OFFSET, record->security_id);
  zi_write_u32_le(bytes + ZIFS_RECORD_EXTENT_COUNT_OFFSET, record->extent_count);
  for (size_t index = 0; index < ZI_FS_INLINE_EXTENT_COUNT; ++index) {
    size_t offset = ZIFS_RECORD_EXTENTS_OFFSET + (index * 32u);
    zi_write_u64_le(bytes + offset, record->extents[index].logical_block);
    zi_write_u64_le(bytes + offset + 8, record->extents[index].physical_block);
    zi_write_u64_le(bytes + offset + 16, record->extents[index].block_count);
    zi_write_u32_le(bytes + offset + 24, record->extents[index].flags);
    zi_write_u32_le(bytes + offset + 28, record->extents[index].reserved);
  }
  zi_write_u64_le(bytes + ZIFS_RECORD_CREATED_TIME_OFFSET, record->created_time);
  zi_write_u64_le(bytes + ZIFS_RECORD_MODIFIED_TIME_OFFSET, record->modified_time);
  zi_write_u64_le(bytes + ZIFS_RECORD_CHANGED_TIME_OFFSET, record->changed_time);
  zi_write_u64_le(bytes + ZIFS_RECORD_ACCESSED_TIME_OFFSET, record->accessed_time);
  zi_write_u64_le(bytes + ZIFS_RECORD_DIRECTORY_BLOCK_OFFSET, record->directory_block);
  uint32_t checksum = zi_crc32c(0, bytes, ZIFS_RECORD_CHECKSUM_OFFSET);
  zi_write_u32_le(bytes + ZIFS_RECORD_CHECKSUM_OFFSET, checksum);
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsDecodeFileRecord(const void* data, size_t data_size, ZiFsFileRecord* out_record) {
  if (data == NULL || out_record == NULL || data_size < ZI_FS_FILE_RECORD_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const unsigned char* bytes = data;
  if (zi_memory_compare(bytes + ZIFS_RECORD_MAGIC_OFFSET, k_record_magic, sizeof k_record_magic) !=
          0 ||
      zi_read_u16_le(bytes + ZIFS_RECORD_VERSION_OFFSET) != 1) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  if (zi_read_u32_le(bytes + ZIFS_RECORD_CHECKSUM_OFFSET) !=
      zi_crc32c(0, bytes, ZIFS_RECORD_CHECKSUM_OFFSET)) {
    return ZI_STATUS_CHECKSUM_MISMATCH;
  }

  zi_memory_zero(out_record, sizeof *out_record);
  out_record->file_type = zi_read_u16_le(bytes + ZIFS_RECORD_TYPE_OFFSET);
  out_record->file_id = zi_read_u64_le(bytes + ZIFS_RECORD_FILE_ID_OFFSET);
  out_record->parent_file_id = zi_read_u64_le(bytes + ZIFS_RECORD_PARENT_ID_OFFSET);
  out_record->flags = zi_read_u64_le(bytes + ZIFS_RECORD_FLAGS_OFFSET);
  out_record->file_size = zi_read_u64_le(bytes + ZIFS_RECORD_FILE_SIZE_OFFSET);
  out_record->allocated_size = zi_read_u64_le(bytes + ZIFS_RECORD_ALLOCATED_SIZE_OFFSET);
  out_record->security_id = zi_read_u64_le(bytes + ZIFS_RECORD_SECURITY_ID_OFFSET);
  out_record->extent_count = zi_read_u32_le(bytes + ZIFS_RECORD_EXTENT_COUNT_OFFSET);
  if (out_record->extent_count > ZI_FS_INLINE_EXTENT_COUNT) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  for (size_t index = 0; index < ZI_FS_INLINE_EXTENT_COUNT; ++index) {
    size_t offset = ZIFS_RECORD_EXTENTS_OFFSET + (index * 32u);
    out_record->extents[index].logical_block = zi_read_u64_le(bytes + offset);
    out_record->extents[index].physical_block = zi_read_u64_le(bytes + offset + 8);
    out_record->extents[index].block_count = zi_read_u64_le(bytes + offset + 16);
    out_record->extents[index].flags = zi_read_u32_le(bytes + offset + 24);
    out_record->extents[index].reserved = zi_read_u32_le(bytes + offset + 28);
  }
  out_record->created_time = zi_read_u64_le(bytes + ZIFS_RECORD_CREATED_TIME_OFFSET);
  out_record->modified_time = zi_read_u64_le(bytes + ZIFS_RECORD_MODIFIED_TIME_OFFSET);
  out_record->changed_time = zi_read_u64_le(bytes + ZIFS_RECORD_CHANGED_TIME_OFFSET);
  out_record->accessed_time = zi_read_u64_le(bytes + ZIFS_RECORD_ACCESSED_TIME_OFFSET);
  out_record->directory_block = zi_read_u64_le(bytes + ZIFS_RECORD_DIRECTORY_BLOCK_OFFSET);
  if (out_record->file_id == 0 || out_record->file_type < ZI_FS_FILE_TYPE_REGULAR ||
      out_record->file_type > ZI_FS_FILE_TYPE_DEVICE) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  ZiStatus status = validate_file_record_shape(out_record);
  if (ZiFailed(status)) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsInitialiseDirectoryBlock(void* block,
                                      size_t block_size,
                                      uint64_t directory_file_id,
                                      uint64_t generation) {
  if (block == NULL || block_size < ZI_FS_BLOCK_SIZE || directory_file_id == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char* bytes = block;
  zi_memory_zero(bytes, ZI_FS_BLOCK_SIZE);
  zi_memory_copy(bytes + ZIFS_DIRECTORY_MAGIC_OFFSET, k_directory_magic, sizeof k_directory_magic);
  zi_write_u16_le(bytes + ZIFS_DIRECTORY_VERSION_OFFSET, 1);
  zi_write_u16_le(bytes + ZIFS_DIRECTORY_HEADER_SIZE_OFFSET, ZI_FS_DIRECTORY_HEADER_SIZE);
  zi_write_u64_le(bytes + ZIFS_DIRECTORY_FILE_ID_OFFSET, directory_file_id);
  zi_write_u32_le(bytes + ZIFS_DIRECTORY_ENTRY_COUNT_OFFSET, 0);
  zi_write_u32_le(bytes + ZIFS_DIRECTORY_USED_BYTES_OFFSET, ZI_FS_DIRECTORY_HEADER_SIZE);
  zi_write_u64_le(bytes + ZIFS_DIRECTORY_GENERATION_OFFSET, generation);
  zi_write_u32_le(bytes + ZIFS_DIRECTORY_CHECKSUM_OFFSET, 0);
  zi_write_u32_le(bytes + ZIFS_DIRECTORY_CHECKSUM_OFFSET, zi_crc32c(0, bytes, ZI_FS_BLOCK_SIZE));
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsValidateDirectoryBlock(const void* block,
                                    size_t block_size,
                                    uint64_t expected_directory_file_id) {
  if (expected_directory_file_id == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_directory_block(block, block_size);
  if (ZiFailed(status)) {
    return status;
  }
  const unsigned char* bytes = block;
  return zi_read_u64_le(bytes + ZIFS_DIRECTORY_FILE_ID_OFFSET) == expected_directory_file_id
             ? ZI_STATUS_SUCCESS
             : ZI_STATUS_CORRUPT_FILESYSTEM;
}

ZiStatus ZiFsAddDirectoryEntry(void* block, size_t block_size, const ZiFsDirectoryEntry* entry) {
  if (block == NULL || entry == NULL || entry->name.data == NULL || entry->name.size == 0 ||
      entry->name.size > ZI_FS_MAX_DIRECTORY_NAME_BYTES || entry->file_id == 0 ||
      entry->file_type < ZI_FS_FILE_TYPE_REGULAR || entry->file_type > ZI_FS_FILE_TYPE_DEVICE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_directory_block(block, block_size);
  if (ZiFailed(status)) {
    return status;
  }
  status = validate_directory_name(entry->name);
  if (ZiFailed(status)) {
    return status;
  }
  ZiFsDirectoryEntry existing = {0};
  status = ZiFsFindDirectoryEntry(block, block_size, entry->name, &existing);
  if (ZiSucceeded(status)) {
    return ZI_STATUS_ALREADY_EXISTS;
  }
  if (status != ZI_STATUS_NOT_FOUND) {
    return status;
  }

  unsigned char* bytes = block;
  uint32_t used_bytes = zi_read_u32_le(bytes + ZIFS_DIRECTORY_USED_BYTES_OFFSET);
  size_t entry_size = align_up_eight(ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE + entry->name.size);
  if (entry_size > ZI_FS_BLOCK_SIZE - used_bytes) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }

  unsigned char* destination = bytes + used_bytes;
  zi_memory_zero(destination, entry_size);
  zi_write_u16_le(destination, (uint16_t)entry_size);
  zi_write_u16_le(destination + 2, (uint16_t)entry->name.size);
  zi_write_u16_le(destination + 4, entry->file_type);
  zi_write_u16_le(destination + 6, entry->flags);
  zi_write_u64_le(destination + 8, entry->file_id);
  zi_write_u64_le(destination + 16, entry->record_index);
  zi_memory_copy(destination + ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE,
                 entry->name.data,
                 entry->name.size);
  uint32_t count = zi_read_u32_le(bytes + ZIFS_DIRECTORY_ENTRY_COUNT_OFFSET);
  zi_write_u32_le(bytes + ZIFS_DIRECTORY_ENTRY_COUNT_OFFSET, count + 1u);
  zi_write_u32_le(bytes + ZIFS_DIRECTORY_USED_BYTES_OFFSET, used_bytes + (uint32_t)entry_size);
  update_directory_checksum(bytes);
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsRemoveDirectoryEntry(void* block,
                                  size_t block_size,
                                  ZiStringView name,
                                  ZiFsDirectoryEntry* out_entry) {
  if (block == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_directory_block(block, block_size);
  if (ZiFailed(status)) {
    return status;
  }
  status = validate_directory_name(name);
  if (ZiFailed(status)) {
    return status;
  }

  unsigned char* bytes = block;
  uint32_t entry_count = zi_read_u32_le(bytes + ZIFS_DIRECTORY_ENTRY_COUNT_OFFSET);
  uint32_t used_bytes = zi_read_u32_le(bytes + ZIFS_DIRECTORY_USED_BYTES_OFFSET);
  size_t found_offset = 0;
  uint16_t found_size = 0;
  ZiFsDirectoryEntry found = {0};
  size_t offset = ZI_FS_DIRECTORY_HEADER_SIZE;
  for (uint32_t index = 0; index < entry_count; ++index) {
    unsigned char* source = bytes + offset;
    uint16_t entry_size = zi_read_u16_le(source);
    uint16_t name_size = zi_read_u16_le(source + 2);
    ZiStringView candidate = {
        (const char*)source + ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE,
        name_size,
    };
    int comparison = 0;
    status = zi_path_compare_component(candidate, name, &comparison);
    if (ZiFailed(status)) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    if (comparison == 0) {
      if (found_size != 0) {
        return ZI_STATUS_CORRUPT_FILESYSTEM;
      }
      found_offset = offset;
      found_size = entry_size;
      found.file_type = zi_read_u16_le(source + 4);
      found.flags = zi_read_u16_le(source + 6);
      found.file_id = zi_read_u64_le(source + 8);
      found.record_index = zi_read_u64_le(source + 16);
      found.name = name;
    }
    offset += entry_size;
  }
  if (found_size == 0) {
    return ZI_STATUS_NOT_FOUND;
  }

  size_t trailing_size = (size_t)used_bytes - found_offset - found_size;
  for (size_t index = 0; index < trailing_size; ++index) {
    bytes[found_offset + index] = bytes[found_offset + found_size + index];
  }
  size_t new_used_bytes = (size_t)used_bytes - found_size;
  zi_memory_zero(bytes + new_used_bytes, found_size);
  zi_write_u32_le(bytes + ZIFS_DIRECTORY_ENTRY_COUNT_OFFSET, entry_count - 1u);
  zi_write_u32_le(bytes + ZIFS_DIRECTORY_USED_BYTES_OFFSET, (uint32_t)new_used_bytes);
  update_directory_checksum(bytes);
  if (out_entry != NULL) {
    *out_entry = found;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsSetDirectoryGeneration(void* block, size_t block_size, uint64_t generation) {
  if (block == NULL || generation == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_directory_block(block, block_size);
  if (ZiFailed(status)) {
    return status;
  }
  unsigned char* bytes = block;
  zi_write_u64_le(bytes + ZIFS_DIRECTORY_GENERATION_OFFSET, generation);
  update_directory_checksum(bytes);
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsFindDirectoryEntry(const void* block,
                                size_t block_size,
                                ZiStringView name,
                                ZiFsDirectoryEntry* out_entry) {
  if (block == NULL || out_entry == NULL || (name.data == NULL && name.size != 0)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_directory_block(block, block_size);
  if (ZiFailed(status)) {
    return status;
  }
  status = validate_directory_name(name);
  if (ZiFailed(status)) {
    return status;
  }

  const unsigned char* bytes = block;
  uint32_t entry_count = zi_read_u32_le(bytes + ZIFS_DIRECTORY_ENTRY_COUNT_OFFSET);
  uint32_t used_bytes = zi_read_u32_le(bytes + ZIFS_DIRECTORY_USED_BYTES_OFFSET);
  size_t offset = ZI_FS_DIRECTORY_HEADER_SIZE;
  for (uint32_t index = 0; index < entry_count; ++index) {
    if (offset > used_bytes || ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE > used_bytes - offset) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    const unsigned char* source = bytes + offset;
    uint16_t entry_size = zi_read_u16_le(source);
    uint16_t name_size = zi_read_u16_le(source + 2);
    if (entry_size < ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE || entry_size > used_bytes - offset ||
        name_size > entry_size - ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }

    ZiStringView candidate = {
        (const char*)source + ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE,
        name_size,
    };
    int comparison = 0;
    status = zi_path_compare_component(candidate, name, &comparison);
    if (ZiFailed(status)) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    if (comparison == 0) {
      out_entry->file_type = zi_read_u16_le(source + 4);
      out_entry->flags = zi_read_u16_le(source + 6);
      out_entry->file_id = zi_read_u64_le(source + 8);
      out_entry->record_index = zi_read_u64_le(source + 16);
      out_entry->name = candidate;
      return ZI_STATUS_SUCCESS;
    }
    offset += entry_size;
  }
  return ZI_STATUS_NOT_FOUND;
}

ZiStatus ZiFsMountVolume(const ZiBlockDevice* device,
                         void* block_buffer,
                         size_t block_buffer_size,
                         ZiFsVolume* out_volume) {
  if (!mount_device_contract_is_valid(device, block_buffer, block_buffer_size, out_volume)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  ZiFsSuperblock primary = {0};
  ZiFsSuperblock backup = {0};
  ZiStatus primary_status =
      read_mount_superblock(device, 0, block_buffer, block_buffer_size, &primary);
  ZiStatus backup_status = read_mount_superblock(device,
                                                 device->block_count - 1u,
                                                 block_buffer,
                                                 block_buffer_size,
                                                 &backup);
  MountSelection selection = {0};
  ZiStatus status =
      select_mount_superblock(&primary, primary_status, &backup, backup_status, &selection);
  if (ZiFailed(status)) {
    return status;
  }
  if (selection.superblock.total_blocks != device->block_count ||
      (selection.superblock.incompatible_features & ~ZI_FS_FEATURE_INCOMPAT_SUPPORTED) != 0 ||
      (selection.superblock.incompatible_features & ZI_FS_FEATURE_INCOMPAT_SECURITY_V1) == 0) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }

  zi_memory_zero(out_volume, sizeof *out_volume);
  out_volume->device = *device;
  out_volume->superblock = selection.superblock;
  out_volume->mounted_from_backup = selection.mounted_from_backup;
  if (selection.redundancy_mismatch ||
      selection.superblock.state_flags != ZI_FS_SUPERBLOCK_STATE_NONE) {
    out_volume->needs_recovery = 1;
  }
  assess_journal_mount_state(block_buffer, block_buffer_size, out_volume);
  bool supports_writes = device_supports_zifs_writes(device);
  bool journal_feature = superblock_uses_journal(&selection.superblock);
  if (!supports_writes || !journal_feature || out_volume->needs_recovery != 0) {
    out_volume->is_read_only = 1;
  }
  if (selection.superblock.state_flags != ZI_FS_SUPERBLOCK_STATE_NONE ||
      (supports_writes && out_volume->needs_recovery != 0)) {
    return ZI_STATUS_RECOVERY_REQUIRED;
  }

  status = ZiFsValidateSecurityState(out_volume, block_buffer, block_buffer_size);
  if (ZiFailed(status)) {
    return status;
  }

  ZiFsFileRecord root_record = {0};
  status = ZiFsReadFileRecord(out_volume,
                              selection.superblock.root_record_index,
                              block_buffer,
                              block_buffer_size,
                              &root_record);
  if (ZiFailed(status) || root_record.file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  return ZI_STATUS_SUCCESS;
}

static bool mount_device_contract_is_valid(const ZiBlockDevice* device,
                                           const void* block_buffer,
                                           size_t block_buffer_size,
                                           const ZiFsVolume* out_volume) {
  if (device == NULL || block_buffer == NULL || out_volume == NULL ||
      device->struct_size < sizeof *device || device->version != ZI_BLOCK_DEVICE_VERSION ||
      device->read_blocks == NULL || device->block_size != ZI_FS_BLOCK_SIZE ||
      block_buffer_size < ZI_FS_BLOCK_SIZE || device->block_count < 2) {
    return false;
  }
  if ((device->flags & ZI_BLOCK_DEVICE_WRITE_SUPPORTED) != 0 && device->write_blocks == NULL) {
    return false;
  }
  if ((device->flags & ZI_BLOCK_DEVICE_WRITE_SUPPORTED) == 0 && device->write_blocks != NULL) {
    return false;
  }
  if ((device->flags & ZI_BLOCK_DEVICE_FLUSH_SUPPORTED) != 0 && device->flush == NULL) {
    return false;
  }
  if ((device->flags & ZI_BLOCK_DEVICE_FLUSH_SUPPORTED) == 0 && device->flush != NULL) {
    return false;
  }
  if ((device->flags & ZI_BLOCK_DEVICE_READ_ONLY) != 0 &&
      (device->flags & ZI_BLOCK_DEVICE_WRITE_SUPPORTED) != 0) {
    return false;
  }
  return true;
}

static ZiStatus read_mount_superblock(const ZiBlockDevice* device,
                                      uint64_t block_number,
                                      void* block_buffer,
                                      size_t block_buffer_size,
                                      ZiFsSuperblock* out_superblock) {
  ZiStatus status =
      device->read_blocks(device->context, block_number, 1, block_buffer, block_buffer_size);
  if (ZiFailed(status)) {
    return status;
  }
  return ZiFsDecodeSuperblock(block_buffer, block_buffer_size, out_superblock);
}

static ZiStatus select_mount_superblock(const ZiFsSuperblock* primary,
                                        ZiStatus primary_status,
                                        const ZiFsSuperblock* backup,
                                        ZiStatus backup_status,
                                        MountSelection* out_selection) {
  if (ZiFailed(primary_status) && ZiFailed(backup_status)) {
    return backup_status;
  }
  out_selection->superblock = *primary;
  if (ZiFailed(primary_status)) {
    out_selection->superblock = *backup;
    out_selection->mounted_from_backup = 1;
    out_selection->redundancy_mismatch = true;
    return ZI_STATUS_SUCCESS;
  }
  if (ZiFailed(backup_status)) {
    out_selection->redundancy_mismatch = true;
    return ZI_STATUS_SUCCESS;
  }
  if (!superblocks_have_same_identity(primary, backup)) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  if (backup->generation > primary->generation ||
      (backup->generation == primary->generation &&
       backup->state_flags == ZI_FS_SUPERBLOCK_STATE_NONE &&
       primary->state_flags != ZI_FS_SUPERBLOCK_STATE_NONE)) {
    out_selection->superblock = *backup;
    out_selection->mounted_from_backup = 1;
  }
  if (!superblocks_have_same_recovery_state(primary, backup)) {
    out_selection->redundancy_mismatch = true;
  }
  return ZI_STATUS_SUCCESS;
}

static bool device_supports_zifs_writes(const ZiBlockDevice* device) {
  return (device->flags & (ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED)) ==
         (ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED);
}

static bool superblock_uses_journal(const ZiFsSuperblock* superblock) {
  return (superblock->incompatible_features & ZI_FS_FEATURE_INCOMPAT_JOURNAL_V1) != 0;
}

static void
assess_journal_mount_state(void* block_buffer, size_t block_buffer_size, ZiFsVolume* volume) {
  if (!superblock_uses_journal(&volume->superblock)) {
    return;
  }
  uint64_t expected_capacity = 0;
  ZiFsJournalHeader journal_header = {0};
  uint32_t journal_copy = 0;
  ZiStatus status =
      ZiFsJournalRecordCapacity(volume->superblock.journal_blocks, &expected_capacity);
  if (ZiSucceeded(status)) {
    status = ZiFsLoadJournalHeader(&volume->device,
                                   volume->superblock.journal_start,
                                   block_buffer,
                                   block_buffer_size,
                                   &journal_header,
                                   &journal_copy);
  }
  if (ZiFailed(status) || journal_header.record_capacity != expected_capacity) {
    volume->needs_recovery = 1;
    return;
  }
  volume->journal_header_valid = 1;
  if (journal_header.volume_generation != volume->superblock.generation ||
      journal_header.last_checkpoint_transaction != volume->superblock.last_committed_transaction) {
    volume->needs_recovery = 1;
  }
}

ZiStatus ZiFsReadFileRecord(const ZiFsVolume* volume,
                            uint64_t record_index,
                            void* block_buffer,
                            size_t block_buffer_size,
                            ZiFsFileRecord* out_record) {
  if (volume == NULL || block_buffer == NULL || out_record == NULL ||
      block_buffer_size < ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t records_per_block = ZI_FS_BLOCK_SIZE / ZI_FS_FILE_RECORD_SIZE;
  uint64_t table_block_offset = record_index / records_per_block;
  if (table_block_offset >= volume->superblock.record_table_blocks) {
    return ZI_STATUS_NOT_FOUND;
  }
  uint64_t block_number = volume->superblock.record_table_start + table_block_offset;
  ZiStatus status = volume->device.read_blocks(volume->device.context,
                                               block_number,
                                               1,
                                               block_buffer,
                                               block_buffer_size);
  if (ZiFailed(status)) {
    return status;
  }
  size_t record_offset = (size_t)(record_index % records_per_block) * ZI_FS_FILE_RECORD_SIZE;
  status = ZiFsDecodeFileRecord((unsigned char*)block_buffer + record_offset,
                                ZI_FS_FILE_RECORD_SIZE,
                                out_record);
  if (ZiFailed(status)) {
    return status;
  }
  return ZiFsValidateFileRecord(volume, out_record);
}

// Extent validation and bounded partial reads remain together to keep every trust check visible.
// NOLINTNEXTLINE(readability-function-size)
ZiStatus ZiFsReadFile(const ZiFsVolume* volume,
                      const ZiFsFileRecord* record,
                      uint64_t offset,
                      void* output,
                      size_t output_size,
                      size_t* out_bytes_read,
                      void* block_buffer,
                      size_t block_buffer_size) {
  if (volume == NULL || record == NULL || out_bytes_read == NULL || block_buffer == NULL ||
      block_buffer_size < ZI_FS_BLOCK_SIZE || (output == NULL && output_size != 0)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_bytes_read = 0;
  ZiStatus status = ZiFsValidateFileRecord(volume, record);
  if (ZiFailed(status)) {
    return status;
  }
  if (record->file_type != ZI_FS_FILE_TYPE_REGULAR) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (output_size == 0 || offset >= record->file_size) {
    return ZI_STATUS_SUCCESS;
  }

  uint64_t remaining_file_bytes = record->file_size - offset;
  size_t remaining_output_bytes = output_size;
  if (remaining_file_bytes < remaining_output_bytes) {
    remaining_output_bytes = (size_t)remaining_file_bytes;
  }

  unsigned char* destination = output;
  uint64_t file_offset = offset;
  while (remaining_output_bytes != 0) {
    uint64_t logical_block = file_offset / ZI_FS_BLOCK_SIZE;
    size_t block_offset = (size_t)(file_offset % ZI_FS_BLOCK_SIZE);
    const ZiFsExtent* containing_extent = NULL;
    for (size_t index = 0; index < record->extent_count; ++index) {
      const ZiFsExtent* extent = &record->extents[index];
      if (logical_block >= extent->logical_block &&
          logical_block - extent->logical_block < extent->block_count) {
        containing_extent = extent;
        break;
      }
    }
    if (containing_extent == NULL) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }

    uint64_t physical_block =
        containing_extent->physical_block + (logical_block - containing_extent->logical_block);
    status = volume->device.read_blocks(volume->device.context,
                                        physical_block,
                                        1,
                                        block_buffer,
                                        block_buffer_size);
    if (ZiFailed(status)) {
      return status;
    }
    size_t copy_size = ZI_FS_BLOCK_SIZE - block_offset;
    if (copy_size > remaining_output_bytes) {
      copy_size = remaining_output_bytes;
    }
    zi_memory_copy(destination, (unsigned char*)block_buffer + block_offset, copy_size);
    destination += copy_size;
    remaining_output_bytes -= copy_size;
    file_offset += copy_size;
    *out_bytes_read += copy_size;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsLookupPath(const ZiFsVolume* volume,
                        const ZiParsedPath* path,
                        void* block_buffer,
                        size_t block_buffer_size,
                        ZiFsFileRecord* out_record) {
  uint64_t record_index = 0;
  return ZiFsLookupPathRecord(volume,
                              path,
                              block_buffer,
                              block_buffer_size,
                              out_record,
                              &record_index);
}

ZiStatus ZiFsLookupPathRecord(const ZiFsVolume* volume,
                              const ZiParsedPath* path,
                              void* block_buffer,
                              size_t block_buffer_size,
                              ZiFsFileRecord* out_record,
                              uint64_t* out_record_index) {
  if (volume == NULL || path == NULL || out_record == NULL || block_buffer == NULL ||
      out_record_index == NULL || block_buffer_size < ZI_FS_BLOCK_SIZE ||
      path->drive_letter != 'C') {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  uint64_t current_record_index = volume->superblock.root_record_index;
  ZiFsFileRecord current = {0};
  ZiStatus status =
      ZiFsReadFileRecord(volume, current_record_index, block_buffer, block_buffer_size, &current);
  if (ZiFailed(status)) {
    return status;
  }

  for (size_t index = 0; index < path->component_count; ++index) {
    if (current.file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
      return ZI_STATUS_NOT_FOUND;
    }
    status = read_directory_block(volume, current.directory_block, block_buffer, block_buffer_size);
    if (ZiFailed(status)) {
      return status;
    }
    status = ZiFsValidateDirectoryBlock(block_buffer, block_buffer_size, current.file_id);
    if (ZiFailed(status)) {
      return status;
    }
    ZiFsDirectoryEntry entry = {0};
    status =
        ZiFsFindDirectoryEntry(block_buffer, block_buffer_size, path->components[index], &entry);
    if (ZiFailed(status)) {
      return status;
    }
    uint64_t parent_file_id = current.file_id;
    status =
        ZiFsReadFileRecord(volume, entry.record_index, block_buffer, block_buffer_size, &current);
    if (ZiFailed(status)) {
      return status;
    }
    if (current.file_id != entry.file_id || current.file_type != entry.file_type ||
        current.parent_file_id != parent_file_id) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    current_record_index = entry.record_index;
  }

  *out_record = current;
  *out_record_index = current_record_index;
  return ZI_STATUS_SUCCESS;
}

static bool superblock_ranges_are_valid(const ZiFsSuperblock* superblock) {
  const uint64_t records_per_block = ZI_FS_BLOCK_SIZE / ZI_FS_FILE_RECORD_SIZE;
  const uint64_t bits_per_bitmap_block = (uint64_t)ZI_FS_BLOCK_SIZE * 8u;
  if (superblock->total_blocks < 2 ||
      superblock->backup_superblock != superblock->total_blocks - 1u ||
      superblock->record_table_start >= superblock->total_blocks ||
      superblock->record_table_blocks == 0 ||
      superblock->record_table_blocks > superblock->total_blocks - superblock->record_table_start ||
      superblock->directory_table_start >= superblock->total_blocks ||
      superblock->directory_table_blocks == 0 ||
      superblock->directory_table_blocks >
          superblock->total_blocks - superblock->directory_table_start ||
      superblock->allocation_bitmap_start >= superblock->total_blocks ||
      superblock->allocation_bitmap_blocks == 0 ||
      superblock->allocation_bitmap_blocks >
          superblock->total_blocks - superblock->allocation_bitmap_start ||
      superblock->journal_start >= superblock->total_blocks ||
      superblock->journal_blocks > superblock->total_blocks - superblock->journal_start ||
      superblock->security_table_start >= superblock->total_blocks ||
      superblock->security_table_blocks >
          superblock->total_blocks - superblock->security_table_start ||
      (((superblock->incompatible_features & ZI_FS_FEATURE_INCOMPAT_SECURITY_V1) != 0) &&
       (superblock->security_table_blocks == 0 ||
        superblock->security_table_blocks > ZI_FS_SECURITY_MAXIMUM_TABLE_BLOCKS)) ||
      superblock->allocation_bitmap_blocks <
          1u + ((superblock->total_blocks - 1u) / bits_per_bitmap_block) ||
      superblock->record_table_blocks > UINT64_MAX / records_per_block ||
      superblock->root_record_index >= superblock->record_table_blocks * records_per_block ||
      (((superblock->incompatible_features & ZI_FS_FEATURE_INCOMPAT_JOURNAL_V1) != 0) &&
       (superblock->journal_blocks <= 2 || (superblock->journal_blocks - 2u) % 2u != 0))) {
    return false;
  }

  const uint64_t starts[] = {
      superblock->record_table_start,
      superblock->directory_table_start,
      superblock->allocation_bitmap_start,
      superblock->journal_start,
      superblock->security_table_start,
  };
  const uint64_t counts[] = {
      superblock->record_table_blocks,
      superblock->directory_table_blocks,
      superblock->allocation_bitmap_blocks,
      superblock->journal_blocks,
      superblock->security_table_blocks,
  };
  for (size_t index = 0; index < sizeof starts / sizeof starts[0]; ++index) {
    if (ranges_overlap(starts[index], counts[index], 0, 1) ||
        ranges_overlap(starts[index], counts[index], superblock->backup_superblock, 1)) {
      return false;
    }
    for (size_t other = index + 1u; other < sizeof starts / sizeof starts[0]; ++other) {
      if (ranges_overlap(starts[index], counts[index], starts[other], counts[other])) {
        return false;
      }
    }
  }
  return true;
}

// Inline-extent structural rules intentionally remain one auditable validation sequence.
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static ZiStatus validate_file_record_shape(const ZiFsFileRecord* record) {
  if (record == NULL || record->file_id == 0 || record->security_id == 0 ||
      record->file_type < ZI_FS_FILE_TYPE_REGULAR || record->file_type > ZI_FS_FILE_TYPE_DEVICE ||
      record->extent_count > ZI_FS_INLINE_EXTENT_COUNT) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  for (size_t index = record->extent_count; index < ZI_FS_INLINE_EXTENT_COUNT; ++index) {
    const ZiFsExtent* unused = &record->extents[index];
    if (unused->logical_block != 0 || unused->physical_block != 0 || unused->block_count != 0 ||
        unused->flags != 0 || unused->reserved != 0) {
      return ZI_STATUS_INVALID_ARGUMENT;
    }
  }

  if (record->file_type == ZI_FS_FILE_TYPE_DIRECTORY) {
    return (record->file_size == 0 && record->allocated_size == 0 && record->extent_count == 0 &&
            record->directory_block != 0)
               ? ZI_STATUS_SUCCESS
               : ZI_STATUS_INVALID_ARGUMENT;
  }
  if (record->file_type != ZI_FS_FILE_TYPE_REGULAR) {
    return (record->file_size == 0 && record->allocated_size == 0 && record->extent_count == 0 &&
            record->directory_block == 0)
               ? ZI_STATUS_SUCCESS
               : ZI_STATUS_INVALID_ARGUMENT;
  }
  if (record->directory_block != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (record->file_size == 0) {
    return (record->allocated_size == 0 && record->extent_count == 0) ? ZI_STATUS_SUCCESS
                                                                      : ZI_STATUS_INVALID_ARGUMENT;
  }
  if (record->extent_count == 0 || record->allocated_size < record->file_size ||
      (record->allocated_size & (ZI_FS_BLOCK_SIZE - 1u)) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  uint64_t expected_logical_block = 0;
  uint64_t allocated_blocks = 0;
  for (size_t index = 0; index < record->extent_count; ++index) {
    const ZiFsExtent* extent = &record->extents[index];
    if (extent->block_count == 0 || extent->logical_block != expected_logical_block ||
        extent->flags != 0 || extent->reserved != 0 ||
        extent->block_count > UINT64_MAX - expected_logical_block ||
        extent->block_count > UINT64_MAX - allocated_blocks) {
      return ZI_STATUS_INVALID_ARGUMENT;
    }
    expected_logical_block += extent->block_count;
    allocated_blocks += extent->block_count;
  }
  if (allocated_blocks > (UINT64_MAX >> ZI_FS_BLOCK_SHIFT) ||
      record->allocated_size != (allocated_blocks << ZI_FS_BLOCK_SHIFT)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsValidateFileRecord(const ZiFsVolume* volume, const ZiFsFileRecord* record) {
  if (volume == NULL || record == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_file_record_shape(record);
  if (ZiFailed(status)) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  if (record->file_type == ZI_FS_FILE_TYPE_DIRECTORY) {
    uint64_t directory_end =
        volume->superblock.directory_table_start + volume->superblock.directory_table_blocks;
    return record->directory_block >= volume->superblock.directory_table_start &&
                   record->directory_block < directory_end
               ? ZI_STATUS_SUCCESS
               : ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  if (record->file_type != ZI_FS_FILE_TYPE_REGULAR) {
    return ZI_STATUS_SUCCESS;
  }

  for (size_t index = 0; index < record->extent_count; ++index) {
    const ZiFsExtent* extent = &record->extents[index];
    if (extent->physical_block >= volume->superblock.total_blocks ||
        extent->block_count > volume->superblock.total_blocks - extent->physical_block ||
        extent_overlaps_metadata(&volume->superblock,
                                 extent->physical_block,
                                 extent->block_count)) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static bool extent_overlaps_metadata(const ZiFsSuperblock* superblock,
                                     uint64_t first_block,
                                     uint64_t block_count) {
  return (bool)(ranges_overlap(first_block, block_count, 0, 1) ||
                ranges_overlap(first_block,
                               block_count,
                               superblock->record_table_start,
                               superblock->record_table_blocks) ||
                ranges_overlap(first_block,
                               block_count,
                               superblock->directory_table_start,
                               superblock->directory_table_blocks) ||
                ranges_overlap(first_block,
                               block_count,
                               superblock->allocation_bitmap_start,
                               superblock->allocation_bitmap_blocks) ||
                ranges_overlap(first_block,
                               block_count,
                               superblock->journal_start,
                               superblock->journal_blocks) ||
                ranges_overlap(first_block,
                               block_count,
                               superblock->security_table_start,
                               superblock->security_table_blocks) ||
                ranges_overlap(first_block, block_count, superblock->backup_superblock, 1));
}

static bool ranges_overlap(uint64_t first_start,
                           uint64_t first_count,
                           uint64_t second_start,
                           uint64_t second_count) {
  if (first_count == 0 || second_count == 0) {
    return false;
  }
  if (first_start <= second_start) {
    return first_count > second_start - first_start;
  }
  return second_count > first_start - second_start;
}

static ZiStatus validate_directory_block(const void* block, size_t block_size) {
  if (block == NULL || block_size < ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const unsigned char* bytes = block;
  if (zi_memory_compare(bytes + ZIFS_DIRECTORY_MAGIC_OFFSET,
                        k_directory_magic,
                        sizeof k_directory_magic) != 0 ||
      zi_read_u16_le(bytes + ZIFS_DIRECTORY_VERSION_OFFSET) != 1 ||
      zi_read_u16_le(bytes + ZIFS_DIRECTORY_HEADER_SIZE_OFFSET) != ZI_FS_DIRECTORY_HEADER_SIZE) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  uint32_t used_bytes = zi_read_u32_le(bytes + ZIFS_DIRECTORY_USED_BYTES_OFFSET);
  if (used_bytes < ZI_FS_DIRECTORY_HEADER_SIZE || used_bytes > ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }

  uint32_t stored_checksum = zi_read_u32_le(bytes + ZIFS_DIRECTORY_CHECKSUM_OFFSET);
  const unsigned char zero_checksum[4] = {0};
  uint32_t calculated_checksum = zi_crc32c(0, bytes, ZIFS_DIRECTORY_CHECKSUM_OFFSET);
  calculated_checksum = zi_crc32c(calculated_checksum, zero_checksum, sizeof zero_checksum);
  calculated_checksum =
      zi_crc32c(calculated_checksum,
                bytes + ZIFS_DIRECTORY_CHECKSUM_OFFSET + sizeof zero_checksum,
                ZI_FS_BLOCK_SIZE - ZIFS_DIRECTORY_CHECKSUM_OFFSET - sizeof zero_checksum);
  if (stored_checksum != calculated_checksum) {
    return ZI_STATUS_CHECKSUM_MISMATCH;
  }

  uint32_t entry_count = zi_read_u32_le(bytes + ZIFS_DIRECTORY_ENTRY_COUNT_OFFSET);
  size_t offset = ZI_FS_DIRECTORY_HEADER_SIZE;
  for (uint32_t index = 0; index < entry_count; ++index) {
    if (offset > used_bytes || ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE > used_bytes - offset) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    const unsigned char* entry = bytes + offset;
    uint16_t entry_size = zi_read_u16_le(entry);
    uint16_t name_size = zi_read_u16_le(entry + 2);
    uint16_t file_type = zi_read_u16_le(entry + 4);
    if (entry_size < ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE || (entry_size & 7u) != 0 ||
        entry_size > used_bytes - offset || name_size == 0 ||
        name_size > ZI_FS_MAX_DIRECTORY_NAME_BYTES ||
        name_size > entry_size - ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE ||
        file_type < ZI_FS_FILE_TYPE_REGULAR || file_type > ZI_FS_FILE_TYPE_DEVICE ||
        zi_read_u64_le(entry + 8) == 0 ||
        ZiFailed(validate_directory_name((ZiStringView){
            (const char*)entry + ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE,
            name_size,
        }))) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    size_t padding_start = ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE + name_size;
    for (size_t padding = padding_start; padding < entry_size; ++padding) {
      if (entry[padding] != 0) {
        return ZI_STATUS_CORRUPT_FILESYSTEM;
      }
    }
    offset += entry_size;
  }
  if (offset != used_bytes) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_directory_name(ZiStringView name) {
  if (name.data == NULL || name.size == 0 || name.size > ZI_FS_MAX_DIRECTORY_NAME_BYTES) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_utf8_validate(name.data, name.size);
  if (ZiFailed(status)) {
    return status;
  }
  if ((name.size == 1 && name.data[0] == '.') ||
      (name.size == 2 && name.data[0] == '.' && name.data[1] == '.')) {
    return ZI_STATUS_INVALID_PATH;
  }
  for (size_t index = 0; index < name.size; ++index) {
    if (name.data[index] == '\0' || name.data[index] == '\\' || name.data[index] == '/') {
      return ZI_STATUS_INVALID_PATH;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static void update_directory_checksum(unsigned char* bytes) {
  zi_write_u32_le(bytes + ZIFS_DIRECTORY_CHECKSUM_OFFSET, 0);
  zi_write_u32_le(bytes + ZIFS_DIRECTORY_CHECKSUM_OFFSET, zi_crc32c(0, bytes, ZI_FS_BLOCK_SIZE));
}

static size_t align_up_eight(size_t value) {
  return (value + 7u) & ~(size_t)7u;
}

static ZiStatus read_directory_block(const ZiFsVolume* volume,
                                     uint64_t block_number,
                                     void* block_buffer,
                                     size_t block_buffer_size) {
  if (block_number < volume->superblock.directory_table_start ||
      block_number >=
          volume->superblock.directory_table_start + volume->superblock.directory_table_blocks) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  return volume->device.read_blocks(volume->device.context,
                                    block_number,
                                    1,
                                    block_buffer,
                                    block_buffer_size);
}

static bool superblocks_have_same_identity(const ZiFsSuperblock* left,
                                           const ZiFsSuperblock* right) {
  return (
      bool)((left->format_major == right->format_major &&
             left->format_minor == right->format_minor && left->block_shift == right->block_shift &&
             left->checksum_type == right->checksum_type &&
             left->compatible_features == right->compatible_features &&
             left->read_only_compatible_features == right->read_only_compatible_features &&
             left->incompatible_features == right->incompatible_features &&
             zi_memory_compare(left->volume_uuid, right->volume_uuid, sizeof left->volume_uuid) ==
                 0 &&
             left->total_blocks == right->total_blocks &&
             left->root_record_index == right->root_record_index &&
             left->record_table_start == right->record_table_start &&
             left->record_table_blocks == right->record_table_blocks &&
             left->directory_table_start == right->directory_table_start &&
             left->directory_table_blocks == right->directory_table_blocks &&
             left->allocation_bitmap_start == right->allocation_bitmap_start &&
             left->allocation_bitmap_blocks == right->allocation_bitmap_blocks &&
             left->journal_start == right->journal_start &&
             left->journal_blocks == right->journal_blocks &&
             left->security_table_start == right->security_table_start &&
             left->security_table_blocks == right->security_table_blocks &&
             left->backup_superblock == right->backup_superblock &&
             left->volume_name_size == right->volume_name_size &&
             zi_memory_compare(left->volume_name, right->volume_name, left->volume_name_size) ==
                 0) != 0);
}

static bool superblocks_have_same_recovery_state(const ZiFsSuperblock* left,
                                                 const ZiFsSuperblock* right) {
  return (bool)((left->generation == right->generation && left->state_flags == right->state_flags &&
                 left->last_committed_transaction == right->last_committed_transaction) != 0);
}
