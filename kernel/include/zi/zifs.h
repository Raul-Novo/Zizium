// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/block.h"
#include "zi/path.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_FS_FORMAT_MAJOR UINT16_C(0)
#define ZI_FS_FORMAT_MINOR UINT16_C(1)
#define ZI_FS_BLOCK_SIZE UINT32_C(4096)
#define ZI_FS_BLOCK_SHIFT UINT8_C(12)
#define ZI_FS_SUPERBLOCK_SIZE 256u
#define ZI_FS_FILE_RECORD_SIZE 256u
#define ZI_FS_DIRECTORY_HEADER_SIZE 64u
#define ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE 24u
#define ZI_FS_MAX_VOLUME_NAME_BYTES 64u
#define ZI_FS_MAX_DIRECTORY_NAME_BYTES 255u
#define ZI_FS_INLINE_EXTENT_COUNT 4u
#define ZI_FS_MAX_DIRECTORY_BLOCKS 256u

#define ZI_FS_FEATURE_COMPAT_NONE UINT64_C(0)
#define ZI_FS_FEATURE_READ_ONLY_COMPAT_NONE UINT64_C(0)
#define ZI_FS_FEATURE_INCOMPAT_NONE UINT64_C(0)
#define ZI_FS_FEATURE_INCOMPAT_JOURNAL_V1 (UINT64_C(1) << 0)
#define ZI_FS_FEATURE_INCOMPAT_SECURITY_V1 (UINT64_C(1) << 1)
#define ZI_FS_FEATURE_INCOMPAT_DIRECTORY_EXTENTS_V1 (UINT64_C(1) << 2)
#define ZI_FS_FEATURE_INCOMPAT_SUPPORTED                                                           \
  (ZI_FS_FEATURE_INCOMPAT_JOURNAL_V1 | ZI_FS_FEATURE_INCOMPAT_SECURITY_V1 |                        \
   ZI_FS_FEATURE_INCOMPAT_DIRECTORY_EXTENTS_V1)

#define ZI_FS_SUPERBLOCK_STATE_NONE UINT32_C(0)
#define ZI_FS_SUPERBLOCK_STATE_DIRTY (UINT32_C(1) << 0)
#define ZI_FS_SUPERBLOCK_STATE_SUPPORTED ZI_FS_SUPERBLOCK_STATE_DIRTY

enum ZiFsFileType {
  ZI_FS_FILE_TYPE_REGULAR = 1,
  ZI_FS_FILE_TYPE_DIRECTORY = 2,
  ZI_FS_FILE_TYPE_SYMBOLIC_LINK = 3,
  ZI_FS_FILE_TYPE_DEVICE = 4,
};

typedef struct ZiFsExtent {
  uint64_t logical_block;
  uint64_t physical_block;
  uint64_t block_count;
  uint32_t flags;
  uint32_t reserved;
} ZiFsExtent;

typedef struct ZiFsSuperblock {
  uint16_t format_major;
  uint16_t format_minor;
  uint8_t block_shift;
  uint8_t checksum_type;
  uint64_t compatible_features;
  uint64_t read_only_compatible_features;
  uint64_t incompatible_features;
  unsigned char volume_uuid[16];
  uint64_t generation;
  uint64_t total_blocks;
  uint64_t root_record_index;
  uint64_t record_table_start;
  uint64_t record_table_blocks;
  uint64_t directory_table_start;
  uint64_t directory_table_blocks;
  uint64_t allocation_bitmap_start;
  uint64_t allocation_bitmap_blocks;
  uint64_t journal_start;
  uint64_t journal_blocks;
  uint64_t security_table_start;
  uint64_t security_table_blocks;
  uint64_t backup_superblock;
  uint64_t last_committed_transaction;
  uint32_t state_flags;
  char volume_name[ZI_FS_MAX_VOLUME_NAME_BYTES + 1u];
  uint16_t volume_name_size;
} ZiFsSuperblock;

typedef struct ZiFsFileRecord {
  uint64_t file_id;
  uint64_t parent_file_id;
  uint64_t flags;
  uint64_t file_size;
  uint64_t allocated_size;
  uint64_t security_id;
  uint64_t directory_block;
  uint64_t created_time;
  uint64_t modified_time;
  uint64_t changed_time;
  uint64_t accessed_time;
  uint16_t file_type;
  uint32_t extent_count;
  ZiFsExtent extents[ZI_FS_INLINE_EXTENT_COUNT];
} ZiFsFileRecord;

typedef struct ZiFsDirectoryEntry {
  uint64_t file_id;
  uint64_t record_index;
  uint16_t file_type;
  uint16_t flags;
  ZiStringView name;
} ZiFsDirectoryEntry;

typedef struct ZiFsVolume {
  ZiBlockDevice device;
  ZiFsSuperblock superblock;
  uint32_t mounted_from_backup;
  uint32_t is_read_only;
  uint32_t needs_recovery;
  uint32_t journal_header_valid;
  uint64_t security_generation;
  uint32_t security_record_count;
} ZiFsVolume;

ZiStatus ZiFsEncodeSuperblock(const ZiFsSuperblock* superblock, void* output, size_t output_size);
ZiStatus ZiFsDecodeSuperblock(const void* data, size_t data_size, ZiFsSuperblock* out_superblock);
ZiStatus ZiFsEncodeFileRecord(const ZiFsFileRecord* record, void* output, size_t output_size);
ZiStatus ZiFsDecodeFileRecord(const void* data, size_t data_size, ZiFsFileRecord* out_record);
ZiStatus ZiFsValidateFileRecord(const ZiFsVolume* volume, const ZiFsFileRecord* record);
ZiStatus ZiFsInitialiseDirectoryBlock(void* block,
                                      size_t block_size,
                                      uint64_t directory_file_id,
                                      uint64_t generation);
ZiStatus ZiFsValidateDirectoryBlock(const void* block,
                                    size_t block_size,
                                    uint64_t expected_directory_file_id);
ZiStatus ZiFsCanAddDirectoryEntry(const void* block,
                                  size_t block_size,
                                  const ZiFsDirectoryEntry* entry,
                                  bool* out_can_add);
ZiStatus ZiFsAddDirectoryEntry(void* block, size_t block_size, const ZiFsDirectoryEntry* entry);
ZiStatus ZiFsRemoveDirectoryEntry(void* block,
                                  size_t block_size,
                                  ZiStringView name,
                                  ZiFsDirectoryEntry* out_entry);
ZiStatus ZiFsSetDirectoryGeneration(void* block, size_t block_size, uint64_t generation);
ZiStatus ZiFsFindDirectoryEntry(const void* block,
                                size_t block_size,
                                ZiStringView name,
                                ZiFsDirectoryEntry* out_entry);
ZiStatus ZiFsDirectoryBlockCount(const ZiFsVolume* volume,
                                 const ZiFsFileRecord* directory,
                                 uint64_t* out_block_count);
ZiStatus ZiFsDirectoryBlockAt(const ZiFsVolume* volume,
                              const ZiFsFileRecord* directory,
                              uint64_t logical_block,
                              uint64_t* out_physical_block);
ZiStatus ZiFsFindDirectoryEntryInRecord(const ZiFsVolume* volume,
                                        const ZiFsFileRecord* directory,
                                        ZiStringView name,
                                        void* block_buffer,
                                        size_t block_buffer_size,
                                        ZiFsDirectoryEntry* out_entry,
                                        uint64_t* out_directory_block);
ZiStatus ZiFsMountVolume(const ZiBlockDevice* device,
                         void* block_buffer,
                         size_t block_buffer_size,
                         ZiFsVolume* out_volume);
ZiStatus ZiFsReadFileRecord(const ZiFsVolume* volume,
                            uint64_t record_index,
                            void* block_buffer,
                            size_t block_buffer_size,
                            ZiFsFileRecord* out_record);
ZiStatus ZiFsReadFile(const ZiFsVolume* volume,
                      const ZiFsFileRecord* record,
                      uint64_t offset,
                      void* output,
                      size_t output_size,
                      size_t* out_bytes_read,
                      void* block_buffer,
                      size_t block_buffer_size);
ZiStatus ZiFsLookupPath(const ZiFsVolume* volume,
                        const ZiParsedPath* path,
                        void* block_buffer,
                        size_t block_buffer_size,
                        ZiFsFileRecord* out_record);
ZiStatus ZiFsLookupPathRecord(const ZiFsVolume* volume,
                              const ZiParsedPath* path,
                              void* block_buffer,
                              size_t block_buffer_size,
                              ZiFsFileRecord* out_record,
                              uint64_t* out_record_index);
