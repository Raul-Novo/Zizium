// SPDX-License-Identifier: GPL-3.0-or-later

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "zi/byte_order.h"
#include "zi/path.h"
#include "zi/security.h"
#include "zi/zifs.h"
#include "zi/zifs_journal.h"
#include "zi/zifs_security.h"
#include "zizium/status.h"
#include "zizium/types.h"

// Secondary diagnostics and cleanup on an already-failing host-tool path are best effort.
// NOLINTBEGIN(cert-err33-c, clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)

typedef struct DirectoryDefinition {
  const char* path;
} DirectoryDefinition;

typedef struct DirectoryNode {
  const char* path;
  size_t path_size;
  size_t name_offset;
  size_t parent_index;
  uint64_t file_id;
  uint64_t record_index;
  uint64_t directory_block;
  uint64_t continuation_block;
  uint64_t continuation_block_count;
} DirectoryNode;

typedef struct InputFile {
  const char* volume_path;
  const char* host_path;
  const char* relative_path;
  size_t relative_path_size;
  size_t name_offset;
  size_t parent_index;
  uint64_t file_id;
  uint64_t record_index;
  uint64_t file_size;
  uint64_t data_block;
  uint64_t data_block_count;
} InputFile;

#define MAX_INPUT_FILES 64u
#define MAX_PATH_COMPONENTS 32u
#define MAX_VOLUME_SIZE_MIB 2048u
#define MAX_ALLOCATION_BITMAP_BLOCKS 16u
#define RECORD_TABLE_RESERVE_BLOCKS UINT64_C(8)
#define JOURNAL_RECORD_CAPACITY UINT64_C(32)
#define JOURNAL_BLOCKS                                                                             \
  (ZI_FS_JOURNAL_HEADER_COPIES + (JOURNAL_RECORD_CAPACITY * ZI_FS_JOURNAL_RECORD_BLOCKS))

static const DirectoryDefinition k_default_directories[] = {
    {""},
    {"Zizium"},
    {"Users"},
    {"Program Files"},
    {"Program Data"},
    {"Temp"},
    {"Recovery"},
    {"System Volume"},
    {"Zizium\\Boot"},
    {"Zizium\\System"},
    {"Zizium\\System21"},
    {"Zizium\\Drivers"},
    {"Zizium\\Config"},
    {"Zizium\\Logs"},
    {"Zizium\\Fonts"},
    {"Zizium\\Shell"},
    {"Zizium\\Themes"},
    {"Zizium\\SDK"},
    {"Zizium\\Runtime"},
    {"Zizium\\Services"},
    {"Zizium\\Security"},
    {"Zizium\\Cache"},
    {"Zizium\\Symbols"},
    {"Zizium\\Diagnostics"},
    {"Zizium\\System21\\x64"},
    {"Zizium\\System21\\Libraries"},
    {"Zizium\\System21\\Native"},
    {"Zizium\\System21\\Console"},
    {"Zizium\\System21\\Unicode"},
    {"Zizium\\System21\\Loader"},
    {"Zizium\\System21\\Graphics"},
    {"Zizium\\System21\\Compatibility"},
    {"Zizium\\Logs\\System"},
    {"Zizium\\Logs\\Security"},
    {"Zizium\\Logs\\Boot"},
    {"Zizium\\Logs\\Crash"},
    {"Zizium\\SDK\\bin"},
    {"Zizium\\SDK\\include"},
    {"Zizium\\SDK\\lib"},
    {"Zizium\\SDK\\crt"},
    {"Zizium\\SDK\\tools"},
    {"Zizium\\SDK\\examples"},
    {"Zizium\\SDK\\docs"},
    {"Users\\Default"},
    {"Users\\Public"},
    {"Users\\Default\\Desktop"},
    {"Users\\Default\\Documents"},
    {"Users\\Default\\Downloads"},
    {"Users\\Default\\Pictures"},
    {"Users\\Default\\Music"},
    {"Users\\Default\\Videos"},
    {"Users\\Default\\Projects"},
    {"Users\\Default\\Config"},
    {"Users\\Default\\AppData"},
    {"Users\\Default\\Temp"},
    {"Program Files\\Common"},
    {"Program Files\\Zizium"},
    {"Program Data\\Packages"},
    {"Program Data\\Services"},
    {"Program Data\\Shared"},
    {"Program Data\\Cache"},
    {"Program Data\\Logs"},
    {"Program Data\\Indexes"},
    {"Program Data\\Manifests"},
    {"Recovery\\Boot"},
    {"Recovery\\Images"},
    {"Recovery\\Tools"},
    {"Recovery\\Logs"},
    {"Recovery\\Rollback"},
    {"System Volume\\ZiFS"},
    {"System Volume\\Snapshots"},
    {"System Volume\\Journal"},
    {"System Volume\\Metadata"},
    {"System Volume\\Quotas"},
    {"System Volume\\Indexes"},
};

static const unsigned char k_default_volume_uuid[16] = {
    0x21,
    0x5a,
    0x69,
    0x46,
    0x53,
    0x00,
    0x40,
    0x01,
    0x80,
    0x00,
    0x64,
    0x96,
    0xe6,
    0xd1,
    0xec,
    0xfc,
};

static int
format_volume(const char* path, uint64_t size_mib, InputFile* input_files, size_t input_file_count);
static size_t string_size(const char* text);
static bool string_equal(const char* left, size_t left_size, const char* right, size_t right_size);
static ZiStatus initialise_nodes(DirectoryNode* nodes, size_t node_count, uint64_t directory_start);
static ZiStatus initialise_input_files(InputFile* input_files,
                                       size_t input_file_count,
                                       const DirectoryNode* nodes,
                                       size_t node_count,
                                       uint64_t first_data_block,
                                       uint64_t backup_superblock,
                                       uint64_t* out_next_data_block);
static ZiStatus assign_directory_continuations(DirectoryNode* nodes,
                                               size_t node_count,
                                               const InputFile* input_files,
                                               size_t input_file_count,
                                               uint64_t first_continuation_block,
                                               uint64_t backup_superblock,
                                               uint64_t* out_first_data_block);
static ZiStatus account_child_directories(const DirectoryNode* nodes,
                                          size_t node_count,
                                          size_t parent_index,
                                          size_t* used_bytes,
                                          uint64_t* block_count);
static ZiStatus account_child_files(const InputFile* input_files,
                                    size_t input_file_count,
                                    size_t parent_index,
                                    size_t* used_bytes,
                                    uint64_t* block_count);
static ZiStatus
account_directory_entry(size_t name_size, size_t* used_bytes, uint64_t* block_count);
static ZiStatus append_directory_entry(FILE* volume,
                                       const DirectoryNode* node,
                                       ZiFsDirectoryEntry* entry,
                                       unsigned char* block,
                                       uint64_t* logical_block);
static uint64_t directory_physical_block(const DirectoryNode* node, uint64_t logical_block);
static ZiStatus query_file_size(const char* path, uint64_t* out_size);
static ZiStatus write_input_file(FILE* volume, const InputFile* input_file);
static ZiStatus write_at_block(FILE* file, uint64_t block_number, const void* block);
static ZiStatus initialise_default_security_table(void* block, size_t block_size);
static ZiStatus mark_extent(unsigned char* allocation_bitmap,
                            size_t allocation_bitmap_size,
                            uint64_t first_block,
                            uint64_t block_count);
static bool parse_size(const char* text, uint64_t* out_size);
static bool parse_arguments(int argc,
                            char* argv[],
                            uint64_t* out_size_mib,
                            InputFile* input_files,
                            size_t* out_input_file_count);

int main(int argc, char* argv[]) {
  if (argc < 2) {
    fputs("Usage: mkzifs.exe <volume image> [size in MiB] "
          "[--file <C:\\path> <host file>]...\n",
          stderr);
    return 2;
  }

  uint64_t size_mib = 32;
  InputFile input_files[MAX_INPUT_FILES] = {0};
  size_t input_file_count = 0;
  if (!parse_arguments(argc, argv, &size_mib, input_files, &input_file_count)) {
    return 2;
  }
  return format_volume(argv[1], size_mib, input_files, input_file_count);
}

// The formatter is a linear transaction; splitting it would obscure cleanup ownership in Seed.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static int format_volume(const char* path,
                         uint64_t size_mib,
                         InputFile* input_files,
                         size_t input_file_count) {
  const size_t node_count = sizeof k_default_directories / sizeof k_default_directories[0];
  const size_t record_count = node_count + input_file_count;
  const uint64_t records_per_block = ZI_FS_BLOCK_SIZE / ZI_FS_FILE_RECORD_SIZE;
  const uint64_t total_blocks = size_mib * 1024u * 1024u / ZI_FS_BLOCK_SIZE;
  const uint64_t record_table_start = 1;
  const uint64_t record_table_blocks =
      ((record_count + records_per_block - 1u) / records_per_block) + RECORD_TABLE_RESERVE_BLOCKS;
  const uint64_t first_bitmap_block = record_table_start + record_table_blocks;
  uint64_t bitmap_block_count = 0;
  ZiStatus status = ZiFsAllocationBitmapBlockCount(total_blocks, &bitmap_block_count);
  if (ZiFailed(status) || bitmap_block_count > MAX_ALLOCATION_BITMAP_BLOCKS) {
    fputs("The selected ZiFS volume exceeds the formatter's allocation-map limit.\n", stderr);
    return 1;
  }
  const uint64_t journal_start = first_bitmap_block + bitmap_block_count;
  const uint64_t journal_blocks = JOURNAL_BLOCKS;
  const uint64_t security_start = journal_start + journal_blocks;
  const uint64_t security_blocks = 1;
  const uint64_t directory_start = security_start + security_blocks;
  const uint64_t directory_blocks = node_count;
  const uint64_t backup_superblock = total_blocks - 1;
  if (directory_start + directory_blocks >= backup_superblock) {
    fputs("The selected ZiFS volume cannot represent the default layout.\n", stderr);
    return 1;
  }

  DirectoryNode nodes[sizeof k_default_directories / sizeof k_default_directories[0]];
  status = initialise_nodes(nodes, node_count, directory_start);
  if (ZiFailed(status)) {
    fputs("The built-in ZiFS directory layout is invalid.\n", stderr);
    return 1;
  }
  uint64_t relative_data_blocks = 0;
  status = initialise_input_files(input_files,
                                  input_file_count,
                                  nodes,
                                  node_count,
                                  0,
                                  backup_superblock,
                                  &relative_data_blocks);
  uint64_t first_data_block = 0;
  if (ZiSucceeded(status)) {
    status = assign_directory_continuations(nodes,
                                            node_count,
                                            input_files,
                                            input_file_count,
                                            directory_start + directory_blocks,
                                            backup_superblock,
                                            &first_data_block);
  }
  if (ZiSucceeded(status) && relative_data_blocks > backup_superblock - first_data_block) {
    status = ZI_STATUS_BUFFER_TOO_SMALL;
  }
  if (ZiSucceeded(status)) {
    for (size_t index = 0; index < input_file_count; ++index) {
      if (input_files[index].data_block_count != 0) {
        input_files[index].data_block += first_data_block;
      }
    }
  }
  if (ZiFailed(status)) {
    fputs("The selected ZiFS volume is too small for directory growth and input files.\n", stderr);
    return 1;
  }

  FILE* file = NULL;
  errno_t open_error = fopen_s(&file, path, "w+b");
  if (open_error != 0 || file == NULL) {
    fprintf(stderr, "Unable to create ZiFS image '%s' (error %d).\n", path, (int)open_error);
    return 1;
  }

  uint64_t volume_size = total_blocks * ZI_FS_BLOCK_SIZE;
  if (volume_size > LONG_MAX || fseek(file, (long)(volume_size - 1u), SEEK_SET) != 0 ||
      fputc(0, file) == EOF) {
    fputs("Unable to allocate the ZiFS image.\n", stderr);
    fclose(file);
    return 1;
  }

  unsigned char block[ZI_FS_BLOCK_SIZE];
  unsigned char allocation_bitmap[MAX_ALLOCATION_BITMAP_BLOCKS * ZI_FS_BLOCK_SIZE];
  ZiFsSuperblock superblock = {0};
  superblock.format_major = ZI_FS_FORMAT_MAJOR;
  superblock.format_minor = ZI_FS_FORMAT_MINOR;
  superblock.block_shift = ZI_FS_BLOCK_SHIFT;
  superblock.checksum_type = 1;
  superblock.compatible_features = ZI_FS_FEATURE_COMPAT_NONE;
  superblock.read_only_compatible_features = ZI_FS_FEATURE_READ_ONLY_COMPAT_NONE;
  superblock.incompatible_features = ZI_FS_FEATURE_INCOMPAT_JOURNAL_V1 |
                                     ZI_FS_FEATURE_INCOMPAT_SECURITY_V1 |
                                     ZI_FS_FEATURE_INCOMPAT_DIRECTORY_EXTENTS_V1;
  zi_memory_copy(superblock.volume_uuid, k_default_volume_uuid, sizeof k_default_volume_uuid);
  superblock.generation = 1;
  superblock.total_blocks = total_blocks;
  superblock.root_record_index = 0;
  superblock.record_table_start = record_table_start;
  superblock.record_table_blocks = record_table_blocks;
  superblock.directory_table_start = directory_start;
  superblock.directory_table_blocks = directory_blocks;
  superblock.allocation_bitmap_start = first_bitmap_block;
  superblock.allocation_bitmap_blocks = bitmap_block_count;
  superblock.journal_start = journal_start;
  superblock.journal_blocks = journal_blocks;
  superblock.security_table_start = security_start;
  superblock.security_table_blocks = security_blocks;
  superblock.backup_superblock = backup_superblock;
  superblock.last_committed_transaction = 0;
  superblock.state_flags = ZI_FS_SUPERBLOCK_STATE_NONE;
  superblock.volume_name_size = 6;
  zi_memory_copy(superblock.volume_name, "Zizium", superblock.volume_name_size);

  status = ZiFsEncodeSuperblock(&superblock, block, sizeof block);
  if (ZiFailed(status) || ZiFailed(write_at_block(file, 0, block)) ||
      ZiFailed(write_at_block(file, backup_superblock, block))) {
    fputs("Unable to write the ZiFS superblocks.\n", stderr);
    fclose(file);
    return 1;
  }

  for (uint64_t table_block = 0; table_block < record_table_blocks; ++table_block) {
    zi_memory_zero(block, sizeof block);
    for (uint64_t slot = 0; slot < records_per_block; ++slot) {
      uint64_t node_index = (table_block * records_per_block) + slot;
      if (node_index >= record_count) {
        break;
      }
      ZiFsFileRecord record = {0};
      if (node_index < node_count) {
        DirectoryNode* node = &nodes[node_index];
        record.file_id = node->file_id;
        record.parent_file_id = nodes[node->parent_index].file_id;
        record.security_id = 1;
        record.directory_block = node->directory_block;
        record.file_type = ZI_FS_FILE_TYPE_DIRECTORY;
        if (node->continuation_block_count != 0) {
          record.allocated_size = node->continuation_block_count * ZI_FS_BLOCK_SIZE;
          record.extent_count = 1;
          record.extents[0].logical_block = 1;
          record.extents[0].physical_block = node->continuation_block;
          record.extents[0].block_count = node->continuation_block_count;
        }
      } else {
        InputFile* input_file = &input_files[node_index - node_count];
        record.file_id = input_file->file_id;
        record.parent_file_id = nodes[input_file->parent_index].file_id;
        record.security_id = 1;
        record.file_type = ZI_FS_FILE_TYPE_REGULAR;
        record.file_size = input_file->file_size;
        record.allocated_size = input_file->data_block_count * ZI_FS_BLOCK_SIZE;
        if (input_file->data_block_count != 0) {
          record.extent_count = 1;
          record.extents[0].physical_block = input_file->data_block;
          record.extents[0].block_count = input_file->data_block_count;
        }
      }
      status = ZiFsEncodeFileRecord(&record,
                                    block + (size_t)(slot * ZI_FS_FILE_RECORD_SIZE),
                                    ZI_FS_FILE_RECORD_SIZE);
      if (ZiFailed(status)) {
        fputs("Unable to encode a ZiFS file record.\n", stderr);
        fclose(file);
        return 1;
      }
    }
    if (ZiFailed(write_at_block(file, record_table_start + table_block, block))) {
      fputs("Unable to write the ZiFS record table.\n", stderr);
      fclose(file);
      return 1;
    }
  }

  for (size_t parent_index = 0; parent_index < node_count; ++parent_index) {
    uint64_t logical_block = 0;
    status = ZiFsInitialiseDirectoryBlock(block, sizeof block, nodes[parent_index].file_id, 1);
    if (ZiFailed(status)) {
      fclose(file);
      return 1;
    }
    for (size_t child_index = 1; child_index < node_count; ++child_index) {
      if (nodes[child_index].parent_index != parent_index) {
        continue;
      }
      ZiFsDirectoryEntry entry = {0};
      entry.file_id = nodes[child_index].file_id;
      entry.record_index = nodes[child_index].record_index;
      entry.file_type = ZI_FS_FILE_TYPE_DIRECTORY;
      entry.name.data = nodes[child_index].path + nodes[child_index].name_offset;
      entry.name.size = nodes[child_index].path_size - nodes[child_index].name_offset;
      status = append_directory_entry(file, &nodes[parent_index], &entry, block, &logical_block);
      if (ZiFailed(status)) {
        fputs("A ZiFS directory exceeded its formatter capacity.\n", stderr);
        fclose(file);
        return 1;
      }
    }
    for (size_t file_index = 0; file_index < input_file_count; ++file_index) {
      InputFile* input_file = &input_files[file_index];
      if (input_file->parent_index != parent_index) {
        continue;
      }
      ZiFsDirectoryEntry entry = {0};
      entry.file_id = input_file->file_id;
      entry.record_index = input_file->record_index;
      entry.file_type = ZI_FS_FILE_TYPE_REGULAR;
      entry.name.data = input_file->relative_path + input_file->name_offset;
      entry.name.size = input_file->relative_path_size - input_file->name_offset;
      status = append_directory_entry(file, &nodes[parent_index], &entry, block, &logical_block);
      if (ZiFailed(status)) {
        fputs("A ZiFS directory exceeded its formatter capacity.\n", stderr);
        fclose(file);
        return 1;
      }
    }
    if (logical_block != nodes[parent_index].continuation_block_count ||
        ZiFailed(write_at_block(file,
                                directory_physical_block(&nodes[parent_index], logical_block),
                                block))) {
      fputs("Unable to write a ZiFS directory.\n", stderr);
      fclose(file);
      return 1;
    }
  }

  const size_t allocation_bitmap_size = (size_t)bitmap_block_count * ZI_FS_BLOCK_SIZE;
  zi_memory_zero(allocation_bitmap, allocation_bitmap_size);
  status = mark_extent(allocation_bitmap, allocation_bitmap_size, 0, 1);
  if (ZiSucceeded(status)) {
    status = mark_extent(allocation_bitmap,
                         allocation_bitmap_size,
                         record_table_start,
                         record_table_blocks);
  }
  if (ZiSucceeded(status)) {
    status = mark_extent(allocation_bitmap,
                         allocation_bitmap_size,
                         first_bitmap_block,
                         bitmap_block_count);
  }
  if (ZiSucceeded(status)) {
    status = mark_extent(allocation_bitmap, allocation_bitmap_size, journal_start, journal_blocks);
  }
  if (ZiSucceeded(status)) {
    status =
        mark_extent(allocation_bitmap, allocation_bitmap_size, security_start, security_blocks);
  }
  if (ZiSucceeded(status)) {
    status =
        mark_extent(allocation_bitmap, allocation_bitmap_size, directory_start, directory_blocks);
  }
  for (size_t node_index = 0; node_index < node_count; ++node_index) {
    if (ZiSucceeded(status) && nodes[node_index].continuation_block_count != 0) {
      status = mark_extent(allocation_bitmap,
                           allocation_bitmap_size,
                           nodes[node_index].continuation_block,
                           nodes[node_index].continuation_block_count);
    }
  }
  for (size_t file_index = 0; file_index < input_file_count; ++file_index) {
    if (ZiSucceeded(status)) {
      status = mark_extent(allocation_bitmap,
                           allocation_bitmap_size,
                           input_files[file_index].data_block,
                           input_files[file_index].data_block_count);
    }
  }
  if (ZiSucceeded(status)) {
    status = mark_extent(allocation_bitmap, allocation_bitmap_size, backup_superblock, 1);
  }
  if (ZiFailed(status)) {
    fputs("Unable to represent allocated ZiFS blocks in the allocation bitmap.\n", stderr);
    fclose(file);
    return 1;
  }
  for (uint64_t index = 0; index < bitmap_block_count; ++index) {
    status = write_at_block(file,
                            first_bitmap_block + index,
                            allocation_bitmap + ((size_t)index * ZI_FS_BLOCK_SIZE));
    if (ZiFailed(status)) {
      break;
    }
  }
  if (ZiFailed(status)) {
    fputs("Unable to write the ZiFS allocation bitmap.\n", stderr);
    fclose(file);
    return 1;
  }

  ZiFsJournalHeader journal_header = {0};
  journal_header.volume_generation = superblock.generation;
  journal_header.record_capacity = JOURNAL_RECORD_CAPACITY;
  journal_header.next_sequence = 1;
  journal_header.next_transaction_id = 1;
  journal_header.flags = ZI_FS_JOURNAL_HEADER_FLAGS_NONE;
  for (uint64_t copy_index = 0; copy_index < ZI_FS_JOURNAL_HEADER_COPIES; ++copy_index) {
    journal_header.header_sequence = copy_index + 1u;
    status = ZiFsEncodeJournalHeader(&journal_header, block, sizeof block);
    if (ZiFailed(status) || ZiFailed(write_at_block(file, journal_start + copy_index, block))) {
      fputs("Unable to write the ZiFS journal headers.\n", stderr);
      fclose(file);
      return 1;
    }
  }
  status = initialise_default_security_table(block, sizeof block);
  if (ZiFailed(status) || ZiFailed(write_at_block(file, security_start, block))) {
    fputs("Unable to write the ZiFS security-descriptor table.\n", stderr);
    fclose(file);
    return 1;
  }

  for (size_t file_index = 0; file_index < input_file_count; ++file_index) {
    status = write_input_file(file, &input_files[file_index]);
    if (ZiFailed(status)) {
      fprintf(stderr,
              "Unable to copy host file '%s' into '%s'.\n",
              input_files[file_index].host_path,
              input_files[file_index].volume_path);
      fclose(file);
      return 1;
    }
  }

  if (fflush(file) != 0 || fclose(file) != 0) {
    fputs("Unable to finish the ZiFS image cleanly.\n", stderr);
    return 1;
  }
  printf("Created ZiFS %u.%u volume '%s' with %zu directories and %zu files (%llu MiB).\n",
         (unsigned)ZI_FS_FORMAT_MAJOR,
         (unsigned)ZI_FS_FORMAT_MINOR,
         path,
         node_count,
         input_file_count,
         (unsigned long long)size_mib);
  return 0;
}

static size_t string_size(const char* text) {
  size_t size = 0;
  while (text[size] != '\0') {
    ++size;
  }
  return size;
}

static bool string_equal(const char* left, size_t left_size, const char* right, size_t right_size) {
  if (left_size != right_size) {
    return false;
  }
  return zi_memory_compare(left, right, left_size) == 0;
}

static ZiStatus
initialise_nodes(DirectoryNode* nodes, size_t node_count, uint64_t directory_start) {
  for (size_t index = 0; index < node_count; ++index) {
    nodes[index].path = k_default_directories[index].path;
    nodes[index].path_size = string_size(nodes[index].path);
    nodes[index].file_id = index + 1u;
    nodes[index].record_index = index;
    nodes[index].directory_block = directory_start + index;
    nodes[index].continuation_block = 0;
    nodes[index].continuation_block_count = 0;
    nodes[index].parent_index = 0;
    nodes[index].name_offset = 0;

    if (index == 0) {
      continue;
    }
    size_t separator = nodes[index].path_size;
    while (separator > 0 && nodes[index].path[separator - 1] != '\\') {
      --separator;
    }
    nodes[index].name_offset = separator;
    size_t parent_size = separator == 0 ? 0 : separator - 1;
    bool found_parent = false;
    for (size_t parent_index = 0; parent_index < index; ++parent_index) {
      if (string_equal(nodes[parent_index].path,
                       nodes[parent_index].path_size,
                       nodes[index].path,
                       parent_size)) {
        nodes[index].parent_index = parent_index;
        found_parent = true;
        break;
      }
    }
    if (!found_parent) {
      return ZI_STATUS_INVALID_PATH;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus assign_directory_continuations(DirectoryNode* nodes,
                                               size_t node_count,
                                               const InputFile* input_files,
                                               size_t input_file_count,
                                               uint64_t first_continuation_block,
                                               uint64_t backup_superblock,
                                               uint64_t* out_first_data_block) {
  if (nodes == NULL || input_files == NULL || out_first_data_block == NULL ||
      first_continuation_block >= backup_superblock) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t next_block = first_continuation_block;
  for (size_t parent_index = 0; parent_index < node_count; ++parent_index) {
    size_t used_bytes = ZI_FS_DIRECTORY_HEADER_SIZE;
    uint64_t block_count = 1;
    ZiStatus status =
        account_child_directories(nodes, node_count, parent_index, &used_bytes, &block_count);
    if (ZiFailed(status)) {
      return status;
    }
    status =
        account_child_files(input_files, input_file_count, parent_index, &used_bytes, &block_count);
    if (ZiFailed(status)) {
      return status;
    }
    uint64_t continuation_count = block_count - 1u;
    if (block_count > ZI_FS_MAX_DIRECTORY_BLOCKS ||
        continuation_count > backup_superblock - next_block) {
      return ZI_STATUS_BUFFER_TOO_SMALL;
    }
    nodes[parent_index].continuation_block = 0;
    if (continuation_count != 0) {
      nodes[parent_index].continuation_block = next_block;
    }
    nodes[parent_index].continuation_block_count = continuation_count;
    next_block += continuation_count;
  }
  *out_first_data_block = next_block;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus account_child_directories(const DirectoryNode* nodes,
                                          size_t node_count,
                                          size_t parent_index,
                                          size_t* used_bytes,
                                          uint64_t* block_count) {
  for (size_t child_index = 1; child_index < node_count; ++child_index) {
    if (nodes[child_index].parent_index != parent_index) {
      continue;
    }
    ZiStatus status =
        account_directory_entry(nodes[child_index].path_size - nodes[child_index].name_offset,
                                used_bytes,
                                block_count);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus account_child_files(const InputFile* input_files,
                                    size_t input_file_count,
                                    size_t parent_index,
                                    size_t* used_bytes,
                                    uint64_t* block_count) {
  for (size_t file_index = 0; file_index < input_file_count; ++file_index) {
    if (input_files[file_index].parent_index != parent_index) {
      continue;
    }
    ZiStatus status = account_directory_entry(input_files[file_index].relative_path_size -
                                                  input_files[file_index].name_offset,
                                              used_bytes,
                                              block_count);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus
account_directory_entry(size_t name_size, size_t* used_bytes, uint64_t* block_count) {
  if (used_bytes == NULL || block_count == NULL || name_size == 0 ||
      name_size > ZI_FS_MAX_DIRECTORY_NAME_BYTES || *used_bytes < ZI_FS_DIRECTORY_HEADER_SIZE ||
      *used_bytes > ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  size_t entry_size = (ZI_FS_DIRECTORY_ENTRY_HEADER_SIZE + name_size + 7u) & ~(size_t)7u;
  if (entry_size > ZI_FS_BLOCK_SIZE - ZI_FS_DIRECTORY_HEADER_SIZE) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  if (entry_size > ZI_FS_BLOCK_SIZE - *used_bytes) {
    if (*block_count == UINT64_MAX) {
      return ZI_STATUS_OUT_OF_BOUNDS;
    }
    ++*block_count;
    *used_bytes = ZI_FS_DIRECTORY_HEADER_SIZE;
  }
  *used_bytes += entry_size;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus append_directory_entry(FILE* volume,
                                       const DirectoryNode* node,
                                       ZiFsDirectoryEntry* entry,
                                       unsigned char* block,
                                       uint64_t* logical_block) {
  if (volume == NULL || node == NULL || entry == NULL || block == NULL || logical_block == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = ZiFsAddDirectoryEntry(block, ZI_FS_BLOCK_SIZE, entry);
  if (status != ZI_STATUS_BUFFER_TOO_SMALL) {
    return status;
  }
  if (*logical_block >= node->continuation_block_count) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  status = write_at_block(volume, directory_physical_block(node, *logical_block), block);
  if (ZiFailed(status)) {
    return status;
  }
  ++*logical_block;
  status = ZiFsInitialiseDirectoryBlock(block, ZI_FS_BLOCK_SIZE, node->file_id, 1);
  if (ZiFailed(status)) {
    return status;
  }
  return ZiFsAddDirectoryEntry(block, ZI_FS_BLOCK_SIZE, entry);
}

static uint64_t directory_physical_block(const DirectoryNode* node, uint64_t logical_block) {
  return logical_block == 0 ? node->directory_block : node->continuation_block + logical_block - 1u;
}

// The bounded pass validates parentage, duplicates, host files, and extent placement atomically.
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static ZiStatus initialise_input_files(InputFile* input_files,
                                       size_t input_file_count,
                                       const DirectoryNode* nodes,
                                       size_t node_count,
                                       uint64_t first_data_block,
                                       uint64_t backup_superblock,
                                       uint64_t* out_next_data_block) {
  if (input_files == NULL || nodes == NULL || out_next_data_block == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t next_data_block = first_data_block;
  for (size_t index = 0; index < input_file_count; ++index) {
    InputFile* input_file = &input_files[index];
    size_t volume_path_size = string_size(input_file->volume_path);
    ZiStringView components[MAX_PATH_COMPONENTS] = {0};
    ZiParsedPath parsed = {0};
    ZiStatus status = zi_path_parse_absolute(input_file->volume_path,
                                             volume_path_size,
                                             components,
                                             MAX_PATH_COMPONENTS,
                                             &parsed);
    if (ZiFailed(status) || parsed.drive_letter != 'C' || parsed.component_count == 0 ||
        volume_path_size < 4 || input_file->volume_path[2] != '\\') {
      fprintf(stderr,
              "The ZiFS destination '%s' is not a valid absolute C: path.\n",
              input_file->volume_path);
      return ZI_STATUS_INVALID_PATH;
    }

    input_file->relative_path = input_file->volume_path + 3;
    input_file->relative_path_size = volume_path_size - 3u;
    size_t separator = input_file->relative_path_size;
    while (separator > 0 && input_file->relative_path[separator - 1u] != '\\') {
      --separator;
    }
    input_file->name_offset = separator;
    size_t name_size = input_file->relative_path_size - separator;
    if (name_size == 0 || name_size > ZI_FS_MAX_DIRECTORY_NAME_BYTES) {
      fprintf(stderr, "The ZiFS file name in '%s' is invalid.\n", input_file->volume_path);
      return ZI_STATUS_INVALID_PATH;
    }

    size_t parent_size = separator == 0 ? 0 : separator - 1u;
    for (size_t node_index = 0; node_index < node_count; ++node_index) {
      if (string_equal(nodes[node_index].path,
                       nodes[node_index].path_size,
                       input_file->relative_path,
                       input_file->relative_path_size)) {
        fprintf(stderr,
                "The ZiFS destination '%s' conflicts with a directory.\n",
                input_file->volume_path);
        return ZI_STATUS_ALREADY_EXISTS;
      }
    }
    bool found_parent = false;
    for (size_t parent_index = 0; parent_index < node_count; ++parent_index) {
      if (string_equal(nodes[parent_index].path,
                       nodes[parent_index].path_size,
                       input_file->relative_path,
                       parent_size)) {
        input_file->parent_index = parent_index;
        found_parent = true;
        break;
      }
    }
    if (!found_parent) {
      fprintf(stderr,
              "The parent directory for ZiFS destination '%s' does not exist.\n",
              input_file->volume_path);
      return ZI_STATUS_NOT_FOUND;
    }
    for (size_t previous = 0; previous < index; ++previous) {
      if (string_equal(input_files[previous].relative_path,
                       input_files[previous].relative_path_size,
                       input_file->relative_path,
                       input_file->relative_path_size)) {
        fprintf(stderr,
                "The ZiFS destination '%s' was specified twice.\n",
                input_file->volume_path);
        return ZI_STATUS_ALREADY_EXISTS;
      }
    }

    status = query_file_size(input_file->host_path, &input_file->file_size);
    if (ZiFailed(status)) {
      fprintf(stderr, "Unable to inspect host file '%s'.\n", input_file->host_path);
      return status;
    }
    input_file->data_block_count =
        (input_file->file_size + ZI_FS_BLOCK_SIZE - 1u) / ZI_FS_BLOCK_SIZE;
    if (input_file->data_block_count > backup_superblock - next_data_block) {
      fputs("The selected ZiFS volume is too small for the requested files.\n", stderr);
      return ZI_STATUS_BUFFER_TOO_SMALL;
    }
    input_file->file_id = node_count + index + 1u;
    input_file->record_index = node_count + index;
    input_file->data_block = input_file->data_block_count == 0 ? 0 : next_data_block;
    next_data_block += input_file->data_block_count;
  }
  *out_next_data_block = next_data_block;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus query_file_size(const char* path, uint64_t* out_size) {
  if (path == NULL || out_size == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  FILE* file = NULL;
  if (fopen_s(&file, path, "rb") != 0 || file == NULL) {
    return ZI_STATUS_NOT_FOUND;
  }
  if (fseek(file, 0, SEEK_END) != 0) {
    fclose(file);
    return ZI_STATUS_DEVICE_ERROR;
  }
  long size = ftell(file);
  if (size < 0 || fclose(file) != 0) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  *out_size = (uint64_t)size;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus write_input_file(FILE* volume, const InputFile* input_file) {
  if (volume == NULL || input_file == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  FILE* source = NULL;
  if (fopen_s(&source, input_file->host_path, "rb") != 0 || source == NULL) {
    return ZI_STATUS_NOT_FOUND;
  }

  unsigned char block[ZI_FS_BLOCK_SIZE];
  uint64_t remaining = input_file->file_size;
  for (uint64_t block_index = 0; block_index < input_file->data_block_count; ++block_index) {
    zi_memory_zero(block, sizeof block);
    size_t copy_size = remaining > ZI_FS_BLOCK_SIZE ? ZI_FS_BLOCK_SIZE : (size_t)remaining;
    if (copy_size != 0 && fread(block, 1, copy_size, source) != copy_size) {
      fclose(source);
      return ZI_STATUS_DEVICE_ERROR;
    }
    ZiStatus status = write_at_block(volume, input_file->data_block + block_index, block);
    if (ZiFailed(status)) {
      fclose(source);
      return status;
    }
    remaining -= copy_size;
  }
  int trailing_byte = fgetc(source);
  if (remaining != 0 || trailing_byte != EOF || ferror(source) != 0 || fclose(source) != 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus write_at_block(FILE* file, uint64_t block_number, const void* block) {
  uint64_t offset = block_number * ZI_FS_BLOCK_SIZE;
  if (offset > LONG_MAX || fseek(file, (long)offset, SEEK_SET) != 0 ||
      fwrite(block, 1, ZI_FS_BLOCK_SIZE, file) != ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus initialise_default_security_table(void* block, size_t block_size) {
  const ZiSecurityId system = {ZI_SECURITY_AUTHORITY_SYSTEM, 1};
  const ZiSecurityId administrators = {ZI_SECURITY_AUTHORITY_GROUP, 1};
  const ZiSecurityId users = {ZI_SECURITY_AUTHORITY_GROUP, 2};
  const ZiSecurityId guests = {ZI_SECURITY_AUTHORITY_GROUP, 3};
  const ZiAccessMask guest_denials = ZI_ACCESS_WRITE | ZI_ACCESS_DELETE | ZI_ACCESS_CREATE |
                                     ZI_ACCESS_MODIFY_ACL | ZI_ACCESS_TAKE_OWNERSHIP;
  const ZiAce entries[] = {
      {ZI_ACE_DENY, 0, 0, guest_denials, guests},
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_FULL_CONTROL, system},
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_FULL_CONTROL, administrators},
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_READ | ZI_ACCESS_EXECUTE | ZI_ACCESS_LIST, users},
  };
  const ZiAcl dacl = {sizeof(ZiAcl), ZI_ACL_VERSION, entries, sizeof entries / sizeof entries[0]};
  const ZiSecurityDescriptor descriptor = {
      sizeof(ZiSecurityDescriptor),
      ZI_SECURITY_DESCRIPTOR_VERSION,
      system,
      administrators,
      &dacl,
      ZI_SECURITY_DESCRIPTOR_CONTROL_NONE,
  };
  ZiStatus status = ZiFsInitialiseSecurityTable(block, block_size, 1);
  if (ZiFailed(status)) {
    return status;
  }
  return ZiFsAppendSecurityDescriptor(block,
                                      block_size,
                                      1,
                                      ZI_FS_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT,
                                      &descriptor);
}

static ZiStatus mark_extent(unsigned char* allocation_bitmap,
                            size_t allocation_bitmap_size,
                            uint64_t first_block,
                            uint64_t block_count) {
  if (allocation_bitmap == NULL || allocation_bitmap_size == 0 ||
      first_block > UINT64_MAX - block_count) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  for (uint64_t offset = 0; offset < block_count; ++offset) {
    ZiStatus status =
        ZiFsAllocationBitSet(allocation_bitmap, allocation_bitmap_size, first_block + offset, true);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static bool parse_size(const char* text, uint64_t* out_size) {
  errno = 0;
  char* end = NULL;
  unsigned long parsed = strtoul(text, &end, 10);
  if (errno == ERANGE || end == text || *end != '\0' || parsed < 8u ||
      parsed > MAX_VOLUME_SIZE_MIB) {
    return false;
  }
  *out_size = parsed;
  return true;
}

static bool parse_arguments(int argc,
                            char* argv[],
                            uint64_t* out_size_mib,
                            InputFile* input_files,
                            size_t* out_input_file_count) {
  int argument_index = 2;
  if (argument_index < argc &&
      !string_equal(argv[argument_index], string_size(argv[argument_index]), "--file", 6)) {
    if (!parse_size(argv[argument_index], out_size_mib)) {
      fprintf(stderr,
              "The ZiFS volume size must be an integer from 8 to %u MiB.\n",
              MAX_VOLUME_SIZE_MIB);
      return false;
    }
    ++argument_index;
  }

  size_t input_file_count = 0;
  while (argument_index < argc) {
    if (argument_index + 2 >= argc ||
        !string_equal(argv[argument_index], string_size(argv[argument_index]), "--file", 6)) {
      fputs("Each input must use --file <C:\\path> <host file>.\n", stderr);
      return false;
    }
    if (input_file_count >= MAX_INPUT_FILES) {
      fprintf(stderr, "No more than %u input files may be added in one format operation.\n", 64u);
      return false;
    }
    input_files[input_file_count].volume_path = argv[argument_index + 1];
    input_files[input_file_count].host_path = argv[argument_index + 2];
    ++input_file_count;
    argument_index += 3;
  }
  *out_input_file_count = input_file_count;
  return true;
}
// NOLINTEND(cert-err33-c, clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
