// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "phase6_tests.h"
#include "zi/block.h"
#include "zi/byte_order.h"
#include "zi/path.h"
#include "zi/security.h"
#include "zi/zifs.h"
#include "zi/zifs_image_source.h"
#include "zi/zifs_security.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define PHASE6_ASSERT(expression)                                                                  \
  do {                                                                                             \
    ++assertions;                                                                                  \
    if (!(expression)) {                                                                           \
      (void)fprintf_s(stderr, "%s:%d: assertion failed: %s\n", __FILE__, __LINE__, #expression);   \
      *out_assertion_count = assertions;                                                           \
      return false;                                                                                \
    }                                                                                              \
  } while (false)

#define TEST_VOLUME_BLOCKS 16u
#define TEST_DATA_BLOCK_ONE 7u
#define TEST_DATA_BLOCK_TWO 9u
#define TEST_SOURCE_ARENA_SIZE (3u * ZI_FS_BLOCK_SIZE)

typedef struct MemoryVolume {
  unsigned char* bytes;
  size_t size;
} MemoryVolume;

typedef struct TestSourceAllocator {
  unsigned char arena[TEST_SOURCE_ARENA_SIZE];
  size_t used;
  size_t active_allocations;
  bool fail_allocation;
} TestSourceAllocator;

static unsigned char s_volume[TEST_VOLUME_BLOCKS][ZI_FS_BLOCK_SIZE];

static ZiStatus memory_read_blocks(void* context,
                                   uint64_t first_block,
                                   uint32_t block_count,
                                   void* output,
                                   size_t output_size);
static ZiStatus test_source_allocate(void* context, size_t size, void** out_allocation);
static ZiStatus test_source_release(void* context, void* allocation);
static bool initialise_file_volume(void);
static bool initialise_security_table(void);

// The assertions intentionally keep every hostile extent case beside the successful read path.
// NOLINTNEXTLINE(readability-function-cognitive-complexity, readability-function-size)
bool phase6_zifs_file_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  size_t assertions = 0;
  *out_assertion_count = 0;
  PHASE6_ASSERT(initialise_file_volume());

  MemoryVolume memory = {&s_volume[0][0], sizeof s_volume};
  ZiBlockDevice device = {
      sizeof(ZiBlockDevice),
      ZI_BLOCK_DEVICE_VERSION,
      &memory,
      ZI_FS_BLOCK_SIZE,
      TEST_VOLUME_BLOCKS,
      memory_read_blocks,
      NULL,
      ZI_BLOCK_DEVICE_READ_ONLY,
      NULL,
  };
  unsigned char scratch[ZI_FS_BLOCK_SIZE] = {0};
  ZiFsVolume volume = {0};
  PHASE6_ASSERT(ZiSucceeded(ZiFsMountVolume(&device, scratch, sizeof scratch, &volume)));

  const char file_path[] = "C:\\Temp\\Seed File.txt";
  ZiStringView components[3] = {0};
  ZiParsedPath path = {0};
  PHASE6_ASSERT(ZiSucceeded(zi_path_parse_absolute(file_path,
                                                   sizeof file_path - 1u,
                                                   components,
                                                   sizeof components / sizeof components[0],
                                                   &path)));
  ZiFsFileRecord record = {0};
  PHASE6_ASSERT(ZiSucceeded(ZiFsLookupPath(&volume, &path, scratch, sizeof scratch, &record)));
  PHASE6_ASSERT(record.file_type == ZI_FS_FILE_TYPE_REGULAR &&
                record.file_size == ZI_FS_BLOCK_SIZE + 17u && record.extent_count == 2);

  unsigned char output[64] = {0};
  size_t bytes_read = 0;
  PHASE6_ASSERT(ZiSucceeded(ZiFsReadFile(&volume,
                                         &record,
                                         ZI_FS_BLOCK_SIZE - 13u,
                                         output,
                                         40,
                                         &bytes_read,
                                         scratch,
                                         sizeof scratch)));
  PHASE6_ASSERT(bytes_read == 30);
  for (size_t index = 0; index < 13; ++index) {
    PHASE6_ASSERT(output[index] == (unsigned char)(0x80u + index));
  }
  for (size_t index = 0; index < 17; ++index) {
    PHASE6_ASSERT(output[13u + index] == (unsigned char)(0x40u + index));
  }

  PHASE6_ASSERT(ZiSucceeded(ZiFsReadFile(&volume,
                                         &record,
                                         record.file_size,
                                         output,
                                         sizeof output,
                                         &bytes_read,
                                         scratch,
                                         sizeof scratch)) &&
                bytes_read == 0);
  PHASE6_ASSERT(ZiSucceeded(ZiFsReadFile(&volume,
                                         &record,
                                         UINT64_MAX,
                                         output,
                                         sizeof output,
                                         &bytes_read,
                                         scratch,
                                         sizeof scratch)) &&
                bytes_read == 0);

  const char wrong_case[] = "C:\\Temp\\seed File.txt";
  PHASE6_ASSERT(ZiSucceeded(zi_path_parse_absolute(wrong_case,
                                                   sizeof wrong_case - 1u,
                                                   components,
                                                   sizeof components / sizeof components[0],
                                                   &path)));
  PHASE6_ASSERT(ZiFsLookupPath(&volume, &path, scratch, sizeof scratch, &record) ==
                ZI_STATUS_NOT_FOUND);

  PHASE6_ASSERT(ZiSucceeded(ZiFsReadFileRecord(&volume, 2, scratch, sizeof scratch, &record)));
  ZiFsFileRecord malformed = record;
  malformed.extents[1].logical_block = 2;
  PHASE6_ASSERT(ZiFsReadFile(&volume,
                             &malformed,
                             0,
                             output,
                             sizeof output,
                             &bytes_read,
                             scratch,
                             sizeof scratch) == ZI_STATUS_CORRUPT_FILESYSTEM);
  malformed = record;
  malformed.extents[0].physical_block = volume.superblock.directory_table_start;
  PHASE6_ASSERT(ZiFsReadFile(&volume,
                             &malformed,
                             0,
                             output,
                             sizeof output,
                             &bytes_read,
                             scratch,
                             sizeof scratch) == ZI_STATUS_CORRUPT_FILESYSTEM);
  malformed = record;
  malformed.extents[0].physical_block = volume.superblock.total_blocks;
  PHASE6_ASSERT(ZiFsReadFile(&volume,
                             &malformed,
                             0,
                             output,
                             sizeof output,
                             &bytes_read,
                             scratch,
                             sizeof scratch) == ZI_STATUS_CORRUPT_FILESYSTEM);
  malformed = record;
  malformed.extents[0].flags = 1;
  PHASE6_ASSERT(ZiFsReadFile(&volume,
                             &malformed,
                             0,
                             output,
                             sizeof output,
                             &bytes_read,
                             scratch,
                             sizeof scratch) == ZI_STATUS_CORRUPT_FILESYSTEM);
  malformed = record;
  malformed.allocated_size -= ZI_FS_BLOCK_SIZE;
  PHASE6_ASSERT(ZiFsReadFile(&volume,
                             &malformed,
                             0,
                             output,
                             sizeof output,
                             &bytes_read,
                             scratch,
                             sizeof scratch) == ZI_STATUS_CORRUPT_FILESYSTEM);

  ZiFsFileRecord directory = {0};
  PHASE6_ASSERT(ZiSucceeded(ZiFsReadFileRecord(&volume, 0, scratch, sizeof scratch, &directory)));
  PHASE6_ASSERT(ZiFsReadFile(&volume,
                             &directory,
                             0,
                             output,
                             sizeof output,
                             &bytes_read,
                             scratch,
                             sizeof scratch) == ZI_STATUS_INVALID_ARGUMENT);
  PHASE6_ASSERT(ZiFsReadFile(&volume, &record, 0, NULL, 1, &bytes_read, scratch, sizeof scratch) ==
                ZI_STATUS_INVALID_ARGUMENT);

  TestSourceAllocator source_allocator = {0};
  ZiFsImageSourceAllocator allocator = {
      sizeof(ZiFsImageSourceAllocator),
      ZI_FS_IMAGE_SOURCE_ALLOCATOR_VERSION,
      &source_allocator,
      (size_t)2u * ZI_FS_BLOCK_SIZE,
      (size_t)2u * ZI_FS_BLOCK_SIZE,
      test_source_allocate,
      test_source_release,
  };
  const ZiFsImageSourceRequest request = {
      {"Seed.exe", sizeof "Seed.exe" - 1u},
      {file_path, sizeof file_path - 1u},
  };
  ZiFsImageSourceSet source_set = {0};
  PHASE6_ASSERT(ZiSucceeded(zi_zifs_image_source_set_load(&volume,
                                                          &request,
                                                          1,
                                                          &allocator,
                                                          scratch,
                                                          sizeof scratch,
                                                          &source_set)));
  PHASE6_ASSERT(source_set.source_count == 1 && source_set.total_size == record.file_size &&
                source_allocator.active_allocations == 1);
  PHASE6_ASSERT(source_set.sources[0].file_data == source_set.allocations[0] &&
                source_set.sources[0].file_size == record.file_size);
  const unsigned char* source_bytes = source_set.sources[0].file_data;
  PHASE6_ASSERT(source_bytes[ZI_FS_BLOCK_SIZE - 13u] == 0x80u &&
                source_bytes[ZI_FS_BLOCK_SIZE] == 0x40u &&
                source_bytes[ZI_FS_BLOCK_SIZE + 16u] == 0x50u);
  PHASE6_ASSERT(ZiSucceeded(zi_zifs_image_source_set_release(&allocator, &source_set)) &&
                source_allocator.active_allocations == 0 && source_set.struct_size == 0);

  ZiFsImageSourceRequest wrong_case_request = request;
  wrong_case_request.file_path = (ZiStringView){wrong_case, sizeof wrong_case - 1u};
  PHASE6_ASSERT(zi_zifs_image_source_set_load(&volume,
                                              &wrong_case_request,
                                              1,
                                              &allocator,
                                              scratch,
                                              sizeof scratch,
                                              &source_set) == ZI_STATUS_NOT_FOUND &&
                source_allocator.active_allocations == 0);

  allocator.maximum_file_size = 128;
  PHASE6_ASSERT(zi_zifs_image_source_set_load(&volume,
                                              &request,
                                              1,
                                              &allocator,
                                              scratch,
                                              sizeof scratch,
                                              &source_set) == ZI_STATUS_BUFFER_TOO_SMALL &&
                source_allocator.active_allocations == 0);
  allocator.maximum_file_size = (size_t)2u * ZI_FS_BLOCK_SIZE;

  ZiFsImageSourceRequest duplicate_requests[2] = {request, request};
  PHASE6_ASSERT(zi_zifs_image_source_set_load(&volume,
                                              duplicate_requests,
                                              2,
                                              &allocator,
                                              scratch,
                                              sizeof scratch,
                                              &source_set) == ZI_STATUS_INVALID_ARGUMENT &&
                source_allocator.active_allocations == 0);
  duplicate_requests[1].module_name = (ZiStringView){"Other.dll", sizeof "Other.dll" - 1u};
  allocator.maximum_total_size = 6000;
  PHASE6_ASSERT(zi_zifs_image_source_set_load(&volume,
                                              duplicate_requests,
                                              2,
                                              &allocator,
                                              scratch,
                                              sizeof scratch,
                                              &source_set) == ZI_STATUS_BUFFER_TOO_SMALL &&
                source_allocator.active_allocations == 0);
  allocator.maximum_total_size = (size_t)2u * ZI_FS_BLOCK_SIZE;

  ZiFsImageSourceRequest invalid_request = request;
  invalid_request.module_name = (ZiStringView){"bad/name.dll", sizeof "bad/name.dll" - 1u};
  PHASE6_ASSERT(zi_zifs_image_source_set_load(&volume,
                                              &invalid_request,
                                              1,
                                              &allocator,
                                              scratch,
                                              sizeof scratch,
                                              &source_set) == ZI_STATUS_INVALID_ARGUMENT);
  source_allocator.fail_allocation = true;
  PHASE6_ASSERT(zi_zifs_image_source_set_load(&volume,
                                              &request,
                                              1,
                                              &allocator,
                                              scratch,
                                              sizeof scratch,
                                              &source_set) == ZI_STATUS_NO_MEMORY &&
                source_allocator.active_allocations == 0);
  *out_assertion_count = assertions;
  return true;
}

static ZiStatus memory_read_blocks(void* context,
                                   uint64_t first_block,
                                   uint32_t block_count,
                                   void* output,
                                   size_t output_size) {
  if (context == NULL || output == NULL || block_count == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  MemoryVolume* memory = context;
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

static ZiStatus test_source_allocate(void* context, size_t size, void** out_allocation) {
  if (context == NULL || size == 0 || out_allocation == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  TestSourceAllocator* allocator = context;
  *out_allocation = NULL;
  if (allocator->fail_allocation || allocator->used > sizeof allocator->arena ||
      size > sizeof allocator->arena - allocator->used) {
    return ZI_STATUS_NO_MEMORY;
  }
  *out_allocation = &allocator->arena[allocator->used];
  allocator->used += size;
  ++allocator->active_allocations;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus test_source_release(void* context, void* allocation) {
  if (context == NULL || allocation == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  TestSourceAllocator* allocator = context;
  uintptr_t first = (uintptr_t)&allocator->arena[0];
  uintptr_t end = (uintptr_t)&allocator->arena[sizeof allocator->arena];
  uintptr_t address = (uintptr_t)allocation;
  if (address < first || address >= end || allocator->active_allocations == 0) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  --allocator->active_allocations;
  return ZI_STATUS_SUCCESS;
}

static bool initialise_file_volume(void) {
  zi_memory_zero(s_volume, sizeof s_volume);
  ZiFsSuperblock superblock = {0};
  superblock.format_major = ZI_FS_FORMAT_MAJOR;
  superblock.format_minor = ZI_FS_FORMAT_MINOR;
  superblock.block_shift = ZI_FS_BLOCK_SHIFT;
  superblock.checksum_type = 1;
  superblock.incompatible_features = ZI_FS_FEATURE_INCOMPAT_SECURITY_V1;
  superblock.generation = 1;
  superblock.total_blocks = TEST_VOLUME_BLOCKS;
  superblock.root_record_index = 0;
  superblock.record_table_start = 1;
  superblock.record_table_blocks = 1;
  superblock.allocation_bitmap_start = 2;
  superblock.allocation_bitmap_blocks = 1;
  superblock.journal_start = 3;
  superblock.journal_blocks = 1;
  superblock.security_table_start = 4;
  superblock.security_table_blocks = 1;
  superblock.directory_table_start = 5;
  superblock.directory_table_blocks = 2;
  superblock.backup_superblock = TEST_VOLUME_BLOCKS - 1u;
  superblock.volume_name_size = 6;
  zi_memory_copy(superblock.volume_name, "Zizium", superblock.volume_name_size);
  if (ZiFailed(ZiFsEncodeSuperblock(&superblock, s_volume[0], ZI_FS_BLOCK_SIZE))) {
    return false;
  }
  zi_memory_copy(s_volume[TEST_VOLUME_BLOCKS - 1u], s_volume[0], ZI_FS_BLOCK_SIZE);
  if (!initialise_security_table()) {
    return false;
  }

  ZiFsFileRecord records[3] = {0};
  records[0].file_id = 1;
  records[0].parent_file_id = 1;
  records[0].security_id = 1;
  records[0].file_type = ZI_FS_FILE_TYPE_DIRECTORY;
  records[0].directory_block = 5;
  records[1].file_id = 2;
  records[1].parent_file_id = 1;
  records[1].security_id = 1;
  records[1].file_type = ZI_FS_FILE_TYPE_DIRECTORY;
  records[1].directory_block = 6;
  records[2].file_id = 3;
  records[2].parent_file_id = 2;
  records[2].security_id = 1;
  records[2].file_type = ZI_FS_FILE_TYPE_REGULAR;
  records[2].file_size = ZI_FS_BLOCK_SIZE + 17u;
  records[2].allocated_size = UINT64_C(2) * ZI_FS_BLOCK_SIZE;
  records[2].extent_count = 2;
  records[2].extents[0].logical_block = 0;
  records[2].extents[0].physical_block = TEST_DATA_BLOCK_ONE;
  records[2].extents[0].block_count = 1;
  records[2].extents[1].logical_block = 1;
  records[2].extents[1].physical_block = TEST_DATA_BLOCK_TWO;
  records[2].extents[1].block_count = 1;
  for (size_t index = 0; index < sizeof records / sizeof records[0]; ++index) {
    if (ZiFailed(ZiFsEncodeFileRecord(&records[index],
                                      s_volume[1] + (index * ZI_FS_FILE_RECORD_SIZE),
                                      ZI_FS_FILE_RECORD_SIZE))) {
      return false;
    }
  }

  if (ZiFailed(ZiFsInitialiseDirectoryBlock(s_volume[5], ZI_FS_BLOCK_SIZE, 1, 1)) ||
      ZiFailed(ZiFsInitialiseDirectoryBlock(s_volume[6], ZI_FS_BLOCK_SIZE, 2, 1))) {
    return false;
  }
  ZiFsDirectoryEntry temp_entry = {2, 1, ZI_FS_FILE_TYPE_DIRECTORY, 0, {"Temp", 4}};
  ZiFsDirectoryEntry file_entry = {
      3,
      2,
      ZI_FS_FILE_TYPE_REGULAR,
      0,
      {"Seed File.txt", 13},
  };
  if (ZiFailed(ZiFsAddDirectoryEntry(s_volume[5], ZI_FS_BLOCK_SIZE, &temp_entry)) ||
      ZiFailed(ZiFsAddDirectoryEntry(s_volume[6], ZI_FS_BLOCK_SIZE, &file_entry))) {
    return false;
  }
  for (size_t index = 0; index < 13; ++index) {
    s_volume[TEST_DATA_BLOCK_ONE][ZI_FS_BLOCK_SIZE - 13u + index] = (unsigned char)(0x80u + index);
  }
  for (size_t index = 0; index < 17; ++index) {
    s_volume[TEST_DATA_BLOCK_TWO][index] = (unsigned char)(0x40u + index);
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
      bool)(ZiSucceeded(ZiFsInitialiseSecurityTable(s_volume[4], ZI_FS_BLOCK_SIZE, 1)) &&
            ZiSucceeded(ZiFsAppendSecurityDescriptor(s_volume[4],
                                                     ZI_FS_BLOCK_SIZE,
                                                     1,
                                                     ZI_FS_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT,
                                                     &descriptor)));
}
