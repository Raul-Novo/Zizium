// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "phase7_tests.h"
#include "zi/block.h"
#include "zi/byte_order.h"
#include "zi/crc32c.h"
#include "zi/security.h"
#include "zi/zifs.h"
#include "zi/zifs_security.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define SECURITY_TEST_VOLUME_BLOCKS 16u
#define SECURITY_TEST_TABLE_BLOCKS 2u
#define SECURITY_TEST_RECORD_COUNT 16u
#define SECURITY_TEST_TABLE_CHECKSUM_OFFSET 252u
#define SECURITY_TEST_RECORD_CHECKSUM_OFFSET 252u
#define SECURITY_TEST_FIRST_RECORD_OFFSET ZI_FS_SECURITY_TABLE_HEADER_SIZE
#define SECURITY_TEST_TABLE_SIZE ((size_t)SECURITY_TEST_TABLE_BLOCKS * (size_t)ZI_FS_BLOCK_SIZE)
#define SECURITY_TEST_USED_BYTES                                                                   \
  (ZI_FS_SECURITY_TABLE_HEADER_SIZE +                                                              \
   (SECURITY_TEST_RECORD_COUNT * ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE))

typedef struct SecurityTestDevice {
  unsigned char* bytes;
  size_t size;
} SecurityTestDevice;

typedef struct SecurityTestState {
  size_t assertions;
} SecurityTestState;

static unsigned char s_security_volume[SECURITY_TEST_VOLUME_BLOCKS][ZI_FS_BLOCK_SIZE];

static ZiStatus security_test_read(void* context,
                                   uint64_t first_block,
                                   uint32_t block_count,
                                   void* output,
                                   size_t output_size);
static bool initialise_security_test_volume(void);
static bool append_test_descriptors(void* table, size_t table_size);
static bool security_table_round_trip_test(SecurityTestState* state);
static bool security_access_test(SecurityTestState* state);
static bool security_corruption_test(SecurityTestState* state);
static bool security_mount_access_test(SecurityTestState* state);
static bool security_mount_corruption_test(SecurityTestState* state);
static bool
security_test_expect(SecurityTestState* state, bool result, int line, const char* expression);
static ZiSecurityDescriptor
make_test_descriptor(ZiAcl* out_dacl, ZiAce* entries, size_t entry_count);
static void update_table_checksum(unsigned char* table, size_t table_size);
static void update_record_checksum(unsigned char* record);

#define SECURITY_EXPECT(state, expression)                                                         \
  security_test_expect((state), (bool)(expression), __LINE__, #expression)

bool phase7_zifs_security_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  SecurityTestState state = {0};
  bool passed = security_table_round_trip_test(&state);
  if (passed) {
    passed = security_access_test(&state);
  }
  if (passed) {
    passed = security_corruption_test(&state);
  }
  if (passed) {
    passed = security_mount_access_test(&state);
  }
  if (passed) {
    passed = security_mount_corruption_test(&state);
  }
  *out_assertion_count = state.assertions;
  return passed;
}

static bool security_table_round_trip_test(SecurityTestState* state) {
  unsigned char table[SECURITY_TEST_TABLE_SIZE] = {0};
  if (!SECURITY_EXPECT(state, ZiSucceeded(ZiFsInitialiseSecurityTable(table, sizeof table, 21))) ||
      !SECURITY_EXPECT(state, append_test_descriptors(table, sizeof table))) {
    return false;
  }
  ZiFsSecurityTableHeader header = {0};
  if (!SECURITY_EXPECT(state,
                       ZiSucceeded(ZiFsValidateSecurityTable(table, sizeof table, &header))) ||
      !SECURITY_EXPECT(
          state,
          header.generation == 21 && header.table_block_count == SECURITY_TEST_TABLE_BLOCKS &&
              header.record_count == SECURITY_TEST_RECORD_COUNT && header.record_capacity == 31 &&
              header.used_bytes == SECURITY_TEST_USED_BYTES)) {
    return false;
  }

  ZiFsSecurityDescriptorStorage decoded = {0};
  return SECURITY_EXPECT(
             state,
             ZiSucceeded(ZiFsDecodeSecurityDescriptor(table + SECURITY_TEST_FIRST_RECORD_OFFSET,
                                                      ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE,
                                                      &decoded))) &&
         SECURITY_EXPECT(state,
                         decoded.security_id == 1 && decoded.descriptor.dacl == &decoded.dacl &&
                             decoded.dacl.entry_count == 3 &&
                             decoded.dacl.entries == decoded.entries);
}

static bool security_access_test(SecurityTestState* state) {
  unsigned char table[SECURITY_TEST_TABLE_SIZE] = {0};
  ZiFsSecurityDescriptorStorage decoded = {0};
  if (!SECURITY_EXPECT(state, ZiSucceeded(ZiFsInitialiseSecurityTable(table, sizeof table, 21))) ||
      !SECURITY_EXPECT(state, append_test_descriptors(table, sizeof table)) ||
      !SECURITY_EXPECT(
          state,
          ZiSucceeded(ZiFsDecodeSecurityDescriptor(table + SECURITY_TEST_FIRST_RECORD_OFFSET,
                                                   ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE,
                                                   &decoded)))) {
    return false;
  }
  const ZiSecurityId user = {ZI_SECURITY_AUTHORITY_USER, 21};
  const ZiSecurityId group = {ZI_SECURITY_AUTHORITY_GROUP, 7};
  const ZiSecurityId groups[] = {group};
  const ZiAccessToken token = {sizeof(ZiAccessToken), ZI_ACCESS_TOKEN_VERSION, user, groups, 1, 0};
  ZiAccessMask granted = 0;
  return SECURITY_EXPECT(state,
                         ZiSucceeded(zi_security_access_check(&decoded.descriptor,
                                                              &token,
                                                              ZI_ACCESS_READ | ZI_ACCESS_EXECUTE,
                                                              &granted))) &&
         SECURITY_EXPECT(state, granted == (ZI_ACCESS_READ | ZI_ACCESS_EXECUTE)) &&
         SECURITY_EXPECT(
             state,
             zi_security_access_check(&decoded.descriptor, &token, ZI_ACCESS_DELETE, &granted) ==
                 ZI_STATUS_ACCESS_DENIED);
}

static bool security_corruption_test(SecurityTestState* state) {
  unsigned char table[SECURITY_TEST_TABLE_SIZE] = {0};
  if (!SECURITY_EXPECT(state, ZiSucceeded(ZiFsInitialiseSecurityTable(table, sizeof table, 21))) ||
      !SECURITY_EXPECT(state, append_test_descriptors(table, sizeof table))) {
    return false;
  }
  ZiFsSecurityTableHeader header = {0};

  unsigned char damaged[sizeof table] = {0};
  zi_memory_copy(damaged, table, sizeof table);
  damaged[SECURITY_TEST_FIRST_RECORD_OFFSET + 48u + 4u] ^= UINT8_C(0x01);
  if (!SECURITY_EXPECT(state,
                       ZiFsValidateSecurityTable(damaged, sizeof damaged, &header) ==
                           ZI_STATUS_CHECKSUM_MISMATCH)) {
    return false;
  }

  zi_memory_copy(damaged, table, sizeof table);
  damaged[SECURITY_TEST_FIRST_RECORD_OFFSET + 48u + 4u] ^= UINT8_C(0x01);
  update_table_checksum(damaged, sizeof damaged);
  if (!SECURITY_EXPECT(state,
                       ZiFsValidateSecurityTable(damaged, sizeof damaged, &header) ==
                           ZI_STATUS_CHECKSUM_MISMATCH)) {
    return false;
  }

  zi_memory_copy(damaged, table, sizeof table);
  unsigned char* second_record =
      damaged + SECURITY_TEST_FIRST_RECORD_OFFSET + ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE;
  zi_write_u64_le(second_record + 8, 1);
  update_record_checksum(second_record);
  update_table_checksum(damaged, sizeof damaged);
  if (!SECURITY_EXPECT(state,
                       ZiFsValidateSecurityTable(damaged, sizeof damaged, &header) ==
                           ZI_STATUS_CORRUPT_FILESYSTEM)) {
    return false;
  }

  zi_memory_copy(damaged, table, sizeof table);
  unsigned char* first_record = damaged + SECURITY_TEST_FIRST_RECORD_OFFSET;
  zi_write_u32_le(first_record + 48u + 8u, 99);
  update_record_checksum(first_record);
  update_table_checksum(damaged, sizeof damaged);
  if (!SECURITY_EXPECT(state,
                       ZiFsValidateSecurityTable(damaged, sizeof damaged, &header) ==
                           ZI_STATUS_CORRUPT_FILESYSTEM)) {
    return false;
  }

  zi_memory_copy(damaged, table, sizeof table);
  damaged[SECURITY_TEST_USED_BYTES] = UINT8_C(0x21);
  update_table_checksum(damaged, sizeof damaged);
  if (!SECURITY_EXPECT(state,
                       ZiFsValidateSecurityTable(damaged, sizeof damaged, &header) ==
                           ZI_STATUS_CORRUPT_FILESYSTEM)) {
    return false;
  }

  const ZiSecurityId user = {ZI_SECURITY_AUTHORITY_USER, 21};
  ZiAce duplicate_entry = {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_READ, user};
  ZiAcl duplicate_dacl = {0};
  ZiSecurityDescriptor duplicate_descriptor =
      make_test_descriptor(&duplicate_dacl, &duplicate_entry, 1);
  return SECURITY_EXPECT(state,
                         ZiFsAppendSecurityDescriptor(table,
                                                      sizeof table,
                                                      SECURITY_TEST_RECORD_COUNT,
                                                      ZI_FS_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT,
                                                      &duplicate_descriptor) ==
                             ZI_STATUS_ALREADY_EXISTS);
}

static bool security_mount_access_test(SecurityTestState* state) {
  if (!SECURITY_EXPECT(state, initialise_security_test_volume())) {
    return false;
  }

  SecurityTestDevice memory = {&s_security_volume[0][0], sizeof s_security_volume};
  ZiBlockDevice device = {
      sizeof(ZiBlockDevice),
      ZI_BLOCK_DEVICE_VERSION,
      &memory,
      ZI_FS_BLOCK_SIZE,
      SECURITY_TEST_VOLUME_BLOCKS,
      security_test_read,
      NULL,
      ZI_BLOCK_DEVICE_READ_ONLY,
      NULL,
  };
  unsigned char scratch[ZI_FS_BLOCK_SIZE] = {0};
  ZiFsVolume volume = {0};
  ZiFsSecurityDescriptorStorage decoded = {0};
  const ZiSecurityId user = {ZI_SECURITY_AUTHORITY_USER, 21};
  const ZiSecurityId groups[] = {{ZI_SECURITY_AUTHORITY_GROUP, 7}};
  const ZiAccessToken token = {sizeof(ZiAccessToken), ZI_ACCESS_TOKEN_VERSION, user, groups, 1, 0};
  ZiAccessMask granted = 0;
  return SECURITY_EXPECT(state,
                         ZiSucceeded(ZiFsMountVolume(&device, scratch, sizeof scratch, &volume))) &&
         SECURITY_EXPECT(state,
                         volume.security_generation == 21 &&
                             volume.security_record_count == SECURITY_TEST_RECORD_COUNT) &&
         SECURITY_EXPECT(
             state,
             ZiSucceeded(
                 ZiFsLoadSecurityDescriptor(&volume, 16, scratch, sizeof scratch, &decoded))) &&
         SECURITY_EXPECT(state,
                         decoded.security_id == 16 && decoded.dacl.entries == decoded.entries &&
                             decoded.descriptor.dacl == &decoded.dacl) &&
         SECURITY_EXPECT(
             state,
             ZiFsLoadSecurityDescriptor(&volume, 17, scratch, sizeof scratch, &decoded) ==
                 ZI_STATUS_NOT_FOUND) &&
         SECURITY_EXPECT(state,
                         ZiSucceeded(ZiFsCheckSecurityAccess(&volume,
                                                             16,
                                                             &token,
                                                             ZI_ACCESS_READ | ZI_ACCESS_EXECUTE,
                                                             &granted,
                                                             scratch,
                                                             sizeof scratch))) &&
         SECURITY_EXPECT(state, granted == (ZI_ACCESS_READ | ZI_ACCESS_EXECUTE)) &&
         SECURITY_EXPECT(state,
                         ZiFsCheckSecurityAccess(&volume,
                                                 16,
                                                 &token,
                                                 ZI_ACCESS_DELETE,
                                                 &granted,
                                                 scratch,
                                                 sizeof scratch) == ZI_STATUS_ACCESS_DENIED);
}

static bool security_mount_corruption_test(SecurityTestState* state) {
  if (!SECURITY_EXPECT(state, initialise_security_test_volume())) {
    return false;
  }
  SecurityTestDevice memory = {&s_security_volume[0][0], sizeof s_security_volume};
  ZiBlockDevice device = {
      sizeof(ZiBlockDevice),
      ZI_BLOCK_DEVICE_VERSION,
      &memory,
      ZI_FS_BLOCK_SIZE,
      SECURITY_TEST_VOLUME_BLOCKS,
      security_test_read,
      NULL,
      ZI_BLOCK_DEVICE_READ_ONLY,
      NULL,
  };
  unsigned char scratch[ZI_FS_BLOCK_SIZE] = {0};
  ZiFsVolume volume = {0};

  ZiFsFileRecord root = {0};
  if (!SECURITY_EXPECT(
          state,
          ZiSucceeded(ZiFsDecodeFileRecord(s_security_volume[1], ZI_FS_FILE_RECORD_SIZE, &root)))) {
    return false;
  }
  root.security_id = 99;
  if (!SECURITY_EXPECT(
          state,
          ZiSucceeded(ZiFsEncodeFileRecord(&root, s_security_volume[1], ZI_FS_FILE_RECORD_SIZE))) ||
      !SECURITY_EXPECT(state,
                       ZiFsMountVolume(&device, scratch, sizeof scratch, &volume) ==
                           ZI_STATUS_CORRUPT_FILESYSTEM)) {
    return false;
  }

  if (!SECURITY_EXPECT(state, initialise_security_test_volume())) {
    return false;
  }
  s_security_volume[4][SECURITY_TEST_FIRST_RECORD_OFFSET + 48u + 4u] ^= UINT8_C(0x80);
  if (!SECURITY_EXPECT(state,
                       ZiFsMountVolume(&device, scratch, sizeof scratch, &volume) ==
                           ZI_STATUS_CHECKSUM_MISMATCH)) {
    return false;
  }

  if (!SECURITY_EXPECT(state, initialise_security_test_volume())) {
    return false;
  }
  ZiFsSuperblock superblock = {0};
  if (!SECURITY_EXPECT(
          state,
          ZiSucceeded(ZiFsDecodeSuperblock(s_security_volume[0], ZI_FS_BLOCK_SIZE, &superblock)))) {
    return false;
  }
  superblock.incompatible_features &= ~ZI_FS_FEATURE_INCOMPAT_SECURITY_V1;
  if (!SECURITY_EXPECT(
          state,
          ZiSucceeded(ZiFsEncodeSuperblock(&superblock, s_security_volume[0], ZI_FS_BLOCK_SIZE)))) {
    return false;
  }
  zi_memory_copy(s_security_volume[SECURITY_TEST_VOLUME_BLOCKS - 1u],
                 s_security_volume[0],
                 ZI_FS_BLOCK_SIZE);
  return SECURITY_EXPECT(state,
                         ZiFsMountVolume(&device, scratch, sizeof scratch, &volume) ==
                             ZI_STATUS_CORRUPT_FILESYSTEM);
}

static bool
security_test_expect(SecurityTestState* state, bool result, int line, const char* expression) {
  ++state->assertions;
  if (!result) {
    (void)fprintf_s(stderr, "Phase 7 security assertion failed at line %d: %s\n", line, expression);
  }
  return result;
}

static ZiStatus security_test_read(void* context,
                                   uint64_t first_block,
                                   uint32_t block_count,
                                   void* output,
                                   size_t output_size) {
  if (context == NULL || output == NULL || block_count == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  SecurityTestDevice* memory = context;
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

static bool initialise_security_test_volume(void) {
  zi_memory_zero(s_security_volume, sizeof s_security_volume);
  ZiFsSuperblock superblock = {0};
  superblock.format_major = ZI_FS_FORMAT_MAJOR;
  superblock.format_minor = ZI_FS_FORMAT_MINOR;
  superblock.block_shift = ZI_FS_BLOCK_SHIFT;
  superblock.checksum_type = 1;
  superblock.incompatible_features = ZI_FS_FEATURE_INCOMPAT_SECURITY_V1;
  superblock.generation = 1;
  superblock.total_blocks = SECURITY_TEST_VOLUME_BLOCKS;
  superblock.root_record_index = 0;
  superblock.record_table_start = 1;
  superblock.record_table_blocks = 1;
  superblock.allocation_bitmap_start = 2;
  superblock.allocation_bitmap_blocks = 1;
  superblock.journal_start = 3;
  superblock.journal_blocks = 0;
  superblock.security_table_start = 4;
  superblock.security_table_blocks = SECURITY_TEST_TABLE_BLOCKS;
  superblock.directory_table_start = 6;
  superblock.directory_table_blocks = 1;
  superblock.backup_superblock = SECURITY_TEST_VOLUME_BLOCKS - 1u;
  superblock.volume_name_size = 6;
  zi_memory_copy(superblock.volume_name, "Zizium", superblock.volume_name_size);
  if (ZiFailed(ZiFsEncodeSuperblock(&superblock, s_security_volume[0], ZI_FS_BLOCK_SIZE))) {
    return false;
  }
  zi_memory_copy(s_security_volume[SECURITY_TEST_VOLUME_BLOCKS - 1u],
                 s_security_volume[0],
                 ZI_FS_BLOCK_SIZE);

  if (ZiFailed(ZiFsInitialiseSecurityTable(s_security_volume[4], SECURITY_TEST_TABLE_SIZE, 21)) ||
      !append_test_descriptors(s_security_volume[4], SECURITY_TEST_TABLE_SIZE)) {
    return false;
  }
  ZiFsFileRecord root = {0};
  root.file_id = 1;
  root.parent_file_id = 1;
  root.security_id = SECURITY_TEST_RECORD_COUNT;
  root.file_type = ZI_FS_FILE_TYPE_DIRECTORY;
  root.directory_block = 6;
  return (bool)(ZiSucceeded(
                    ZiFsEncodeFileRecord(&root, s_security_volume[1], ZI_FS_FILE_RECORD_SIZE)) &&
                ZiSucceeded(ZiFsInitialiseDirectoryBlock(s_security_volume[6],
                                                         ZI_FS_BLOCK_SIZE,
                                                         root.file_id,
                                                         1)));
}

static bool append_test_descriptors(void* table, size_t table_size) {
  ZiAce entries[] = {
      {ZI_ACE_DENY, 0, 0, ZI_ACCESS_DELETE, {ZI_SECURITY_AUTHORITY_GROUP, 7}},
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_READ | ZI_ACCESS_WRITE, {ZI_SECURITY_AUTHORITY_USER, 21}},
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_EXECUTE, {ZI_SECURITY_AUTHORITY_GROUP, 7}},
  };
  ZiAcl dacl = {0};
  ZiSecurityDescriptor descriptor = make_test_descriptor(&dacl, entries, 3);
  for (uint64_t security_id = 1; security_id <= SECURITY_TEST_RECORD_COUNT; ++security_id) {
    if (ZiFailed(ZiFsAppendSecurityDescriptor(table,
                                              table_size,
                                              security_id,
                                              ZI_FS_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT,
                                              &descriptor))) {
      return false;
    }
  }
  return true;
}

static ZiSecurityDescriptor
make_test_descriptor(ZiAcl* out_dacl, ZiAce* entries, size_t entry_count) {
  *out_dacl = (ZiAcl){sizeof(ZiAcl), ZI_ACL_VERSION, entries, entry_count};
  return (ZiSecurityDescriptor){
      sizeof(ZiSecurityDescriptor),
      ZI_SECURITY_DESCRIPTOR_VERSION,
      {ZI_SECURITY_AUTHORITY_USER, 21},
      {ZI_SECURITY_AUTHORITY_GROUP, 7},
      out_dacl,
      ZI_SECURITY_DESCRIPTOR_CONTROL_NONE,
  };
}

static void update_table_checksum(unsigned char* table, size_t table_size) {
  const unsigned char zero_checksum[4] = {0};
  zi_write_u32_le(table + SECURITY_TEST_TABLE_CHECKSUM_OFFSET, 0);
  uint32_t checksum = zi_crc32c(0, table, SECURITY_TEST_TABLE_CHECKSUM_OFFSET);
  checksum = zi_crc32c(checksum, zero_checksum, sizeof zero_checksum);
  checksum = zi_crc32c(checksum,
                       table + SECURITY_TEST_TABLE_CHECKSUM_OFFSET + sizeof zero_checksum,
                       table_size - SECURITY_TEST_TABLE_CHECKSUM_OFFSET - sizeof zero_checksum);
  zi_write_u32_le(table + SECURITY_TEST_TABLE_CHECKSUM_OFFSET, checksum);
}

static void update_record_checksum(unsigned char* record) {
  zi_write_u32_le(record + SECURITY_TEST_RECORD_CHECKSUM_OFFSET,
                  zi_crc32c(0, record, SECURITY_TEST_RECORD_CHECKSUM_OFFSET));
}
