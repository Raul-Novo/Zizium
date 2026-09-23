// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "phase8_tests.h"
#include "zi/byte_order.h"
#include "zi/crc32c.h"
#include "zi/identity.h"
#include "zi/identity_database.h"
#include "zi/security.h"
#include "zizium/status.h"

static const ZiIdentityDatabaseAuthority k_authority = {sizeof(ZiIdentityDatabaseAuthority),
                                                        ZI_IDENTITY_DATABASE_VERSION,
                                                        {1},
                                                        {2},
                                                        {3}};
static unsigned char s_bytes[ZI_IDENTITY_DATABASE_SIZE];
static unsigned char s_saved[ZI_IDENTITY_DATABASE_SIZE];
static bool expect(size_t* count, bool condition, int line);
static ZiIdentityCreateRequest request_for(uint32_t authority, const char* name, size_t name_size);
static void checksum(void);
static void record_checksum(size_t index);
static bool test_lifecycle(size_t* count);
static bool test_empty_database(size_t* count);
static bool test_name_reuse(size_t* count, const ZiNativeIdentity* first);
static bool test_groups(size_t* count);
static bool test_group_removal(size_t* count,
                               const ZiNativeIdentity* group,
                               const ZiNativeIdentity* first,
                               ZiIdentityCreateRequest* user);
static bool test_header_failures(size_t* count);
static bool test_header_binding(size_t* count);
static bool test_record_failures(size_t* count);
static bool test_capacity(size_t* count);
static bool test_exhaustion(size_t* count);
static bool test_invalid_requests(size_t* count);

#define EXPECT(condition)                                                                          \
  do {                                                                                             \
    if (!expect(count, (condition), __LINE__)) {                                                   \
      return false;                                                                                \
    }                                                                                              \
  } while (false)

bool phase8_database_test(size_t* out_assertion_count) {
  size_t count = 0;
  bool result = (bool)(test_lifecycle(&count) && test_groups(&count) &&
                       test_header_failures(&count) && test_record_failures(&count) &&
                       test_capacity(&count) && test_invalid_requests(&count));
  *out_assertion_count = count;
  return result;
}

static bool test_empty_database(size_t* count) {
  EXPECT(zi_identity_database_initialise(&k_authority, s_bytes, sizeof s_bytes) ==
         ZI_STATUS_SUCCESS);
  const unsigned char golden[] = {'Z', 'I', 'D', 'B', 1, 0, 0, 16, 0, 144, 0, 0, 0, 2, 64, 0};
  EXPECT(zi_memory_compare(s_bytes, golden, sizeof golden) == 0);
  ZiIdentityDatabaseState state = {0};
  EXPECT(zi_identity_database_validate(s_bytes, sizeof s_bytes, &k_authority, 1, &state) ==
         ZI_STATUS_SUCCESS);
  EXPECT(state.generation == 1 && state.record_count == 0 && state.issuer.user_high_water == 255);
  return true;
}

static bool test_lifecycle(size_t* count) {
  if (!test_empty_database(count)) {
    return false;
  }
  ZiIdentityCreateRequest request = request_for(ZI_SECURITY_AUTHORITY_USER, "First User", 10);
  ZiNativeIdentity first = {0};
  EXPECT(zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, &request, &first) ==
         ZI_STATUS_SUCCESS);
  EXPECT(first.local_id.value == 256);
  ZiIdentityDatabaseRecord record = {0};
  EXPECT(zi_identity_database_record(s_bytes, sizeof s_bytes, &k_authority, 0, &record) ==
         ZI_STATUS_SUCCESS);
  EXPECT(record.state == ZI_IDENTITY_RECORD_DISABLED && record.generation == 2 &&
         record.name_size == 10);
  return test_name_reuse(count, &first);
}

static bool test_name_reuse(size_t* count, const ZiNativeIdentity* first) {
  ZiIdentityCreateRequest request = request_for(ZI_SECURITY_AUTHORITY_USER, "First User", 10);
  ZiIdentityDatabaseRecord record = {0};
  EXPECT(zi_identity_database_remove(s_bytes, sizeof s_bytes, &k_authority, first) ==
         ZI_STATUS_SUCCESS);
  ZiNativeIdentity second = {0};
  EXPECT(zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, &request, &second) ==
         ZI_STATUS_SUCCESS);
  EXPECT(second.local_id.value == 257 && !zi_identity_equal(first, &second));
  EXPECT(zi_identity_database_record(s_bytes, sizeof s_bytes, &k_authority, 0, &record) ==
         ZI_STATUS_SUCCESS);
  EXPECT(record.state == ZI_IDENTITY_RECORD_TOMBSTONE && record.identity.local_id.value == 256);
  EXPECT(zi_identity_database_remove(s_bytes, sizeof s_bytes, &k_authority, first) ==
         ZI_STATUS_NOT_FOUND);
  return true;
}

static bool test_groups(size_t* count) {
  EXPECT(zi_identity_database_initialise(&k_authority, s_bytes, sizeof s_bytes) ==
         ZI_STATUS_SUCCESS);
  ZiIdentityCreateRequest group_request =
      request_for(ZI_SECURITY_AUTHORITY_GROUP, "Local Group", 11);
  ZiNativeIdentity group = {0};
  EXPECT(
      zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, &group_request, &group) ==
      ZI_STATUS_SUCCESS);
  uint32_t groups[] = {256};
  ZiIdentityCreateRequest user = request_for(ZI_SECURITY_AUTHORITY_USER, "Temp", 4);
  user.groups = groups;
  user.group_count = 1;
  ZiNativeIdentity first = {0};
  EXPECT(zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, &user, &first) ==
         ZI_STATUS_SUCCESS);
  EXPECT(zi_identity_database_remove(s_bytes, sizeof s_bytes, &k_authority, &group) ==
         ZI_STATUS_RESOURCE_IN_USE);
  zi_memory_copy(s_saved, s_bytes, sizeof s_bytes);
  ZiNativeIdentity sentinel = first;
  EXPECT(zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, &user, &sentinel) ==
         ZI_STATUS_ALREADY_EXISTS);
  EXPECT(zi_memory_compare(s_saved, s_bytes, sizeof s_bytes) == 0 &&
         zi_identity_equal(&sentinel, &first));
  return test_group_removal(count, &group, &first, &user);
}

static bool test_group_removal(size_t* count,
                               const ZiNativeIdentity* group,
                               const ZiNativeIdentity* first,
                               ZiIdentityCreateRequest* user) {
  ZiNativeIdentity second = {0};
  user->name.data = "temp";
  EXPECT(zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, user, &second) ==
         ZI_STATUS_SUCCESS);
  EXPECT(zi_identity_database_remove(s_bytes, sizeof s_bytes, &k_authority, first) ==
         ZI_STATUS_SUCCESS);
  EXPECT(zi_identity_database_remove(s_bytes, sizeof s_bytes, &k_authority, &second) ==
         ZI_STATUS_SUCCESS);
  EXPECT(zi_identity_database_remove(s_bytes, sizeof s_bytes, &k_authority, group) ==
         ZI_STATUS_SUCCESS);
  user->name.data = "lost";
  EXPECT(zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, user, &second) ==
         ZI_STATUS_INVALID_ARGUMENT);
  return true;
}

static bool test_header_failures(size_t* count) {
  EXPECT(zi_identity_database_initialise(&k_authority, s_bytes, sizeof s_bytes) ==
         ZI_STATUS_SUCCESS);
  zi_memory_copy(s_saved, s_bytes, sizeof s_bytes);
  ZiIdentityDatabaseState state = {.generation = UINT64_MAX};
  const size_t offsets[] = {0, 4, 6, 8, 12, 14, 20, 92, 4091, 4096};
  for (size_t index = 0; index < sizeof offsets / sizeof offsets[0]; ++index) {
    zi_memory_copy(s_bytes, s_saved, sizeof s_bytes);
    s_bytes[offsets[index]] ^= 128u;
    checksum();
    EXPECT(
        ZiFailed(zi_identity_database_validate(s_bytes, sizeof s_bytes, &k_authority, 1, &state)));
    EXPECT(state.generation == UINT64_MAX);
  }
  return test_header_binding(count);
}

static bool test_header_binding(size_t* count) {
  ZiIdentityDatabaseState state = {.generation = UINT64_MAX};
  zi_memory_copy(s_bytes, s_saved, sizeof s_bytes);
  EXPECT(zi_identity_database_validate(s_bytes, sizeof s_bytes - 1u, &k_authority, 1, &state) ==
         ZI_STATUS_INVALID_ARGUMENT);
  EXPECT(zi_identity_database_validate(s_bytes, sizeof s_bytes + 1u, &k_authority, 1, &state) ==
         ZI_STATUS_INVALID_ARGUMENT);
  EXPECT(zi_identity_database_validate(s_bytes, sizeof s_bytes, &k_authority, 2, &state) ==
         ZI_STATUS_INVALID_STATE);
  s_bytes[4092] ^= 1u;
  EXPECT(zi_identity_database_validate(s_bytes, sizeof s_bytes, &k_authority, 1, &state) ==
         ZI_STATUS_CHECKSUM_MISMATCH);
  zi_memory_copy(s_bytes, s_saved, sizeof s_bytes);
  for (size_t offset = 32; offset < 80; ++offset) {
    s_bytes[offset] ^= 1u;
    checksum();
    EXPECT(zi_identity_database_validate(s_bytes, sizeof s_bytes, &k_authority, 1, &state) ==
           ZI_STATUS_ACCESS_DENIED);
    s_bytes[offset] ^= 1u;
  }
  return true;
}

static bool test_record_failures(size_t* count) {
  EXPECT(zi_identity_database_initialise(&k_authority, s_bytes, sizeof s_bytes) ==
         ZI_STATUS_SUCCESS);
  ZiIdentityCreateRequest request = request_for(ZI_SECURITY_AUTHORITY_USER, "Valid", 5);
  ZiNativeIdentity identity = {0};
  EXPECT(zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, &request, &identity) ==
         ZI_STATUS_SUCCESS);
  zi_memory_copy(s_saved, s_bytes, sizeof s_bytes);
  // Recompute both CRCs so semantic rejection cannot hide behind checksum failure.
  const size_t offsets[] = {0, 4, 6, 8, 12, 16, 24, 40, 44, 48, 50, 52, 56, 69, 192, 256, 507};
  ZiIdentityDatabaseState state = {0};
  for (size_t index = 0; index < sizeof offsets / sizeof offsets[0]; ++index) {
    zi_memory_copy(s_bytes, s_saved, sizeof s_bytes);
    s_bytes[4096 + offsets[index]] ^= 128u;
    record_checksum(0);
    EXPECT(
        ZiFailed(zi_identity_database_validate(s_bytes, sizeof s_bytes, &k_authority, 1, &state)));
  }
  zi_memory_copy(s_bytes, s_saved, sizeof s_bytes);
  zi_write_u32_le(s_bytes + 84, 255);
  checksum();
  EXPECT(zi_identity_database_validate(s_bytes, sizeof s_bytes, &k_authority, 1, &state) ==
         ZI_STATUS_INVALID_ARGUMENT);
  zi_memory_copy(s_bytes, s_saved, sizeof s_bytes);
  zi_memory_copy(s_bytes + 4608, s_bytes + 4096, 512);
  zi_write_u32_le(s_bytes + 16, 2);
  checksum();
  EXPECT(zi_identity_database_validate(s_bytes, sizeof s_bytes, &k_authority, 1, &state) ==
         ZI_STATUS_ALREADY_EXISTS);
  return true;
}

static bool test_capacity(size_t* count) {
  EXPECT(zi_identity_database_initialise(&k_authority, s_bytes, sizeof s_bytes) ==
         ZI_STATUS_SUCCESS);
  ZiIdentityCreateRequest request = request_for(ZI_SECURITY_AUTHORITY_SERVICE, "service", 7);
  ZiNativeIdentity identity = {0};
  for (uint32_t index = 0; index < ZI_IDENTITY_DATABASE_CAPACITY; ++index) {
    EXPECT(
        zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, &request, &identity) ==
        ZI_STATUS_SUCCESS);
    EXPECT(identity.local_id.value == 256u + index);
    EXPECT(zi_identity_database_remove(s_bytes, sizeof s_bytes, &k_authority, &identity) ==
           ZI_STATUS_SUCCESS);
  }
  EXPECT(zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, &request, &identity) ==
         ZI_STATUS_OUT_OF_BOUNDS);
  return test_exhaustion(count);
}

static bool test_exhaustion(size_t* count) {
  ZiIdentityCreateRequest request = request_for(ZI_SECURITY_AUTHORITY_SERVICE, "service", 7);
  ZiNativeIdentity identity = {0};
  EXPECT(zi_identity_database_initialise(&k_authority, s_bytes, sizeof s_bytes) ==
         ZI_STATUS_SUCCESS);
  zi_write_u32_le(s_bytes + 88, UINT32_MAX);
  checksum();
  EXPECT(zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, &request, &identity) ==
         ZI_STATUS_OUT_OF_BOUNDS);
  zi_write_u32_le(s_bytes + 88, 255);
  zi_write_u64_le(s_bytes + 24, UINT64_MAX);
  checksum();
  EXPECT(zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, &request, &identity) ==
         ZI_STATUS_OUT_OF_BOUNDS);
  return true;
}

static bool test_invalid_requests(size_t* count) {
  EXPECT(zi_identity_database_initialise(&k_authority, s_bytes, sizeof s_bytes) ==
         ZI_STATUS_SUCCESS);
  ZiNativeIdentity identity = {0};
  ZiIdentityCreateRequest request = request_for(ZI_SECURITY_AUTHORITY_SYSTEM, "SYSTEM", 6);
  EXPECT(zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, &request, &identity) ==
         ZI_STATUS_INVALID_ARGUMENT);
  const char* names[] = {"", "a\\b", "a/b", "a:b", "a\n", "\xc0\x80"};
  const size_t sizes[] = {0, 3, 3, 3, 2, 2};
  for (size_t index = 0; index < sizeof sizes / sizeof sizes[0]; ++index) {
    request = request_for(ZI_SECURITY_AUTHORITY_USER, names[index], sizes[index]);
    EXPECT(
        zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, &request, &identity) ==
        ZI_STATUS_INVALID_ARGUMENT);
  }
  const char* valid_names[] = {"\xc3\xa9", "e\xcc\x81"};
  for (size_t index = 0; index < 2; ++index) {
    request = request_for(ZI_SECURITY_AUTHORITY_USER, valid_names[index], index + 2u);
    EXPECT(
        zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, &request, &identity) ==
        ZI_STATUS_SUCCESS);
  }
  request.group_count = 17;
  EXPECT(zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, &request, &identity) ==
         ZI_STATUS_INVALID_ARGUMENT);
  request.group_count = 1;
  EXPECT(zi_identity_database_append(s_bytes, sizeof s_bytes, &k_authority, &request, &identity) ==
         ZI_STATUS_INVALID_ARGUMENT);
  return true;
}

static ZiIdentityCreateRequest request_for(uint32_t authority, const char* name, size_t name_size) {
  return (ZiIdentityCreateRequest){sizeof(ZiIdentityCreateRequest),
                                   ZI_IDENTITY_DATABASE_VERSION,
                                   authority,
                                   {name, name_size},
                                   NULL,
                                   0};
}

static void checksum(void) {
  zi_write_u32_le(s_bytes + 4092, 0);
  zi_write_u32_le(s_bytes + 4092, zi_crc32c(0, s_bytes, sizeof s_bytes));
}

static void record_checksum(size_t index) {
  unsigned char* record = s_bytes + 4096 + (index * 512);
  zi_write_u32_le(record + 508, zi_crc32c(0, record, 508));
  checksum();
}

static bool expect(size_t* count, bool condition, int line) {
  ++*count;
  if (!condition) {
    (void)fprintf_s(stderr, "Identity database test failed at line %d.\n", line);
  }
  return condition;
}
