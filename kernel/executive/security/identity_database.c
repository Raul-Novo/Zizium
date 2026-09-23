// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/identity_database.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/byte_order.h"
#include "zi/crc32c.h"
#include "zi/identity.h"
#include "zi/security.h"
#include "zi/unicode.h"
#include "zizium/status.h"
#include "zizium/types.h"

static bool is_zero(const unsigned char* bytes, size_t size);
static bool authority_valid(const ZiIdentityDatabaseAuthority* authority);
static bool name_valid(ZiStringView name);
static uint32_t database_checksum(const unsigned char* bytes);
static void update_checksum(unsigned char* bytes);
static void write_state(unsigned char* bytes, const ZiIdentityDatabaseState* state);
static void read_state(const unsigned char* bytes, ZiIdentityDatabaseState* state);
static const unsigned char* record_bytes(const unsigned char* bytes, uint32_t index);
static ZiStatus decode_record(const unsigned char* bytes, ZiIdentityDatabaseRecord* out_record);
static ZiStatus validate_records(const unsigned char* bytes, const ZiIdentityDatabaseState* state);
static bool has_group(const unsigned char* bytes, uint32_t count, uint32_t value);
static ZiStatus validate_request(const unsigned char* bytes,
                                 const ZiIdentityDatabaseState* state,
                                 const ZiIdentityCreateRequest* request);
static ZiStatus validate_record_binding(const ZiIdentityDatabaseRecord* record,
                                        const ZiIdentityDatabaseState* state);

ZiStatus zi_identity_database_authority_validate(const ZiIdentityDatabaseAuthority* authority) {
  if (!authority_valid(authority)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_identity_database_initialise(const ZiIdentityDatabaseAuthority* authority,
                                         void* bytes,
                                         size_t size) {
  if (!authority_valid(authority) || bytes == NULL || size != ZI_IDENTITY_DATABASE_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char* output = bytes;
  zi_memory_zero(output, size);
  zi_memory_copy(output, "ZIDB", 4);
  zi_write_u16_le(output + 4, ZI_IDENTITY_DATABASE_VERSION);
  zi_write_u16_le(output + 6, ZI_IDENTITY_DATABASE_HEADER_SIZE);
  zi_write_u32_le(output + 8, ZI_IDENTITY_DATABASE_SIZE);
  zi_write_u16_le(output + 12, ZI_IDENTITY_DATABASE_RECORD_SIZE);
  zi_write_u16_le(output + 14, ZI_IDENTITY_DATABASE_CAPACITY);
  zi_write_u64_le(output + 24, 1);
  zi_memory_copy(output + 32, authority->issuer, 16);
  zi_memory_copy(output + 48, authority->volume, 16);
  zi_memory_copy(output + 64, authority->database, 16);
  for (size_t offset = 80; offset < 92; offset += 4) {
    zi_write_u32_le(output + offset, ZI_IDENTITY_FIRST_DYNAMIC_VALUE - 1u);
  }
  update_checksum(output);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_identity_database_validate(const void* bytes,
                                       size_t size,
                                       const ZiIdentityDatabaseAuthority* authority,
                                       uint64_t minimum_generation,
                                       ZiIdentityDatabaseState* out_state) {
  if (bytes == NULL || size != ZI_IDENTITY_DATABASE_SIZE || !authority_valid(authority) ||
      minimum_generation == 0 || out_state == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const unsigned char* input = bytes;
  if (zi_memory_compare(input, "ZIDB", 4) != 0 ||
      zi_read_u16_le(input + 4) != ZI_IDENTITY_DATABASE_VERSION ||
      zi_read_u16_le(input + 6) != ZI_IDENTITY_DATABASE_HEADER_SIZE ||
      zi_read_u32_le(input + 8) != ZI_IDENTITY_DATABASE_SIZE ||
      zi_read_u16_le(input + 12) != ZI_IDENTITY_DATABASE_RECORD_SIZE ||
      zi_read_u16_le(input + 14) != ZI_IDENTITY_DATABASE_CAPACITY ||
      zi_read_u32_le(input + 20) != 0 || !is_zero(input + 92, 4000)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (zi_read_u32_le(input + 4092) != database_checksum(input)) {
    return ZI_STATUS_CHECKSUM_MISMATCH;
  }
  if (zi_memory_compare(input + 32, authority->issuer, 16) != 0 ||
      zi_memory_compare(input + 48, authority->volume, 16) != 0 ||
      zi_memory_compare(input + 64, authority->database, 16) != 0) {
    return ZI_STATUS_ACCESS_DENIED;
  }
  ZiIdentityDatabaseState state = {0};
  read_state(input, &state);
  if (state.record_count > ZI_IDENTITY_DATABASE_CAPACITY || state.generation == 0 ||
      ZiFailed(zi_identity_issuer_validate(&state.issuer))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (state.generation < minimum_generation) {
    return ZI_STATUS_INVALID_STATE;
  }
  size_t used = ZI_IDENTITY_DATABASE_HEADER_SIZE +
                ((size_t)state.record_count * ZI_IDENTITY_DATABASE_RECORD_SIZE);
  if (!is_zero(input + used, size - used)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_records(input, &state);
  if (ZiFailed(status)) {
    return status;
  }
  *out_state = state;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_identity_database_record(const void* bytes,
                                     size_t size,
                                     const ZiIdentityDatabaseAuthority* authority,
                                     uint32_t index,
                                     ZiIdentityDatabaseRecord* out_record) {
  if (out_record == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiIdentityDatabaseState state = {0};
  ZiStatus status = zi_identity_database_validate(bytes, size, authority, 1, &state);
  if (ZiFailed(status)) {
    return status;
  }
  if (index >= state.record_count) {
    return ZI_STATUS_NOT_FOUND;
  }
  return decode_record(record_bytes(bytes, index), out_record);
}

ZiStatus zi_identity_database_append(void* bytes,
                                     size_t size,
                                     const ZiIdentityDatabaseAuthority* authority,
                                     const ZiIdentityCreateRequest* request,
                                     ZiNativeIdentity* out_identity) {
  if (out_identity == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiIdentityDatabaseState state = {0};
  ZiStatus status = zi_identity_database_validate(bytes, size, authority, 1, &state);
  if (ZiFailed(status)) {
    return status;
  }
  status = validate_request(bytes, &state, request);
  if (ZiFailed(status)) {
    return status;
  }
  if (state.record_count == ZI_IDENTITY_DATABASE_CAPACITY || state.generation == UINT64_MAX) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  ZiNativeIdentity identity = {0};
  status = zi_identity_reserve(&state.issuer, request->authority, &state.issuer, &identity);
  if (ZiFailed(status)) {
    return status;
  }
  unsigned char encoded[ZI_IDENTITY_DATABASE_RECORD_SIZE] = {0};
  zi_memory_copy(encoded, "ZIAR", 4);
  zi_write_u16_le(encoded + 4, ZI_IDENTITY_DATABASE_VERSION);
  zi_write_u16_le(encoded + 6, ZI_IDENTITY_DATABASE_RECORD_SIZE);
  zi_write_u32_le(encoded + 8, ZI_IDENTITY_RECORD_DISABLED);
  status = zi_identity_encode(&identity, encoded + 16, ZI_NATIVE_IDENTITY_WIRE_SIZE);
  if (ZiFailed(status)) {
    return status;
  }
  ++state.generation;
  zi_write_u16_le(encoded + 48, (uint16_t)request->name.size);
  zi_write_u16_le(encoded + 50, (uint16_t)request->group_count);
  zi_write_u64_le(encoded + 56, state.generation);
  zi_memory_copy(encoded + 64, request->name.data, request->name.size);
  for (size_t index = 0; index < request->group_count; ++index) {
    zi_write_u32_le(encoded + 192 + (index * 4), request->groups[index]);
  }
  zi_write_u32_le(encoded + 508, zi_crc32c(0, encoded, 508));
  unsigned char* output = bytes;
  zi_memory_copy(output + ZI_IDENTITY_DATABASE_HEADER_SIZE +
                     ((size_t)state.record_count * ZI_IDENTITY_DATABASE_RECORD_SIZE),
                 encoded,
                 sizeof encoded);
  ++state.record_count;
  write_state(output, &state);
  update_checksum(output);
  *out_identity = identity;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_identity_database_remove(void* bytes,
                                     size_t size,
                                     const ZiIdentityDatabaseAuthority* authority,
                                     const ZiNativeIdentity* identity) {
  if (ZiFailed(zi_identity_validate(identity))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiIdentityDatabaseState state = {0};
  ZiStatus status = zi_identity_database_validate(bytes, size, authority, 1, &state);
  if (ZiFailed(status)) {
    return status;
  }
  if (state.generation == UINT64_MAX) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  uint32_t target = UINT32_MAX;
  for (uint32_t index = 0; index < state.record_count; ++index) {
    ZiIdentityDatabaseRecord record = {0};
    status = decode_record(record_bytes(bytes, index), &record);
    if (ZiFailed(status)) {
      return status;
    }
    if (record.state == ZI_IDENTITY_RECORD_TOMBSTONE) {
      continue;
    }
    if (zi_identity_equal(&record.identity, identity)) {
      target = index;
    }
    if (identity->local_id.authority == ZI_SECURITY_AUTHORITY_GROUP &&
        zi_memory_compare(identity->issuer, authority->issuer, 16) == 0) {
      for (size_t group = 0; group < record.group_count; ++group) {
        if (record.groups[group] == identity->local_id.value) {
          return ZI_STATUS_RESOURCE_IN_USE;
        }
      }
    }
  }
  if (target == UINT32_MAX) {
    return ZI_STATUS_NOT_FOUND;
  }
  unsigned char* output = bytes;
  unsigned char* record = output + ZI_IDENTITY_DATABASE_HEADER_SIZE +
                          ((size_t)target * ZI_IDENTITY_DATABASE_RECORD_SIZE);
  ++state.generation;
  zi_write_u32_le(record + 8, ZI_IDENTITY_RECORD_TOMBSTONE);
  zi_write_u16_le(record + 50, 0);
  zi_memory_zero(record + 192, 64);
  zi_write_u64_le(record + 56, state.generation);
  zi_write_u32_le(record + 508, zi_crc32c(0, record, 508));
  write_state(output, &state);
  update_checksum(output);
  return ZI_STATUS_SUCCESS;
}

static bool is_zero(const unsigned char* bytes, size_t size) {
  for (size_t index = 0; index < size; ++index) {
    if (bytes[index] != 0) {
      return false;
    }
  }
  return true;
}

static bool authority_valid(const ZiIdentityDatabaseAuthority* authority) {
  return (bool)(authority != NULL && authority->struct_size == sizeof *authority &&
                authority->version == ZI_IDENTITY_DATABASE_VERSION &&
                !is_zero(authority->issuer, 16) && !is_zero(authority->volume, 16) &&
                !is_zero(authority->database, 16));
}

static bool name_valid(ZiStringView name) {
  if (name.data == NULL || name.size == 0 || name.size > ZI_IDENTITY_DATABASE_NAME_BYTES) {
    return false;
  }
  size_t offset = 0;
  while (offset < name.size) {
    ZiUtf8DecodeResult decoded = {0};
    if (ZiFailed(zi_utf8_decode(name.data + offset, name.size - offset, &decoded)) ||
        decoded.scalar < 32 || (decoded.scalar >= 127 && decoded.scalar <= 159) ||
        decoded.scalar == '/' || decoded.scalar == '\\' || decoded.scalar == ':') {
      return false;
    }
    offset += decoded.consumed;
  }
  return true;
}

static uint32_t database_checksum(const unsigned char* bytes) {
  const unsigned char zero[4] = {0};
  uint32_t checksum = zi_crc32c(0, bytes, 4092);
  checksum = zi_crc32c(checksum, zero, sizeof zero);
  return zi_crc32c(checksum, bytes + 4096, ZI_IDENTITY_DATABASE_SIZE - 4096);
}

static void update_checksum(unsigned char* bytes) {
  zi_write_u32_le(bytes + 4092, database_checksum(bytes));
}

static void write_state(unsigned char* bytes, const ZiIdentityDatabaseState* state) {
  zi_write_u32_le(bytes + 16, state->record_count);
  zi_write_u64_le(bytes + 24, state->generation);
  zi_write_u32_le(bytes + 80, state->issuer.group_high_water);
  zi_write_u32_le(bytes + 84, state->issuer.user_high_water);
  zi_write_u32_le(bytes + 88, state->issuer.service_high_water);
}

static void read_state(const unsigned char* bytes, ZiIdentityDatabaseState* state) {
  state->record_count = zi_read_u32_le(bytes + 16);
  state->generation = zi_read_u64_le(bytes + 24);
  state->issuer.struct_size = sizeof state->issuer;
  state->issuer.version = ZI_IDENTITY_ISSUER_STATE_VERSION;
  zi_memory_copy(state->issuer.issuer, bytes + 32, 16);
  state->issuer.group_high_water = zi_read_u32_le(bytes + 80);
  state->issuer.user_high_water = zi_read_u32_le(bytes + 84);
  state->issuer.service_high_water = zi_read_u32_le(bytes + 88);
}

static const unsigned char* record_bytes(const unsigned char* bytes, uint32_t index) {
  return bytes + ZI_IDENTITY_DATABASE_HEADER_SIZE +
         ((size_t)index * ZI_IDENTITY_DATABASE_RECORD_SIZE);
}

static ZiStatus decode_record(const unsigned char* bytes, ZiIdentityDatabaseRecord* out_record) {
  if (zi_memory_compare(bytes, "ZIAR", 4) != 0 ||
      zi_read_u16_le(bytes + 4) != ZI_IDENTITY_DATABASE_VERSION ||
      zi_read_u16_le(bytes + 6) != ZI_IDENTITY_DATABASE_RECORD_SIZE ||
      zi_read_u32_le(bytes + 12) != 0 || zi_read_u32_le(bytes + 52) != 0 ||
      !is_zero(bytes + 256, 252)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (zi_read_u32_le(bytes + 508) != zi_crc32c(0, bytes, 508)) {
    return ZI_STATUS_CHECKSUM_MISMATCH;
  }
  ZiIdentityDatabaseRecord record = {0};
  ZiStatus status = zi_identity_decode(bytes + 16, ZI_NATIVE_IDENTITY_WIRE_SIZE, &record.identity);
  if (ZiFailed(status)) {
    return status;
  }
  record.state = zi_read_u32_le(bytes + 8);
  record.name_size = zi_read_u16_le(bytes + 48);
  record.group_count = zi_read_u16_le(bytes + 50);
  record.generation = zi_read_u64_le(bytes + 56);
  if ((record.state != ZI_IDENTITY_RECORD_DISABLED &&
       record.state != ZI_IDENTITY_RECORD_TOMBSTONE) ||
      record.name_size > sizeof record.name || record.group_count > ZI_IDENTITY_DATABASE_GROUPS ||
      ((record.state == ZI_IDENTITY_RECORD_TOMBSTONE ||
        record.identity.local_id.authority == ZI_SECURITY_AUTHORITY_GROUP) &&
       record.group_count != 0)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStringView name = {(const char*)bytes + 64, record.name_size};
  if (!name_valid(name) || !is_zero(bytes + 64 + record.name_size, 128u - record.name_size) ||
      !is_zero(bytes + 192 + ((size_t)record.group_count * 4),
               64u - ((size_t)record.group_count * 4))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_memory_copy(record.name, name.data, name.size);
  for (size_t index = 0; index < record.group_count; ++index) {
    record.groups[index] = zi_read_u32_le(bytes + 192 + (index * 4));
    if (record.groups[index] < ZI_IDENTITY_FIRST_DYNAMIC_VALUE ||
        (index > 0 && record.groups[index] <= record.groups[index - 1])) {
      return ZI_STATUS_INVALID_ARGUMENT;
    }
  }
  *out_record = record;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_record_binding(const ZiIdentityDatabaseRecord* record,
                                        const ZiIdentityDatabaseState* state) {
  ZiSecurityId local = {0};
  ZiStatus status = zi_identity_resolve_local(&record->identity, state->issuer.issuer, &local);
  if (ZiFailed(status)) {
    return status;
  }
  uint32_t high_water = state->issuer.user_high_water;
  if (local.authority == ZI_SECURITY_AUTHORITY_GROUP) {
    high_water = state->issuer.group_high_water;
  } else if (local.authority == ZI_SECURITY_AUTHORITY_SERVICE) {
    high_water = state->issuer.service_high_water;
  }
  return local.value <= high_water && record->generation > 0 &&
                 record->generation <= state->generation
             ? ZI_STATUS_SUCCESS
             : ZI_STATUS_INVALID_ARGUMENT;
}

static bool has_group(const unsigned char* bytes, uint32_t count, uint32_t value) {
  for (uint32_t index = 0; index < count; ++index) {
    ZiIdentityDatabaseRecord record = {0};
    if (ZiSucceeded(decode_record(record_bytes(bytes, index), &record)) &&
        record.state == ZI_IDENTITY_RECORD_DISABLED &&
        record.identity.local_id.authority == ZI_SECURITY_AUTHORITY_GROUP &&
        record.identity.local_id.value == value) {
      return true;
    }
  }
  return false;
}

static ZiStatus validate_records(const unsigned char* bytes, const ZiIdentityDatabaseState* state) {
  for (uint32_t index = 0; index < state->record_count; ++index) {
    ZiIdentityDatabaseRecord record = {0};
    ZiStatus status = decode_record(record_bytes(bytes, index), &record);
    if (ZiFailed(status)) {
      return status;
    }
    status = validate_record_binding(&record, state);
    if (ZiFailed(status)) {
      return status;
    }
    for (uint32_t other = 0; other < index; ++other) {
      ZiIdentityDatabaseRecord previous = {0};
      status = decode_record(record_bytes(bytes, other), &previous);
      if (ZiFailed(status)) {
        return status;
      }
      if (zi_identity_equal(&record.identity, &previous.identity) ||
          (record.state != ZI_IDENTITY_RECORD_TOMBSTONE &&
           previous.state != ZI_IDENTITY_RECORD_TOMBSTONE &&
           record.identity.local_id.authority == previous.identity.local_id.authority &&
           record.name_size == previous.name_size &&
           zi_memory_compare(record.name, previous.name, record.name_size) == 0)) {
        return ZI_STATUS_ALREADY_EXISTS;
      }
    }
    for (size_t group = 0; group < record.group_count; ++group) {
      if (!has_group(bytes, state->record_count, record.groups[group])) {
        return ZI_STATUS_INVALID_ARGUMENT;
      }
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_request(const unsigned char* bytes,
                                 const ZiIdentityDatabaseState* state,
                                 const ZiIdentityCreateRequest* request) {
  if (request == NULL || request->struct_size != sizeof *request ||
      request->version != ZI_IDENTITY_DATABASE_VERSION || !name_valid(request->name) ||
      request->group_count > ZI_IDENTITY_DATABASE_GROUPS ||
      (request->group_count != 0 && request->groups == NULL) ||
      (request->authority == ZI_SECURITY_AUTHORITY_GROUP && request->group_count != 0)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  for (size_t group = 0; group < request->group_count; ++group) {
    if ((group > 0 && request->groups[group] <= request->groups[group - 1]) ||
        !has_group(bytes, state->record_count, request->groups[group])) {
      return ZI_STATUS_INVALID_ARGUMENT;
    }
  }
  for (uint32_t index = 0; index < state->record_count; ++index) {
    ZiIdentityDatabaseRecord record = {0};
    ZiStatus status = decode_record(record_bytes(bytes, index), &record);
    if (ZiFailed(status)) {
      return status;
    }
    if (record.state != ZI_IDENTITY_RECORD_TOMBSTONE &&
        record.identity.local_id.authority == request->authority &&
        record.name_size == request->name.size &&
        zi_memory_compare(record.name, request->name.data, request->name.size) == 0) {
      return ZI_STATUS_ALREADY_EXISTS;
    }
  }
  return ZI_STATUS_SUCCESS;
}
