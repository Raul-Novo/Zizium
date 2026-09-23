// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/identity_acceptance.h"

#include <stddef.h>
#include <stdint.h>

#include "zi/byte_order.h"
#include "zi/identity.h"
#include "zi/identity_database.h"
#include "zi/identity_store.h"
#include "zi/security.h"
#include "zi/zifs.h"
#include "zizium/status.h"
#include "zizium/types.h"

// Matches the explicit disposable host fixture, not bytes learned from a guest file.
static const ZiIdentityDatabaseAuthority k_authority = {
    sizeof(ZiIdentityDatabaseAuthority),
    ZI_IDENTITY_DATABASE_VERSION,
    {0x51, 0x19, 0x20, 0x26},
    {0x21, 0x5a, 0x69, 0x46, 0x53, 0, 0x40, 1, 0x80, 0, 0x64, 0x96, 0xe6, 0xd1, 0xec, 0xfc},
    {0x62, 0x19, 0x20, 0x26},
};
static const ZiAccessToken k_system =
    {sizeof(ZiAccessToken), ZI_ACCESS_TOKEN_VERSION, {ZI_SECURITY_AUTHORITY_SYSTEM, 1}, NULL, 0, 0};
static const ZiIdentityCreateRequest k_request = {sizeof(ZiIdentityCreateRequest),
                                                  ZI_IDENTITY_DATABASE_VERSION,
                                                  ZI_SECURITY_AUTHORITY_USER,
                                                  {"Seed User", 9},
                                                  NULL,
                                                  0};

static ZiStatus parse_token(ZiStringView token, ZiIdentityAcceptanceParameters* out_parameters);
static ZiStatus parse_number(ZiStringView token, size_t* offset, uint64_t* out_value);
static ZiStatus
verify_generation(ZiIdentityStore* store, void* workspace, size_t size, uint64_t generation);
static ZiStatus verify_record(const void* workspace, uint32_t index, uint32_t state);
static ZiStatus verify_denials(const ZiIdentityStore* store, void* workspace, size_t size);
static ZiStatus verify_user_denial(ZiIdentityStore* store, void* workspace, size_t size);
static ZiStatus mutate_store(ZiIdentityStore* store, uint64_t stage, void* workspace, size_t size);

ZiStatus zi_identity_acceptance_parse(const char* command_line,
                                      ZiIdentityAcceptanceParameters* out_parameters) {
  if (out_parameters == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiIdentityAcceptanceParameters parameters = {0};
  if (command_line == NULL) {
    *out_parameters = parameters;
    return ZI_STATUS_SUCCESS;
  }
  size_t size = 0;
  while (size < 1024 && command_line[size] != '\0') {
    ++size;
  }
  if (size == 1024) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  const char prefix[] = "zi.identity=";
  size_t offset = 0;
  while (offset < size) {
    if (command_line[offset] == ' ' || command_line[offset] == '\t') {
      ++offset;
      continue;
    }
    size_t start = offset;
    while (offset < size && command_line[offset] != ' ' && command_line[offset] != '\t') {
      ++offset;
    }
    size_t token_size = offset - start;
    if (token_size < sizeof prefix - 1u ||
        zi_memory_compare(command_line + start, prefix, sizeof prefix - 1u) != 0) {
      continue;
    }
    if (parameters.stage != 0) {
      return ZI_STATUS_INVALID_ARGUMENT;
    }
    ZiStatus status = parse_token((ZiStringView){command_line + start + sizeof prefix - 1u,
                                                 token_size - (sizeof prefix - 1u)},
                                  &parameters);
    if (ZiFailed(status)) {
      return status;
    }
  }
  *out_parameters = parameters;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_identity_acceptance_run(ZiFsVolume* volume,
                                    const ZiIdentityAcceptanceParameters* parameters,
                                    void* workspace,
                                    size_t workspace_size) {
  if (volume == NULL || parameters == NULL || parameters->stage < 1 || parameters->stage > 6 ||
      parameters->file_id == 0 || volume->is_read_only != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiIdentityStore store = {sizeof(ZiIdentityStore),
                           ZI_IDENTITY_STORE_VERSION,
                           volume,
                           k_authority,
                           parameters->record_index,
                           parameters->file_id,
                           1,
                           0};
  // Pairs alternate mutation and independent reboot verification.
  const uint64_t generations[] = {0, 1, 2, 2, 3, 3, 4};
  uint64_t generation = generations[parameters->stage];
  ZiStatus status = verify_generation(&store, workspace, workspace_size, generation);
  if (ZiSucceeded(status)) {
    status = verify_denials(&store, workspace, workspace_size);
  }
  if (ZiSucceeded(status)) {
    status = mutate_store(&store, parameters->stage, workspace, workspace_size);
  }
  if (ZiFailed(status)) {
    return status;
  }
  if ((parameters->stage & 1u) != 0) {
    ++generation;
  }
  return verify_generation(&store, workspace, workspace_size, generation);
}

static ZiStatus parse_number(ZiStringView token, size_t* offset, uint64_t* out_value) {
  size_t start = *offset;
  uint64_t value = 0;
  while (*offset < token.size && token.data[*offset] != ':') {
    unsigned char character = (unsigned char)token.data[*offset];
    if (character < '0' || character > '9') {
      return ZI_STATUS_INVALID_ARGUMENT;
    }
    uint64_t digit = (uint64_t)character - (uint64_t)'0';
    if (value > (UINT64_MAX - digit) / 10u) {
      return ZI_STATUS_OUT_OF_BOUNDS;
    }
    value = (value * 10u) + digit;
    ++*offset;
  }
  if (*offset == start) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_value = value;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus parse_token(ZiStringView token, ZiIdentityAcceptanceParameters* out_parameters) {
  uint64_t values[3] = {0};
  size_t offset = 0;
  for (size_t index = 0; index < 3; ++index) {
    ZiStatus status = parse_number(token, &offset, &values[index]);
    if (ZiFailed(status)) {
      return status;
    }
    if (index < 2) {
      if (offset == token.size || token.data[offset] != ':') {
        return ZI_STATUS_INVALID_ARGUMENT;
      }
      ++offset;
    }
  }
  if (offset != token.size || values[0] < 1 || values[0] > 6 || values[2] == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_parameters = (ZiIdentityAcceptanceParameters){values[0], values[1], values[2]};
  return ZI_STATUS_SUCCESS;
}

static ZiStatus verify_record(const void* workspace, uint32_t index, uint32_t state) {
  ZiIdentityDatabaseRecord record = {0};
  ZiStatus status = zi_identity_database_record(workspace,
                                                ZI_IDENTITY_DATABASE_SIZE,
                                                &k_authority,
                                                index,
                                                &record);
  if (ZiFailed(status)) {
    return status;
  }
  return record.state == state &&
                 record.identity.local_id.authority == ZI_SECURITY_AUTHORITY_USER &&
                 record.identity.local_id.value == 256u + index && record.name_size == 9 &&
                 zi_memory_compare(record.name, "Seed User", 9) == 0 && record.group_count == 0
             ? ZI_STATUS_SUCCESS
             : ZI_STATUS_INVALID_STATE;
}

static ZiStatus
verify_generation(ZiIdentityStore* store, void* workspace, size_t size, uint64_t generation) {
  ZiIdentityDatabaseState state = {0};
  ZiStatus status = zi_identity_store_load(store, &k_system, workspace, size, &state);
  if (ZiFailed(status)) {
    return status;
  }
  const uint32_t counts[] = {0, 0, 1, 1, 2};
  if (state.generation != generation || state.record_count != counts[generation] ||
      state.issuer.user_high_water != 255u + counts[generation] ||
      state.issuer.group_high_water != 255 || state.issuer.service_high_water != 255) {
    return ZI_STATUS_INVALID_STATE;
  }
  if (state.record_count != 0) {
    uint32_t record_state = ZI_IDENTITY_RECORD_DISABLED;
    if (generation >= 3) {
      record_state = ZI_IDENTITY_RECORD_TOMBSTONE;
    }
    status = verify_record(workspace, 0, record_state);
  }
  if (ZiSucceeded(status) && state.record_count == 2) {
    status = verify_record(workspace, 1, ZI_IDENTITY_RECORD_DISABLED);
  }
  return status;
}

static ZiStatus verify_user_denial(ZiIdentityStore* store, void* workspace, size_t size) {
  const ZiSecurityId groups[] = {{ZI_SECURITY_AUTHORITY_GROUP, 1},
                                 {ZI_SECURITY_AUTHORITY_GROUP, 2}};
  const ZiAccessToken user = {sizeof(ZiAccessToken),
                              ZI_ACCESS_TOKEN_VERSION,
                              {ZI_SECURITY_AUTHORITY_USER, 21},
                              groups,
                              2,
                              0};
  ZiIdentityDatabaseState state = {.generation = UINT64_MAX};
  ZiNativeIdentity output = {{9}, {ZI_SECURITY_AUTHORITY_USER, 999}};
  if (zi_identity_store_load(store, &user, workspace, size, &state) != ZI_STATUS_ACCESS_DENIED ||
      state.generation != UINT64_MAX ||
      zi_identity_store_issue(store, &user, &k_request, workspace, size, &output) !=
          ZI_STATUS_ACCESS_DENIED ||
      output.issuer[0] != 9 || output.local_id.value != 999) {
    return ZI_STATUS_INVALID_STATE;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus verify_denials(const ZiIdentityStore* store, void* workspace, size_t size) {
  // Copies here are deliberate negative fixtures, never replacement live freshness owners.
  for (size_t variant = 0; variant < 4; ++variant) {
    ZiIdentityStore wrong = *store;
    if (variant == 0) {
      wrong.file_id ^= UINT64_C(0x8000000000000000);
    } else if (variant == 1) {
      wrong.authority.issuer[0] ^= 0x40u;
    } else if (variant == 2) {
      wrong.authority.volume[0] ^= 0x40u;
    } else {
      wrong.authority.database[0] ^= 0x40u;
    }
    ZiIdentityDatabaseState output = {.generation = UINT64_MAX};
    if (zi_identity_store_load(&wrong, &k_system, workspace, size, &output) !=
            ZI_STATUS_ACCESS_DENIED ||
        output.generation != UINT64_MAX) {
      return ZI_STATUS_INVALID_STATE;
    }
  }
  ZiIdentityStore denied = *store;
  return verify_user_denial(&denied, workspace, size);
}

static ZiStatus mutate_store(ZiIdentityStore* store, uint64_t stage, void* workspace, size_t size) {
  if (stage == 3) {
    ZiNativeIdentity identity = {0};
    zi_memory_copy(identity.issuer, k_authority.issuer, sizeof identity.issuer);
    identity.local_id = (ZiSecurityId){ZI_SECURITY_AUTHORITY_USER, 256};
    return zi_identity_store_remove(store, &k_system, &identity, workspace, size);
  }
  if (stage == 1 || stage == 5) {
    ZiNativeIdentity identity = {0};
    ZiStatus status =
        zi_identity_store_issue(store, &k_system, &k_request, workspace, size, &identity);
    if (ZiFailed(status)) {
      return status;
    }
    uint32_t expected = 256;
    if (stage == 5) {
      expected = 257;
    }
    if (identity.local_id.value != expected) {
      return ZI_STATUS_INVALID_STATE;
    }
  }
  return ZI_STATUS_SUCCESS;
}
