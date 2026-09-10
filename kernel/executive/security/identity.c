// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/identity.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/byte_order.h"
#include "zi/security.h"
#include "zizium/status.h"

static bool issuer_is_valid(const unsigned char* issuer);
static bool authority_is_dynamic(uint32_t authority);

ZiStatus zi_identity_validate(const ZiNativeIdentity* identity) {
  if (identity == NULL || !issuer_is_valid(identity->issuer) ||
      ZiFailed(zi_security_id_validate(identity->local_id))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return ZI_STATUS_SUCCESS;
}

bool zi_identity_equal(const ZiNativeIdentity* left, const ZiNativeIdentity* right) {
  if (ZiFailed(zi_identity_validate(left)) || ZiFailed(zi_identity_validate(right))) {
    return false;
  }
  return (bool)(zi_security_id_equal(left->local_id, right->local_id) &&
                zi_memory_compare(left->issuer, right->issuer, ZI_IDENTITY_ISSUER_BYTES) == 0);
}

ZiStatus zi_identity_encode(const ZiNativeIdentity* identity, void* output, size_t output_size) {
  if (output == NULL || ZiFailed(zi_identity_validate(identity))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (output_size < ZI_NATIVE_IDENTITY_WIRE_SIZE) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  unsigned char bytes[ZI_NATIVE_IDENTITY_WIRE_SIZE] = {0};
  zi_memory_copy(bytes, "ZNID", 4);
  zi_write_u16_le(bytes + 4, ZI_NATIVE_IDENTITY_WIRE_VERSION);
  zi_write_u16_le(bytes + 6, ZI_NATIVE_IDENTITY_WIRE_SIZE);
  zi_memory_copy(bytes + 8, identity->issuer, ZI_IDENTITY_ISSUER_BYTES);
  zi_write_u32_le(bytes + 24, identity->local_id.authority);
  zi_write_u32_le(bytes + 28, identity->local_id.value);
  zi_memory_copy(output, bytes, sizeof bytes);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_identity_decode(const void* data, size_t data_size, ZiNativeIdentity* out_identity) {
  if (data == NULL || out_identity == NULL || data_size != ZI_NATIVE_IDENTITY_WIRE_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const unsigned char* bytes = data;
  if (zi_memory_compare(bytes, "ZNID", 4) != 0 ||
      zi_read_u16_le(bytes + 4) != ZI_NATIVE_IDENTITY_WIRE_VERSION ||
      zi_read_u16_le(bytes + 6) != ZI_NATIVE_IDENTITY_WIRE_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiNativeIdentity identity = {0};
  zi_memory_copy(identity.issuer, bytes + 8, sizeof identity.issuer);
  identity.local_id.authority = zi_read_u32_le(bytes + 24);
  identity.local_id.value = zi_read_u32_le(bytes + 28);
  ZiStatus status = zi_identity_validate(&identity);
  if (ZiFailed(status)) {
    return status;
  }
  *out_identity = identity;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_identity_resolve_local(const ZiNativeIdentity* identity,
                                   const unsigned char active_issuer[ZI_IDENTITY_ISSUER_BYTES],
                                   ZiSecurityId* out_id) {
  if (out_id == NULL || !issuer_is_valid(active_issuer) ||
      ZiFailed(zi_identity_validate(identity))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (!authority_is_dynamic(identity->local_id.authority) ||
      identity->local_id.value < ZI_IDENTITY_FIRST_DYNAMIC_VALUE ||
      zi_memory_compare(identity->issuer, active_issuer, ZI_IDENTITY_ISSUER_BYTES) != 0) {
    return ZI_STATUS_ACCESS_DENIED;
  }
  *out_id = identity->local_id;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_identity_issuer_validate(const ZiIdentityIssuerState* state) {
  if (state == NULL || state->struct_size != sizeof *state ||
      state->version != ZI_IDENTITY_ISSUER_STATE_VERSION || !issuer_is_valid(state->issuer) ||
      state->group_high_water < ZI_IDENTITY_FIRST_DYNAMIC_VALUE - 1u ||
      state->user_high_water < ZI_IDENTITY_FIRST_DYNAMIC_VALUE - 1u ||
      state->service_high_water < ZI_IDENTITY_FIRST_DYNAMIC_VALUE - 1u) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_identity_reserve(const ZiIdentityIssuerState* state,
                             uint32_t authority,
                             ZiIdentityIssuerState* out_state,
                             ZiNativeIdentity* out_identity) {
  if (out_state == NULL || out_identity == NULL ||
      ZiFailed(zi_identity_issuer_validate(state)) || !authority_is_dynamic(authority)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiIdentityIssuerState candidate = *state;
  uint32_t* high_water = &candidate.user_high_water;
  if (authority == ZI_SECURITY_AUTHORITY_GROUP) {
    high_water = &candidate.group_high_water;
  } else if (authority == ZI_SECURITY_AUTHORITY_SERVICE) {
    high_water = &candidate.service_high_water;
  }
  if (*high_water == UINT32_MAX) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  ++*high_water;
  ZiNativeIdentity identity = {0};
  zi_memory_copy(identity.issuer, candidate.issuer, sizeof identity.issuer);
  identity.local_id = (ZiSecurityId){authority, *high_water};
  *out_state = candidate;
  *out_identity = identity;
  return ZI_STATUS_SUCCESS;
}

static bool issuer_is_valid(const unsigned char* issuer) {
  if (issuer == NULL) {
    return false;
  }
  for (size_t index = 0; index < ZI_IDENTITY_ISSUER_BYTES; ++index) {
    if (issuer[index] != 0) {
      return true;
    }
  }
  return false;
}

static bool authority_is_dynamic(uint32_t authority) {
  return (bool)(authority == ZI_SECURITY_AUTHORITY_GROUP || authority == ZI_SECURITY_AUTHORITY_USER ||
                authority == ZI_SECURITY_AUTHORITY_SERVICE);
}
