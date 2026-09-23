// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "phase8_tests.h"
#include "zi/byte_order.h"
#include "zi/identity.h"
#include "zi/security.h"
#include "zizium/status.h"

static bool expect(size_t* count, bool condition, int line);
static bool test_codec(size_t* count);
static bool test_invalid_identity(size_t* count);
static bool test_malformed(size_t* count);
static bool test_invalid_header(size_t* count);
static bool test_invalid_buffers(size_t* count);
static bool test_binding(size_t* count);
static bool test_reserved_binding(size_t* count);
static bool test_reservation(size_t* count);
static bool
test_group_reservation(size_t* count, ZiIdentityIssuerState* state, ZiNativeIdentity* identity);
static bool test_exhaustion(size_t* count);
static bool test_invalid_state(size_t* count);

#define EXPECT(condition)                                                                          \
  do {                                                                                             \
    if (!expect(count, (condition), __LINE__)) {                                                   \
      return false;                                                                                \
    }                                                                                              \
  } while (false)

static const ZiNativeIdentity k_identity = {
    {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
    {ZI_SECURITY_AUTHORITY_USER, UINT32_C(0x12345678)},
};
static const unsigned char k_golden[ZI_NATIVE_IDENTITY_WIRE_SIZE] = {
    'Z', 'N', 'I', 'D', 1,  0,  32, 0,  1, 2, 3, 4, 5,    6,    7,    8,
    9,   10,  11,  12,  13, 14, 15, 16, 3, 0, 0, 0, 0x78, 0x56, 0x34, 0x12,
};
static const ZiIdentityIssuerState k_initial = {
    sizeof(ZiIdentityIssuerState),
    ZI_IDENTITY_ISSUER_STATE_VERSION,
    {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
    255,
    255,
    255,
};

bool phase8_identity_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  *out_assertion_count = 0;
  return (bool)(test_codec(out_assertion_count) && test_invalid_identity(out_assertion_count) &&
                test_malformed(out_assertion_count) && test_invalid_buffers(out_assertion_count) &&
                test_invalid_header(out_assertion_count) && test_binding(out_assertion_count) &&
                test_reserved_binding(out_assertion_count) &&
                test_reservation(out_assertion_count) && test_exhaustion(out_assertion_count) &&
                test_invalid_state(out_assertion_count));
}

static bool test_codec(size_t* count) {
  unsigned char bytes[ZI_NATIVE_IDENTITY_WIRE_SIZE + 1u] = {0};
  bytes[ZI_NATIVE_IDENTITY_WIRE_SIZE] = 0xa5;
  EXPECT(zi_identity_encode(&k_identity, bytes, sizeof bytes) == ZI_STATUS_SUCCESS);
  EXPECT(zi_memory_compare(bytes, k_golden, sizeof k_golden) == 0);
  EXPECT(bytes[ZI_NATIVE_IDENTITY_WIRE_SIZE] == 0xa5);
  ZiNativeIdentity decoded = {0};
  EXPECT(zi_identity_decode(k_golden, sizeof k_golden, &decoded) == ZI_STATUS_SUCCESS);
  EXPECT(zi_identity_equal(&k_identity, &decoded));
  return true;
}

static bool test_invalid_identity(size_t* count) {
  ZiNativeIdentity decoded = k_identity;
  EXPECT(!zi_identity_equal(NULL, &decoded));
  decoded.local_id.value = 0;
  EXPECT(zi_identity_validate(&decoded) == ZI_STATUS_INVALID_ARGUMENT);
  decoded = k_identity;
  zi_memory_zero(decoded.issuer, sizeof decoded.issuer);
  EXPECT(zi_identity_validate(&decoded) == ZI_STATUS_INVALID_ARGUMENT);
  EXPECT(!zi_identity_equal(&decoded, &decoded));
  return true;
}

static bool test_malformed(size_t* count) {
  ZiNativeIdentity decoded = k_identity;
  for (size_t size = 0; size < ZI_NATIVE_IDENTITY_WIRE_SIZE; ++size) {
    EXPECT(zi_identity_decode(k_golden, size, &decoded) == ZI_STATUS_INVALID_ARGUMENT);
    EXPECT(zi_identity_equal(&decoded, &k_identity));
  }
  EXPECT(zi_identity_decode(k_golden, SIZE_MAX, &decoded) == ZI_STATUS_INVALID_ARGUMENT);
  return true;
}

static bool test_invalid_header(size_t* count) {
  ZiNativeIdentity decoded = k_identity;
  const size_t invalid_offsets[] = {0, 1, 2, 3, 4, 5, 6, 7, 24, 25, 26, 27};
  for (size_t index = 0; index < sizeof invalid_offsets / sizeof invalid_offsets[0]; ++index) {
    unsigned char bytes[ZI_NATIVE_IDENTITY_WIRE_SIZE];
    zi_memory_copy(bytes, k_golden, sizeof bytes);
    bytes[invalid_offsets[index]] = 0xff;
    EXPECT(zi_identity_decode(bytes, sizeof bytes, &decoded) == ZI_STATUS_INVALID_ARGUMENT);
    EXPECT(zi_identity_equal(&decoded, &k_identity));
  }
  return true;
}

static bool test_invalid_buffers(size_t* count) {
  ZiNativeIdentity decoded = k_identity;
  unsigned char output[1] = {0xa5};
  EXPECT(zi_identity_encode(&k_identity, output, sizeof output) == ZI_STATUS_BUFFER_TOO_SMALL);
  EXPECT(output[0] == 0xa5);
  EXPECT(zi_identity_encode(NULL, output, sizeof output) == ZI_STATUS_INVALID_ARGUMENT);
  EXPECT(zi_identity_decode(NULL, sizeof k_golden, &decoded) == ZI_STATUS_INVALID_ARGUMENT);
  EXPECT(zi_identity_decode(k_golden, sizeof k_golden, NULL) == ZI_STATUS_INVALID_ARGUMENT);
  return true;
}

static bool test_binding(size_t* count) {
  ZiSecurityId resolved = {ZI_SECURITY_AUTHORITY_USER, 99};
  EXPECT(zi_identity_resolve_local(&k_identity, k_identity.issuer, &resolved) == ZI_STATUS_SUCCESS);
  EXPECT(zi_security_id_equal(resolved, k_identity.local_id));
  for (size_t index = 0; index < ZI_IDENTITY_ISSUER_BYTES; ++index) {
    ZiNativeIdentity foreign = k_identity;
    foreign.issuer[index] ^= 0x80u;
    EXPECT(!zi_identity_equal(&foreign, &k_identity));
    EXPECT(zi_identity_resolve_local(&foreign, k_identity.issuer, &resolved) ==
           ZI_STATUS_ACCESS_DENIED);
    EXPECT(zi_security_id_equal(resolved, k_identity.local_id));
  }
  return true;
}

static bool test_reserved_binding(size_t* count) {
  ZiSecurityId resolved = {ZI_SECURITY_AUTHORITY_USER, 99};
  ZiNativeIdentity reserved = k_identity;
  reserved.local_id.value = ZI_IDENTITY_FIRST_DYNAMIC_VALUE - 1u;
  EXPECT(zi_identity_resolve_local(&reserved, k_identity.issuer, &resolved) ==
         ZI_STATUS_ACCESS_DENIED);
  reserved.local_id.value = ZI_IDENTITY_FIRST_DYNAMIC_VALUE;
  EXPECT(zi_identity_resolve_local(&reserved, k_identity.issuer, &resolved) == ZI_STATUS_SUCCESS);
  reserved.local_id.authority = ZI_SECURITY_AUTHORITY_SYSTEM;
  EXPECT(zi_identity_resolve_local(&reserved, k_identity.issuer, &resolved) ==
         ZI_STATUS_ACCESS_DENIED);
  EXPECT(zi_identity_resolve_local(&k_identity, NULL, &resolved) == ZI_STATUS_INVALID_ARGUMENT);
  return true;
}

static bool test_reservation(size_t* count) {
  ZiIdentityIssuerState next = {0};
  ZiNativeIdentity identity = {0};
  EXPECT(zi_identity_reserve(&k_initial, ZI_SECURITY_AUTHORITY_USER, &next, &identity) ==
         ZI_STATUS_SUCCESS);
  EXPECT(identity.local_id.authority == ZI_SECURITY_AUTHORITY_USER &&
         identity.local_id.value == 256);
  EXPECT(next.user_high_water == 256 && next.group_high_water == 255 &&
         next.service_high_water == 255);
  EXPECT(zi_memory_compare(identity.issuer, k_initial.issuer, sizeof identity.issuer) == 0);
  EXPECT(zi_identity_reserve(&next, ZI_SECURITY_AUTHORITY_USER, &next, &identity) ==
         ZI_STATUS_SUCCESS);
  EXPECT(identity.local_id.value == 257 && next.user_high_water == 257);
  return test_group_reservation(count, &next, &identity);
}

static bool
test_group_reservation(size_t* count, ZiIdentityIssuerState* state, ZiNativeIdentity* identity) {
  EXPECT(zi_identity_reserve(state, ZI_SECURITY_AUTHORITY_GROUP, state, identity) ==
         ZI_STATUS_SUCCESS);
  EXPECT(identity->local_id.authority == ZI_SECURITY_AUTHORITY_GROUP &&
         identity->local_id.value == 256);
  EXPECT(zi_identity_reserve(state, ZI_SECURITY_AUTHORITY_SERVICE, state, identity) ==
         ZI_STATUS_SUCCESS);
  EXPECT(identity->local_id.authority == ZI_SECURITY_AUTHORITY_SERVICE &&
         identity->local_id.value == 256);
  EXPECT(state->user_high_water == 257 && state->group_high_water == 256 &&
         state->service_high_water == 256);
  return true;
}

static bool test_exhaustion(size_t* count) {
  ZiIdentityIssuerState state = k_initial;
  state.group_high_water = UINT32_MAX;
  state.user_high_water = UINT32_MAX;
  state.service_high_water = UINT32_MAX;
  ZiIdentityIssuerState next = k_initial;
  ZiNativeIdentity identity = k_identity;
  for (uint32_t authority = ZI_SECURITY_AUTHORITY_GROUP; authority <= ZI_SECURITY_AUTHORITY_SERVICE;
       ++authority) {
    EXPECT(zi_identity_reserve(&state, authority, &next, &identity) == ZI_STATUS_OUT_OF_BOUNDS);
    EXPECT(next.user_high_water == 255 && next.group_high_water == 255 &&
           next.service_high_water == 255 && zi_identity_equal(&identity, &k_identity));
  }
  EXPECT(zi_identity_reserve(&k_initial, ZI_SECURITY_AUTHORITY_SYSTEM, &next, &identity) ==
         ZI_STATUS_INVALID_ARGUMENT);
  EXPECT(zi_identity_reserve(&k_initial, UINT32_MAX, &next, &identity) ==
         ZI_STATUS_INVALID_ARGUMENT);
  return true;
}

static bool test_invalid_state(size_t* count) {
  ZiIdentityIssuerState state = k_initial;
  ZiIdentityIssuerState next = k_initial;
  ZiNativeIdentity identity = k_identity;
  state.group_high_water = 254;
  EXPECT(zi_identity_issuer_validate(&state) == ZI_STATUS_INVALID_ARGUMENT);
  state = k_initial;
  state.version = UINT32_MAX;
  EXPECT(zi_identity_issuer_validate(&state) == ZI_STATUS_INVALID_ARGUMENT);
  EXPECT(zi_identity_reserve(&state, ZI_SECURITY_AUTHORITY_USER, &next, &identity) ==
         ZI_STATUS_INVALID_ARGUMENT);
  EXPECT(next.user_high_water == 255 && zi_identity_equal(&identity, &k_identity));
  return true;
}

static bool expect(size_t* count, bool condition, int line) {
  ++*count;
  if (!condition) {
    printf("Identity prerequisite test failed at line %d.\n", line);
  }
  return condition;
}
