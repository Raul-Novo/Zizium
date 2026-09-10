// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/security.h"
#include "zizium/status.h"

#define ZI_NATIVE_IDENTITY_WIRE_VERSION UINT16_C(1)
#define ZI_NATIVE_IDENTITY_WIRE_SIZE 32u
#define ZI_IDENTITY_ISSUER_BYTES 16u
#define ZI_IDENTITY_FIRST_DYNAMIC_VALUE UINT32_C(256)
#define ZI_IDENTITY_ISSUER_STATE_VERSION 1u

// Issuer bytes are opaque UUID octets in canonical order, not a Windows GUID overlay.
// The existing eight-byte ZiSecurityId and ZiFS security records remain unchanged.
typedef struct ZiNativeIdentity {
  unsigned char issuer[ZI_IDENTITY_ISSUER_BYTES];
  ZiSecurityId local_id;
} ZiNativeIdentity;

typedef struct ZiIdentityIssuerState {
  uint32_t struct_size;
  uint32_t version;
  unsigned char issuer[ZI_IDENTITY_ISSUER_BYTES];
  uint32_t group_high_water;
  uint32_t user_high_water;
  uint32_t service_high_water;
} ZiIdentityIssuerState;

ZiStatus zi_identity_validate(const ZiNativeIdentity* identity);
bool zi_identity_equal(const ZiNativeIdentity* left, const ZiNativeIdentity* right);
ZiStatus zi_identity_encode(const ZiNativeIdentity* identity, void* output, size_t output_size);
ZiStatus zi_identity_decode(const void* data, size_t data_size, ZiNativeIdentity* out_identity);

// Explicit one-issuer bridge for already authorised dynamic database records only.
// Matching the issuer is necessary, not sufficient evidence of issuance or authentication.
// The caller supplies the trusted active issuer; never take it from the imported record.
ZiStatus zi_identity_resolve_local(const ZiNativeIdentity* identity,
                                   const unsigned char active_issuer[ZI_IDENTITY_ISSUER_BYTES],
                                   ZiSecurityId* out_id);
ZiStatus zi_identity_issuer_validate(const ZiIdentityIssuerState* state);

// Produces an unpublished candidate. The database must durably commit both the updated
// high-water state and disabled record before releasing the identity to any consumer.
// Never call this on an older/restored state without the database's rollback policy.
// On failure both outputs are unchanged; outputs must not overlap.
ZiStatus zi_identity_reserve(const ZiIdentityIssuerState* state,
                             uint32_t authority,
                             ZiIdentityIssuerState* out_state,
                             ZiNativeIdentity* out_identity);
