// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/identity.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_IDENTITY_DATABASE_VERSION 1u
#define ZI_IDENTITY_DATABASE_HEADER_SIZE 4096u
#define ZI_IDENTITY_DATABASE_RECORD_SIZE 512u
#define ZI_IDENTITY_DATABASE_CAPACITY 64u
#define ZI_IDENTITY_DATABASE_NAME_BYTES 128u
#define ZI_IDENTITY_DATABASE_GROUPS 16u
#define ZI_IDENTITY_DATABASE_SIZE                                                                  \
  (ZI_IDENTITY_DATABASE_HEADER_SIZE +                                                              \
   (ZI_IDENTITY_DATABASE_CAPACITY * ZI_IDENTITY_DATABASE_RECORD_SIZE))
#define ZI_IDENTITY_RECORD_DISABLED 1u
#define ZI_IDENTITY_RECORD_TOMBSTONE 2u

// Must originate in trusted provisioning state, never from the database being checked.
typedef struct ZiIdentityDatabaseAuthority {
  uint32_t struct_size;
  uint32_t version;
  unsigned char issuer[16];
  unsigned char volume[16];
  unsigned char database[16];
} ZiIdentityDatabaseAuthority;

typedef struct ZiIdentityDatabaseState {
  ZiIdentityIssuerState issuer;
  uint64_t generation;
  uint32_t record_count;
} ZiIdentityDatabaseState;

typedef struct ZiIdentityDatabaseRecord {
  ZiNativeIdentity identity;
  uint64_t generation;
  uint32_t state;
  uint16_t name_size;
  uint16_t group_count;
  char name[ZI_IDENTITY_DATABASE_NAME_BYTES];
  uint32_t groups[ZI_IDENTITY_DATABASE_GROUPS];
} ZiIdentityDatabaseRecord;

typedef struct ZiIdentityCreateRequest {
  uint32_t struct_size;
  uint32_t version;
  uint32_t authority;
  ZiStringView name;
  const uint32_t* groups;
  size_t group_count;
} ZiIdentityCreateRequest;

// All buffers and authority/request storage must be stable and non-overlapping.
// These byte operations do NOT publish or persist an account. Appended IDs remain
// unpublished candidates until the storage layer commits the complete database.
// Outputs and candidate bytes are unchanged on failure. No credentials are accepted.
ZiStatus zi_identity_database_authority_validate(const ZiIdentityDatabaseAuthority* authority);
ZiStatus zi_identity_database_initialise(const ZiIdentityDatabaseAuthority* authority,
                                         void* bytes,
                                         size_t size);
ZiStatus zi_identity_database_validate(const void* bytes,
                                       size_t size,
                                       const ZiIdentityDatabaseAuthority* authority,
                                       uint64_t minimum_generation,
                                       ZiIdentityDatabaseState* out_state);
ZiStatus zi_identity_database_record(const void* bytes,
                                     size_t size,
                                     const ZiIdentityDatabaseAuthority* authority,
                                     uint32_t index,
                                     ZiIdentityDatabaseRecord* out_record);
ZiStatus zi_identity_database_append(void* bytes,
                                     size_t size,
                                     const ZiIdentityDatabaseAuthority* authority,
                                     const ZiIdentityCreateRequest* request,
                                     ZiNativeIdentity* out_identity);
ZiStatus zi_identity_database_remove(void* bytes,
                                     size_t size,
                                     const ZiIdentityDatabaseAuthority* authority,
                                     const ZiNativeIdentity* identity);
