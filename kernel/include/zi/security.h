// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_ACCESS_READ UINT32_C(0x00000001)
#define ZI_ACCESS_WRITE UINT32_C(0x00000002)
#define ZI_ACCESS_EXECUTE UINT32_C(0x00000004)
#define ZI_ACCESS_DELETE UINT32_C(0x00000008)
#define ZI_ACCESS_LIST UINT32_C(0x00000010)
#define ZI_ACCESS_CREATE UINT32_C(0x00000020)
#define ZI_ACCESS_MODIFY_ACL UINT32_C(0x00000040)
#define ZI_ACCESS_TAKE_OWNERSHIP UINT32_C(0x00000080)
#define ZI_ACCESS_FULL_CONTROL UINT32_C(0x000000ff)

#define ZI_ACL_VERSION 1u
#define ZI_SECURITY_DESCRIPTOR_VERSION 1u
#define ZI_ACCESS_TOKEN_VERSION 1u
#define ZI_SECURITY_MAXIMUM_ACES 64u

#define ZI_ACE_INHERIT_FILE (UINT8_C(1) << 0)
#define ZI_ACE_INHERIT_DIRECTORY (UINT8_C(1) << 1)
#define ZI_ACE_INHERIT_ONLY (UINT8_C(1) << 2)
#define ZI_ACE_INHERITED (UINT8_C(1) << 3)
#define ZI_ACE_INHERIT_SUPPORTED                                                                   \
  (ZI_ACE_INHERIT_FILE | ZI_ACE_INHERIT_DIRECTORY | ZI_ACE_INHERIT_ONLY | ZI_ACE_INHERITED)

#define ZI_SECURITY_DESCRIPTOR_CONTROL_NONE UINT32_C(0)

enum ZiAceType {
  ZI_ACE_DENY = 0,
  ZI_ACE_ALLOW = 1,
};

enum ZiSecurityAuthority {
  ZI_SECURITY_AUTHORITY_SYSTEM = 1,
  ZI_SECURITY_AUTHORITY_GROUP = 2,
  ZI_SECURITY_AUTHORITY_USER = 3,
  ZI_SECURITY_AUTHORITY_SERVICE = 4,
};

typedef struct ZiSecurityId {
  uint32_t authority;
  uint32_t value;
} ZiSecurityId;

typedef struct ZiAce {
  uint8_t type;
  uint8_t inheritance_flags;
  uint16_t reserved;
  ZiAccessMask access_mask;
  ZiSecurityId trustee;
} ZiAce;

typedef struct ZiAcl {
  uint32_t struct_size;
  uint32_t version;
  const ZiAce* entries;
  size_t entry_count;
} ZiAcl;

typedef struct ZiSecurityDescriptor {
  uint32_t struct_size;
  uint32_t version;
  ZiSecurityId owner;
  ZiSecurityId primary_group;
  const ZiAcl* dacl;
  uint32_t control_flags;
} ZiSecurityDescriptor;

typedef struct ZiAccessToken {
  uint32_t struct_size;
  uint32_t version;
  ZiSecurityId user;
  const ZiSecurityId* groups;
  size_t group_count;
  uint64_t privileges;
} ZiAccessToken;

bool zi_security_id_equal(ZiSecurityId left, ZiSecurityId right);
ZiStatus zi_security_id_validate(ZiSecurityId id);
ZiStatus zi_security_token_validate(const ZiAccessToken* token);
ZiStatus zi_security_descriptor_validate(const ZiSecurityDescriptor* descriptor);
ZiStatus zi_security_access_check(const ZiSecurityDescriptor* descriptor,
                                  const ZiAccessToken* token,
                                  ZiAccessMask requested_access,
                                  ZiAccessMask* out_granted_access);
