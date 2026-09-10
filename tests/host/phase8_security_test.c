// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "phase8_tests.h"
#include "zi/nvme_registers.h"
#include "zi/security.h"
#include "zizium/status.h"
#include "zizium/types.h"

static bool check_status(size_t* count, ZiStatus actual, ZiStatus expected, int line);
static bool test_token_roles(size_t* count);
static bool test_token_memberships(size_t* count, ZiAccessToken* token, ZiSecurityId* groups);
static bool test_inherit_only(size_t* count);

#define CHECK_STATUS(actual, expected)                                                             \
  do {                                                                                             \
    if (!check_status(count, (actual), (expected), __LINE__)) {                                    \
      return false;                                                                                \
    }                                                                                              \
  } while (false)

bool phase8_security_boundary_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  *out_assertion_count = 0;
  return (bool)(test_token_roles(out_assertion_count) && test_inherit_only(out_assertion_count));
}

static bool test_token_roles(size_t* count) {
  ZiSecurityId groups[ZI_SECURITY_MAXIMUM_TOKEN_GROUPS] = {0};
  for (size_t index = 0; index < ZI_SECURITY_MAXIMUM_TOKEN_GROUPS; ++index) {
    groups[index] = (ZiSecurityId){ZI_SECURITY_AUTHORITY_GROUP, (uint32_t)index + 1u};
  }
  ZiAccessToken token = {
      sizeof token,
      ZI_ACCESS_TOKEN_VERSION,
      {ZI_SECURITY_AUTHORITY_USER, 1},
      groups,
      ZI_SECURITY_MAXIMUM_TOKEN_GROUPS,
      0,
  };
  CHECK_STATUS(zi_security_token_validate(&token), ZI_STATUS_SUCCESS);
  token.user.authority = ZI_SECURITY_AUTHORITY_GROUP;
  CHECK_STATUS(zi_security_token_validate(&token), ZI_STATUS_INVALID_ARGUMENT);
  token.user.authority = ZI_SECURITY_AUTHORITY_SYSTEM;
  CHECK_STATUS(zi_security_token_validate(&token), ZI_STATUS_SUCCESS);
  token.user.authority = ZI_SECURITY_AUTHORITY_SERVICE;
  CHECK_STATUS(zi_security_token_validate(&token), ZI_STATUS_SUCCESS);
  return test_token_memberships(count, &token, groups);
}

static bool test_token_memberships(size_t* count, ZiAccessToken* token, ZiSecurityId* groups) {
  const ZiStatus authority_status[] = {
      ZI_STATUS_INVALID_ARGUMENT,
      ZI_STATUS_SUCCESS,
      ZI_STATUS_INVALID_ARGUMENT,
      ZI_STATUS_INVALID_ARGUMENT,
  };
  for (uint32_t authority = ZI_SECURITY_AUTHORITY_SYSTEM;
       authority <= ZI_SECURITY_AUTHORITY_SERVICE;
       ++authority) {
    groups[0].authority = authority;
    CHECK_STATUS(zi_security_token_validate(token),
                 authority_status[authority - ZI_SECURITY_AUTHORITY_SYSTEM]);
  }
  groups[0].authority = ZI_SECURITY_AUTHORITY_GROUP;
  groups[0].value = 0;
  CHECK_STATUS(zi_security_token_validate(token), ZI_STATUS_INVALID_ARGUMENT);
  groups[0] = groups[1];
  CHECK_STATUS(zi_security_token_validate(token), ZI_STATUS_INVALID_ARGUMENT);
  groups[0].value = 1;
  token->group_count = ZI_SECURITY_MAXIMUM_TOKEN_GROUPS + 1u;
  CHECK_STATUS(zi_security_token_validate(token), ZI_STATUS_INVALID_ARGUMENT);
  // Only one element is readable: the count must be rejected before traversal.
  const ZiSecurityId single_group = {ZI_SECURITY_AUTHORITY_GROUP, 1};
  token->groups = &single_group;
  token->group_count = SIZE_MAX;
  CHECK_STATUS(zi_security_token_validate(token), ZI_STATUS_INVALID_ARGUMENT);
  token->groups = NULL;
  token->group_count = 1;
  CHECK_STATUS(zi_security_token_validate(token), ZI_STATUS_INVALID_ARGUMENT);
  token->group_count = 0;
  CHECK_STATUS(zi_security_token_validate(token), ZI_STATUS_SUCCESS);
  return true;
}

static bool test_inherit_only(size_t* count) {
  const ZiSecurityId user = {ZI_SECURITY_AUTHORITY_USER, 42};
  const ZiSecurityId group = {ZI_SECURITY_AUTHORITY_GROUP, 2};
  const ZiAccessToken token = {sizeof token, ZI_ACCESS_TOKEN_VERSION, user, &group, 1, 0};
  ZiAce entries[] = {
      {ZI_ACE_ALLOW, ZI_ACE_INHERIT_FILE | ZI_ACE_INHERIT_ONLY, 0, ZI_ACCESS_READ, user},
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_WRITE, group},
  };
  const ZiAcl acl = {sizeof acl, ZI_ACL_VERSION, entries, 2};
  const ZiSecurityDescriptor descriptor = {
      sizeof descriptor,
      ZI_SECURITY_DESCRIPTOR_VERSION,
      user,
      group,
      &acl,
      0,
  };
  ZiAccessMask granted = 0;
  CHECK_STATUS(zi_security_access_check(&descriptor, &token, ZI_ACCESS_READ, &granted),
               ZI_STATUS_ACCESS_DENIED);
  CHECK_STATUS(granted == 0 ? ZI_STATUS_SUCCESS : ZI_STATUS_INVALID_STATE, ZI_STATUS_SUCCESS);
  entries[0].type = ZI_ACE_DENY;
  entries[0].access_mask = ZI_ACCESS_WRITE;
  entries[0].trustee = group;
  CHECK_STATUS(zi_security_access_check(&descriptor, &token, ZI_ACCESS_WRITE, &granted),
               ZI_STATUS_SUCCESS);
  CHECK_STATUS(granted == ZI_ACCESS_WRITE ? ZI_STATUS_SUCCESS : ZI_STATUS_INVALID_STATE,
               ZI_STATUS_SUCCESS);
  entries[0].inheritance_flags = ZI_ACE_INHERITED;
  CHECK_STATUS(zi_security_access_check(&descriptor, &token, ZI_ACCESS_WRITE, &granted),
               ZI_STATUS_ACCESS_DENIED);
  entries[0].type = ZI_ACE_ALLOW;
  CHECK_STATUS(zi_security_access_check(&descriptor, &token, ZI_ACCESS_WRITE, &granted),
               ZI_STATUS_SUCCESS);
  entries[0].inheritance_flags = ZI_ACE_INHERIT_ONLY;
  entries[0].reserved = 1;
  CHECK_STATUS(zi_security_access_check(&descriptor, &token, ZI_ACCESS_WRITE, &granted),
               ZI_STATUS_INVALID_ARGUMENT);
  return true;
}

bool phase8_nvme_window_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  *out_assertion_count = 0;
  size_t* count = out_assertion_count;
  const struct NvmeWindowCase {
    uint64_t base;
    uint64_t size;
    uint32_t stride;
    ZiStatus expected;
  } cases[] = {
      {0x100000, 0x2000, 4, ZI_STATUS_SUCCESS},
      {0, 0x2000, 4, ZI_STATUS_INVALID_ARGUMENT},
      {0x100004, 0x2000, 4, ZI_STATUS_INVALID_ARGUMENT},
      {0x100000, 0x1fff, 4, ZI_STATUS_INVALID_ARGUMENT},
      {UINT64_MAX - 7u, 0x2000, 4, ZI_STATUS_INVALID_ARGUMENT},
      {0x100000, UINT64_MAX, 4, ZI_STATUS_INVALID_ARGUMENT},
      {0x100000, 0x2000, 0, ZI_STATUS_INVALID_ARGUMENT},
      {0x100000, 0x2000, 6, ZI_STATUS_INVALID_ARGUMENT},
      {0x100000, 0x2000, 0x40000, ZI_STATUS_INVALID_ARGUMENT},
      {0x100000, 0x2000, 0x20000, ZI_STATUS_NOT_IMPLEMENTED},
      {0x100000, 0x61003, 0x20000, ZI_STATUS_NOT_IMPLEMENTED},
      {0x100000, 0x61004, 0x20000, ZI_STATUS_SUCCESS},
  };
  for (size_t index = 0; index < sizeof cases / sizeof cases[0]; ++index) {
    CHECK_STATUS(
        zi_nvme_register_window_validate(cases[index].base, cases[index].size, cases[index].stride),
        cases[index].expected);
  }
  return true;
}

static bool check_status(size_t* count, ZiStatus actual, ZiStatus expected, int line) {
  ++*count;
  if (actual != expected) {
    printf("Phase 8 security check failed at line %d: status %d, expected %d.\n",
           line,
           actual,
           expected);
    return false;
  }
  return true;
}
