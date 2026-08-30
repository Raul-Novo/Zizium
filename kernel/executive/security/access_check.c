// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>

#include "zi/security.h"
#include "zizium/status.h"
#include "zizium/types.h"

static bool token_contains_id(const ZiAccessToken* token, ZiSecurityId id);

bool zi_security_id_equal(ZiSecurityId left, ZiSecurityId right) {
  return (bool)(left.authority == right.authority && left.value == right.value);
}

ZiStatus zi_security_token_validate(const ZiAccessToken* token) {
  if (token == NULL || token->struct_size != sizeof *token ||
      token->version != ZI_ACCESS_TOKEN_VERSION || ZiFailed(zi_security_id_validate(token->user)) ||
      (token->groups == NULL && token->group_count != 0)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  for (size_t index = 0; index < token->group_count; ++index) {
    if (ZiFailed(zi_security_id_validate(token->groups[index]))) {
      return ZI_STATUS_INVALID_ARGUMENT;
    }
    for (size_t previous = 0; previous < index; ++previous) {
      if (zi_security_id_equal(token->groups[previous], token->groups[index])) {
        return ZI_STATUS_INVALID_ARGUMENT;
      }
    }
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_security_id_validate(ZiSecurityId id) {
  return id.value != 0 && id.authority >= ZI_SECURITY_AUTHORITY_SYSTEM &&
                 id.authority <= ZI_SECURITY_AUTHORITY_SERVICE
             ? ZI_STATUS_SUCCESS
             : ZI_STATUS_INVALID_ARGUMENT;
}

ZiStatus zi_security_descriptor_validate(const ZiSecurityDescriptor* descriptor) {
  if (descriptor == NULL || descriptor->struct_size != sizeof *descriptor ||
      descriptor->version != ZI_SECURITY_DESCRIPTOR_VERSION ||
      ZiFailed(zi_security_id_validate(descriptor->owner)) ||
      ZiFailed(zi_security_id_validate(descriptor->primary_group)) ||
      descriptor->control_flags != ZI_SECURITY_DESCRIPTOR_CONTROL_NONE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (descriptor->dacl == NULL) {
    return ZI_STATUS_SUCCESS;
  }
  const ZiAcl* dacl = descriptor->dacl;
  if (dacl->struct_size != sizeof *dacl || dacl->version != ZI_ACL_VERSION ||
      dacl->entry_count > ZI_SECURITY_MAXIMUM_ACES ||
      (dacl->entries == NULL && dacl->entry_count != 0)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  for (size_t index = 0; index < dacl->entry_count; ++index) {
    const ZiAce* entry = &dacl->entries[index];
    if ((entry->type != ZI_ACE_DENY && entry->type != ZI_ACE_ALLOW) || entry->reserved != 0 ||
        (entry->inheritance_flags & ~ZI_ACE_INHERIT_SUPPORTED) != 0 || entry->access_mask == 0 ||
        (entry->access_mask & ~ZI_ACCESS_FULL_CONTROL) != 0 ||
        ZiFailed(zi_security_id_validate(entry->trustee))) {
      return ZI_STATUS_INVALID_ARGUMENT;
    }
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_security_access_check(const ZiSecurityDescriptor* descriptor,
                                  const ZiAccessToken* token,
                                  ZiAccessMask requested_access,
                                  ZiAccessMask* out_granted_access) {
  if (descriptor == NULL || out_granted_access == NULL ||
      (requested_access & ~ZI_ACCESS_FULL_CONTROL) != 0 ||
      ZiFailed(zi_security_descriptor_validate(descriptor)) ||
      ZiFailed(zi_security_token_validate(token))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  *out_granted_access = 0;
  if (requested_access == 0) {
    return ZI_STATUS_SUCCESS;
  }
  if (descriptor->dacl == NULL) {
    return ZI_STATUS_ACCESS_DENIED;
  }
  if (descriptor->dacl->entry_count == 0) {
    return ZI_STATUS_ACCESS_DENIED;
  }

  ZiAccessMask remaining_access = requested_access;
  ZiAccessMask granted_access = 0;
  for (size_t index = 0; index < descriptor->dacl->entry_count; ++index) {
    const ZiAce* entry = &descriptor->dacl->entries[index];
    if (!token_contains_id(token, entry->trustee)) {
      continue;
    }

    ZiAccessMask relevant_access = entry->access_mask & remaining_access;
    if (relevant_access == 0) {
      continue;
    }
    if (entry->type == ZI_ACE_DENY) {
      return ZI_STATUS_ACCESS_DENIED;
    }
    if (entry->type != ZI_ACE_ALLOW) {
      return ZI_STATUS_INVALID_ARGUMENT;
    }

    granted_access |= relevant_access;
    remaining_access &= ~relevant_access;
    if (remaining_access == 0) {
      *out_granted_access = granted_access;
      return ZI_STATUS_SUCCESS;
    }
  }

  *out_granted_access = granted_access;
  return ZI_STATUS_ACCESS_DENIED;
}

static bool token_contains_id(const ZiAccessToken* token, ZiSecurityId id) {
  if (zi_security_id_equal(token->user, id)) {
    return true;
  }
  for (size_t index = 0; index < token->group_count; ++index) {
    if (zi_security_id_equal(token->groups[index], id)) {
      return true;
    }
  }
  return false;
}
