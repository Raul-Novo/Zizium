// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/byte_order.h"
#include "zi/security.h"
#include "zi/service.h"
#include "zi/service_identity.h"
#include "zizium/status.h"
#include "zizium/types.h"

typedef struct ZiBootstrapServiceIdentity {
  ZiStringView name;
  ZiStringView executable_path;
  ZiStringView identity;
  uint32_t token_policy;
  ZiSecurityId principal;
} ZiBootstrapServiceIdentity;

// Reserved bootstrap identities: values are explicit, never hashes or table ordinals.
// Do not reuse these pairs for authenticated accounts or silently migrate old hash IDs.
static const ZiBootstrapServiceIdentity k_bootstrap_identities[] = {
    {{"ServiceHost", sizeof "ServiceHost" - 1u},
     {"C:\\Zizium\\System\\ServiceHost.exe", sizeof "C:\\Zizium\\System\\ServiceHost.exe" - 1u},
     {"NID:SYSTEM", sizeof "NID:SYSTEM" - 1u},
     ZI_SERVICE_TOKEN_SYSTEM,
     {ZI_SECURITY_AUTHORITY_SYSTEM, 1}},
    {{"SecurityHost", sizeof "SecurityHost" - 1u},
     {"C:\\Zizium\\System\\SecurityHost.exe", sizeof "C:\\Zizium\\System\\SecurityHost.exe" - 1u},
     {"NID:SYSTEM", sizeof "NID:SYSTEM" - 1u},
     ZI_SERVICE_TOKEN_SYSTEM,
     {ZI_SECURITY_AUTHORITY_SYSTEM, 1}},
    {{"LogHost", sizeof "LogHost" - 1u},
     {"C:\\Zizium\\System\\LogHost.exe", sizeof "C:\\Zizium\\System\\LogHost.exe" - 1u},
     {"NID:SERVICE:LogHost", sizeof "NID:SERVICE:LogHost" - 1u},
     ZI_SERVICE_TOKEN_SERVICE,
     {ZI_SECURITY_AUTHORITY_SERVICE, 1}},
    {{"MountHost", sizeof "MountHost" - 1u},
     {"C:\\Zizium\\System\\MountHost.exe", sizeof "C:\\Zizium\\System\\MountHost.exe" - 1u},
     {"NID:SERVICE:MountHost", sizeof "NID:SERVICE:MountHost" - 1u},
     ZI_SERVICE_TOKEN_SERVICE,
     {ZI_SECURITY_AUTHORITY_SERVICE, 2}},
    {{"SessionHost", sizeof "SessionHost" - 1u},
     {"C:\\Zizium\\System\\SessionHost.exe", sizeof "C:\\Zizium\\System\\SessionHost.exe" - 1u},
     {"NID:SERVICE:SessionHost", sizeof "NID:SERVICE:SessionHost" - 1u},
     ZI_SERVICE_TOKEN_SESSION_BOOTSTRAP,
     {ZI_SECURITY_AUTHORITY_SERVICE, 3}},
};

static bool views_equal(ZiStringView left, ZiStringView right);

ZiStatus zi_service_bootstrap_token_create(const ZiServiceManifest* manifest,
                                           ZiSecurityId* group_storage,
                                           ZiAccessToken* out_token) {
  if (group_storage == NULL || out_token == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_service_manifest_validate(manifest);
  if (ZiFailed(status)) {
    return status;
  }
  if (manifest->service_kind != ZI_SERVICE_KIND_SYSTEM ||
      manifest->start_mode == ZI_SERVICE_DISABLED) {
    return ZI_STATUS_ACCESS_DENIED;
  }
  for (size_t index = 0; index < sizeof k_bootstrap_identities / sizeof k_bootstrap_identities[0];
       ++index) {
    const ZiBootstrapServiceIdentity* policy = &k_bootstrap_identities[index];
    if (!views_equal(manifest->name, policy->name)) {
      continue;
    }
    if (!views_equal(manifest->executable_path, policy->executable_path) ||
        !views_equal(manifest->identity, policy->identity) ||
        manifest->token_policy != policy->token_policy) {
      return ZI_STATUS_ACCESS_DENIED;
    }
    ZiAccessToken token =
        {sizeof(ZiAccessToken), ZI_ACCESS_TOKEN_VERSION, policy->principal, NULL, 0, 0};
    *group_storage = (ZiSecurityId){0};
    if (policy->principal.authority != ZI_SECURITY_AUTHORITY_SYSTEM) {
      *group_storage = (ZiSecurityId){ZI_SECURITY_AUTHORITY_GROUP, 2};
      token.groups = group_storage;
      token.group_count = 1;
    }
    *out_token = token;
    return ZI_STATUS_SUCCESS;
  }
  return ZI_STATUS_ACCESS_DENIED;
}

static bool views_equal(ZiStringView left, ZiStringView right) {
  return (bool)(left.size == right.size &&
                zi_memory_compare(left.data, right.data, left.size) == 0);
}
