// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "phase8_tests.h"
#include "zi/security.h"
#include "zi/service.h"
#include "zi/service_identity.h"
#include "zizium/status.h"
#include "zizium/types.h"

typedef struct ServiceIdentityCase {
  const char* name;
  const char* path;
  const char* identity;
  uint32_t policy;
  uint32_t authority;
  uint32_t value;
} ServiceIdentityCase;

static ZiStringView text_view(const char* text);
static ZiServiceManifest make_manifest(const ServiceIdentityCase* entry);
static bool check(size_t* count, bool condition, int line);
static bool test_approved(size_t* count);
static bool test_approved_case(size_t* count, const ServiceIdentityCase* entry);
static bool test_membership(size_t* count, const ZiAccessToken* token, const ZiSecurityId* group);
static bool test_rejected(size_t* count);
static bool test_rejected_policy(size_t* count);
static bool test_invalid_input(size_t* count);
static bool test_rejection(size_t* count, const ZiServiceManifest* manifest, ZiStatus expected);
static bool test_group_access(size_t* count, const ZiAccessToken* token);
static uint32_t legacy_hash(const char* name);

#define CHECK(condition)                                                                           \
  do {                                                                                             \
    if (!check(count, (condition), __LINE__)) {                                                    \
      return false;                                                                                \
    }                                                                                              \
  } while (false)

static const ServiceIdentityCase k_cases[] = {
    {"ServiceHost",
     "C:\\Zizium\\System\\ServiceHost.exe",
     "NID:SYSTEM",
     ZI_SERVICE_TOKEN_SYSTEM,
     ZI_SECURITY_AUTHORITY_SYSTEM,
     1},
    {"SecurityHost",
     "C:\\Zizium\\System\\SecurityHost.exe",
     "NID:SYSTEM",
     ZI_SERVICE_TOKEN_SYSTEM,
     ZI_SECURITY_AUTHORITY_SYSTEM,
     1},
    {"LogHost",
     "C:\\Zizium\\System\\LogHost.exe",
     "NID:SERVICE:LogHost",
     ZI_SERVICE_TOKEN_SERVICE,
     ZI_SECURITY_AUTHORITY_SERVICE,
     1},
    {"MountHost",
     "C:\\Zizium\\System\\MountHost.exe",
     "NID:SERVICE:MountHost",
     ZI_SERVICE_TOKEN_SERVICE,
     ZI_SECURITY_AUTHORITY_SERVICE,
     2},
    {"SessionHost",
     "C:\\Zizium\\System\\SessionHost.exe",
     "NID:SERVICE:SessionHost",
     ZI_SERVICE_TOKEN_SESSION_BOOTSTRAP,
     ZI_SECURITY_AUTHORITY_SERVICE,
     3},
};

bool phase8_service_identity_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  *out_assertion_count = 0;
  return (bool)(test_approved(out_assertion_count) && test_rejected(out_assertion_count) &&
                test_rejected_policy(out_assertion_count) &&
                test_invalid_input(out_assertion_count));
}

static bool test_approved(size_t* count) {
  for (size_t index = 0; index < sizeof k_cases / sizeof k_cases[0]; ++index) {
    if (!test_approved_case(count, &k_cases[index])) {
      return false;
    }
  }
  return true;
}

static bool test_approved_case(size_t* count, const ServiceIdentityCase* entry) {
  ZiServiceManifest manifest = make_manifest(entry);
  ZiAccessToken token = {0};
  ZiSecurityId group = {0};
  CHECK(zi_service_bootstrap_token_create(&manifest, &group, &token) == ZI_STATUS_SUCCESS);
  CHECK(zi_security_token_validate(&token) == ZI_STATUS_SUCCESS);
  CHECK(token.user.authority == entry->authority && token.user.value == entry->value);
  CHECK(token.privileges == 0);
  return test_membership(count, &token, &group);
}

static bool test_membership(size_t* count, const ZiAccessToken* token, const ZiSecurityId* group) {
  if (token->user.authority == ZI_SECURITY_AUTHORITY_SYSTEM) {
    CHECK(token->group_count == 0 && token->groups == NULL);
  } else {
    CHECK(token->group_count == 1 && token->groups == group);
    CHECK(group->authority == ZI_SECURITY_AUTHORITY_GROUP && group->value == 2);
    CHECK(test_group_access(count, token));
  }
  return true;
}

static bool test_group_access(size_t* count, const ZiAccessToken* token) {
  ZiAce entries[] = {
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_FULL_CONTROL, {ZI_SECURITY_AUTHORITY_GROUP, 1}},
      {ZI_ACE_ALLOW,
       0,
       0,
       ZI_ACCESS_READ | ZI_ACCESS_EXECUTE | ZI_ACCESS_LIST,
       {ZI_SECURITY_AUTHORITY_GROUP, 2}},
  };
  ZiAcl acl = {sizeof acl, ZI_ACL_VERSION, entries, 2};
  ZiSecurityDescriptor descriptor = {sizeof descriptor,
                                     ZI_SECURITY_DESCRIPTOR_VERSION,
                                     {ZI_SECURITY_AUTHORITY_SYSTEM, 1},
                                     {ZI_SECURITY_AUTHORITY_GROUP, 1},
                                     &acl,
                                     0};
  ZiAccessMask granted = 0;
  CHECK(
      zi_security_access_check(&descriptor, token, ZI_ACCESS_READ | ZI_ACCESS_EXECUTE, &granted) ==
      ZI_STATUS_SUCCESS);
  CHECK(zi_security_access_check(&descriptor, token, ZI_ACCESS_WRITE, &granted) ==
        ZI_STATUS_ACCESS_DENIED);
  CHECK(zi_security_access_check(&descriptor, token, ZI_ACCESS_MODIFY_ACL, &granted) ==
        ZI_STATUS_ACCESS_DENIED);
  return true;
}

static bool test_rejected(size_t* count) {
  ZiServiceManifest manifest = make_manifest(&k_cases[2]);
  const ZiStringView wrong_names[] = {
      {"logHost", sizeof "logHost" - 1u},
      {"SvcbPEvTBVorR", sizeof "SvcbPEvTBVorR" - 1u},
      {"SvcJJdsVevOgL", sizeof "SvcJJdsVevOgL" - 1u},
  };
  // These distinct valid names collided in the removed FNV-1a identity scheme.
  CHECK(legacy_hash(wrong_names[1].data) == UINT32_C(807251377));
  CHECK(legacy_hash(wrong_names[1].data) == legacy_hash(wrong_names[2].data));
  for (size_t index = 0; index < sizeof wrong_names / sizeof wrong_names[0]; ++index) {
    manifest.name = wrong_names[index];
    CHECK(test_rejection(count, &manifest, ZI_STATUS_ACCESS_DENIED));
  }
  manifest = make_manifest(&k_cases[2]);
  manifest.executable_path = text_view("C:\\Temp\\LogHost.exe");
  CHECK(test_rejection(count, &manifest, ZI_STATUS_ACCESS_DENIED));
  manifest.executable_path = text_view("C:\\Zizium\\System\\logHost.exe");
  CHECK(test_rejection(count, &manifest, ZI_STATUS_ACCESS_DENIED));
  return true;
}

static bool test_rejected_policy(size_t* count) {
  ZiServiceManifest manifest = make_manifest(&k_cases[2]);
  manifest.identity = text_view("NID:SERVICE:MountHost");
  CHECK(test_rejection(count, &manifest, ZI_STATUS_ACCESS_DENIED));
  manifest.identity = text_view("NID:SYSTEM");
  CHECK(test_rejection(count, &manifest, ZI_STATUS_INVALID_SERVICE_MANIFEST));
  manifest.token_policy = ZI_SERVICE_TOKEN_SYSTEM;
  CHECK(test_rejection(count, &manifest, ZI_STATUS_ACCESS_DENIED));
  manifest = make_manifest(&k_cases[2]);
  manifest.service_kind = ZI_SERVICE_KIND_USER;
  CHECK(test_rejection(count, &manifest, ZI_STATUS_ACCESS_DENIED));
  manifest = make_manifest(&k_cases[2]);
  manifest.start_mode = ZI_SERVICE_DISABLED;
  CHECK(test_rejection(count, &manifest, ZI_STATUS_ACCESS_DENIED));
  manifest = make_manifest(&k_cases[4]);
  manifest.identity = text_view("NID:SYSTEM");
  CHECK(test_rejection(count, &manifest, ZI_STATUS_INVALID_SERVICE_MANIFEST));
  return true;
}

static bool test_invalid_input(size_t* count) {
  ZiServiceManifest manifest = make_manifest(&k_cases[0]);
  manifest.version = UINT32_MAX;
  CHECK(test_rejection(count, &manifest, ZI_STATUS_INVALID_SERVICE_MANIFEST));
  CHECK(test_rejection(count, NULL, ZI_STATUS_INVALID_SERVICE_MANIFEST));
  ZiAccessToken token = {0};
  ZiSecurityId group = {0};
  CHECK(zi_service_bootstrap_token_create(&manifest, NULL, &token) == ZI_STATUS_INVALID_ARGUMENT);
  CHECK(zi_service_bootstrap_token_create(&manifest, &group, NULL) == ZI_STATUS_INVALID_ARGUMENT);
  return true;
}

static bool test_rejection(size_t* count, const ZiServiceManifest* manifest, ZiStatus expected) {
  ZiSecurityId group = {ZI_SECURITY_AUTHORITY_GROUP, 77};
  ZiAccessToken token =
      {sizeof token, ZI_ACCESS_TOKEN_VERSION, {ZI_SECURITY_AUTHORITY_USER, 99}, &group, 1, 123};
  CHECK(zi_service_bootstrap_token_create(manifest, &group, &token) == expected);
  CHECK(token.user.authority == ZI_SECURITY_AUTHORITY_USER && token.user.value == 99 &&
        token.privileges == 123 && token.group_count == 1 && token.groups == &group);
  CHECK(group.authority == ZI_SECURITY_AUTHORITY_GROUP && group.value == 77);
  return true;
}

static ZiServiceManifest make_manifest(const ServiceIdentityCase* entry) {
  ZiServiceManifest manifest = {0};
  manifest.struct_size = sizeof manifest;
  manifest.version = ZI_SERVICE_MANIFEST_VERSION;
  manifest.format_version = ZI_SERVICE_MANIFEST_FORMAT_VERSION;
  manifest.name = text_view(entry->name);
  manifest.executable_path = text_view(entry->path);
  manifest.identity = text_view(entry->identity);
  manifest.service_kind = ZI_SERVICE_KIND_SYSTEM;
  manifest.token_policy = entry->policy;
  return manifest;
}

static ZiStringView text_view(const char* text) {
  return (ZiStringView){text, strlen(text)};
}

static uint32_t legacy_hash(const char* name) {
  uint32_t value = UINT32_C(2166136261);
  for (size_t index = 0; name[index] != '\0'; ++index) {
    value ^= (unsigned char)name[index];
    value *= UINT32_C(16777619);
  }
  return value;
}

static bool check(size_t* count, bool condition, int line) {
  ++*count;
  if (!condition) {
    printf("Service identity check failed at line %d.\n", line);
  }
  return condition;
}
