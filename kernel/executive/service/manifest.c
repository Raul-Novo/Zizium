// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/byte_order.h"
#include "zi/path.h"
#include "zi/service.h"
#include "zi/unicode.h"
#include "zizium/status.h"
#include "zizium/types.h"

enum ManifestField {
  MANIFEST_FIELD_FORMAT_VERSION = 1u << 0,
  MANIFEST_FIELD_NAME = 1u << 1,
  MANIFEST_FIELD_EXECUTABLE = 1u << 2,
  MANIFEST_FIELD_SERVICE_KIND = 1u << 3,
  MANIFEST_FIELD_IDENTITY = 1u << 4,
  MANIFEST_FIELD_START_MODE = 1u << 5,
  MANIFEST_FIELD_START_ORDER = 1u << 6,
  MANIFEST_FIELD_DEPENDENCIES = 1u << 7,
  MANIFEST_FIELD_RESTART_POLICY = 1u << 8,
  MANIFEST_FIELD_TOKEN_POLICY = 1u << 9,
  MANIFEST_FIELD_MAXIMUM_RESTARTS = 1u << 10,
  MANIFEST_FIELD_PERMISSIONS = 1u << 11,
  MANIFEST_FIELD_LOG = 1u << 12,
  MANIFEST_FIELD_STATUS = 1u << 13,
};

#define MANIFEST_REQUIRED_FIELDS                                                                   \
  (MANIFEST_FIELD_FORMAT_VERSION | MANIFEST_FIELD_NAME | MANIFEST_FIELD_EXECUTABLE |               \
   MANIFEST_FIELD_SERVICE_KIND | MANIFEST_FIELD_IDENTITY | MANIFEST_FIELD_START_MODE |             \
   MANIFEST_FIELD_START_ORDER | MANIFEST_FIELD_DEPENDENCIES | MANIFEST_FIELD_RESTART_POLICY |      \
   MANIFEST_FIELD_TOKEN_POLICY | MANIFEST_FIELD_MAXIMUM_RESTARTS)

static bool view_equals(ZiStringView view, const char* expected, size_t expected_size);
static int compare_views(ZiStringView left, ZiStringView right);
static ZiStatus validate_service_name(ZiStringView name);
static ZiStatus validate_executable_path(ZiStringView path);
static ZiStatus validate_identity(ZiStringView identity);
static ZiStatus parse_uint32(ZiStringView value, uint32_t maximum, uint32_t* out_value);
static ZiStatus parse_start_mode(ZiStringView value, uint32_t* out_mode);
static ZiStatus parse_restart_policy(ZiStringView value, uint32_t* out_policy);
static ZiStatus parse_service_kind(ZiStringView value, uint32_t* out_kind);
static ZiStatus parse_token_policy(ZiStringView value, uint32_t* out_policy);
static ZiStatus parse_implementation_status(ZiStringView value, uint32_t* out_status);
static ZiStatus parse_dependencies(ZiStringView value,
                                   ZiServiceDependency* dependency_storage,
                                   size_t dependency_capacity,
                                   size_t* out_dependency_count);
static ZiStatus assign_manifest_field(ZiStringView key,
                                      ZiStringView value,
                                      ZiServiceDependency* dependency_storage,
                                      size_t dependency_capacity,
                                      uint32_t* fields,
                                      ZiServiceManifest* manifest);
static ZiStatus validate_manifest_dependencies(const ZiServiceManifest* manifest);
static ZiStatus find_manifest(const ZiServiceManifest* manifests,
                              size_t manifest_count,
                              ZiStringView name,
                              size_t* out_index);
static bool dependencies_are_emitted(const ZiServiceManifest* manifests,
                                     size_t manifest_count,
                                     const bool* emitted,
                                     size_t manifest_index);
static bool candidate_precedes(const ZiServiceManifest* manifests,
                               size_t manifest_index,
                               size_t current_candidate_index);

// The parser is linear and keeps all field ownership visible in one bounded transaction.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
ZiStatus zi_service_manifest_parse(const char* data,
                                   size_t data_size,
                                   ZiServiceDependency* dependency_storage,
                                   size_t dependency_capacity,
                                   ZiServiceManifest* out_manifest) {
  if (data == NULL || data_size == 0 || data_size > ZI_SERVICE_MAX_MANIFEST_BYTES ||
      out_manifest == NULL || (dependency_storage == NULL && dependency_capacity != 0) ||
      dependency_capacity > ZI_SERVICE_MAX_DEPENDENCIES) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_memory_zero(out_manifest, sizeof *out_manifest);
  ZiStatus status = zi_utf8_validate(data, data_size);
  if (ZiFailed(status)) {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  for (size_t index = 0; index < data_size; ++index) {
    if (data[index] == '\0') {
      return ZI_STATUS_INVALID_SERVICE_MANIFEST;
    }
  }

  ZiServiceManifest manifest = {
      .struct_size = sizeof(ZiServiceManifest),
      .version = ZI_SERVICE_MANIFEST_VERSION,
      .dependencies = dependency_storage,
  };
  uint32_t fields = 0;
  size_t offset = 0;
  while (offset < data_size) {
    size_t line_start = offset;
    while (offset < data_size && data[offset] != '\n' && data[offset] != '\r') {
      ++offset;
    }
    size_t line_size = offset - line_start;
    if (offset < data_size && data[offset] == '\r') {
      if (offset + 1u >= data_size || data[offset + 1u] != '\n') {
        return ZI_STATUS_INVALID_SERVICE_MANIFEST;
      }
      offset += 2u;
    } else if (offset < data_size) {
      ++offset;
    }
    if (line_size == 0 || data[line_start] == '#') {
      continue;
    }

    size_t equals_offset = 0;
    while (equals_offset < line_size && data[line_start + equals_offset] != '=') {
      ++equals_offset;
    }
    if (equals_offset == 0 || equals_offset == line_size) {
      return ZI_STATUS_INVALID_SERVICE_MANIFEST;
    }
    ZiStringView key = {data + line_start, equals_offset};
    ZiStringView value = {
        data + line_start + equals_offset + 1u,
        line_size - equals_offset - 1u,
    };
    status = assign_manifest_field(key,
                                   value,
                                   dependency_storage,
                                   dependency_capacity,
                                   &fields,
                                   &manifest);
    if (ZiFailed(status)) {
      return ZI_STATUS_INVALID_SERVICE_MANIFEST;
    }
  }
  if ((fields & MANIFEST_REQUIRED_FIELDS) != MANIFEST_REQUIRED_FIELDS) {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  status = zi_service_manifest_validate(&manifest);
  if (ZiFailed(status)) {
    return status;
  }
  *out_manifest = manifest;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_service_manifest_validate(const ZiServiceManifest* manifest) {
  if (manifest == NULL || manifest->struct_size < sizeof *manifest ||
      manifest->version != ZI_SERVICE_MANIFEST_VERSION ||
      manifest->format_version != ZI_SERVICE_MANIFEST_FORMAT_VERSION ||
      manifest->dependency_count > ZI_SERVICE_MAX_DEPENDENCIES ||
      (manifest->dependencies == NULL && manifest->dependency_count != 0) ||
      manifest->start_order > UINT16_MAX || manifest->maximum_restarts > ZI_SERVICE_MAX_RESTARTS ||
      (manifest->service_kind != ZI_SERVICE_KIND_SYSTEM &&
       manifest->service_kind != ZI_SERVICE_KIND_USER) ||
      manifest->start_mode > ZI_SERVICE_DISABLED ||
      manifest->restart_policy > ZI_SERVICE_RESTART_ALWAYS ||
      manifest->token_policy < ZI_SERVICE_TOKEN_SYSTEM ||
      manifest->token_policy > ZI_SERVICE_TOKEN_SESSION_BOOTSTRAP || manifest->flags != 0) {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  if (ZiFailed(validate_service_name(manifest->name)) ||
      ZiFailed(validate_executable_path(manifest->executable_path)) ||
      ZiFailed(validate_identity(manifest->identity)) ||
      ZiFailed(validate_manifest_dependencies(manifest))) {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  if (manifest->log_path.size != 0 && ZiFailed(validate_executable_path(manifest->log_path))) {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  if (manifest->restart_policy == ZI_SERVICE_RESTART_NEVER) {
    if (manifest->maximum_restarts != 0) {
      return ZI_STATUS_INVALID_SERVICE_MANIFEST;
    }
  } else if (manifest->maximum_restarts == 0) {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  if (manifest->token_policy == ZI_SERVICE_TOKEN_SYSTEM &&
      !view_equals(manifest->identity, "NID:SYSTEM", sizeof "NID:SYSTEM" - 1u)) {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  if (manifest->token_policy == ZI_SERVICE_TOKEN_SERVICE &&
      (manifest->identity.size <= sizeof "NID:SERVICE:" - 1u ||
       zi_memory_compare(manifest->identity.data, "NID:SERVICE:", sizeof "NID:SERVICE:" - 1u) !=
           0)) {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  if (manifest->token_policy == ZI_SERVICE_TOKEN_SERVICE &&
      ZiFailed(validate_service_name(
          (ZiStringView){manifest->identity.data + sizeof "NID:SERVICE:" - 1u,
                         manifest->identity.size - (sizeof "NID:SERVICE:" - 1u)}))) {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  if (manifest->token_policy == ZI_SERVICE_TOKEN_SESSION_BOOTSTRAP &&
      !view_equals(manifest->identity, "NID:SYSTEM", sizeof "NID:SYSTEM" - 1u)) {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  return ZI_STATUS_SUCCESS;
}

// The bounded 32-manifest scan favours an auditable deterministic order over a recursive graph.
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
ZiStatus zi_service_resolve_start_order(const ZiServiceManifest* manifests,
                                        size_t manifest_count,
                                        size_t* order_storage,
                                        size_t order_capacity,
                                        size_t* out_order_count) {
  if (manifests == NULL || order_storage == NULL || out_order_count == NULL ||
      manifest_count == 0 || manifest_count > ZI_SERVICE_MAX_MANIFESTS ||
      order_capacity < manifest_count) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_order_count = 0;
  for (size_t index = 0; index < manifest_count; ++index) {
    if (ZiFailed(zi_service_manifest_validate(&manifests[index]))) {
      return ZI_STATUS_INVALID_SERVICE_MANIFEST;
    }
    for (size_t previous = 0; previous < index; ++previous) {
      if (compare_views(manifests[index].name, manifests[previous].name) == 0) {
        return ZI_STATUS_ALREADY_EXISTS;
      }
    }
    for (size_t dependency = 0; dependency < manifests[index].dependency_count; ++dependency) {
      size_t dependency_index = 0;
      ZiStatus status = find_manifest(manifests,
                                      manifest_count,
                                      manifests[index].dependencies[dependency].service_name,
                                      &dependency_index);
      if (ZiFailed(status)) {
        return status;
      }
    }
  }

  bool emitted[ZI_SERVICE_MAX_MANIFESTS] = {false};
  while (*out_order_count < manifest_count) {
    size_t current_candidate_index = SIZE_MAX;
    for (size_t manifest_index = 0; manifest_index < manifest_count; ++manifest_index) {
      if (emitted[manifest_index] ||
          !dependencies_are_emitted(manifests, manifest_count, emitted, manifest_index)) {
        continue;
      }
      if (current_candidate_index == SIZE_MAX ||
          candidate_precedes(manifests, manifest_index, current_candidate_index)) {
        current_candidate_index = manifest_index;
      }
    }
    if (current_candidate_index == SIZE_MAX) {
      return ZI_STATUS_SERVICE_DEPENDENCY_CYCLE;
    }
    emitted[current_candidate_index] = true;
    order_storage[*out_order_count] = current_candidate_index;
    ++*out_order_count;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_service_supervise(const ZiServiceManifest* manifest,
                              ZiServiceLaunchRoutine launch,
                              void* context,
                              ZiServiceSupervisionResult* out_result) {
  if (launch == NULL || out_result == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_service_manifest_validate(manifest);
  if (ZiFailed(status)) {
    return status;
  }

  ZiServiceSupervisionResult result = {
      sizeof(ZiServiceSupervisionResult),
      ZI_SERVICE_SUPERVISION_RESULT_VERSION,
      0,
      0,
      ZI_STATUS_NOT_IMPLEMENTED,
      ZI_STATUS_PROCESS_TERMINATED,
  };
  for (;;) {
    int32_t exit_code = ZI_STATUS_PROCESS_TERMINATED;
    status = launch(context, manifest, result.attempt_count, &exit_code);
    ++result.attempt_count;
    result.last_launch_status = status;
    result.last_exit_code = exit_code;

    bool failed =
        (bool)(status < ZI_STATUS_SUCCESS || (status != ZI_STATUS_PENDING && exit_code != 0));
    bool restart = (bool)(manifest->restart_policy == ZI_SERVICE_RESTART_ALWAYS ||
                          (manifest->restart_policy == ZI_SERVICE_RESTART_ON_FAILURE && failed));
    if (!restart) {
      *out_result = result;
      if (ZiFailed(status)) {
        return status;
      }
      if (failed) {
        return ZI_STATUS_PROCESS_TERMINATED;
      }
      return ZI_STATUS_SUCCESS;
    }
    if (result.restart_count >= manifest->maximum_restarts) {
      *out_result = result;
      return ZI_STATUS_SERVICE_RESTART_LIMIT;
    }
    ++result.restart_count;
  }
}

static bool view_equals(ZiStringView view, const char* expected, size_t expected_size) {
  return (bool)(view.size == expected_size &&
                zi_memory_compare(view.data, expected, expected_size) == 0);
}

static int compare_views(ZiStringView left, ZiStringView right) {
  size_t common_size = left.size < right.size ? left.size : right.size;
  int comparison = zi_memory_compare(left.data, right.data, common_size);
  if (comparison != 0) {
    return comparison;
  }
  if (left.size < right.size) {
    return -1;
  }
  if (left.size > right.size) {
    return 1;
  }
  return 0;
}

static ZiStatus validate_service_name(ZiStringView name) {
  if (name.data == NULL || name.size == 0 || name.size > ZI_SERVICE_MAX_NAME_BYTES ||
      ZiFailed(zi_utf8_validate(name.data, name.size))) {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  for (size_t index = 0; index < name.size; ++index) {
    unsigned char byte = (unsigned char)name.data[index];
    if (byte <= 0x20u || byte == 0x7fu || byte == '\\' || byte == '/' || byte == ':' ||
        byte == ',' || byte == '=' || byte == '@') {
      return ZI_STATUS_INVALID_SERVICE_MANIFEST;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_executable_path(ZiStringView path) {
  if (path.data == NULL || path.size == 0 || path.size > ZI_SERVICE_MAX_PATH_BYTES) {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  ZiStringView components[32] = {0};
  ZiParsedPath parsed = {0};
  ZiStatus status = zi_path_parse_absolute(path.data,
                                           path.size,
                                           components,
                                           sizeof components / sizeof components[0],
                                           &parsed);
  if (ZiSucceeded(status) && parsed.drive_letter == 'C' && parsed.component_count != 0) {
    return ZI_STATUS_SUCCESS;
  }
  return ZI_STATUS_INVALID_SERVICE_MANIFEST;
}

static ZiStatus validate_identity(ZiStringView identity) {
  if (identity.data == NULL || identity.size < sizeof "NID:X" - 1u ||
      identity.size > ZI_SERVICE_MAX_IDENTITY_BYTES ||
      zi_memory_compare(identity.data, "NID:", sizeof "NID:" - 1u) != 0 ||
      ZiFailed(zi_utf8_validate(identity.data, identity.size))) {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  for (size_t index = 4; index < identity.size; ++index) {
    unsigned char byte = (unsigned char)identity.data[index];
    if (byte <= 0x20u || byte == 0x7fu || byte == '\\' || byte == '/' || byte == ',' ||
        byte == '=') {
      return ZI_STATUS_INVALID_SERVICE_MANIFEST;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus parse_uint32(ZiStringView value, uint32_t maximum, uint32_t* out_value) {
  if (value.data == NULL || value.size == 0 || out_value == NULL) {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  uint32_t result = 0;
  for (size_t index = 0; index < value.size; ++index) {
    unsigned char digit = (unsigned char)value.data[index];
    if (digit < '0' || digit > '9') {
      return ZI_STATUS_INVALID_SERVICE_MANIFEST;
    }
    uint32_t value_digit = digit - '0';
    if (value_digit > maximum || result > (maximum - value_digit) / 10u) {
      return ZI_STATUS_INVALID_SERVICE_MANIFEST;
    }
    result = (result * 10u) + value_digit;
  }
  *out_value = result;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus parse_start_mode(ZiStringView value, uint32_t* out_mode) {
  if (view_equals(value, "Boot", 4)) {
    *out_mode = ZI_SERVICE_BOOT;
  } else if (view_equals(value, "System", 6)) {
    *out_mode = ZI_SERVICE_SYSTEM;
  } else if (view_equals(value, "Automatic", 9)) {
    *out_mode = ZI_SERVICE_AUTOMATIC;
  } else if (view_equals(value, "Demand", 6)) {
    *out_mode = ZI_SERVICE_DEMAND;
  } else if (view_equals(value, "Disabled", 8)) {
    *out_mode = ZI_SERVICE_DISABLED;
  } else {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus parse_restart_policy(ZiStringView value, uint32_t* out_policy) {
  if (view_equals(value, "Never", 5)) {
    *out_policy = ZI_SERVICE_RESTART_NEVER;
  } else if (view_equals(value, "OnFailure", 9)) {
    *out_policy = ZI_SERVICE_RESTART_ON_FAILURE;
  } else if (view_equals(value, "Always", 6)) {
    *out_policy = ZI_SERVICE_RESTART_ALWAYS;
  } else {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus parse_service_kind(ZiStringView value, uint32_t* out_kind) {
  if (view_equals(value, "System", 6)) {
    *out_kind = ZI_SERVICE_KIND_SYSTEM;
  } else if (view_equals(value, "User", 4)) {
    *out_kind = ZI_SERVICE_KIND_USER;
  } else {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus parse_token_policy(ZiStringView value, uint32_t* out_policy) {
  if (view_equals(value, "System", 6)) {
    *out_policy = ZI_SERVICE_TOKEN_SYSTEM;
  } else if (view_equals(value, "Service", 7)) {
    *out_policy = ZI_SERVICE_TOKEN_SERVICE;
  } else if (view_equals(value, "SessionBootstrap", 16)) {
    *out_policy = ZI_SERVICE_TOKEN_SESSION_BOOTSTRAP;
  } else {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus parse_implementation_status(ZiStringView value, uint32_t* out_status) {
  if (view_equals(value, "Scaffolded", 10)) {
    *out_status = ZI_SERVICE_IMPLEMENTATION_SCAFFOLDED;
  } else if (view_equals(value, "Implemented", 11)) {
    *out_status = ZI_SERVICE_IMPLEMENTATION_IMPLEMENTED;
  } else if (view_equals(value, "Future", 6)) {
    *out_status = ZI_SERVICE_IMPLEMENTATION_FUTURE;
  } else {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus parse_dependencies(ZiStringView value,
                                   ZiServiceDependency* dependency_storage,
                                   size_t dependency_capacity,
                                   size_t* out_dependency_count) {
  *out_dependency_count = 0;
  if (value.size == 0) {
    return ZI_STATUS_SUCCESS;
  }
  size_t offset = 0;
  while (offset < value.size) {
    size_t end = offset;
    while (end < value.size && value.data[end] != ',') {
      ++end;
    }
    ZiStringView name = {value.data + offset, end - offset};
    if (*out_dependency_count >= dependency_capacity || ZiFailed(validate_service_name(name))) {
      return ZI_STATUS_INVALID_SERVICE_MANIFEST;
    }
    for (size_t previous = 0; previous < *out_dependency_count; ++previous) {
      if (compare_views(dependency_storage[previous].service_name, name) == 0) {
        return ZI_STATUS_INVALID_SERVICE_MANIFEST;
      }
    }
    dependency_storage[*out_dependency_count] = (ZiServiceDependency){name, 0};
    ++*out_dependency_count;
    if (end == value.size) {
      break;
    }
    offset = end + 1u;
    if (offset == value.size) {
      return ZI_STATUS_INVALID_SERVICE_MANIFEST;
    }
  }
  return ZI_STATUS_SUCCESS;
}

// Field names are deliberately exact-case; accepting aliases would weaken manifest review.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static ZiStatus assign_manifest_field(ZiStringView key,
                                      ZiStringView value,
                                      ZiServiceDependency* dependency_storage,
                                      size_t dependency_capacity,
                                      uint32_t* fields,
                                      ZiServiceManifest* manifest) {
  uint32_t field = 0;
  ZiStatus status = ZI_STATUS_SUCCESS;
  if (view_equals(key, "FormatVersion", 13)) {
    field = MANIFEST_FIELD_FORMAT_VERSION;
    status = parse_uint32(value, ZI_SERVICE_MANIFEST_FORMAT_VERSION, &manifest->format_version);
    if (ZiSucceeded(status) && manifest->format_version != ZI_SERVICE_MANIFEST_FORMAT_VERSION) {
      status = ZI_STATUS_INVALID_SERVICE_MANIFEST;
    }
  } else if (view_equals(key, "Name", 4)) {
    field = MANIFEST_FIELD_NAME;
    manifest->name = value;
    status = validate_service_name(value);
  } else if (view_equals(key, "Executable", 10)) {
    field = MANIFEST_FIELD_EXECUTABLE;
    manifest->executable_path = value;
    status = validate_executable_path(value);
  } else if (view_equals(key, "ServiceKind", 11)) {
    field = MANIFEST_FIELD_SERVICE_KIND;
    status = parse_service_kind(value, &manifest->service_kind);
  } else if (view_equals(key, "Identity", 8)) {
    field = MANIFEST_FIELD_IDENTITY;
    manifest->identity = value;
    status = validate_identity(value);
  } else if (view_equals(key, "StartMode", 9)) {
    field = MANIFEST_FIELD_START_MODE;
    status = parse_start_mode(value, &manifest->start_mode);
  } else if (view_equals(key, "StartOrder", 10)) {
    field = MANIFEST_FIELD_START_ORDER;
    status = parse_uint32(value, UINT16_MAX, &manifest->start_order);
  } else if (view_equals(key, "Dependencies", 12)) {
    field = MANIFEST_FIELD_DEPENDENCIES;
    status = parse_dependencies(value,
                                dependency_storage,
                                dependency_capacity,
                                &manifest->dependency_count);
  } else if (view_equals(key, "RestartPolicy", 13)) {
    field = MANIFEST_FIELD_RESTART_POLICY;
    status = parse_restart_policy(value, &manifest->restart_policy);
  } else if (view_equals(key, "TokenPolicy", 11)) {
    field = MANIFEST_FIELD_TOKEN_POLICY;
    status = parse_token_policy(value, &manifest->token_policy);
  } else if (view_equals(key, "MaximumRestarts", 15)) {
    field = MANIFEST_FIELD_MAXIMUM_RESTARTS;
    status = parse_uint32(value, ZI_SERVICE_MAX_RESTARTS, &manifest->maximum_restarts);
  } else if (view_equals(key, "Permissions", 11)) {
    field = MANIFEST_FIELD_PERMISSIONS;
    manifest->permissions = value;
  } else if (view_equals(key, "Log", 3)) {
    field = MANIFEST_FIELD_LOG;
    manifest->log_path = value;
    if (value.size != 0) {
      status = validate_executable_path(value);
    }
  } else if (view_equals(key, "Status", 6)) {
    field = MANIFEST_FIELD_STATUS;
    status = parse_implementation_status(value, &manifest->implementation_status);
  } else {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  if (field == 0 || (*fields & field) != 0 || ZiFailed(status)) {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  *fields |= field;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_manifest_dependencies(const ZiServiceManifest* manifest) {
  for (size_t index = 0; index < manifest->dependency_count; ++index) {
    ZiStringView dependency = manifest->dependencies[index].service_name;
    if (manifest->dependencies[index].minimum_version != 0 ||
        ZiFailed(validate_service_name(dependency)) ||
        compare_views(manifest->name, dependency) == 0) {
      return ZI_STATUS_INVALID_SERVICE_MANIFEST;
    }
    for (size_t previous = 0; previous < index; ++previous) {
      if (compare_views(manifest->dependencies[previous].service_name, dependency) == 0) {
        return ZI_STATUS_INVALID_SERVICE_MANIFEST;
      }
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus find_manifest(const ZiServiceManifest* manifests,
                              size_t manifest_count,
                              ZiStringView name,
                              size_t* out_index) {
  for (size_t index = 0; index < manifest_count; ++index) {
    if (compare_views(manifests[index].name, name) == 0) {
      *out_index = index;
      return ZI_STATUS_SUCCESS;
    }
  }
  return ZI_STATUS_NOT_FOUND;
}

static bool dependencies_are_emitted(const ZiServiceManifest* manifests,
                                     size_t manifest_count,
                                     const bool* emitted,
                                     size_t manifest_index) {
  const ZiServiceManifest* manifest = &manifests[manifest_index];
  for (size_t dependency = 0; dependency < manifest->dependency_count; ++dependency) {
    size_t dependency_index = 0;
    if (ZiFailed(find_manifest(manifests,
                               manifest_count,
                               manifest->dependencies[dependency].service_name,
                               &dependency_index)) ||
        !emitted[dependency_index]) {
      return false;
    }
  }
  return true;
}

static bool candidate_precedes(const ZiServiceManifest* manifests,
                               size_t manifest_index,
                               size_t current_candidate_index) {
  if (manifests[manifest_index].start_order != manifests[current_candidate_index].start_order) {
    return manifests[manifest_index].start_order < manifests[current_candidate_index].start_order;
  }
  return compare_views(manifests[manifest_index].name, manifests[current_candidate_index].name) < 0;
}
