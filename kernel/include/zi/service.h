// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_SERVICE_MANIFEST_VERSION 1u
#define ZI_SERVICE_MANIFEST_FORMAT_VERSION 1u
#define ZI_SERVICE_MAX_MANIFEST_BYTES 4096u
#define ZI_SERVICE_MAX_NAME_BYTES 96u
#define ZI_SERVICE_MAX_PATH_BYTES 512u
#define ZI_SERVICE_MAX_IDENTITY_BYTES 128u
#define ZI_SERVICE_MAX_DEPENDENCIES 16u
#define ZI_SERVICE_MAX_MANIFESTS 32u
#define ZI_SERVICE_MAX_RESTARTS 8u
#define ZI_SERVICE_SUPERVISION_RESULT_VERSION 1u

enum ZiServiceStartMode {
  ZI_SERVICE_BOOT = 0,
  ZI_SERVICE_SYSTEM = 1,
  ZI_SERVICE_AUTOMATIC = 2,
  ZI_SERVICE_DEMAND = 3,
  ZI_SERVICE_DISABLED = 4,
};

enum ZiServiceRestartPolicy {
  ZI_SERVICE_RESTART_NEVER = 0,
  ZI_SERVICE_RESTART_ON_FAILURE = 1,
  ZI_SERVICE_RESTART_ALWAYS = 2,
};

enum ZiServiceKind {
  ZI_SERVICE_KIND_SYSTEM = 1,
  ZI_SERVICE_KIND_USER = 2,
};

enum ZiServiceTokenPolicy {
  ZI_SERVICE_TOKEN_SYSTEM = 1,
  ZI_SERVICE_TOKEN_SERVICE = 2,
  ZI_SERVICE_TOKEN_SESSION_BOOTSTRAP = 3,
};

enum ZiServiceImplementationStatus {
  ZI_SERVICE_IMPLEMENTATION_UNSPECIFIED = 0,
  ZI_SERVICE_IMPLEMENTATION_SCAFFOLDED = 1,
  ZI_SERVICE_IMPLEMENTATION_IMPLEMENTED = 2,
  ZI_SERVICE_IMPLEMENTATION_FUTURE = 3,
};

typedef struct ZiServiceDependency {
  ZiStringView service_name;
  uint32_t minimum_version;
} ZiServiceDependency;

typedef struct ZiServiceManifest {
  uint32_t struct_size;
  uint32_t version;
  uint32_t format_version;
  ZiStringView name;
  ZiStringView executable_path;
  ZiStringView identity;
  ZiStringView permissions;
  ZiStringView log_path;
  const ZiServiceDependency* dependencies;
  size_t dependency_count;
  uint32_t service_kind;
  uint32_t start_mode;
  uint32_t start_order;
  uint32_t restart_policy;
  uint32_t token_policy;
  uint32_t maximum_restarts;
  uint32_t implementation_status;
  uint32_t flags;
} ZiServiceManifest;

typedef ZiStatus (*ZiServiceLaunchRoutine)(void* context,
                                           const ZiServiceManifest* manifest,
                                           uint32_t attempt,
                                           int32_t* out_exit_code);

typedef struct ZiServiceSupervisionResult {
  uint32_t struct_size;
  uint32_t version;
  uint32_t attempt_count;
  uint32_t restart_count;
  ZiStatus last_launch_status;
  int32_t last_exit_code;
} ZiServiceSupervisionResult;

ZiStatus zi_service_manifest_parse(const char* data,
                                   size_t data_size,
                                   ZiServiceDependency* dependency_storage,
                                   size_t dependency_capacity,
                                   ZiServiceManifest* out_manifest);
ZiStatus zi_service_manifest_validate(const ZiServiceManifest* manifest);
ZiStatus zi_service_resolve_start_order(const ZiServiceManifest* manifests,
                                        size_t manifest_count,
                                        size_t* order_storage,
                                        size_t order_capacity,
                                        size_t* out_order_count);
ZiStatus zi_service_supervise(const ZiServiceManifest* manifest,
                              ZiServiceLaunchRoutine launch,
                              void* context,
                              ZiServiceSupervisionResult* out_result);
