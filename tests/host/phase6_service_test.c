// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "phase6_tests.h"
#include "zi/service.h"
#include "zizium/status.h"

#define PHASE6_ASSERT(expression)                                                                  \
  do {                                                                                             \
    ++assertions;                                                                                  \
    if (!(expression)) {                                                                           \
      (void)fprintf_s(stderr, "%s:%d: assertion failed: %s\n", __FILE__, __LINE__, #expression);   \
      *out_assertion_count = assertions;                                                           \
      return false;                                                                                \
    }                                                                                              \
  } while (false)

static const char k_service_host[] = "# Core service supervisor\r\n"
                                     "FormatVersion=1\r\n"
                                     "Name=ServiceHost\r\n"
                                     "Executable=C:\\Zizium\\System\\ServiceHost.exe\r\n"
                                     "ServiceKind=System\r\n"
                                     "Identity=NID:SYSTEM\r\n"
                                     "StartMode=Boot\r\n"
                                     "StartOrder=1\r\n"
                                     "Dependencies=\r\n"
                                     "RestartPolicy=Always\r\n"
                                     "TokenPolicy=System\r\n"
                                     "MaximumRestarts=2\r\n"
                                     "Permissions=ServiceManagement\r\n"
                                     "Log=C:\\Zizium\\Logs\\System\\ServiceHost.log\r\n"
                                     "Status=Implemented\r\n";

static const char k_security_host[] =
    "FormatVersion=1\nName=SecurityHost\nExecutable=C:\\Zizium\\System\\SecurityHost.exe\n"
    "ServiceKind=System\nIdentity=NID:SERVICE:SecurityHost\nStartMode=Boot\nStartOrder=2\n"
    "Dependencies=ServiceHost\nRestartPolicy=Always\nTokenPolicy=Service\n"
    "MaximumRestarts=2\nStatus=Scaffolded\n";

static const char k_log_host[] =
    "FormatVersion=1\nName=LogHost\nExecutable=C:\\Zizium\\System\\LogHost.exe\n"
    "ServiceKind=System\nIdentity=NID:SERVICE:LogHost\nStartMode=Boot\nStartOrder=3\n"
    "Dependencies=ServiceHost\nRestartPolicy=OnFailure\nTokenPolicy=Service\n"
    "MaximumRestarts=1\nStatus=Scaffolded\n";

static const char k_session_host[] =
    "FormatVersion=1\nName=SessionHost\nExecutable=C:\\Zizium\\System\\SessionHost.exe\n"
    "ServiceKind=System\nIdentity=NID:SYSTEM\nStartMode=System\nStartOrder=10\n"
    "Dependencies=SecurityHost,LogHost\nRestartPolicy=OnFailure\n"
    "TokenPolicy=SessionBootstrap\nMaximumRestarts=1\nStatus=Implemented\n";

static const char k_cycle_a[] =
    "FormatVersion=1\nName=CycleA\nExecutable=C:\\Zizium\\System\\CycleA.exe\n"
    "ServiceKind=System\nIdentity=NID:SERVICE:CycleA\nStartMode=System\nStartOrder=1\n"
    "Dependencies=CycleB\nRestartPolicy=Never\nTokenPolicy=Service\nMaximumRestarts=0\n";

static const char k_cycle_b[] =
    "FormatVersion=1\nName=CycleB\nExecutable=C:\\Zizium\\System\\CycleB.exe\n"
    "ServiceKind=System\nIdentity=NID:SERVICE:CycleB\nStartMode=System\nStartOrder=2\n"
    "Dependencies=CycleA\nRestartPolicy=Never\nTokenPolicy=Service\nMaximumRestarts=0\n";

static bool parse_manifest(const char* data,
                           size_t data_size,
                           ZiServiceDependency* dependencies,
                           size_t dependency_capacity,
                           ZiServiceManifest* out_manifest);

typedef struct ServiceLaunchFixture {
  uint32_t failures_before_success;
  uint32_t call_count;
  ZiStatus failure_status;
  int32_t success_exit_code;
} ServiceLaunchFixture;

static ZiStatus service_launch_fixture(void* context,
                                       const ZiServiceManifest* manifest,
                                       uint32_t attempt,
                                       int32_t* out_exit_code);

// Hostile parser and graph cases are kept together so the service boundary is auditable.
// NOLINTNEXTLINE(readability-function-cognitive-complexity, readability-function-size)
bool phase6_service_manifest_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  size_t assertions = 0;
  *out_assertion_count = 0;

  ZiServiceDependency dependency_storage[4][ZI_SERVICE_MAX_DEPENDENCIES] = {0};
  ZiServiceManifest manifests[4] = {0};
  PHASE6_ASSERT(parse_manifest(k_service_host,
                               sizeof k_service_host - 1u,
                               dependency_storage[0],
                               ZI_SERVICE_MAX_DEPENDENCIES,
                               &manifests[0]));
  PHASE6_ASSERT(manifests[0].format_version == 1 && manifests[0].dependency_count == 0 &&
                manifests[0].restart_policy == ZI_SERVICE_RESTART_ALWAYS &&
                manifests[0].token_policy == ZI_SERVICE_TOKEN_SYSTEM &&
                manifests[0].implementation_status == ZI_SERVICE_IMPLEMENTATION_IMPLEMENTED);
  PHASE6_ASSERT(parse_manifest(k_security_host,
                               sizeof k_security_host - 1u,
                               dependency_storage[1],
                               ZI_SERVICE_MAX_DEPENDENCIES,
                               &manifests[1]));
  PHASE6_ASSERT(parse_manifest(k_log_host,
                               sizeof k_log_host - 1u,
                               dependency_storage[2],
                               ZI_SERVICE_MAX_DEPENDENCIES,
                               &manifests[2]));
  PHASE6_ASSERT(parse_manifest(k_session_host,
                               sizeof k_session_host - 1u,
                               dependency_storage[3],
                               ZI_SERVICE_MAX_DEPENDENCIES,
                               &manifests[3]));
  PHASE6_ASSERT(manifests[3].dependency_count == 2 &&
                manifests[3].token_policy == ZI_SERVICE_TOKEN_SESSION_BOOTSTRAP);

  size_t order[4] = {0};
  size_t order_count = 0;
  PHASE6_ASSERT(ZiSucceeded(zi_service_resolve_start_order(manifests,
                                                           4,
                                                           order,
                                                           sizeof order / sizeof order[0],
                                                           &order_count)));
  PHASE6_ASSERT(order_count == 4 && order[0] == 0 && order[1] == 1 && order[2] == 2 &&
                order[3] == 3);
  PHASE6_ASSERT(zi_service_resolve_start_order(manifests, 4, order, 3, &order_count) ==
                ZI_STATUS_INVALID_ARGUMENT);

  ZiServiceManifest duplicate_manifests[2] = {manifests[0], manifests[0]};
  PHASE6_ASSERT(zi_service_resolve_start_order(duplicate_manifests,
                                               2,
                                               order,
                                               sizeof order / sizeof order[0],
                                               &order_count) == ZI_STATUS_ALREADY_EXISTS);
  ZiServiceDependency wrong_case_dependency = {{"servicehost", 11}, 0};
  ZiServiceManifest wrong_case_manifest = manifests[1];
  wrong_case_manifest.dependencies = &wrong_case_dependency;
  ZiServiceManifest wrong_case_set[2] = {manifests[0], wrong_case_manifest};
  PHASE6_ASSERT(zi_service_resolve_start_order(wrong_case_set,
                                               2,
                                               order,
                                               sizeof order / sizeof order[0],
                                               &order_count) == ZI_STATUS_NOT_FOUND);

  ZiServiceDependency cycle_dependencies[2][ZI_SERVICE_MAX_DEPENDENCIES] = {0};
  ZiServiceManifest cycle[2] = {0};
  PHASE6_ASSERT(parse_manifest(k_cycle_a,
                               sizeof k_cycle_a - 1u,
                               cycle_dependencies[0],
                               ZI_SERVICE_MAX_DEPENDENCIES,
                               &cycle[0]));
  PHASE6_ASSERT(parse_manifest(k_cycle_b,
                               sizeof k_cycle_b - 1u,
                               cycle_dependencies[1],
                               ZI_SERVICE_MAX_DEPENDENCIES,
                               &cycle[1]));
  PHASE6_ASSERT(zi_service_resolve_start_order(cycle,
                                               2,
                                               order,
                                               sizeof order / sizeof order[0],
                                               &order_count) == ZI_STATUS_SERVICE_DEPENDENCY_CYCLE);

  const char duplicate_field[] =
      "FormatVersion=1\nFormatVersion=1\nName=Duplicate\nExecutable=C:\\Duplicate.exe\n"
      "ServiceKind=System\nIdentity=NID:SERVICE:Duplicate\nStartMode=System\nStartOrder=1\n"
      "Dependencies=\nRestartPolicy=Never\nTokenPolicy=Service\nMaximumRestarts=0\n";
  ZiServiceDependency hostile_dependencies[ZI_SERVICE_MAX_DEPENDENCIES] = {0};
  ZiServiceManifest hostile = {0};
  PHASE6_ASSERT(zi_service_manifest_parse(duplicate_field,
                                          sizeof duplicate_field - 1u,
                                          hostile_dependencies,
                                          ZI_SERVICE_MAX_DEPENDENCIES,
                                          &hostile) == ZI_STATUS_INVALID_SERVICE_MANIFEST);
  const char duplicate_dependency[] =
      "FormatVersion=1\nName=DuplicateDependency\nExecutable=C:\\DuplicateDependency.exe\n"
      "ServiceKind=System\nIdentity=NID:SERVICE:DuplicateDependency\nStartMode=System\n"
      "StartOrder=1\nDependencies=ServiceHost,ServiceHost\nRestartPolicy=Never\n"
      "TokenPolicy=Service\nMaximumRestarts=0\n";
  PHASE6_ASSERT(zi_service_manifest_parse(duplicate_dependency,
                                          sizeof duplicate_dependency - 1u,
                                          hostile_dependencies,
                                          ZI_SERVICE_MAX_DEPENDENCIES,
                                          &hostile) == ZI_STATUS_INVALID_SERVICE_MANIFEST);
  PHASE6_ASSERT(zi_service_manifest_parse(k_session_host,
                                          sizeof k_session_host - 1u,
                                          hostile_dependencies,
                                          1,
                                          &hostile) == ZI_STATUS_INVALID_SERVICE_MANIFEST);
  const char unknown_field[] =
      "FormatVersion=1\nName=Unknown\nExecutable=C:\\Unknown.exe\nServiceKind=System\n"
      "Identity=NID:SERVICE:Unknown\nStartMode=System\nStartOrder=1\nDependencies=\n"
      "RestartPolicy=Never\nTokenPolicy=Service\nMaximumRestarts=0\nBehaviour=Unknown\n";
  PHASE6_ASSERT(zi_service_manifest_parse(unknown_field,
                                          sizeof unknown_field - 1u,
                                          hostile_dependencies,
                                          ZI_SERVICE_MAX_DEPENDENCIES,
                                          &hostile) == ZI_STATUS_INVALID_SERVICE_MANIFEST);
  const char invalid_restart[] =
      "FormatVersion=1\nName=InvalidRestart\nExecutable=C:\\InvalidRestart.exe\n"
      "ServiceKind=System\nIdentity=NID:SERVICE:InvalidRestart\nStartMode=System\n"
      "StartOrder=1\nDependencies=\nRestartPolicy=Never\nTokenPolicy=Service\n"
      "MaximumRestarts=1\n";
  PHASE6_ASSERT(zi_service_manifest_parse(invalid_restart,
                                          sizeof invalid_restart - 1u,
                                          hostile_dependencies,
                                          ZI_SERVICE_MAX_DEPENDENCIES,
                                          &hostile) == ZI_STATUS_INVALID_SERVICE_MANIFEST);
  const unsigned char invalid_utf8[] = {0xc0u, 0xafu};
  PHASE6_ASSERT(zi_service_manifest_parse((const char*)invalid_utf8,
                                          sizeof invalid_utf8,
                                          hostile_dependencies,
                                          ZI_SERVICE_MAX_DEPENDENCIES,
                                          &hostile) == ZI_STATUS_INVALID_SERVICE_MANIFEST);
  const char embedded_null[] =
      {'F', 'o', 'r', 'm', 'a', 't', '\0', 'V', 'e', 'r', 's', 'i', 'o', 'n'};
  PHASE6_ASSERT(zi_service_manifest_parse(embedded_null,
                                          sizeof embedded_null,
                                          hostile_dependencies,
                                          ZI_SERVICE_MAX_DEPENDENCIES,
                                          &hostile) == ZI_STATUS_INVALID_SERVICE_MANIFEST);
  const char bare_carriage_return[] = "FormatVersion=1\rName=Invalid";
  PHASE6_ASSERT(zi_service_manifest_parse(bare_carriage_return,
                                          sizeof bare_carriage_return - 1u,
                                          hostile_dependencies,
                                          ZI_SERVICE_MAX_DEPENDENCIES,
                                          &hostile) == ZI_STATUS_INVALID_SERVICE_MANIFEST);
  PHASE6_ASSERT(zi_service_manifest_parse(k_service_host,
                                          ZI_SERVICE_MAX_MANIFEST_BYTES + 1u,
                                          hostile_dependencies,
                                          ZI_SERVICE_MAX_DEPENDENCIES,
                                          &hostile) == ZI_STATUS_INVALID_ARGUMENT);

  ServiceLaunchFixture launch_fixture = {1, 0, ZI_STATUS_DEVICE_ERROR, 0};
  ZiServiceSupervisionResult supervision = {0};
  PHASE6_ASSERT(ZiSucceeded(
      zi_service_supervise(&manifests[3], service_launch_fixture, &launch_fixture, &supervision)));
  PHASE6_ASSERT(launch_fixture.call_count == 2 && supervision.attempt_count == 2 &&
                supervision.restart_count == 1 && supervision.last_launch_status == 0 &&
                supervision.last_exit_code == 0);

  launch_fixture = (ServiceLaunchFixture){0, 0, ZI_STATUS_DEVICE_ERROR, 0};
  PHASE6_ASSERT(
      zi_service_supervise(&manifests[0], service_launch_fixture, &launch_fixture, &supervision) ==
      ZI_STATUS_SERVICE_RESTART_LIMIT);
  PHASE6_ASSERT(launch_fixture.call_count == 3 && supervision.attempt_count == 3 &&
                supervision.restart_count == 2);

  launch_fixture = (ServiceLaunchFixture){3, 0, ZI_STATUS_DEVICE_ERROR, 0};
  PHASE6_ASSERT(
      zi_service_supervise(&cycle[0], service_launch_fixture, &launch_fixture, &supervision) ==
      ZI_STATUS_DEVICE_ERROR);
  PHASE6_ASSERT(launch_fixture.call_count == 1 && supervision.attempt_count == 1 &&
                supervision.restart_count == 0);
  PHASE6_ASSERT(zi_service_supervise(&manifests[3], NULL, NULL, &supervision) ==
                ZI_STATUS_INVALID_ARGUMENT);

  *out_assertion_count = assertions;
  return true;
}

static bool parse_manifest(const char* data,
                           size_t data_size,
                           ZiServiceDependency* dependencies,
                           size_t dependency_capacity,
                           ZiServiceManifest* out_manifest) {
  return ZiSucceeded(
      zi_service_manifest_parse(data, data_size, dependencies, dependency_capacity, out_manifest));
}

static ZiStatus service_launch_fixture(void* context,
                                       const ZiServiceManifest* manifest,
                                       uint32_t attempt,
                                       int32_t* out_exit_code) {
  if (context == NULL || manifest == NULL || out_exit_code == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ServiceLaunchFixture* fixture = context;
  ++fixture->call_count;
  if (attempt < fixture->failures_before_success) {
    *out_exit_code = ZI_STATUS_PROCESS_TERMINATED;
    return fixture->failure_status;
  }
  *out_exit_code = fixture->success_exit_code;
  return ZI_STATUS_SUCCESS;
}
