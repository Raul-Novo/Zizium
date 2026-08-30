// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/system_bootstrap.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/byte_order.h"
#include "zi/handle.h"
#include "zi/ipc.h"
#include "zi/kernel_pool.h"
#include "zi/log.h"
#include "zi/object.h"
#include "zi/path.h"
#include "zi/process_parameters.h"
#include "zi/security.h"
#include "zi/service.h"
#include "zi/user_image.h"
#include "zi/user_process.h"
#include "zi/zifs.h"
#include "zi/zifs_image_source.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_SYSTEM_IMAGE_FILE_LIMIT ((size_t)64u * (size_t)1024u)
#define ZI_SYSTEM_IMAGE_TOTAL_LIMIT ((size_t)128u * (size_t)1024u)

typedef struct ZiServiceLaunchContext {
  ZiSystemBootstrap* bootstrap;
  bool failure_probe;
} ZiServiceLaunchContext;

static const ZiStringView k_system_environment[] = {
    {"SystemRoot=C:\\Zizium", sizeof "SystemRoot=C:\\Zizium" - 1u},
    {"ReleaseChannel=Preview", sizeof "ReleaseChannel=Preview" - 1u},
};
static const ZiFsImageSourceRequest k_core_library_requests[] = {
    {{"zx.dll", sizeof "zx.dll" - 1u},
     {"C:\\Zizium\\System21\\Libraries\\zx.dll",
      sizeof "C:\\Zizium\\System21\\Libraries\\zx.dll" - 1u}},
    {{"zicrt.dll", sizeof "zicrt.dll" - 1u},
     {"C:\\Zizium\\System21\\Libraries\\zicrt.dll",
      sizeof "C:\\Zizium\\System21\\Libraries\\zicrt.dll" - 1u}},
    {{"zia.dll", sizeof "zia.dll" - 1u},
     {"C:\\Zizium\\System21\\Libraries\\zia.dll",
      sizeof "C:\\Zizium\\System21\\Libraries\\zia.dll" - 1u}},
};
static const ZiStringView k_failure_probe_argument = {
    "--failure-probe",
    sizeof "--failure-probe" - 1u,
};
static const ZiStringView k_luma_path = {
    "C:\\Zizium\\Shell\\luma.exe",
    sizeof "C:\\Zizium\\Shell\\luma.exe" - 1u,
};

static ZiStatus image_source_allocate(void* context, size_t size, void** out_allocation);
static ZiStatus image_source_release(void* context, void* allocation);
static ZiStatus create_from_path(void* context,
                                 ZiUserProcessManager* manager,
                                 ZiUserProcess* parent,
                                 ZiStringView image_path,
                                 ZiUserProcess** out_process);
static ZiStatus create_zifs_process(ZiSystemBootstrap* bootstrap,
                                    ZiUserProcess* parent,
                                    ZiStringView image_path,
                                    const ZiProcessParameterInput* parameters,
                                    const ZiAccessToken* token,
                                    ZiUserProcess** out_process);
static ZiStatus service_launch(void* context,
                               const ZiServiceManifest* manifest,
                               uint32_t attempt,
                               int32_t* out_exit_code);
static ZiStatus supervise_core_services(ZiSystemBootstrap* bootstrap,
                                        const ZiServiceManifest* manifests,
                                        size_t manifest_count,
                                        const size_t* start_order,
                                        size_t start_order_count,
                                        size_t* out_session_index);
static ZiStatus verify_service_failure_policy(ZiSystemBootstrap* bootstrap,
                                              const ZiServiceManifest* manifest);
static ZiStatus run_user_session(ZiSystemBootstrap* bootstrap,
                                 const ZiServiceManifest* session_manifest);
static ZiStatus initialise_session_channels(ZiSystemBootstrap* bootstrap,
                                            ZiUserProcess* session,
                                            ZiUserProcess* luma,
                                            const ZiSecurityDescriptor* descriptor,
                                            ZiChannel* session_channel,
                                            ZiChannel* luma_channel,
                                            ZiHandle* out_session_handle,
                                            ZiHandle* out_luma_handle);
static ZiStatus release_session_resources(ZiSystemBootstrap* bootstrap,
                                          ZiUserProcess* session,
                                          ZiUserProcess* luma,
                                          ZiChannel* session_channel,
                                          ZiChannel* luma_channel);
static ZiAccessToken make_service_token(const ZiServiceManifest* manifest,
                                        ZiSecurityId* group_storage);
static uint32_t service_identity_value(ZiStringView name);
static const char* service_marker(ZiStringView name);
static bool view_equals(ZiStringView view, const char* text, size_t text_size);

ZiStatus zi_system_bootstrap_initialise(ZiSystemBootstrap* bootstrap,
                                        const ZiFsVolume* root_volume,
                                        void* block_buffer,
                                        size_t block_buffer_size,
                                        ZiUserProcessManager* process_manager) {
  if (bootstrap == NULL || root_volume == NULL || block_buffer == NULL ||
      block_buffer_size < ZI_FS_BLOCK_SIZE || process_manager == NULL ||
      process_manager->struct_size != sizeof *process_manager ||
      process_manager->version != ZI_USER_PROCESS_MANAGER_VERSION ||
      process_manager->process_count != 0 || process_manager->active_process != NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  *bootstrap = (ZiSystemBootstrap){
      sizeof(ZiSystemBootstrap),
      ZI_SYSTEM_BOOTSTRAP_VERSION,
      root_volume,
      block_buffer,
      block_buffer_size,
      process_manager,
      {
          sizeof(ZiFsImageSourceAllocator),
          ZI_FS_IMAGE_SOURCE_ALLOCATOR_VERSION,
          NULL,
          ZI_SYSTEM_IMAGE_FILE_LIMIT,
          ZI_SYSTEM_IMAGE_TOTAL_LIMIT,
          image_source_allocate,
          image_source_release,
      },
  };
  ZiUserProcessLaunchProvider provider = {
      sizeof(ZiUserProcessLaunchProvider),
      ZI_USER_PROCESS_LAUNCH_PROVIDER_VERSION,
      bootstrap,
      create_from_path,
  };
  return zi_user_process_manager_set_launch_provider(process_manager, &provider);
}

ZiStatus zi_system_bootstrap_run(ZiSystemBootstrap* bootstrap,
                                 const ZiServiceManifest* manifests,
                                 size_t manifest_count,
                                 const size_t* start_order,
                                 size_t start_order_count) {
  if (bootstrap == NULL || bootstrap->struct_size != sizeof *bootstrap ||
      bootstrap->version != ZI_SYSTEM_BOOTSTRAP_VERSION || manifests == NULL ||
      manifest_count == 0 || start_order == NULL || start_order_count != manifest_count) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  size_t session_index = SIZE_MAX;
  ZiStatus status = supervise_core_services(bootstrap,
                                            manifests,
                                            manifest_count,
                                            start_order,
                                            start_order_count,
                                            &session_index);
  if (ZiFailed(status)) {
    return status;
  }
  if (session_index == SIZE_MAX) {
    return ZI_STATUS_NOT_FOUND;
  }
  status = run_user_session(bootstrap, &manifests[session_index]);
  if (ZiSucceeded(status) && bootstrap->process_manager->process_count != 0) {
    return ZI_STATUS_RESOURCE_LEAK;
  }
  return status;
}

static ZiStatus image_source_allocate(void* context, size_t size, void** out_allocation) {
  (void)context;
  return zi_kernel_pool_allocate(size, out_allocation);
}

static ZiStatus image_source_release(void* context, void* allocation) {
  (void)context;
  return zi_kernel_pool_free(allocation);
}

static ZiStatus create_from_path(void* context,
                                 ZiUserProcessManager* manager,
                                 ZiUserProcess* parent,
                                 ZiStringView image_path,
                                 ZiUserProcess** out_process) {
  ZiSystemBootstrap* bootstrap = context;
  if (bootstrap == NULL || manager != bootstrap->process_manager || parent == NULL ||
      out_process == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStringView arguments[] = {image_path};
  ZiProcessParameterInput parameters = {
      sizeof(ZiProcessParameterInput),
      ZI_PROCESS_PARAMETER_INPUT_VERSION,
      image_path,
      image_path,
      arguments,
      sizeof arguments / sizeof arguments[0],
      k_system_environment,
      sizeof k_system_environment / sizeof k_system_environment[0],
  };
  return create_zifs_process(bootstrap,
                             parent,
                             image_path,
                             &parameters,
                             &parent->token,
                             out_process);
}

// Raw ZiFS image buffers are released after the PE mapper has copied every mapped image.
static ZiStatus create_zifs_process(ZiSystemBootstrap* bootstrap,
                                    ZiUserProcess* parent,
                                    ZiStringView image_path,
                                    const ZiProcessParameterInput* parameters,
                                    const ZiAccessToken* token,
                                    ZiUserProcess** out_process) {
  if (bootstrap == NULL || parameters == NULL || token == NULL || out_process == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_process = NULL;
  ZiStringView components[ZI_FS_IMAGE_PATH_COMPONENT_CAPACITY] = {0};
  ZiParsedPath parsed = {0};
  ZiStatus status = zi_path_parse_absolute(image_path.data,
                                           image_path.size,
                                           components,
                                           ZI_FS_IMAGE_PATH_COMPONENT_CAPACITY,
                                           &parsed);
  if (ZiFailed(status) || parsed.component_count == 0) {
    if (ZiFailed(status)) {
      return status;
    }
    return ZI_STATUS_INVALID_PATH;
  }
  ZiStringView module_name = parsed.components[parsed.component_count - 1u];

  ZiFsImageSourceSet libraries = {0};
  status = zi_zifs_image_source_set_load(bootstrap->root_volume,
                                         k_core_library_requests,
                                         sizeof k_core_library_requests /
                                             sizeof k_core_library_requests[0],
                                         &bootstrap->image_allocator,
                                         bootstrap->block_buffer,
                                         bootstrap->block_buffer_size,
                                         &libraries);
  if (ZiFailed(status)) {
    return status;
  }

  ZiFsImageSourceRequest request = {module_name, image_path};
  ZiFsImageSourceSet main_source = {0};
  status = zi_zifs_image_source_set_load(bootstrap->root_volume,
                                         &request,
                                         1,
                                         &bootstrap->image_allocator,
                                         bootstrap->block_buffer,
                                         bootstrap->block_buffer_size,
                                         &main_source);
  if (ZiSucceeded(status)) {
    ZiUserProcessLaunch launch = {
        sizeof(ZiUserProcessLaunch),
        ZI_USER_PROCESS_LAUNCH_VERSION,
        module_name,
        main_source.sources[0].file_data,
        main_source.sources[0].file_size,
        libraries.sources,
        libraries.source_count,
        parameters,
        token,
        ZI_USER_IMAGE_LOAD_FORCE_RELOCATION,
        0,
    };
    status = parent == NULL
                 ? zi_user_process_create(bootstrap->process_manager, &launch, out_process)
                 : zi_user_process_create_child(bootstrap->process_manager,
                                                parent,
                                                &launch,
                                                out_process);
  }

  if (main_source.version != 0) {
    ZiStatus release_status =
        zi_zifs_image_source_set_release(&bootstrap->image_allocator, &main_source);
    if (ZiSucceeded(status) && ZiFailed(release_status)) {
      status = ZI_STATUS_MEMORY_CORRUPTION;
    }
  }
  ZiStatus library_release_status =
      zi_zifs_image_source_set_release(&bootstrap->image_allocator, &libraries);
  if (ZiSucceeded(status) && ZiFailed(library_release_status)) {
    status = ZI_STATUS_MEMORY_CORRUPTION;
  }
  return status;
}

static ZiStatus service_launch(void* context,
                               const ZiServiceManifest* manifest,
                               uint32_t attempt,
                               int32_t* out_exit_code) {
  (void)attempt;
  ZiServiceLaunchContext* launch_context = context;
  if (launch_context == NULL || launch_context->bootstrap == NULL || manifest == NULL ||
      out_exit_code == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiSecurityId group = {0};
  ZiAccessToken token = make_service_token(manifest, &group);
  ZiStringView arguments[2] = {manifest->executable_path, {0}};
  size_t argument_count = 1;
  if (launch_context->failure_probe) {
    arguments[argument_count] = k_failure_probe_argument;
    ++argument_count;
  }
  ZiProcessParameterInput parameters = {
      sizeof(ZiProcessParameterInput),
      ZI_PROCESS_PARAMETER_INPUT_VERSION,
      manifest->executable_path,
      manifest->executable_path,
      arguments,
      argument_count,
      k_system_environment,
      sizeof k_system_environment / sizeof k_system_environment[0],
  };
  ZiUserProcess* process = NULL;
  ZiStatus status = create_zifs_process(launch_context->bootstrap,
                                        NULL,
                                        manifest->executable_path,
                                        &parameters,
                                        &token,
                                        &process);
  if (ZiSucceeded(status)) {
    status = zi_user_process_run(launch_context->bootstrap->process_manager, process, false);
  }
  if (ZiSucceeded(status) || status == ZI_STATUS_PROCESS_TERMINATED) {
    ZiStatus wait_status = zi_user_process_wait(process, 0, out_exit_code);
    if (ZiSucceeded(status) && ZiFailed(wait_status)) {
      status = wait_status;
    }
  }
  if (process != NULL && process->state != ZI_USER_PROCESS_RUNNING) {
    ZiStatus release_status =
        zi_user_process_release(launch_context->bootstrap->process_manager, process);
    if (ZiSucceeded(status) && ZiFailed(release_status)) {
      status = release_status;
    }
  }
  return status;
}

static ZiStatus supervise_core_services(ZiSystemBootstrap* bootstrap,
                                        const ZiServiceManifest* manifests,
                                        size_t manifest_count,
                                        const size_t* start_order,
                                        size_t start_order_count,
                                        size_t* out_session_index) {
  if (out_session_index == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_session_index = SIZE_MAX;
  ZiServiceLaunchContext launch_context = {bootstrap, false};
  bool failure_policy_verified = false;
  for (size_t position = 0; position < start_order_count; ++position) {
    size_t index = start_order[position];
    if (index >= manifest_count) {
      return ZI_STATUS_INVALID_SERVICE_MANIFEST;
    }
    const ZiServiceManifest* manifest = &manifests[index];
    if (view_equals(manifest->name, "SessionHost", sizeof "SessionHost" - 1u)) {
      *out_session_index = index;
      continue;
    }
    ZiServiceSupervisionResult result = {0};
    ZiStatus status = zi_service_supervise(manifest, service_launch, &launch_context, &result);
    if (ZiFailed(status) || result.attempt_count != 1 || result.restart_count != 0 ||
        result.last_exit_code != 0) {
      if (ZiFailed(status)) {
        return status;
      }
      return ZI_STATUS_INVALID_STATE;
    }
    const char* marker = service_marker(manifest->name);
    if (marker != NULL) {
      zi_log_boot_marker(marker);
    }
    zi_log_boot_marker("SERVICE_LAUNCH");
    if (view_equals(manifest->name, "ServiceHost", sizeof "ServiceHost" - 1u)) {
      status = verify_service_failure_policy(bootstrap, manifest);
      if (ZiFailed(status)) {
        return status;
      }
      failure_policy_verified = true;
    }
  }
  if (!failure_policy_verified) {
    return ZI_STATUS_NOT_FOUND;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus verify_service_failure_policy(ZiSystemBootstrap* bootstrap,
                                              const ZiServiceManifest* manifest) {
  ZiServiceManifest probe = *manifest;
  probe.restart_policy = ZI_SERVICE_RESTART_ON_FAILURE;
  probe.maximum_restarts = 2;
  ZiServiceLaunchContext context = {bootstrap, true};
  ZiServiceSupervisionResult result = {0};
  ZiStatus status = zi_service_supervise(&probe, service_launch, &context, &result);
  if (status != ZI_STATUS_SERVICE_RESTART_LIMIT || result.attempt_count != 3 ||
      result.restart_count != 2 || result.last_launch_status != ZI_STATUS_SUCCESS ||
      result.last_exit_code == 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  zi_log_boot_marker("SERVICE_FAILURE_DETECTED");
  zi_log_boot_marker("SERVICE_RESTART_LIMIT");
  return ZI_STATUS_SUCCESS;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity, readability-function-size) -- cleanup is ownership-ordered.
static ZiStatus run_user_session(ZiSystemBootstrap* bootstrap,
                                 const ZiServiceManifest* session_manifest) {
  ZiSecurityId session_group = {0};
  ZiAccessToken session_token = make_service_token(session_manifest, &session_group);
  ZiStringView session_arguments[] = {session_manifest->executable_path};
  ZiProcessParameterInput session_parameters = {
      sizeof(ZiProcessParameterInput),
      ZI_PROCESS_PARAMETER_INPUT_VERSION,
      session_manifest->executable_path,
      session_manifest->executable_path,
      session_arguments,
      sizeof session_arguments / sizeof session_arguments[0],
      k_system_environment,
      sizeof k_system_environment / sizeof k_system_environment[0],
  };
  ZiSecurityId luma_group = {ZI_SECURITY_AUTHORITY_GROUP, 1};
  ZiAccessToken luma_token = {
      sizeof(ZiAccessToken),
      ZI_ACCESS_TOKEN_VERSION,
      {ZI_SECURITY_AUTHORITY_USER, 21},
      &luma_group,
      1,
      0,
  };
  ZiStringView luma_arguments[] = {k_luma_path};
  ZiProcessParameterInput luma_parameters = {
      sizeof(ZiProcessParameterInput),
      ZI_PROCESS_PARAMETER_INPUT_VERSION,
      k_luma_path,
      k_luma_path,
      luma_arguments,
      sizeof luma_arguments / sizeof luma_arguments[0],
      k_system_environment,
      sizeof k_system_environment / sizeof k_system_environment[0],
  };

  ZiUserProcess* session = NULL;
  ZiUserProcess* luma = NULL;
  ZiChannel session_channel = {0};
  ZiChannel luma_channel = {0};
  ZiHandle session_handle = ZI_INVALID_HANDLE;
  ZiHandle luma_handle = ZI_INVALID_HANDLE;
  ZiAce channel_entries[2] = {0};
  ZiAcl channel_acl = {0};
  ZiSecurityDescriptor channel_descriptor = {0};
  ZiStatus status = create_zifs_process(bootstrap,
                                        NULL,
                                        session_manifest->executable_path,
                                        &session_parameters,
                                        &session_token,
                                        &session);
  if (ZiSucceeded(status)) {
    status =
        create_zifs_process(bootstrap, NULL, k_luma_path, &luma_parameters, &luma_token, &luma);
  }
  if (ZiSucceeded(status)) {
    channel_entries[0] = (ZiAce){
        ZI_ACE_ALLOW,
        0,
        0,
        ZI_ACCESS_READ | ZI_ACCESS_WRITE,
        session->token.user,
    };
    channel_entries[1] = (ZiAce){
        ZI_ACE_ALLOW,
        0,
        0,
        ZI_ACCESS_READ | ZI_ACCESS_WRITE,
        luma->token.user,
    };
    channel_acl = (ZiAcl){
        sizeof(ZiAcl),
        ZI_ACL_VERSION,
        channel_entries,
        sizeof channel_entries / sizeof channel_entries[0],
    };
    channel_descriptor = (ZiSecurityDescriptor){
        sizeof(ZiSecurityDescriptor),
        ZI_SECURITY_DESCRIPTOR_VERSION,
        session->token.user,
        session->token.user,
        &channel_acl,
        0,
    };
    status = initialise_session_channels(bootstrap,
                                         session,
                                         luma,
                                         &channel_descriptor,
                                         &session_channel,
                                         &luma_channel,
                                         &session_handle,
                                         &luma_handle);
  }
  if (ZiSucceeded(status)) {
    status = zi_user_process_set_bootstrap_channel(session, session_handle);
  }
  if (ZiSucceeded(status)) {
    status = zi_user_process_set_bootstrap_channel(luma, luma_handle);
  }
  if (ZiSucceeded(status)) {
    zi_log_boot_marker("SESSION_CHANNEL");
    status = zi_user_process_run(bootstrap->process_manager, session, false);
  }
  int32_t session_exit_code = ZI_STATUS_PROCESS_TERMINATED;
  if (ZiSucceeded(status)) {
    status = zi_user_process_wait(session, 0, &session_exit_code);
  }
  if (ZiSucceeded(status) && session_exit_code != 0) {
    status = ZI_STATUS_PROCESS_TERMINATED;
  }
  if (ZiSucceeded(status)) {
    zi_log_boot_marker("SESSION_HOST");
    status = zi_user_process_release(bootstrap->process_manager, session);
    if (ZiSucceeded(status)) {
      session = NULL;
    }
  }
  if (ZiSucceeded(status)) {
    status = zi_user_process_run(bootstrap->process_manager, luma, false);
  }
  int32_t luma_exit_code = ZI_STATUS_PROCESS_TERMINATED;
  if (ZiSucceeded(status)) {
    status = zi_user_process_wait(luma, 0, &luma_exit_code);
  }
  if (ZiSucceeded(status) && luma_exit_code != 0) {
    status = ZI_STATUS_PROCESS_TERMINATED;
  }
  if (ZiSucceeded(status)) {
    zi_log_boot_marker("LUMA_CHILD_PROCESS");
    zi_log_boot_marker("USER_LUMA");
    zi_log_boot_marker("USER_LUMA_READY");
    status = zi_user_process_release(bootstrap->process_manager, luma);
    if (ZiSucceeded(status)) {
      luma = NULL;
    }
  }

  ZiStatus release_status =
      release_session_resources(bootstrap, session, luma, &session_channel, &luma_channel);
  if (ZiSucceeded(status) && ZiFailed(release_status)) {
    status = release_status;
  }
  if (ZiSucceeded(status)) {
    zi_log_boot_marker("USER_SESSION");
  }
  return status;
}

// NOLINTNEXTLINE(readability-function-size) -- the versioned ACL and paired handles form one transaction.
static ZiStatus initialise_session_channels(ZiSystemBootstrap* bootstrap,
                                            ZiUserProcess* session,
                                            ZiUserProcess* luma,
                                            const ZiSecurityDescriptor* descriptor,
                                            ZiChannel* session_channel,
                                            ZiChannel* luma_channel,
                                            ZiHandle* out_session_handle,
                                            ZiHandle* out_luma_handle) {
  ZiIpcChannelPairOptions options = {
      sizeof(ZiIpcChannelPairOptions),
      ZI_IPC_CHANNEL_OPTIONS_VERSION,
      &bootstrap->process_manager->dispatcher_domain,
      {"SessionBootstrap", sizeof "SessionBootstrap" - 1u},
      {"LumaBootstrap", sizeof "LumaBootstrap" - 1u},
      4,
      &session->handle_table,
      &luma->handle_table,
      &session->token,
      &luma->token,
      descriptor,
      descriptor,
  };
  ZiStatus status = zi_ipc_channel_pair_initialise(&options, session_channel, luma_channel);
  if (ZiSucceeded(status)) {
    status = zi_handle_open(&session->handle_table,
                            &session_channel->object,
                            &session->token,
                            ZI_ACCESS_WRITE,
                            out_session_handle);
  }
  if (ZiSucceeded(status)) {
    status = zi_handle_open(&luma->handle_table,
                            &luma_channel->object,
                            &luma->token,
                            ZI_ACCESS_READ,
                            out_luma_handle);
  }
  return status;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity) -- cleanup must preserve reverse ownership order.
static ZiStatus release_session_resources(ZiSystemBootstrap* bootstrap,
                                          ZiUserProcess* session,
                                          ZiUserProcess* luma,
                                          ZiChannel* session_channel,
                                          ZiChannel* luma_channel) {
  ZiStatus result = ZI_STATUS_SUCCESS;
  if (luma != NULL && luma->state != ZI_USER_PROCESS_RUNNING) {
    result = zi_user_process_release(bootstrap->process_manager, luma);
  }
  if (session != NULL && session->state != ZI_USER_PROCESS_RUNNING) {
    ZiStatus status = zi_user_process_release(bootstrap->process_manager, session);
    if (ZiSucceeded(result) && ZiFailed(status)) {
      result = status;
    }
  }
  if (luma_channel->object.type != NULL && luma_channel->object.is_destroyed == 0) {
    ZiStatus status = zi_ipc_channel_close(luma_channel);
    if (ZiSucceeded(result) && ZiFailed(status)) {
      result = status;
    }
  }
  if (session_channel->object.type != NULL && session_channel->object.is_destroyed == 0) {
    ZiStatus status = zi_ipc_channel_close(session_channel);
    if (ZiSucceeded(result) && ZiFailed(status)) {
      result = status;
    }
  }
  if (luma_channel->object.type != NULL && luma_channel->object.is_destroyed == 0) {
    ZiStatus status = zi_object_dereference(&luma_channel->object);
    if (ZiSucceeded(result) && ZiFailed(status)) {
      result = status;
    }
  }
  if (session_channel->object.type != NULL && session_channel->object.is_destroyed == 0) {
    ZiStatus status = zi_object_dereference(&session_channel->object);
    if (ZiSucceeded(result) && ZiFailed(status)) {
      result = status;
    }
  }
  return result;
}

static ZiAccessToken make_service_token(const ZiServiceManifest* manifest,
                                        ZiSecurityId* group_storage) {
  *group_storage = (ZiSecurityId){ZI_SECURITY_AUTHORITY_GROUP, 1};
  ZiSecurityId user = {ZI_SECURITY_AUTHORITY_SERVICE, service_identity_value(manifest->name)};
  if (manifest->token_policy == ZI_SERVICE_TOKEN_SYSTEM) {
    user = (ZiSecurityId){ZI_SECURITY_AUTHORITY_SYSTEM, 1};
  } else if (manifest->token_policy == ZI_SERVICE_TOKEN_SESSION_BOOTSTRAP) {
    user = (ZiSecurityId){ZI_SECURITY_AUTHORITY_SYSTEM, 2};
  }
  return (ZiAccessToken){
      sizeof(ZiAccessToken),
      ZI_ACCESS_TOKEN_VERSION,
      user,
      group_storage,
      1,
      0,
  };
}

static uint32_t service_identity_value(ZiStringView name) {
  uint32_t value = UINT32_C(2166136261);
  for (size_t index = 0; index < name.size; ++index) {
    value ^= (unsigned char)name.data[index];
    value *= UINT32_C(16777619);
  }
  return value == 0 ? 1 : value;
}

static const char* service_marker(ZiStringView name) {
  if (view_equals(name, "ServiceHost", sizeof "ServiceHost" - 1u)) {
    return "SERVICE_HOST";
  }
  if (view_equals(name, "SecurityHost", sizeof "SecurityHost" - 1u)) {
    return "SECURITY_HOST";
  }
  if (view_equals(name, "LogHost", sizeof "LogHost" - 1u)) {
    return "LOG_HOST";
  }
  if (view_equals(name, "MountHost", sizeof "MountHost" - 1u)) {
    return "MOUNT_HOST";
  }
  return NULL;
}

static bool view_equals(ZiStringView view, const char* text, size_t text_size) {
  return (bool)(view.data != NULL && text != NULL && view.size == text_size &&
                zi_memory_compare(view.data, text, text_size) == 0);
}
