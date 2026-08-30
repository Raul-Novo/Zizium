// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/address_space.h"
#include "zi/dispatcher.h"
#include "zi/handle.h"
#include "zi/kernel_stack.h"
#include "zi/object.h"
#include "zi/process_parameters.h"
#include "zi/scheduler.h"
#include "zi/security.h"
#include "zi/syscall.h"
#include "zi/user_image.h"
#include "zi/x64_interrupt.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_USER_PROCESS_VERSION 3u
#define ZI_USER_PROCESS_MANAGER_VERSION 2u
#define ZI_USER_PROCESS_LAUNCH_PROVIDER_VERSION 1u
#define ZI_USER_PROCESS_MANAGER_CAPACITY 4u
#define ZI_USER_PROCESS_GROUP_CAPACITY 16u
#define ZI_USER_PROCESS_HANDLE_CAPACITY 32u

enum ZiUserProcessState {
  ZI_USER_PROCESS_EMPTY = 0,
  ZI_USER_PROCESS_INITIALISED = 1,
  ZI_USER_PROCESS_RUNNING = 2,
  ZI_USER_PROCESS_TERMINATING = 3,
  ZI_USER_PROCESS_TERMINATED = 4,
};

enum ZiUserTerminationReason {
  ZI_USER_TERMINATION_NONE = 0,
  ZI_USER_TERMINATION_EXIT_SYSCALL = 1,
  ZI_USER_TERMINATION_EXCEPTION = 2,
  ZI_USER_TERMINATION_INVALID_RETURN = 3,
};

struct ZiUserProcess;
struct ZiUserProcessManager;

typedef ZiStatus (*ZiUserProcessCreateFromPathRoutine)(void* context,
                                                       struct ZiUserProcessManager* manager,
                                                       struct ZiUserProcess* parent,
                                                       ZiStringView image_path,
                                                       struct ZiUserProcess** out_process);

typedef struct ZiUserProcessLaunchProvider {
  uint32_t struct_size;
  uint32_t version;
  void* context;
  ZiUserProcessCreateFromPathRoutine create_from_path;
} ZiUserProcessLaunchProvider;

typedef struct ZiUserProcessLaunch {
  uint32_t struct_size;
  uint32_t version;
  ZiStringView module_name;
  const void* file_data;
  size_t file_size;
  const ZiUserModuleSource* module_sources;
  size_t module_source_count;
  const ZiProcessParameterInput* parameters;
  const ZiAccessToken* token;
  uint32_t image_load_flags;
  uint32_t reserved;
} ZiUserProcessLaunch;

#define ZI_USER_PROCESS_LAUNCH_VERSION 1u

typedef struct ZiUserProcess {
  uint32_t struct_size;
  uint32_t version;
  uint32_t state;
  uint32_t termination_reason;
  ZiObjectHeader object;
  ZiAce object_ace;
  ZiAcl object_acl;
  ZiSecurityDescriptor object_security_descriptor;
  ZxProcess executive_process;
  ZxThread initial_thread;
  ZiAddressSpace address_space;
  ZiUserImageSet image_set;
  ZiKernelStack kernel_stack;
  ZiAccessToken token;
  ZiSecurityId token_groups[ZI_USER_PROCESS_GROUP_CAPACITY];
  ZiHandleTable handle_table;
  ZiHandleTableEntry handle_entries[ZI_USER_PROCESS_HANDLE_CAPACITY];
  uint64_t user_stack_base;
  uint64_t user_stack_pointer;
  uint64_t parameters_address;
  uint64_t parameters_size;
  uint64_t fault_vector;
  struct ZiUserProcess* parent;
  ZiHandle bootstrap_channel;
  int32_t exit_code;
  uint32_t reserved;
} ZiUserProcess;

typedef struct ZiUserProcessManager {
  uint32_t struct_size;
  uint32_t version;
  ZiUserProcess processes[ZI_USER_PROCESS_MANAGER_CAPACITY];
  size_t process_count;
  uint64_t next_process_id;
  uint64_t next_thread_id;
  ZiUserProcess* active_process;
  ZiX64SyscallCpuState syscall_cpu;
  ZiDispatcherDomain dispatcher_domain;
  ZiUserProcessLaunchProvider launch_provider;
  uint32_t syscall_is_configured;
  uint32_t syscall_entry_is_logged;
} ZiUserProcessManager;

ZiStatus zi_user_process_manager_initialise(ZiUserProcessManager* manager);
ZiStatus zi_user_process_manager_set_launch_provider(ZiUserProcessManager* manager,
                                                     const ZiUserProcessLaunchProvider* provider);
ZiStatus zi_user_process_create(ZiUserProcessManager* manager,
                                const ZiUserProcessLaunch* launch,
                                ZiUserProcess** out_process);
ZiStatus zi_user_process_create_child(ZiUserProcessManager* manager,
                                      ZiUserProcess* parent,
                                      const ZiUserProcessLaunch* launch,
                                      ZiUserProcess** out_process);
ZiStatus
zi_user_process_run(ZiUserProcessManager* manager, ZiUserProcess* process, bool force_user_fault);
ZiStatus zi_user_process_run_child(ZiUserProcessManager* manager,
                                   ZiUserProcess* parent,
                                   ZiUserProcess* child);
ZiStatus
zi_user_process_wait(const ZiUserProcess* process, uint64_t timeout, int32_t* out_exit_code);
ZiStatus zi_user_process_release(ZiUserProcessManager* manager, ZiUserProcess* process);
ZiStatus zi_user_process_set_bootstrap_channel(ZiUserProcess* process, ZiHandle channel);
const ZiObjectType* zi_user_process_object_type(void);
bool zi_user_process_is_active(void);
ZiStatus zi_user_process_dispatch_syscall(ZiSyscallFrame* frame);
ZiX64InterruptFrame* zi_user_process_handle_exception(ZiX64InterruptFrame* frame);
