// SPDX-License-Identifier: GPL-3.0-or-later

#include "zizium/process.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/address_space.h"
#include "zi/arch_x64.h"
#include "zi/byte_order.h"
#include "zi/dispatcher.h"
#include "zi/framebuffer_console.h"
#include "zi/handle.h"
#include "zi/ipc.h"
#include "zi/kernel_memory.h"
#include "zi/kernel_pool.h"
#include "zi/kernel_stack.h"
#include "zi/log.h"
#include "zi/memory.h"
#include "zi/object.h"
#include "zi/process_parameters.h"
#include "zi/process_record.h"
#include "zi/scheduler.h"
#include "zi/security.h"
#include "zi/serial.h"
#include "zi/syscall.h"
#include "zi/unicode.h"
#include "zi/user_image.h"
#include "zi/user_process.h"
#include "zi/x64_descriptor.h"
#include "zi/x64_interrupt.h"
#include "zi/x64_paging.h"
#include "zizium/ipc.h"
#include "zizium/status.h"
#include "zizium/types.h"
#include "zizium/zx.h"

#define ZI_USER_STACK_SIZE UINT64_C(0x10000)
#define ZI_USER_KERNEL_STACK_SIZE 65536u
#define ZI_USER_DEBUG_WRITE_LIMIT 512u
#define ZI_USER_PROCESS_DATA_SEARCH_BASE UINT64_C(0x0000000010000000)
#define ZI_USER_PROCESS_DATA_SEARCH_END UINT64_C(0x0000000040000000)
#define ZI_USER_IMAGE_SEARCH_BASE UINT64_C(0x0000000150000000)
#define ZI_USER_IMAGE_SEARCH_END UINT64_C(0x0000000300000000)
#define ZI_USER_IMAGE_SEARCH_ALIGNMENT UINT64_C(0x0000000000010000)
#define ZI_USER_PROCESS_PATH_LIMIT 512u

#define ZI_X64_MSR_EFER UINT32_C(0xc0000080)
#define ZI_X64_MSR_STAR UINT32_C(0xc0000081)
#define ZI_X64_MSR_LSTAR UINT32_C(0xc0000082)
#define ZI_X64_MSR_FMASK UINT32_C(0xc0000084)
#define ZI_X64_MSR_GS_BASE UINT32_C(0xc0000101)
#define ZI_X64_MSR_KERNEL_GS_BASE UINT32_C(0xc0000102)
#define ZI_X64_EFER_SYSCALL_ENABLE UINT64_C(1)
#define ZI_X64_SYSCALL_FLAG_MASK UINT64_C(0x0000000000040700)

static ZiUserProcessManager* s_manager;

static void process_object_destroy(ZiObjectHeader* object);
static const ZiObjectOperations k_process_object_operations = {
    sizeof(ZiObjectOperations),
    ZI_OBJECT_OPERATIONS_VERSION,
    process_object_destroy,
    NULL,
};
static const ZiObjectType k_process_object_type = {
    UINT32_C(0x00000103),
    {"Process", sizeof "Process" - 1u},
    &k_process_object_operations,
    0,
};

static ZiStatus process_page_allocate(void* context,
                                      uint64_t page_count,
                                      uint32_t owner,
                                      uint64_t* out_physical_base);
static ZiStatus process_page_release(void* context,
                                     uint64_t physical_base,
                                     uint64_t page_count,
                                     uint32_t expected_owner);
static ZiStatus
process_physical_pointer(void* context, uint64_t physical_base, size_t size, void** out_pointer);
static ZiStatus configure_syscall_entry(ZiUserProcessManager* manager);
static ZiStatus create_process(ZiUserProcessManager* manager,
                               ZiUserProcess* parent,
                               const ZiUserProcessLaunch* launch,
                               ZiUserProcess** out_process);
static ZiStatus run_process(ZiUserProcessManager* manager,
                            ZiUserProcess* process,
                            ZiUserProcess* parent,
                            bool force_user_fault);
static ZiStatus copy_process_token(ZiUserProcess* process, const ZiAccessToken* source);
static ZiStatus prepare_process(ZiUserProcessManager* manager,
                                ZiUserProcess* process,
                                const ZiUserProcessLaunch* launch);
static ZiStatus prepare_process_parameters(ZiUserProcess* process,
                                           const ZiProcessParameterInput* input);
static ZiStatus prepare_process_stacks(ZiUserProcess* process);
static ZiStatus initialise_process_object(ZiUserProcess* process);
static ZiStatus release_process_resources(ZiUserProcess* process);
static ZiStatus dispatch_close_handle(const ZiSyscallFrame* frame);
static ZiStatus dispatch_create_process(const ZiSyscallFrame* frame);
static ZiStatus dispatch_wait_for_object(const ZiSyscallFrame* frame);
static ZiStatus dispatch_send_channel(const ZiSyscallFrame* frame);
static ZiStatus dispatch_receive_channel(const ZiSyscallFrame* frame);
static ZiStatus dispatch_get_bootstrap_channel(const ZiSyscallFrame* frame);
static ZiStatus dispatch_debug_write(const ZiSyscallFrame* frame);
static ZiStatus public_message_to_internal(const ZiChannelMessage* source, ZiMessage* destination);
static void internal_message_to_public(const ZiMessage* source, ZiChannelMessage* destination);
static void terminate_invalid_return(ZiSyscallFrame* frame);
static ZiUserProcess* find_empty_process(ZiUserProcessManager* manager);
static bool process_belongs_to_manager(const ZiUserProcessManager* manager,
                                       const ZiUserProcess* process);
static ZiStatus align_page_size(size_t size, size_t* out_size);

ZiStatus zi_user_process_manager_initialise(ZiUserProcessManager* manager) {
  if (manager == NULL || (s_manager != NULL && s_manager != manager)) {
    return ZI_STATUS_RESOURCE_IN_USE;
  }
  zi_memory_zero(manager, sizeof *manager);
  manager->struct_size = sizeof *manager;
  manager->version = ZI_USER_PROCESS_MANAGER_VERSION;
  manager->next_process_id = 1;
  manager->next_thread_id = 1;
  manager->syscall_cpu.struct_size = sizeof manager->syscall_cpu;
  manager->syscall_cpu.version = ZI_X64_SYSCALL_CPU_STATE_VERSION;
  zi_dispatcher_domain_initialise(&manager->dispatcher_domain);
  s_manager = manager;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_user_process_manager_set_launch_provider(ZiUserProcessManager* manager,
                                                     const ZiUserProcessLaunchProvider* provider) {
  if (manager == NULL || manager != s_manager || manager->struct_size != sizeof *manager ||
      manager->version != ZI_USER_PROCESS_MANAGER_VERSION || manager->active_process != NULL ||
      provider == NULL || provider->struct_size != sizeof *provider ||
      provider->version != ZI_USER_PROCESS_LAUNCH_PROVIDER_VERSION ||
      provider->create_from_path == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  manager->launch_provider = *provider;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_user_process_create(ZiUserProcessManager* manager,
                                const ZiUserProcessLaunch* launch,
                                ZiUserProcess** out_process) {
  return create_process(manager, NULL, launch, out_process);
}

ZiStatus zi_user_process_create_child(ZiUserProcessManager* manager,
                                      ZiUserProcess* parent,
                                      const ZiUserProcessLaunch* launch,
                                      ZiUserProcess** out_process) {
  if (!process_belongs_to_manager(manager, parent) || manager->active_process != parent ||
      parent->state != ZI_USER_PROCESS_RUNNING) {
    return ZI_STATUS_INVALID_STATE;
  }
  return create_process(manager, parent, launch, out_process);
}

static ZiStatus create_process(ZiUserProcessManager* manager,
                               ZiUserProcess* parent,
                               const ZiUserProcessLaunch* launch,
                               ZiUserProcess** out_process) {
  if (manager == NULL || manager != s_manager || manager->struct_size != sizeof *manager ||
      manager->version != ZI_USER_PROCESS_MANAGER_VERSION || launch == NULL ||
      launch->struct_size != sizeof *launch || launch->version != ZI_USER_PROCESS_LAUNCH_VERSION ||
      out_process == NULL ||
      (manager->active_process != NULL && manager->active_process != parent) ||
      manager->next_process_id == 0 || manager->next_process_id == UINT64_MAX ||
      manager->next_thread_id == 0 || manager->next_thread_id == UINT64_MAX) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiUserProcess* process = find_empty_process(manager);
  if (process == NULL) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  ZiStatus status = prepare_process(manager, process, launch);
  if (ZiFailed(status)) {
    ZiStatus release_status = release_process_resources(process);
    zi_memory_zero(process, sizeof *process);
    if (ZiFailed(release_status)) {
      return ZI_STATUS_MEMORY_CORRUPTION;
    }
    return status;
  }
  ++manager->process_count;
  ++manager->next_process_id;
  ++manager->next_thread_id;
  process->parent = parent;
  *out_process = process;
  return ZI_STATUS_SUCCESS;
}

ZiStatus
zi_user_process_run(ZiUserProcessManager* manager, ZiUserProcess* process, bool force_user_fault) {
  return run_process(manager, process, NULL, force_user_fault);
}

ZiStatus zi_user_process_run_child(ZiUserProcessManager* manager,
                                   ZiUserProcess* parent,
                                   ZiUserProcess* child) {
  return run_process(manager, child, parent, false);
}

static ZiStatus run_process(ZiUserProcessManager* manager,
                            ZiUserProcess* process,
                            ZiUserProcess* parent,
                            bool force_user_fault) {
  bool is_nested = parent != NULL;
  if (manager == NULL || manager != s_manager || !process_belongs_to_manager(manager, process) ||
      process->state != ZI_USER_PROCESS_INITIALISED ||
      (!is_nested && manager->active_process != NULL) ||
      (is_nested &&
       (!process_belongs_to_manager(manager, parent) || manager->active_process != parent ||
        parent->state != ZI_USER_PROCESS_RUNNING || process->parent != parent))) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiStatus status = configure_syscall_entry(manager);
  if (ZiFailed(status)) {
    return status;
  }
  uint64_t original_rsp0 = zi_x64_descriptor_rsp0();
  status = zi_x64_descriptor_set_rsp0(zi_kernel_stack_top(&process->kernel_stack));
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_process_record_mark_running(&process->executive_process);
  if (ZiFailed(status)) {
    (void)zi_x64_descriptor_set_rsp0(original_rsp0);
    return status;
  }

  process->state = ZI_USER_PROCESS_RUNNING;
  process->initial_thread.state = ZI_THREAD_RUNNING;
  ZiX64SyscallCpuState saved_cpu = manager->syscall_cpu;
  manager->active_process = process;
  manager->syscall_cpu.active_process_address = (uint64_t)(uintptr_t)process;
  manager->syscall_cpu.kernel_stack_top = zi_kernel_stack_top(&process->kernel_stack);
  manager->syscall_cpu.termination_value = (uint64_t)(int64_t)ZI_STATUS_PROCESS_TERMINATED;
  zi_log_boot_marker("SYSCALL_READY");
  zi_log_boot_marker("RING3_ENTER");
  uint64_t entry_point = process->image_set.images[0].entry_point;
  if (force_user_fault) {
    entry_point = ZI_USER_ADDRESS_MIN;
  }
  int64_t termination_value = 0;
  if (is_nested) {
    termination_value = ZkArchRunNestedUser(entry_point,
                                            process->user_stack_pointer,
                                            process->address_space.paging.root_physical_base,
                                            &manager->syscall_cpu,
                                            process->parameters_address);
  } else {
    termination_value = ZkArchRunUser(entry_point,
                                      process->user_stack_pointer,
                                      process->address_space.paging.root_physical_base,
                                      &manager->syscall_cpu,
                                      process->parameters_address);
  }
  if (is_nested) {
    manager->syscall_cpu = saved_cpu;
    manager->active_process = parent;
  } else {
    manager->syscall_cpu.active_process_address = 0;
    manager->active_process = NULL;
  }

  int32_t exit_status = (int32_t)termination_value;
  ZiStatus run_status = ZI_STATUS_PROCESS_TERMINATED;
  if (process->termination_reason == ZI_USER_TERMINATION_EXIT_SYSCALL) {
    run_status = ZI_STATUS_SUCCESS;
    zi_log_boot_marker("USER_PROCESS_EXIT");
  }
  process->exit_code = exit_status;
  process->state = ZI_USER_PROCESS_TERMINATED;
  process->initial_thread.state = ZI_THREAD_TERMINATED;
  process->executive_process.state = ZI_PROCESS_TERMINATING;
  status = zi_process_record_terminate(&process->executive_process, exit_status);
  ZiStatus rsp_status = zi_x64_descriptor_set_rsp0(original_rsp0);
  if (ZiFailed(status)) {
    return status;
  }
  if (ZiFailed(rsp_status)) {
    return rsp_status;
  }
  return run_status;
}

ZiStatus
zi_user_process_wait(const ZiUserProcess* process, uint64_t timeout, int32_t* out_exit_code) {
  if (process == NULL || process->struct_size != sizeof *process ||
      process->version != ZI_USER_PROCESS_VERSION) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return zi_process_record_wait(&process->executive_process, timeout, out_exit_code);
}

ZiStatus zi_user_process_release(ZiUserProcessManager* manager, ZiUserProcess* process) {
  if (manager == NULL || manager != s_manager || !process_belongs_to_manager(manager, process) ||
      manager->active_process == process ||
      (process->state != ZI_USER_PROCESS_INITIALISED &&
       process->state != ZI_USER_PROCESS_TERMINATED) ||
      process->object.handle_count != 0 || process->object.reference_count != 1) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiStatus status = release_process_resources(process);
  if (ZiFailed(status)) {
    return status;
  }
  zi_memory_zero(process, sizeof *process);
  if (manager->process_count == 0) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  --manager->process_count;
  zi_log_boot_marker("USER_PROCESS_CLEAN");
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_user_process_set_bootstrap_channel(ZiUserProcess* process, ZiHandle channel) {
  if (process == NULL || process->struct_size != sizeof *process ||
      process->version != ZI_USER_PROCESS_VERSION ||
      (process->state != ZI_USER_PROCESS_INITIALISED &&
       process->state != ZI_USER_PROCESS_RUNNING) ||
      channel == ZI_INVALID_HANDLE || process->bootstrap_channel != ZI_INVALID_HANDLE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  process->bootstrap_channel = channel;
  return ZI_STATUS_SUCCESS;
}

const ZiObjectType* zi_user_process_object_type(void) {
  return &k_process_object_type;
}

bool zi_user_process_is_active(void) {
  if (s_manager == NULL || s_manager->active_process == NULL) {
    return false;
  }
  const ZiUserProcess* process = s_manager->active_process;
  return (bool)(process->struct_size == sizeof *process &&
                process->version == ZI_USER_PROCESS_VERSION &&
                process->state == ZI_USER_PROCESS_RUNNING &&
                s_manager->syscall_cpu.active_process_address == (uint64_t)(uintptr_t)process);
}

ZiStatus zi_user_process_dispatch_syscall(ZiSyscallFrame* frame) {
  if (frame == NULL || frame->struct_size != sizeof *frame ||
      frame->version != ZI_X64_SYSCALL_FRAME_VERSION || !zi_user_process_is_active()) {
    if (frame != NULL) {
      terminate_invalid_return(frame);
    }
    return ZI_STATUS_PRIVILEGE_VIOLATION;
  }
  if (s_manager->syscall_entry_is_logged == 0) {
    s_manager->syscall_entry_is_logged = 1;
    zi_log_boot_marker("SYSCALL_ENTRY");
  }

  ZiUserProcess* process = s_manager->active_process;
  ZiStatus status = ZI_STATUS_NOT_IMPLEMENTED;
  switch (frame->number) {
    case ZI_SYSCALL_CLOSE_HANDLE:
      status = dispatch_close_handle(frame);
      break;
    case ZI_SYSCALL_WAIT_FOR_OBJECT:
      status = dispatch_wait_for_object(frame);
      break;
    case ZI_SYSCALL_DEBUG_WRITE:
      status = dispatch_debug_write(frame);
      break;
    case ZI_SYSCALL_CREATE_PROCESS:
      status = dispatch_create_process(frame);
      break;
    case ZI_SYSCALL_SEND_CHANNEL:
      status = dispatch_send_channel(frame);
      break;
    case ZI_SYSCALL_RECEIVE_CHANNEL:
      status = dispatch_receive_channel(frame);
      break;
    case ZI_SYSCALL_GET_BOOTSTRAP_CHANNEL:
      status = dispatch_get_bootstrap_channel(frame);
      break;
    case ZI_SYSCALL_EXIT_PROCESS:
      process->exit_code = (int32_t)frame->argument_1;
      process->termination_reason = ZI_USER_TERMINATION_EXIT_SYSCALL;
      process->state = ZI_USER_PROCESS_TERMINATING;
      process->executive_process.state = ZI_PROCESS_TERMINATING;
      frame->action = ZI_X64_SYSCALL_TERMINATE;
      frame->result = (uint64_t)(int64_t)process->exit_code;
      return ZI_STATUS_SUCCESS;
    default:
      break;
  }
  frame->result = (uint64_t)(int64_t)status;
  if (!zi_x64_syscall_return_is_safe(frame)) {
    terminate_invalid_return(frame);
    return ZI_STATUS_PRIVILEGE_VIOLATION;
  }
  frame->action = ZI_X64_SYSCALL_RETURN;
  return status;
}

ZiX64InterruptFrame* zi_user_process_handle_exception(ZiX64InterruptFrame* frame) {
  if (frame == NULL || !zi_user_process_is_active() || (frame->cs & UINT64_C(3)) != 3u) {
    return NULL;
  }
  ZiUserProcess* process = s_manager->active_process;
  process->fault_vector = frame->vector;
  process->termination_reason = ZI_USER_TERMINATION_EXCEPTION;
  process->state = ZI_USER_PROCESS_TERMINATING;
  process->executive_process.state = ZI_PROCESS_TERMINATING;
  s_manager->syscall_cpu.termination_value = (uint64_t)(int64_t)ZI_STATUS_PROCESS_TERMINATED;
  zi_log_boot_marker("USER_FAULT_CONTAINED");
  zi_log_write_hex(ZI_LOG_WARNING, "Process", "Terminated user exception vector", frame->vector);
  frame->vector = ZI_X64_INTERRUPT_RETURN_USER_TERMINATED;
  return frame;
}

static ZiStatus process_page_allocate(void* context,
                                      uint64_t page_count,
                                      uint32_t owner,
                                      uint64_t* out_physical_base) {
  (void)context;
  return zi_pmm_allocate(zi_kernel_physical_memory_manager(),
                         page_count,
                         1,
                         owner,
                         out_physical_base);
}

static ZiStatus process_page_release(void* context,
                                     uint64_t physical_base,
                                     uint64_t page_count,
                                     uint32_t expected_owner) {
  (void)context;
  return zi_pmm_free(zi_kernel_physical_memory_manager(),
                     physical_base,
                     page_count,
                     expected_owner);
}

static ZiStatus
process_physical_pointer(void* context, uint64_t physical_base, size_t size, void** out_pointer) {
  (void)context;
  return zi_kernel_physical_pointer(physical_base, size, out_pointer);
}

static ZiStatus configure_syscall_entry(ZiUserProcessManager* manager) {
  if (manager->syscall_is_configured != 0) {
    return ZI_STATUS_SUCCESS;
  }
  uint64_t efer = ZkArchReadMsr(ZI_X64_MSR_EFER) | ZI_X64_EFER_SYSCALL_ENABLE;
  uint64_t star = ((uint64_t)ZI_X64_GDT_KERNEL_DATA_SELECTOR << 48) |
                  ((uint64_t)ZI_X64_GDT_KERNEL_CODE_SELECTOR << 32);
  ZkArchWriteMsr(ZI_X64_MSR_EFER, efer);
  ZkArchWriteMsr(ZI_X64_MSR_STAR, star);
  ZkArchWriteMsr(ZI_X64_MSR_LSTAR, (uint64_t)(uintptr_t)ZkX64SyscallEntry);
  ZkArchWriteMsr(ZI_X64_MSR_FMASK, ZI_X64_SYSCALL_FLAG_MASK);
  ZkArchWriteMsr(ZI_X64_MSR_GS_BASE, 0);
  ZkArchWriteMsr(ZI_X64_MSR_KERNEL_GS_BASE, (uint64_t)(uintptr_t)&manager->syscall_cpu);
  if (ZkArchReadMsr(ZI_X64_MSR_EFER) != efer || ZkArchReadMsr(ZI_X64_MSR_STAR) != star ||
      ZkArchReadMsr(ZI_X64_MSR_LSTAR) != (uint64_t)(uintptr_t)ZkX64SyscallEntry ||
      ZkArchReadMsr(ZI_X64_MSR_FMASK) != ZI_X64_SYSCALL_FLAG_MASK ||
      ZkArchReadMsr(ZI_X64_MSR_GS_BASE) != 0 ||
      ZkArchReadMsr(ZI_X64_MSR_KERNEL_GS_BASE) != (uint64_t)(uintptr_t)&manager->syscall_cpu) {
    return ZI_STATUS_INVALID_STATE;
  }
  manager->syscall_is_configured = 1;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus copy_process_token(ZiUserProcess* process, const ZiAccessToken* source) {
  ZiStatus status = zi_security_token_validate(source);
  if (ZiFailed(status)) {
    return status;
  }
  if (source->group_count > ZI_USER_PROCESS_GROUP_CAPACITY) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  for (size_t index = 0; index < source->group_count; ++index) {
    process->token_groups[index] = source->groups[index];
  }
  process->token.struct_size = sizeof process->token;
  process->token.version = ZI_ACCESS_TOKEN_VERSION;
  process->token.user = source->user;
  process->token.groups = process->token_groups;
  process->token.group_count = source->group_count;
  process->token.privileges = source->privileges;
  return zi_security_token_validate(&process->token);
}

static ZiStatus prepare_process(ZiUserProcessManager* manager,
                                ZiUserProcess* process,
                                const ZiUserProcessLaunch* launch) {
  if (launch->file_data == NULL || launch->file_size == 0 || launch->parameters == NULL ||
      launch->token == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_memory_zero(process, sizeof *process);
  process->struct_size = sizeof *process;
  process->version = ZI_USER_PROCESS_VERSION;
  process->state = ZI_USER_PROCESS_INITIALISED;
  ZiStatus status = copy_process_token(process, launch->token);
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_handle_table_initialise(&process->handle_table,
                                      process->handle_entries,
                                      ZI_USER_PROCESS_HANDLE_CAPACITY);
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_process_record_initialise(&process->executive_process,
                                        manager->next_process_id,
                                        8,
                                        UINT64_C(1),
                                        &process->token,
                                        &manager->dispatcher_domain);
  if (ZiFailed(status)) {
    return status;
  }
  process->initial_thread.thread_id = manager->next_thread_id;
  process->initial_thread.process = &process->executive_process;
  process->initial_thread.affinity_mask = UINT64_C(1);
  process->initial_thread.priority = 8;
  process->initial_thread.base_priority = 8;
  process->initial_thread.quantum = ZI_SCHEDULER_DEFAULT_QUANTUM;
  process->initial_thread.quantum_remaining = ZI_SCHEDULER_DEFAULT_QUANTUM;
  process->initial_thread.state = ZI_THREAD_INITIALISED;

  ZiAddressSpaceBacking backing = {
      sizeof(ZiAddressSpaceBacking),
      ZI_ADDRESS_SPACE_BACKING_VERSION,
      NULL,
      process_page_allocate,
      process_page_release,
      process_physical_pointer,
  };
  status =
      zi_address_space_initialise(zi_kernel_paging_context(), &backing, &process->address_space);
  if (ZiFailed(status)) {
    return status;
  }
  process->executive_process.address_space = &process->address_space;
  zi_log_boot_marker("USER_ADDRESS_SPACE");

  ZiUserImageLoadOptions image_options = {
      sizeof(ZiUserImageLoadOptions),
      ZI_USER_IMAGE_LOAD_OPTIONS_VERSION,
      launch->image_load_flags,
      0,
      ZI_USER_IMAGE_SEARCH_BASE,
      ZI_USER_IMAGE_SEARCH_END,
      ZI_USER_IMAGE_SEARCH_ALIGNMENT,
      launch->module_sources,
      launch->module_source_count,
  };
  status = zi_pe_load_user_image(launch->file_data,
                                 launch->file_size,
                                 launch->module_name,
                                 &image_options,
                                 &process->address_space,
                                 &process->image_set);
  if (ZiFailed(status)) {
    return status;
  }
  zi_log_boot_marker("USER_PE_LOADED");
  if ((process->image_set.images[0].flags & ZI_USER_IMAGE_FLAG_RELOCATED) != 0) {
    zi_log_boot_marker("USER_PE_RELOCATED");
  }
  if (process->image_set.image_count > 1) {
    zi_log_boot_marker("USER_IMPORTS_RESOLVED");
  }
  status = prepare_process_parameters(process, launch->parameters);
  if (ZiFailed(status)) {
    return status;
  }
  zi_log_boot_marker("USER_PARAMETERS");
  status = prepare_process_stacks(process);
  if (ZiFailed(status)) {
    return status;
  }
  process->initial_thread.architecture_context = &process->kernel_stack;
  status = initialise_process_object(process);
  if (ZiFailed(status)) {
    return status;
  }
  zi_log_boot_marker("USER_TOKEN_BOUND");
  return ZI_STATUS_SUCCESS;
}

static ZiStatus prepare_process_parameters(ZiUserProcess* process,
                                           const ZiProcessParameterInput* input) {
  size_t required_size = 0;
  ZiStatus status = zi_process_parameters_measure(input, &required_size);
  size_t mapped_size = 0;
  if (ZiSucceeded(status)) {
    status = align_page_size(required_size, &mapped_size);
  }
  uint64_t user_base = 0;
  if (ZiSucceeded(status)) {
    status = zi_address_space_find_free_range(&process->address_space,
                                              ZI_USER_PROCESS_DATA_SEARCH_BASE,
                                              ZI_USER_PROCESS_DATA_SEARCH_END,
                                              mapped_size,
                                              ZI_X64_PAGE_SIZE,
                                              &user_base);
  }
  if (ZiSucceeded(status)) {
    status = zi_address_space_map_owned(&process->address_space,
                                        user_base,
                                        mapped_size,
                                        ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE | ZI_X64_PAGE_USER,
                                        ZI_MEMORY_OWNER_PROCESS_DATA);
  }
  void* staging = NULL;
  if (ZiSucceeded(status)) {
    status = zi_kernel_pool_allocate(required_size, &staging);
  }
  size_t used_size = 0;
  if (ZiSucceeded(status)) {
    status = zi_process_parameters_serialise(input,
                                             user_base,
                                             staging,
                                             required_size,
                                             &used_size,
                                             &process->parameters_address);
  }
  if (ZiSucceeded(status)) {
    status = zi_copy_to_user(&process->address_space, user_base, staging, used_size);
  }
  if (staging != NULL) {
    ZiStatus free_status = zi_kernel_pool_free(staging);
    if (ZiSucceeded(status) && ZiFailed(free_status)) {
      status = ZI_STATUS_MEMORY_CORRUPTION;
    }
  }
  if (ZiSucceeded(status)) {
    status = zi_address_space_protect_owned(&process->address_space,
                                            user_base,
                                            mapped_size,
                                            ZI_X64_PAGE_READ | ZI_X64_PAGE_USER);
  }
  if (ZiSucceeded(status)) {
    process->parameters_size = used_size;
  }
  return status;
}

static ZiStatus prepare_process_stacks(ZiUserProcess* process) {
  process->user_stack_base = ZI_USER_STACK_TOP - ZI_USER_STACK_SIZE;
  ZiStatus status =
      zi_address_space_map_owned(&process->address_space,
                                 process->user_stack_base,
                                 (size_t)ZI_USER_STACK_SIZE,
                                 ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE | ZI_X64_PAGE_USER,
                                 ZI_MEMORY_OWNER_USER_STACK);
  uint64_t synthetic_return = 0;
  if (ZiSucceeded(status)) {
    process->user_stack_pointer = ZI_USER_STACK_TOP - sizeof synthetic_return;
    status = zi_copy_to_user(&process->address_space,
                             process->user_stack_pointer,
                             &synthetic_return,
                             sizeof synthetic_return);
  }
  if (ZiSucceeded(status)) {
    status = zi_kernel_stack_allocate(ZI_USER_KERNEL_STACK_SIZE, &process->kernel_stack);
  }
  return status;
}

static ZiStatus initialise_process_object(ZiUserProcess* process) {
  process->object_ace = (ZiAce){
      ZI_ACE_ALLOW,
      0,
      0,
      ZI_ACCESS_FULL_CONTROL,
      process->token.user,
  };
  process->object_acl = (ZiAcl){
      sizeof(ZiAcl),
      ZI_ACL_VERSION,
      &process->object_ace,
      1,
  };
  ZiSecurityId primary_group = process->token.user;
  if (process->token.group_count != 0) {
    primary_group = process->token.groups[0];
  }
  process->object_security_descriptor = (ZiSecurityDescriptor){
      sizeof(ZiSecurityDescriptor),
      ZI_SECURITY_DESCRIPTOR_VERSION,
      process->token.user,
      primary_group,
      &process->object_acl,
      0,
  };
  ZiStringView name = {
      process->image_set.images[0].module_name,
      process->image_set.images[0].module_name_size,
  };
  return zi_object_initialise(&process->object,
                              &k_process_object_type,
                              name,
                              NULL,
                              &process->object_security_descriptor,
                              "User process");
}

static ZiStatus release_process_resources(ZiUserProcess* process) {
  ZiStatus status = ZI_STATUS_SUCCESS;
  if (process->handle_table.entries != NULL) {
    status = zi_handle_table_close_all(&process->handle_table);
  }
  if (process->address_space.version != 0) {
    ZiStatus address_status = zi_address_space_destroy(&process->address_space);
    if (ZiSucceeded(status) && ZiFailed(address_status)) {
      status = address_status;
    }
  }
  if (process->kernel_stack.version != 0) {
    ZiStatus stack_status = zi_kernel_stack_release(&process->kernel_stack);
    if (ZiSucceeded(status) && ZiFailed(stack_status)) {
      status = stack_status;
    }
  }
  if (process->object.type != NULL && process->object.is_destroyed == 0) {
    ZiStatus object_status = zi_object_dereference(&process->object);
    if (ZiSucceeded(status) && ZiFailed(object_status)) {
      status = object_status;
    }
  }
  return status;
}

static ZiStatus dispatch_close_handle(const ZiSyscallFrame* frame) {
  ZiHandle handle = (ZiHandle)frame->argument_1;
  ZiObjectHeader* object = NULL;
  ZiStatus status =
      zi_handle_lookup(&s_manager->active_process->handle_table, handle, 0, NULL, &object);
  if (ZiFailed(status)) {
    return status;
  }
  ZiUserProcess* child = NULL;
  if (object->type == &k_process_object_type) {
    child = (ZiUserProcess*)((unsigned char*)object - offsetof(ZiUserProcess, object));
    if (!process_belongs_to_manager(s_manager, child) ||
        child->parent != s_manager->active_process || child->state == ZI_USER_PROCESS_RUNNING) {
      (void)zi_object_dereference(object);
      return ZI_STATUS_INVALID_HANDLE;
    }
  }

  status = zi_handle_close(&s_manager->active_process->handle_table, handle);
  ZiStatus dereference_status = zi_object_dereference(object);
  if (ZiSucceeded(status) && ZiFailed(dereference_status)) {
    status = dereference_status;
  }
  if (ZiSucceeded(status) && child != NULL) {
    status = zi_user_process_release(s_manager, child);
  }
  return status;
}

static ZiStatus dispatch_create_process(const ZiSyscallFrame* frame) {
  if (frame->argument_1 == 0 || frame->argument_2 == 0 ||
      frame->argument_2 > ZI_USER_PROCESS_PATH_LIMIT || frame->argument_3 == 0 ||
      s_manager->launch_provider.struct_size != sizeof s_manager->launch_provider ||
      s_manager->launch_provider.version != ZI_USER_PROCESS_LAUNCH_PROVIDER_VERSION ||
      s_manager->launch_provider.create_from_path == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  char path[ZI_USER_PROCESS_PATH_LIMIT] = {0};
  size_t path_size = (size_t)frame->argument_2;
  ZiStatus status = zi_copy_from_user(&s_manager->active_process->address_space,
                                      path,
                                      frame->argument_1,
                                      path_size);
  if (ZiFailed(status)) {
    return status;
  }
  for (size_t index = 0; index < path_size; ++index) {
    if (path[index] == '\0') {
      return ZI_STATUS_INVALID_PATH;
    }
  }

  ZiUserProcess* parent = s_manager->active_process;
  ZiUserProcess* child = NULL;
  status = s_manager->launch_provider.create_from_path(s_manager->launch_provider.context,
                                                       s_manager,
                                                       parent,
                                                       (ZiStringView){path, path_size},
                                                       &child);
  ZiHandle handle = ZI_INVALID_HANDLE;
  if (ZiSucceeded(status)) {
    status = zi_handle_open(&parent->handle_table,
                            &child->object,
                            &parent->token,
                            ZI_ACCESS_READ | ZI_ACCESS_EXECUTE,
                            &handle);
  }
  if (ZiSucceeded(status)) {
    status = zi_copy_to_user(&parent->address_space, frame->argument_3, &handle, sizeof handle);
  }
  if (ZiFailed(status) && handle != ZI_INVALID_HANDLE) {
    (void)zi_handle_close(&parent->handle_table, handle);
  }
  if (ZiFailed(status) && child != NULL) {
    ZiStatus release_status = zi_user_process_release(s_manager, child);
    if (ZiFailed(release_status)) {
      return ZI_STATUS_MEMORY_CORRUPTION;
    }
  }
  if (ZiSucceeded(status)) {
    zi_log_boot_marker("USER_CREATE_PROCESS");
  }
  return status;
}

static ZiStatus dispatch_wait_for_object(const ZiSyscallFrame* frame) {
  if (frame->argument_3 == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiObjectHeader* object = NULL;
  ZiStatus status = zi_handle_lookup(&s_manager->active_process->handle_table,
                                     (ZiHandle)frame->argument_1,
                                     ZI_ACCESS_READ,
                                     &k_process_object_type,
                                     &object);
  if (ZiFailed(status)) {
    return status;
  }
  ZiUserProcess* parent = s_manager->active_process;
  ZiUserProcess* child = (ZiUserProcess*)((unsigned char*)object - offsetof(ZiUserProcess, object));
  if (!process_belongs_to_manager(s_manager, child) || child->parent != parent) {
    status = ZI_STATUS_INVALID_HANDLE;
  } else if (child->state == ZI_USER_PROCESS_INITIALISED && frame->argument_2 != 0) {
    status = zi_user_process_run_child(s_manager, parent, child);
  }
  int32_t exit_code = ZI_STATUS_PROCESS_TERMINATED;
  if (ZiSucceeded(status) || status == ZI_STATUS_PROCESS_TERMINATED) {
    status = zi_user_process_wait(child, 0, &exit_code);
  }
  if (ZiSucceeded(status)) {
    status =
        zi_copy_to_user(&parent->address_space, frame->argument_3, &exit_code, sizeof exit_code);
  }
  ZiStatus dereference_status = zi_object_dereference(object);
  if (ZiSucceeded(status) && ZiFailed(dereference_status)) {
    status = dereference_status;
  }
  if (ZiSucceeded(status)) {
    zi_log_boot_marker("USER_WAIT_PROCESS");
  }
  return status;
}

static ZiStatus dispatch_send_channel(const ZiSyscallFrame* frame) {
  if (frame->argument_2 == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiChannelMessage public_message = {0};
  ZiStatus status = zi_copy_from_user(&s_manager->active_process->address_space,
                                      &public_message,
                                      frame->argument_2,
                                      sizeof public_message);
  ZiMessage message = {0};
  if (ZiSucceeded(status)) {
    status = public_message_to_internal(&public_message, &message);
  }
  ZiObjectHeader* object = NULL;
  if (ZiSucceeded(status)) {
    status = zi_handle_lookup(&s_manager->active_process->handle_table,
                              (ZiHandle)frame->argument_1,
                              ZI_ACCESS_WRITE,
                              zi_ipc_channel_object_type(),
                              &object);
  }
  if (ZiSucceeded(status)) {
    status = zi_ipc_send((ZiChannel*)object, &message);
  }
  if (object != NULL) {
    ZiStatus dereference_status = zi_object_dereference(object);
    if (ZiSucceeded(status) && ZiFailed(dereference_status)) {
      status = dereference_status;
    }
  }
  return status;
}

static ZiStatus dispatch_receive_channel(const ZiSyscallFrame* frame) {
  if (frame->argument_2 == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiObjectHeader* object = NULL;
  ZiStatus status = zi_handle_lookup(&s_manager->active_process->handle_table,
                                     (ZiHandle)frame->argument_1,
                                     ZI_ACCESS_READ,
                                     zi_ipc_channel_object_type(),
                                     &object);
  ZiMessage message = {0};
  if (ZiSucceeded(status)) {
    status = zi_ipc_receive((ZiChannel*)object, &message);
  }
  ZiChannelMessage public_message = {0};
  if (ZiSucceeded(status)) {
    internal_message_to_public(&message, &public_message);
    status = zi_copy_to_user(&s_manager->active_process->address_space,
                             frame->argument_2,
                             &public_message,
                             sizeof public_message);
  }
  if (object != NULL) {
    ZiStatus dereference_status = zi_object_dereference(object);
    if (ZiSucceeded(status) && ZiFailed(dereference_status)) {
      status = dereference_status;
    }
  }
  return status;
}

static ZiStatus dispatch_get_bootstrap_channel(const ZiSyscallFrame* frame) {
  if (frame->argument_1 == 0 || s_manager->active_process->bootstrap_channel == ZI_INVALID_HANDLE) {
    return ZI_STATUS_NOT_FOUND;
  }
  ZiHandle channel = s_manager->active_process->bootstrap_channel;
  return zi_copy_to_user(&s_manager->active_process->address_space,
                         frame->argument_1,
                         &channel,
                         sizeof channel);
}

static ZiStatus dispatch_debug_write(const ZiSyscallFrame* frame) {
  if (frame->argument_2 == 0) {
    return ZI_STATUS_SUCCESS;
  }
  if (frame->argument_2 > ZI_USER_DEBUG_WRITE_LIMIT) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  char text[ZI_USER_DEBUG_WRITE_LIMIT] = {0};
  size_t size = (size_t)frame->argument_2;
  ZiStatus status =
      zi_copy_from_user(&s_manager->active_process->address_space, text, frame->argument_1, size);
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_utf8_validate(text, size);
  if (ZiFailed(status)) {
    return status;
  }
  zi_serial_write(text, size);
  if (zi_framebuffer_console_is_ready()) {
    zi_framebuffer_console_write(text, size);
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus public_message_to_internal(const ZiChannelMessage* source, ZiMessage* destination) {
  if (source == NULL || destination == NULL || source->struct_size != sizeof *source ||
      source->version != ZI_CHANNEL_MESSAGE_VERSION || source->flags != 0 ||
      source->payload_size > ZI_CHANNEL_INLINE_PAYLOAD_CAPACITY ||
      source->transferred_handle != ZI_INVALID_HANDLE || source->transferred_access != 0 ||
      source->reserved != 0) {
    return ZI_STATUS_INVALID_MESSAGE;
  }
  *destination = (ZiMessage){0};
  destination->struct_size = sizeof *destination;
  destination->version = ZI_IPC_MESSAGE_VERSION;
  destination->message_id = source->message_id;
  destination->correlation_id = source->correlation_id;
  destination->message_type = source->message_type;
  destination->payload_size = source->payload_size;
  for (size_t index = 0; index < source->payload_size; ++index) {
    destination->inline_payload[index] = source->inline_payload[index];
  }
  return ZI_STATUS_SUCCESS;
}

static void internal_message_to_public(const ZiMessage* source, ZiChannelMessage* destination) {
  *destination = (ZiChannelMessage){0};
  destination->struct_size = sizeof *destination;
  destination->version = ZI_CHANNEL_MESSAGE_VERSION;
  destination->message_id = source->message_id;
  destination->correlation_id = source->correlation_id;
  destination->message_type = source->message_type;
  destination->payload_size = source->payload_size;
  destination->transferred_handle = source->transferred_handle;
  destination->transferred_access = source->transferred_access;
  for (size_t index = 0; index < source->payload_size; ++index) {
    destination->inline_payload[index] = source->inline_payload[index];
  }
}

static void terminate_invalid_return(ZiSyscallFrame* frame) {
  if (s_manager != NULL && s_manager->active_process != NULL) {
    s_manager->active_process->termination_reason = ZI_USER_TERMINATION_INVALID_RETURN;
    s_manager->active_process->state = ZI_USER_PROCESS_TERMINATING;
    s_manager->active_process->executive_process.state = ZI_PROCESS_TERMINATING;
  }
  frame->action = ZI_X64_SYSCALL_TERMINATE;
  frame->result = (uint64_t)(int64_t)ZI_STATUS_PRIVILEGE_VIOLATION;
}

static ZiUserProcess* find_empty_process(ZiUserProcessManager* manager) {
  for (size_t index = 0; index < ZI_USER_PROCESS_MANAGER_CAPACITY; ++index) {
    if (manager->processes[index].state == ZI_USER_PROCESS_EMPTY) {
      return &manager->processes[index];
    }
  }
  return NULL;
}

static bool process_belongs_to_manager(const ZiUserProcessManager* manager,
                                       const ZiUserProcess* process) {
  if (manager == NULL || process == NULL) {
    return false;
  }
  uintptr_t first = (uintptr_t)&manager->processes[0];
  uintptr_t end = (uintptr_t)&manager->processes[ZI_USER_PROCESS_MANAGER_CAPACITY];
  uintptr_t candidate = (uintptr_t)process;
  return (bool)(candidate >= first && candidate < end &&
                (candidate - first) % sizeof(ZiUserProcess) == 0 &&
                process->struct_size == sizeof *process &&
                process->version == ZI_USER_PROCESS_VERSION);
}

static ZiStatus align_page_size(size_t size, size_t* out_size) {
  if (size == 0 || out_size == NULL || size > SIZE_MAX - (size_t)(ZI_X64_PAGE_SIZE - 1u)) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  *out_size = (size + (size_t)ZI_X64_PAGE_SIZE - 1u) & ~(size_t)(ZI_X64_PAGE_SIZE - 1u);
  return ZI_STATUS_SUCCESS;
}

static void process_object_destroy(ZiObjectHeader* object) {
  (void)object;
}
