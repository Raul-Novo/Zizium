// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "x64_internal.h"
#include "zi/arch_x64.h"
#include "zi/byte_order.h"
#include "zi/kernel_stack.h"
#include "zi/log.h"
#include "zi/scheduler.h"
#include "zi/x64_descriptor.h"
#include "zi/x64_interrupt.h"
#include "zizium/status.h"

#define ZI_X64_KERNEL_THREAD_STACK_SIZE 32768u
#define ZI_X64_PREEMPTION_TIMEOUT_PERIODS 200u

typedef void (*ZiX64KernelThreadEntry)(void);

typedef struct ZiX64ThreadInitialisation {
  uint64_t thread_id;
  uint32_t priority;
  uint32_t quantum;
  unsigned char* stack;
  size_t stack_size;
  ZiX64KernelThreadEntry entry;
} ZiX64ThreadInitialisation;

static ZxScheduler s_scheduler;
static ZxProcess s_kernel_process;
static ZxThread s_boot_thread;
static ZxThread s_idle_thread;
static ZxThread s_worker_a_thread;
static ZxThread s_worker_b_thread;
static ZiX64ThreadContext s_boot_context;
static ZiX64ThreadContext s_idle_context;
static ZiX64ThreadContext s_worker_a_context;
static ZiX64ThreadContext s_worker_b_context;
static ZiKernelStack s_idle_stack;
static ZiKernelStack s_worker_a_stack;
static ZiKernelStack s_worker_b_stack;
static volatile uint64_t s_worker_a_counter;
static volatile uint64_t s_worker_b_counter;
static volatile ZiStatus s_runtime_status;

static ZiStatus initialise_thread(ZxThread* thread,
                                  ZiX64ThreadContext* context,
                                  const ZiX64ThreadInitialisation* initialisation);
static ZiStatus abandon_preemption_initialisation(ZiStatus failure_status);
static ZiStatus retire_smoke_workers(void);
static _Noreturn void idle_thread_main(void);
static _Noreturn void worker_a_main(void);
static _Noreturn void worker_b_main(void);
static _Noreturn void kernel_thread_exit(void);

ZiStatus zi_x64_preemption_start(uint64_t apic_virtual_address) {
  ZiStatus status = zi_x64_apic_initialise(apic_virtual_address);
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_x64_preemption_initialise();
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_x64_apic_timer_start(100u);
  if (ZiFailed(status)) {
    return abandon_preemption_initialisation(status);
  }
  zi_log_boot_marker("APIC_TIMER");
  zi_log_write(ZI_LOG_INFORMATION,
               "Interrupt",
               "The local APIC timer is calibrated and running at 100 Hz.");
  ZkArchEnableInterrupts();
  status = zi_x64_preemption_verify();
  if (ZiFailed(status)) {
    (void)ZkArchDisableInterrupts();
    return status;
  }
  zi_log_boot_marker("SCHEDULER_TICKS");
  zi_log_boot_marker("PREEMPTION");
  zi_log_write(ZI_LOG_INFORMATION,
               "Scheduler",
               "Timer-driven quantum expiry safely pre-empted two kernel workers.");
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_x64_preemption_initialise(void) {
  if (s_idle_stack.version != 0 || s_worker_a_stack.version != 0 || s_worker_b_stack.version != 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  zi_memory_zero(&s_scheduler, sizeof s_scheduler);
  zi_memory_zero(&s_kernel_process, sizeof s_kernel_process);
  zi_memory_zero(&s_boot_thread, sizeof s_boot_thread);
  zi_memory_zero(&s_boot_context, sizeof s_boot_context);
  s_worker_a_counter = 0;
  s_worker_b_counter = 0;
  s_runtime_status = ZI_STATUS_SUCCESS;

  s_kernel_process.process_id = 0;
  s_kernel_process.base_priority = 8;
  s_kernel_process.affinity_mask = UINT64_C(1);

  ZkArchSaveFxState(s_boot_context.fx_state);
  s_boot_thread.thread_id = 1;
  s_boot_thread.process = &s_kernel_process;
  s_boot_thread.affinity_mask = UINT64_C(1);
  s_boot_thread.priority = 8;
  s_boot_thread.base_priority = 8;
  s_boot_thread.quantum = ZI_SCHEDULER_DEFAULT_QUANTUM;
  s_boot_thread.quantum_remaining = ZI_SCHEDULER_DEFAULT_QUANTUM;
  s_boot_thread.state = ZI_THREAD_RUNNING;
  s_boot_thread.scheduler_class = ZI_SCHEDULER_CLASS_NORMAL;
  s_boot_thread.architecture_context = &s_boot_context;

  ZiStatus status = zi_kernel_stack_allocate(ZI_X64_KERNEL_THREAD_STACK_SIZE, &s_idle_stack);
  if (ZiSucceeded(status)) {
    status = zi_kernel_stack_allocate(ZI_X64_KERNEL_THREAD_STACK_SIZE, &s_worker_a_stack);
  }
  if (ZiSucceeded(status)) {
    status = zi_kernel_stack_allocate(ZI_X64_KERNEL_THREAD_STACK_SIZE, &s_worker_b_stack);
  }
  if (ZiFailed(status)) {
    return abandon_preemption_initialisation(status);
  }

  const ZiX64ThreadInitialisation idle_initialisation = {
      2,
      0,
      1,
      (unsigned char*)(uintptr_t)s_idle_stack.mapped_base,
      s_idle_stack.usable_size,
      idle_thread_main};
  const ZiX64ThreadInitialisation worker_a_initialisation = {
      3,
      8,
      ZI_SCHEDULER_DEFAULT_QUANTUM,
      (unsigned char*)(uintptr_t)s_worker_a_stack.mapped_base,
      s_worker_a_stack.usable_size,
      worker_a_main};
  const ZiX64ThreadInitialisation worker_b_initialisation = {
      4,
      8,
      ZI_SCHEDULER_DEFAULT_QUANTUM,
      (unsigned char*)(uintptr_t)s_worker_b_stack.mapped_base,
      s_worker_b_stack.usable_size,
      worker_b_main};
  status = initialise_thread(&s_idle_thread, &s_idle_context, &idle_initialisation);
  if (ZiFailed(status)) {
    return abandon_preemption_initialisation(status);
  }
  status = initialise_thread(&s_worker_a_thread, &s_worker_a_context, &worker_a_initialisation);
  if (ZiFailed(status)) {
    return abandon_preemption_initialisation(status);
  }
  status = initialise_thread(&s_worker_b_thread, &s_worker_b_context, &worker_b_initialisation);
  if (ZiFailed(status)) {
    return abandon_preemption_initialisation(status);
  }

  zi_scheduler_initialise(&s_scheduler, 0, &s_idle_thread);
  s_scheduler.current_thread = &s_boot_thread;
  status = zi_scheduler_enqueue(&s_scheduler, &s_worker_a_thread);
  if (ZiFailed(status)) {
    return abandon_preemption_initialisation(status);
  }
  status = zi_scheduler_enqueue(&s_scheduler, &s_worker_b_thread);
  if (ZiFailed(status)) {
    return abandon_preemption_initialisation(status);
  }
  ZkArchSetActiveFxState(s_boot_context.fx_state);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_x64_preemption_verify(void) {
  uint64_t calibration_ticks = zi_x64_apic_calibration_tsc_ticks();
  if (calibration_ticks == 0 ||
      calibration_ticks > UINT64_MAX / ZI_X64_PREEMPTION_TIMEOUT_PERIODS) {
    return ZI_STATUS_INVALID_STATE;
  }
  uint64_t start = ZkArchReadTimestamp();
  uint64_t timeout = calibration_ticks * ZI_X64_PREEMPTION_TIMEOUT_PERIODS;
  uint64_t deadline = start > UINT64_MAX - timeout ? UINT64_MAX : start + timeout;
  while (s_scheduler.tick_count < 6u || s_scheduler.context_switch_count < 3u ||
         s_worker_a_counter == 0 || s_worker_b_counter == 0) {
    if (ZiFailed(s_runtime_status)) {
      return s_runtime_status;
    }
    if (ZkArchReadTimestamp() >= deadline) {
      return ZI_STATUS_TIMEOUT;
    }
    ZkArchPause();
  }
  return retire_smoke_workers();
}

ZiX64InterruptFrame* zi_x64_preemption_handle_tick(ZiX64InterruptFrame* frame) {
  if (frame == NULL || s_scheduler.current_thread == NULL) {
    s_runtime_status = ZI_STATUS_INVALID_STATE;
    return frame;
  }
  ZxThread* current = s_scheduler.current_thread;
  ZiX64ThreadContext* current_context = current->architecture_context;
  if (current_context == NULL) {
    s_runtime_status = ZI_STATUS_INVALID_STATE;
    return frame;
  }
  current_context->saved_frame = frame;

  ZiSchedulerDispatch dispatch = {0};
  ZiStatus status = zi_scheduler_on_tick(&s_scheduler, &dispatch);
  if (ZiFailed(status)) {
    s_runtime_status = status;
    return frame;
  }
  if (dispatch.next_thread == NULL) {
    s_runtime_status = ZI_STATUS_INVALID_STATE;
    return frame;
  }
  ZiX64ThreadContext* next_context = dispatch.next_thread->architecture_context;
  if (next_context == NULL || next_context->saved_frame == NULL) {
    s_runtime_status = ZI_STATUS_INVALID_STATE;
    return frame;
  }
  if (dispatch.did_switch != 0) {
    ZkArchSetActiveFxState(next_context->fx_state);
  }
  return next_context->saved_frame;
}

uint64_t zi_x64_preemption_tick_count(void) {
  return s_scheduler.tick_count;
}

uint64_t zi_x64_preemption_context_switch_count(void) {
  return s_scheduler.context_switch_count;
}

static ZiStatus initialise_thread(ZxThread* thread,
                                  ZiX64ThreadContext* context,
                                  const ZiX64ThreadInitialisation* initialisation) {
  if (thread == NULL || context == NULL || initialisation == NULL ||
      initialisation->stack == NULL || initialisation->entry == NULL ||
      initialisation->stack_size < sizeof(ZiX64InterruptFrame) + sizeof(uint64_t) + 16u) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_memory_zero(thread, sizeof *thread);
  zi_memory_zero(context, sizeof *context);
  zi_memory_copy(context->fx_state, s_boot_context.fx_state, sizeof context->fx_state);

  uintptr_t stack_begin = (uintptr_t)initialisation->stack;
  if (stack_begin > UINTPTR_MAX - initialisation->stack_size) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  uintptr_t stack_top = (stack_begin + initialisation->stack_size) & ~(uintptr_t)UINT64_C(0x0f);
  stack_top -= sizeof(uint64_t);
  *(uint64_t*)stack_top = (uint64_t)(uintptr_t)kernel_thread_exit;
  stack_top -= sizeof(ZiX64InterruptFrame);
  ZiX64InterruptFrame* frame = (ZiX64InterruptFrame*)stack_top;
  zi_memory_zero(frame, sizeof *frame);
  frame->rip = (uint64_t)(uintptr_t)initialisation->entry;
  frame->cs = ZI_X64_GDT_KERNEL_CODE_SELECTOR;
  frame->rflags = UINT64_C(0x202);
  frame->rsp = stack_top + sizeof(ZiX64InterruptFrame);
  frame->ss = ZI_X64_GDT_KERNEL_DATA_SELECTOR;

  context->saved_frame = frame;
  context->stack_base = initialisation->stack;
  context->stack_size = initialisation->stack_size;
  thread->thread_id = initialisation->thread_id;
  thread->process = &s_kernel_process;
  thread->affinity_mask = UINT64_C(1);
  thread->priority = initialisation->priority;
  thread->base_priority = initialisation->priority;
  thread->quantum = initialisation->quantum;
  thread->quantum_remaining = initialisation->quantum;
  thread->state = ZI_THREAD_INITIALISED;
  thread->scheduler_class =
      initialisation->priority == 0 ? ZI_SCHEDULER_CLASS_IDLE : ZI_SCHEDULER_CLASS_NORMAL;
  thread->architecture_context = context;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus abandon_preemption_initialisation(ZiStatus failure_status) {
  bool clean_up_failed = false;
  if (s_worker_b_thread.is_queued != 0 &&
      ZiFailed(zi_scheduler_remove(&s_scheduler, &s_worker_b_thread))) {
    clean_up_failed = true;
  }
  if (s_worker_a_thread.is_queued != 0 &&
      ZiFailed(zi_scheduler_remove(&s_scheduler, &s_worker_a_thread))) {
    clean_up_failed = true;
  }
  if (s_worker_b_stack.version != 0 && ZiFailed(zi_kernel_stack_release(&s_worker_b_stack))) {
    clean_up_failed = true;
  }
  if (s_worker_a_stack.version != 0 && ZiFailed(zi_kernel_stack_release(&s_worker_a_stack))) {
    clean_up_failed = true;
  }
  if (s_idle_stack.version != 0 && ZiFailed(zi_kernel_stack_release(&s_idle_stack))) {
    clean_up_failed = true;
  }
  if (clean_up_failed) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  return failure_status;
}

static ZiStatus retire_smoke_workers(void) {
  ZiX64InterruptGuard guard = zi_x64_interrupt_guard_acquire(ZI_X64_IRQL_DISPATCH);
  ZiStatus status = ZI_STATUS_SUCCESS;
  if (s_worker_a_thread.is_queued != 0) {
    status = zi_scheduler_remove(&s_scheduler, &s_worker_a_thread);
  }
  if (ZiSucceeded(status) && s_worker_b_thread.is_queued != 0) {
    status = zi_scheduler_remove(&s_scheduler, &s_worker_b_thread);
  }
  if (ZiSucceeded(status) && s_scheduler.current_thread == &s_boot_thread) {
    s_worker_a_thread.state = ZI_THREAD_TERMINATED;
    s_worker_b_thread.state = ZI_THREAD_TERMINATED;
    status = zi_kernel_stack_release(&s_worker_a_stack);
    if (ZiSucceeded(status)) {
      status = zi_kernel_stack_release(&s_worker_b_stack);
    }
    if (ZiSucceeded(status)) {
      s_worker_a_context.stack_base = NULL;
      s_worker_a_context.stack_size = 0;
      s_worker_b_context.stack_base = NULL;
      s_worker_b_context.stack_size = 0;
    }
  } else if (ZiSucceeded(status)) {
    status = ZI_STATUS_INVALID_STATE;
  }
  zi_x64_interrupt_guard_release(guard);
  return status;
}

static _Noreturn void idle_thread_main(void) {
  for (;;) {
    ZkArchPause();
  }
}

static _Noreturn void worker_a_main(void) {
  for (;;) {
    ++s_worker_a_counter;
    ZkArchPause();
  }
}

static _Noreturn void worker_b_main(void) {
  for (;;) {
    ++s_worker_b_counter;
    ZkArchPause();
  }
}

// This is the synthetic return address for a kernel-thread entry routine.
static _Noreturn void kernel_thread_exit(void) {
  zi_panic("A kernel thread returned instead of terminating through the scheduler.");
}
