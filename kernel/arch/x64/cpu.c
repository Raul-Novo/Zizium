// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdint.h>

#include "x64_internal.h"
#include "zi/arch_x64.h"
#include "zi/kernel_stack.h"
#include "zi/x64_interrupt.h"
#include "zizium/status.h"

_Alignas(16) static unsigned char s_boot_fx_state[ZI_X64_FX_STATE_SIZE];
static ZiKernelStack s_bootstrap_stack;
static ZiKernelStack s_double_fault_stack;
static ZiKernelStack s_nmi_stack;
static ZiKernelStack s_machine_check_stack;

ZiStatus zi_x64_cpu_initialise(void) {
  (void)ZkArchDisableInterrupts();
  ZiStatus status = zi_x64_descriptor_tables_initialise();
  if (ZiFailed(status)) {
    return status;
  }

  ZkArchSaveFxState(s_boot_fx_state);
  ZkArchSetActiveFxState(s_boot_fx_state);
  status = zi_x64_idt_initialise();
  if (ZiFailed(status)) {
    return status;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_x64_guarded_stacks_initialise(uintptr_t* out_bootstrap_stack_top,
                                          uint64_t* out_guard_fault_address) {
  if (out_bootstrap_stack_top == NULL || out_guard_fault_address == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_kernel_stack_allocate(65536u, &s_bootstrap_stack);
  if (ZiSucceeded(status)) {
    status = zi_kernel_stack_allocate(32768u, &s_double_fault_stack);
  }
  if (ZiSucceeded(status)) {
    status = zi_kernel_stack_allocate(32768u, &s_nmi_stack);
  }
  if (ZiSucceeded(status)) {
    status = zi_kernel_stack_allocate(32768u, &s_machine_check_stack);
  }
  uintptr_t bootstrap_top = zi_kernel_stack_top(&s_bootstrap_stack);
  uintptr_t double_fault_top = zi_kernel_stack_top(&s_double_fault_stack);
  uintptr_t nmi_top = zi_kernel_stack_top(&s_nmi_stack);
  uintptr_t machine_check_top = zi_kernel_stack_top(&s_machine_check_stack);
  if (ZiSucceeded(status)) {
    status = zi_x64_descriptor_tables_set_stacks(bootstrap_top,
                                                 double_fault_top,
                                                 nmi_top,
                                                 machine_check_top);
  }
  if (ZiFailed(status)) {
    if (s_machine_check_stack.version != 0) {
      (void)zi_kernel_stack_release(&s_machine_check_stack);
    }
    if (s_nmi_stack.version != 0) {
      (void)zi_kernel_stack_release(&s_nmi_stack);
    }
    if (s_double_fault_stack.version != 0) {
      (void)zi_kernel_stack_release(&s_double_fault_stack);
    }
    if (s_bootstrap_stack.version != 0) {
      (void)zi_kernel_stack_release(&s_bootstrap_stack);
    }
    return status;
  }
  *out_bootstrap_stack_top = bootstrap_top;
  *out_guard_fault_address = s_bootstrap_stack.guard_base;
  return ZI_STATUS_SUCCESS;
}
