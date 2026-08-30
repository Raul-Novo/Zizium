// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"

#define ZI_X64_EXCEPTION_COUNT 32u
#define ZI_X64_INTERRUPT_VECTOR_COUNT 256u
#define ZI_X64_INTERRUPT_VECTOR_TIMER 0xd0u
#define ZI_X64_INTERRUPT_VECTOR_APIC_ERROR 0xfeu
#define ZI_X64_INTERRUPT_VECTOR_SPURIOUS 0xffu
#define ZI_X64_INTERRUPT_RETURN_USER_TERMINATED UINT64_MAX
#define ZI_X64_FX_STATE_SIZE 512u

enum ZiX64InterruptLevel {
  ZI_X64_IRQL_PASSIVE = 0,
  ZI_X64_IRQL_DISPATCH = 2,
  ZI_X64_IRQL_CLOCK = 13,
  ZI_X64_IRQL_HIGH = 15,
};

typedef struct ZiX64InterruptFrame {
  uint64_t r15;
  uint64_t r14;
  uint64_t r13;
  uint64_t r12;
  uint64_t r11;
  uint64_t r10;
  uint64_t r9;
  uint64_t r8;
  uint64_t rdi;
  uint64_t rsi;
  uint64_t rbp;
  uint64_t rbx;
  uint64_t rdx;
  uint64_t rcx;
  uint64_t rax;
  uint64_t vector;
  uint64_t error_code;
  uint64_t rip;
  uint64_t cs;
  uint64_t rflags;
  uint64_t rsp;
  uint64_t ss;
} ZiX64InterruptFrame;

typedef struct ZiX64ThreadContext {
  _Alignas(16) unsigned char fx_state[ZI_X64_FX_STATE_SIZE];
  ZiX64InterruptFrame* saved_frame;
  void* stack_base;
  size_t stack_size;
} ZiX64ThreadContext;

typedef struct ZiX64InterruptGuard {
  uint64_t flags;
  uint32_t previous_level;
} ZiX64InterruptGuard;

bool zi_x64_exception_uses_error_code(uint32_t vector);
const char* zi_x64_exception_name(uint32_t vector);
ZiStatus zi_x64_cpu_initialise(void);
ZiStatus zi_x64_guarded_stacks_initialise(uintptr_t* out_bootstrap_stack_top,
                                          uint64_t* out_guard_fault_address);
ZiStatus zi_x64_preemption_start(uint64_t apic_virtual_address);
ZiX64InterruptGuard zi_x64_interrupt_guard_acquire(uint32_t level);
void zi_x64_interrupt_guard_release(ZiX64InterruptGuard guard);
uint32_t zi_x64_current_interrupt_level(void);
uint64_t zi_x64_preemption_tick_count(void);
uint64_t zi_x64_preemption_context_switch_count(void);
ZiX64InterruptFrame* ZkX64InterruptDispatch(ZiX64InterruptFrame* frame);
