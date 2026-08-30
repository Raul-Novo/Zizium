// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"

#define ZI_X64_SYSCALL_FRAME_VERSION 1u
#define ZI_X64_SYSCALL_CPU_STATE_VERSION 1u

enum ZiX64SyscallAction {
  ZI_X64_SYSCALL_RETURN = 0,
  ZI_X64_SYSCALL_TERMINATE = 1,
};

typedef struct ZiSyscallFrame {
  uint32_t struct_size;
  uint32_t version;
  uint32_t action;
  uint32_t reserved;
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
  uint64_t number;
  uint64_t argument_1;
  uint64_t argument_2;
  uint64_t argument_3;
  uint64_t argument_4;
  uint64_t user_instruction_pointer;
  uint64_t user_stack_pointer;
  uint64_t user_flags;
  uint64_t result;
} ZiSyscallFrame;

typedef struct ZiX64SyscallCpuState {
  uint32_t struct_size;
  uint32_t version;
  uint64_t kernel_stack_top;
  uint64_t kernel_cr3;
  uint64_t resume_stack_pointer;
  uint64_t resume_instruction_pointer;
  uint64_t active_process_address;
  uint64_t user_stack_scratch;
  uint64_t termination_value;
} ZiX64SyscallCpuState;

bool zi_x64_syscall_return_is_safe(const ZiSyscallFrame* frame);
ZiStatus ZkDispatchSyscall(ZiSyscallFrame* frame);
