// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/syscall.h"

typedef struct ZiX64CpuidResult {
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
} ZiX64CpuidResult;

typedef void (*ZiX64StackEntry)(void* context);

void ZkArchOut8(uint16_t port, uint8_t value);
uint8_t ZkArchIn8(uint16_t port);
void ZkArchPause(void);
void ZkArchCpuid(uint32_t leaf, uint32_t subleaf, ZiX64CpuidResult* out_result);
uint64_t ZkArchReadMsr(uint32_t index);
void ZkArchWriteMsr(uint32_t index, uint64_t value);
uint64_t ZkArchReadTimestamp(void);
uint64_t ZkArchReadCr2(void);
uint64_t ZkArchReadCr3(void);
void ZkArchLoadCr3(uint64_t physical_base);
void ZkArchInvalidatePage(uint64_t virtual_address);
void ZkArchMemoryBarrier(void);
void ZkArchEnablePagingProtections(void);
_Noreturn void ZkArchSwitchStackAndCall(uintptr_t stack_top, ZiX64StackEntry entry, void* context);
uint64_t ZkArchDisableInterrupts(void);
void ZkArchRestoreInterrupts(uint64_t flags);
void ZkArchEnableInterrupts(void);
void ZkArchLoadGdt(const void* base, uint16_t limit, uint16_t tss_selector);
void ZkArchLoadIdt(const void* base, uint16_t limit);
uintptr_t ZkArchBootstrapStackTop(void);
void ZkArchSaveFxState(void* state);
void ZkArchSetActiveFxState(void* state);
_Noreturn void ZkArchTriggerInvalidOpcode(void);
_Noreturn void ZkArchTriggerPageFault(void);
void ZkX64SyscallEntry(void);
int64_t ZkArchRunUser(uint64_t entry_point,
                      uint64_t user_stack_pointer,
                      uint64_t process_cr3,
                      ZiX64SyscallCpuState* cpu_state,
                      uint64_t process_parameters);
int64_t ZkArchRunNestedUser(uint64_t entry_point,
                            uint64_t user_stack_pointer,
                            uint64_t process_cr3,
                            ZiX64SyscallCpuState* cpu_state,
                            uint64_t process_parameters);
_Noreturn void ZkX64UserFaultResume(void);
_Noreturn void ZkArchHalt(void);
