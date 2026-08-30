// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"

#define ZI_KERNEL_STACK_VERSION 1u

typedef struct ZiKernelStack {
  uint32_t struct_size;
  uint32_t version;
  uint64_t guard_base;
  uint64_t mapped_base;
  uint64_t physical_base;
  uint64_t page_count;
  size_t usable_size;
  uint32_t slot_index;
  uint32_t reserved;
} ZiKernelStack;

ZiStatus zi_kernel_stack_allocate(size_t usable_size, ZiKernelStack* out_stack);
ZiStatus zi_kernel_stack_release(ZiKernelStack* stack);
uintptr_t zi_kernel_stack_top(const ZiKernelStack* stack);
bool zi_kernel_stack_guard_contains(uint64_t virtual_address);
