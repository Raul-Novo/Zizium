// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/arch_x64.h"
#include "zi/byte_order.h"
#include "zi/kernel_memory.h"
#include "zi/kernel_stack.h"
#include "zi/memory.h"
#include "zi/x64_paging.h"
#include "zizium/status.h"

#define ZI_KERNEL_STACK_SLOT_COUNT 16u
#define ZI_KERNEL_STACK_SLOT_SIZE UINT64_C(0x20000)
#define ZI_KERNEL_STACK_GUARD_SIZE ZI_X64_PAGE_SIZE

static ZiKernelStack g_stack_slots[ZI_KERNEL_STACK_SLOT_COUNT];

static bool stack_descriptor_is_valid(const ZiKernelStack* stack);
static uint64_t slot_guard_base(size_t slot_index);

ZiStatus zi_kernel_stack_allocate(size_t usable_size, ZiKernelStack* out_stack) {
  if (out_stack == NULL || usable_size == 0 ||
      usable_size > ZI_KERNEL_STACK_SLOT_SIZE - (2u * ZI_KERNEL_STACK_GUARD_SIZE) ||
      usable_size > SIZE_MAX - (size_t)(ZI_X64_PAGE_SIZE - 1)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t mapped_size = ((uint64_t)usable_size + ZI_X64_PAGE_SIZE - 1) & ~(ZI_X64_PAGE_SIZE - 1);
  uint64_t page_count = mapped_size / ZI_X64_PAGE_SIZE;
  uint64_t flags = ZkArchDisableInterrupts();
  size_t slot_index = ZI_KERNEL_STACK_SLOT_COUNT;
  for (size_t index = 0; index < ZI_KERNEL_STACK_SLOT_COUNT; ++index) {
    if (g_stack_slots[index].version == 0) {
      slot_index = index;
      break;
    }
  }
  if (slot_index == ZI_KERNEL_STACK_SLOT_COUNT) {
    ZkArchRestoreInterrupts(flags);
    return ZI_STATUS_NO_MEMORY;
  }

  uint64_t physical_base = 0;
  ZiStatus status = zi_pmm_allocate(zi_kernel_physical_memory_manager(),
                                    page_count,
                                    1,
                                    ZI_MEMORY_OWNER_KERNEL_STACK,
                                    &physical_base);
  uint64_t guard_base = slot_guard_base(slot_index);
  uint64_t mapped_base = guard_base + ZI_KERNEL_STACK_GUARD_SIZE;
  if (ZiSucceeded(status)) {
    status = zi_kernel_map_pages(mapped_base,
                                 physical_base,
                                 mapped_size,
                                 ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE | ZI_X64_PAGE_GLOBAL);
  }
  if (ZiFailed(status)) {
    if (physical_base != 0) {
      ZiStatus free_status = zi_pmm_free(zi_kernel_physical_memory_manager(),
                                         physical_base,
                                         page_count,
                                         ZI_MEMORY_OWNER_KERNEL_STACK);
      if (ZiFailed(free_status)) {
        status = ZI_STATUS_MEMORY_CORRUPTION;
      }
    }
    ZkArchRestoreInterrupts(flags);
    return status;
  }

  zi_memory_zero((void*)(uintptr_t)mapped_base, (size_t)mapped_size);
  ZiKernelStack stack = {
      sizeof(ZiKernelStack),
      ZI_KERNEL_STACK_VERSION,
      guard_base,
      mapped_base,
      physical_base,
      page_count,
      (size_t)mapped_size,
      (uint32_t)slot_index,
      0,
  };
  g_stack_slots[slot_index] = stack;
  *out_stack = stack;
  ZkArchRestoreInterrupts(flags);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_kernel_stack_release(ZiKernelStack* stack) {
  if (!stack_descriptor_is_valid(stack)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t flags = ZkArchDisableInterrupts();
  ZiKernelStack* slot = &g_stack_slots[stack->slot_index];
  if (!stack_descriptor_is_valid(slot) || slot->mapped_base != stack->mapped_base ||
      slot->physical_base != stack->physical_base || slot->page_count != stack->page_count) {
    ZkArchRestoreInterrupts(flags);
    return ZI_STATUS_INVALID_STATE;
  }
  zi_memory_zero((void*)(uintptr_t)slot->mapped_base, slot->usable_size);
  ZiStatus status = zi_kernel_unmap_pages(slot->mapped_base, slot->page_count * ZI_X64_PAGE_SIZE);
  if (ZiSucceeded(status)) {
    status = zi_pmm_free(zi_kernel_physical_memory_manager(),
                         slot->physical_base,
                         slot->page_count,
                         ZI_MEMORY_OWNER_KERNEL_STACK);
    if (ZiFailed(status)) {
      ZiStatus restore_status =
          zi_kernel_map_pages(slot->mapped_base,
                              slot->physical_base,
                              slot->page_count * ZI_X64_PAGE_SIZE,
                              ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE | ZI_X64_PAGE_GLOBAL);
      if (ZiFailed(restore_status)) {
        status = ZI_STATUS_MEMORY_CORRUPTION;
      }
    }
  }
  if (ZiSucceeded(status)) {
    zi_memory_zero(slot, sizeof *slot);
    zi_memory_zero(stack, sizeof *stack);
  }
  ZkArchRestoreInterrupts(flags);
  return status;
}

uintptr_t zi_kernel_stack_top(const ZiKernelStack* stack) {
  if (!stack_descriptor_is_valid(stack) || stack->mapped_base > UINT64_MAX - stack->usable_size) {
    return 0;
  }
  return (uintptr_t)(stack->mapped_base + stack->usable_size);
}

bool zi_kernel_stack_guard_contains(uint64_t virtual_address) {
  for (size_t index = 0; index < ZI_KERNEL_STACK_SLOT_COUNT; ++index) {
    const ZiKernelStack* stack = &g_stack_slots[index];
    if (!stack_descriptor_is_valid(stack)) {
      continue;
    }
    if (stack->mapped_base > UINT64_MAX - stack->usable_size) {
      continue;
    }
    uint64_t upper_guard = stack->mapped_base + stack->usable_size;
    if (upper_guard > UINT64_MAX - ZI_KERNEL_STACK_GUARD_SIZE) {
      continue;
    }
    if ((virtual_address >= stack->guard_base && virtual_address < stack->mapped_base) ||
        (virtual_address >= upper_guard &&
         virtual_address < upper_guard + ZI_KERNEL_STACK_GUARD_SIZE)) {
      return true;
    }
  }
  return false;
}

static bool stack_descriptor_is_valid(const ZiKernelStack* stack) {
  if (stack == NULL || stack->struct_size != sizeof(ZiKernelStack) ||
      stack->version != ZI_KERNEL_STACK_VERSION ||
      stack->slot_index >= ZI_KERNEL_STACK_SLOT_COUNT || stack->page_count == 0 ||
      stack->page_count > (uint64_t)(SIZE_MAX / (size_t)ZI_X64_PAGE_SIZE)) {
    return false;
  }
  size_t usable_size = (size_t)stack->page_count * (size_t)ZI_X64_PAGE_SIZE;
  return (bool)(usable_size == stack->usable_size &&
                usable_size <= ZI_KERNEL_STACK_SLOT_SIZE - (2u * ZI_KERNEL_STACK_GUARD_SIZE) &&
                stack->guard_base == slot_guard_base(stack->slot_index) &&
                stack->guard_base <= UINT64_MAX - ZI_KERNEL_STACK_GUARD_SIZE &&
                stack->mapped_base == stack->guard_base + ZI_KERNEL_STACK_GUARD_SIZE &&
                stack->mapped_base <= UINT64_MAX - stack->usable_size);
}

static uint64_t slot_guard_base(size_t slot_index) {
  return ZI_KERNEL_STACK_VIRTUAL_BASE + ((uint64_t)slot_index * ZI_KERNEL_STACK_SLOT_SIZE);
}
