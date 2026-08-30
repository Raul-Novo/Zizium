// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/kernel_memory.h"
#include "zi/kernel_pool.h"
#include "zi/kernel_stack.h"
#include "zi/memory.h"
#include "zi/memory_stress.h"
#include "zi/pool.h"
#include "zi/x64_paging.h"
#include "zizium/status.h"

#define ZI_MEMORY_STRESS_ALLOCATION_COUNT 8u
#define ZI_MEMORY_STRESS_PHYSICAL_ROUNDS 16u
#define ZI_MEMORY_STRESS_POOL_ROUNDS 4u
#define ZI_MEMORY_STRESS_STACK_COUNT 4u
#define ZI_MEMORY_STRESS_STACK_ROUNDS 8u
#define ZI_MEMORY_STRESS_VIRTUAL_PAGE_COUNT UINT64_C(8)

static bool physical_statistics_equal(ZiPhysicalMemoryStatistics left,
                                      ZiPhysicalMemoryStatistics right);
static ZiStatus stress_physical_allocator(void);
static ZiStatus stress_pool_allocator(void);
static ZiStatus stress_pool_round(uint32_t round);
static ZiStatus stress_guarded_stacks(void);
static ZiStatus stress_virtual_mapping(void);
static ZiStatus verify_virtual_alias(uint64_t physical_base, uint64_t mapped_size);
static ZiStatus verify_virtual_protection(uint64_t mapped_size);
static ZiStatus verify_virtual_unmapped(void);

ZiStatus zi_kernel_memory_stress_test(void) {
  ZiPhysicalMemoryStatistics before = zi_kernel_memory_statistics();
  ZiStatus status = stress_physical_allocator();
  if (ZiSucceeded(status)) {
    status = stress_virtual_mapping();
  }
  if (ZiSucceeded(status)) {
    status = stress_pool_allocator();
  }
  if (ZiSucceeded(status)) {
    status = stress_guarded_stacks();
  }
  if (ZiFailed(status)) {
    return status;
  }
  ZiPhysicalMemoryStatistics after = zi_kernel_memory_statistics();
  if (!physical_statistics_equal(before, after)) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  return ZI_STATUS_SUCCESS;
}

static bool physical_statistics_equal(ZiPhysicalMemoryStatistics left,
                                      ZiPhysicalMemoryStatistics right) {
  return (bool)(left.managed_pages == right.managed_pages && left.free_pages == right.free_pages &&
                left.reserved_pages == right.reserved_pages &&
                left.allocated_pages == right.allocated_pages);
}

static ZiStatus stress_physical_allocator(void) {
  ZiPhysicalMemoryManager* manager = zi_kernel_physical_memory_manager();
  if (manager == NULL) {
    return ZI_STATUS_INVALID_STATE;
  }
  for (uint32_t round = 0; round < ZI_MEMORY_STRESS_PHYSICAL_ROUNDS; ++round) {
    uint64_t allocations[ZI_MEMORY_STRESS_ALLOCATION_COUNT] = {0};
    uint64_t page_counts[ZI_MEMORY_STRESS_ALLOCATION_COUNT] = {0};
    size_t allocated_count = 0;
    ZiStatus status = ZI_STATUS_SUCCESS;
    for (size_t index = 0; index < ZI_MEMORY_STRESS_ALLOCATION_COUNT; ++index) {
      uint64_t page_count = (((uint64_t)round + index) % 4u) + 1u;
      uint64_t alignment_pages = UINT64_C(1) << (((uint64_t)round + index) % 3u);
      status = zi_pmm_allocate(manager,
                               page_count,
                               alignment_pages,
                               ZI_MEMORY_OWNER_TEST,
                               &allocations[index]);
      if (ZiFailed(status)) {
        break;
      }
      page_counts[index] = page_count;
      ++allocated_count;
      if (((allocations[index] >> ZI_MEMORY_PAGE_SHIFT) & (alignment_pages - 1u)) != 0) {
        status = ZI_STATUS_ALIGNMENT_ERROR;
        break;
      }
      ZiPhysicalPageMetadata metadata = {0};
      status = zi_pmm_query(manager, allocations[index], &metadata);
      if (ZiFailed(status)) {
        break;
      }
      if (metadata.state != ZI_MEMORY_PAGE_ALLOCATED || metadata.owner != ZI_MEMORY_OWNER_TEST) {
        status = ZI_STATUS_MEMORY_CORRUPTION;
        break;
      }
    }
    for (size_t remaining = allocated_count; remaining > 0; --remaining) {
      size_t index = remaining - 1u;
      ZiStatus free_status =
          zi_pmm_free(manager, allocations[index], page_counts[index], ZI_MEMORY_OWNER_TEST);
      if (ZiSucceeded(status) && ZiFailed(free_status)) {
        status = free_status;
      }
    }
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus stress_pool_allocator(void) {
  ZiPoolStatistics before = {0};
  ZiStatus status = zi_kernel_pool_statistics(&before);
  if (ZiFailed(status)) {
    return status;
  }
  for (uint32_t round = 0; round < ZI_MEMORY_STRESS_POOL_ROUNDS; ++round) {
    status = stress_pool_round(round);
    if (ZiFailed(status)) {
      return status;
    }
  }
  ZiPoolStatistics after = {0};
  status = zi_kernel_pool_statistics(&after);
  if (ZiFailed(status)) {
    return status;
  }
  if (after.allocation_count != before.allocation_count ||
      after.allocated_bytes != before.allocated_bytes) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  return zi_kernel_pool_validate();
}

static ZiStatus stress_pool_round(uint32_t round) {
  void* allocations[ZI_MEMORY_STRESS_ALLOCATION_COUNT] = {0};
  size_t sizes[ZI_MEMORY_STRESS_ALLOCATION_COUNT] = {0};
  size_t allocated_count = 0;
  ZiStatus status = ZI_STATUS_SUCCESS;
  for (size_t index = 0; index < ZI_MEMORY_STRESS_ALLOCATION_COUNT; ++index) {
    sizes[index] = ((((size_t)round + 1u) * (index + 3u) * 37u) % 1536u) + 1u;
    status = zi_kernel_pool_allocate(sizes[index], &allocations[index]);
    if (ZiFailed(status)) {
      break;
    }
    ++allocated_count;
    unsigned char* bytes = allocations[index];
    bytes[0] = (unsigned char)(round + 1u);
    bytes[sizes[index] - 1u] = (unsigned char)(index + 1u);
  }
  for (size_t parity = 0; parity < 2; ++parity) {
    for (size_t index = parity; index < allocated_count; index += 2u) {
      ZiStatus free_status = zi_kernel_pool_free(allocations[index]);
      if (ZiSucceeded(status) && ZiFailed(free_status)) {
        status = free_status;
      }
    }
  }
  if (ZiFailed(status)) {
    return status;
  }
  return zi_kernel_pool_self_test();
}

static ZiStatus stress_guarded_stacks(void) {
  for (uint32_t round = 0; round < ZI_MEMORY_STRESS_STACK_ROUNDS; ++round) {
    ZiKernelStack stacks[ZI_MEMORY_STRESS_STACK_COUNT] = {0};
    uint64_t guard_addresses[ZI_MEMORY_STRESS_STACK_COUNT] = {0};
    size_t allocated_count = 0;
    ZiStatus status = ZI_STATUS_SUCCESS;
    for (size_t index = 0; index < ZI_MEMORY_STRESS_STACK_COUNT; ++index) {
      size_t usable_size = (size_t)(index + 2u) * 8192u;
      status = zi_kernel_stack_allocate(usable_size, &stacks[index]);
      if (ZiFailed(status)) {
        break;
      }
      ++allocated_count;
      guard_addresses[index] = stacks[index].guard_base;
      uint64_t upper_guard = stacks[index].mapped_base + stacks[index].usable_size;
      if (zi_kernel_stack_top(&stacks[index]) != upper_guard ||
          !zi_kernel_stack_guard_contains(stacks[index].guard_base) ||
          !zi_kernel_stack_guard_contains(upper_guard)) {
        status = ZI_STATUS_MEMORY_CORRUPTION;
        break;
      }
    }
    for (size_t remaining = allocated_count; remaining > 0; --remaining) {
      size_t index = remaining - 1u;
      ZiStatus release_status = zi_kernel_stack_release(&stacks[index]);
      if (ZiSucceeded(status) && ZiFailed(release_status)) {
        status = release_status;
      }
      if (ZiSucceeded(status) && zi_kernel_stack_guard_contains(guard_addresses[index])) {
        status = ZI_STATUS_MEMORY_CORRUPTION;
      }
    }
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus stress_virtual_mapping(void) {
  ZiPhysicalMemoryManager* manager = zi_kernel_physical_memory_manager();
  if (manager == NULL) {
    return ZI_STATUS_INVALID_STATE;
  }
  uint64_t physical_base = 0;
  ZiStatus status = zi_pmm_allocate(manager,
                                    ZI_MEMORY_STRESS_VIRTUAL_PAGE_COUNT,
                                    1,
                                    ZI_MEMORY_OWNER_TEST,
                                    &physical_base);
  if (ZiFailed(status)) {
    return status;
  }
  uint64_t mapped_size = ZI_MEMORY_STRESS_VIRTUAL_PAGE_COUNT * ZI_X64_PAGE_SIZE;
  bool mapped = false;
  status = zi_kernel_map_pages(ZI_KERNEL_STRESS_VIRTUAL_BASE,
                               physical_base,
                               mapped_size,
                               ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE | ZI_X64_PAGE_GLOBAL);
  mapped = ZiSucceeded(status);
  if (ZiSucceeded(status)) {
    status = verify_virtual_alias(physical_base, mapped_size);
  }
  if (ZiSucceeded(status)) {
    status = verify_virtual_protection(mapped_size);
  }
  if (mapped) {
    ZiStatus unmap_status = zi_kernel_unmap_pages(ZI_KERNEL_STRESS_VIRTUAL_BASE, mapped_size);
    if (ZiSucceeded(status) && ZiFailed(unmap_status)) {
      status = unmap_status;
    }
    mapped = ZiFailed(unmap_status);
  }
  if (ZiSucceeded(status)) {
    status = verify_virtual_unmapped();
  }
  if (!mapped) {
    ZiStatus free_status = zi_pmm_free(manager,
                                       physical_base,
                                       ZI_MEMORY_STRESS_VIRTUAL_PAGE_COUNT,
                                       ZI_MEMORY_OWNER_TEST);
    if (ZiSucceeded(status) && ZiFailed(free_status)) {
      status = free_status;
    }
  }
  return status;
}

static ZiStatus verify_virtual_alias(uint64_t physical_base, uint64_t mapped_size) {
  ZiX64PageMapping mapping = {0};
  ZiStatus status =
      zi_x64_paging_query(zi_kernel_paging_context(), ZI_KERNEL_STRESS_VIRTUAL_BASE, &mapping);
  if (ZiFailed(status)) {
    return status;
  }
  if (mapping.physical_base != physical_base ||
      mapping.protection != (ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE | ZI_X64_PAGE_GLOBAL)) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  void* direct_pointer = NULL;
  status = zi_kernel_physical_pointer(physical_base, (size_t)mapped_size, &direct_pointer);
  if (ZiFailed(status)) {
    return status;
  }
  volatile uint64_t* mapped_words = (volatile uint64_t*)(uintptr_t)ZI_KERNEL_STRESS_VIRTUAL_BASE;
  volatile uint64_t* direct_words = direct_pointer;
  size_t last_word = (size_t)(mapped_size / sizeof(uint64_t)) - 1u;
  // The queried page-table mapping makes this fixed kernel address intentional.
  // NOLINTNEXTLINE(clang-analyzer-core.FixedAddressDereference)
  mapped_words[0] = UINT64_C(0x6496e6d1ecfc1720);
  mapped_words[last_word] = UINT64_C(0x1720335f6f8ad7e7);
  if (direct_words[0] != mapped_words[0] || direct_words[last_word] != mapped_words[last_word]) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus verify_virtual_protection(uint64_t mapped_size) {
  ZiStatus status = zi_kernel_protect_pages(ZI_KERNEL_STRESS_VIRTUAL_BASE,
                                            mapped_size,
                                            ZI_X64_PAGE_READ | ZI_X64_PAGE_GLOBAL);
  if (ZiFailed(status)) {
    return status;
  }
  ZiStatus write_execute_status = zi_kernel_protect_pages(
      ZI_KERNEL_STRESS_VIRTUAL_BASE,
      ZI_X64_PAGE_SIZE,
      ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE | ZI_X64_PAGE_EXECUTE | ZI_X64_PAGE_GLOBAL);
  if (write_execute_status != ZI_STATUS_INVALID_ARGUMENT) {
    if (ZiFailed(write_execute_status)) {
      return write_execute_status;
    }
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  ZiX64PageMapping mapping = {0};
  status = zi_x64_paging_query(zi_kernel_paging_context(), ZI_KERNEL_STRESS_VIRTUAL_BASE, &mapping);
  if (ZiFailed(status)) {
    return status;
  }
  if (mapping.protection != (ZI_X64_PAGE_READ | ZI_X64_PAGE_GLOBAL)) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus verify_virtual_unmapped(void) {
  ZiX64PageMapping mapping = {0};
  ZiStatus status =
      zi_x64_paging_query(zi_kernel_paging_context(), ZI_KERNEL_STRESS_VIRTUAL_BASE, &mapping);
  if (status == ZI_STATUS_PAGE_NOT_MAPPED) {
    return ZI_STATUS_SUCCESS;
  }
  if (ZiFailed(status)) {
    return status;
  }
  return ZI_STATUS_MEMORY_CORRUPTION;
}
