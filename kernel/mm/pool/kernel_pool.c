// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/kernel_pool.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/byte_order.h"
#include "zi/kernel_memory.h"
#include "zi/memory.h"
#include "zi/pool.h"
#include "zi/x64_interrupt.h"
#include "zi/x64_paging.h"
#include "zizium/status.h"

#define ZI_KERNEL_POOL_PAGE_COUNT UINT64_C(64)
#define ZI_KERNEL_DESCRIPTOR_CACHE_CAPACITY 64u

typedef struct ZiKernelMemoryDescriptor {
  uint64_t physical_base;
  uint64_t page_count;
  uint32_t owner;
  uint32_t flags;
} ZiKernelMemoryDescriptor;

static ZiPool g_kernel_pool;
static ZiObjectCache g_descriptor_cache;
static uint64_t g_pool_physical_base;
static bool g_kernel_pool_initialised;

static ZiStatus release_pool_pages(uint64_t physical_base);
static ZiStatus preserve_failure(ZiStatus status, ZiStatus clean_up_status);
static ZiStatus exercise_pool_allocations(void);
static ZiStatus exercise_descriptor_cache(void);

ZiStatus zi_kernel_pool_initialise(void) {
  if (g_kernel_pool_initialised) {
    return ZI_STATUS_INVALID_STATE;
  }
  uint64_t physical_base = 0;
  ZiStatus status = zi_pmm_allocate(zi_kernel_physical_memory_manager(),
                                    ZI_KERNEL_POOL_PAGE_COUNT,
                                    1,
                                    ZI_MEMORY_OWNER_KERNEL_POOL,
                                    &physical_base);
  if (ZiFailed(status)) {
    return status;
  }
  uint64_t pool_size = ZI_KERNEL_POOL_PAGE_COUNT * ZI_X64_PAGE_SIZE;
  status = zi_kernel_map_pages(ZI_KERNEL_POOL_VIRTUAL_BASE,
                               physical_base,
                               pool_size,
                               ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE | ZI_X64_PAGE_GLOBAL);
  if (ZiFailed(status)) {
    ZiStatus free_status = zi_pmm_free(zi_kernel_physical_memory_manager(),
                                       physical_base,
                                       ZI_KERNEL_POOL_PAGE_COUNT,
                                       ZI_MEMORY_OWNER_KERNEL_POOL);
    if (ZiFailed(free_status)) {
      return ZI_STATUS_MEMORY_CORRUPTION;
    }
    return status;
  }

  status = zi_pool_initialise((void*)(uintptr_t)ZI_KERNEL_POOL_VIRTUAL_BASE,
                              (size_t)pool_size,
                              &g_kernel_pool);
  if (ZiSucceeded(status)) {
    status = zi_object_cache_initialise(&g_kernel_pool,
                                        sizeof(ZiKernelMemoryDescriptor),
                                        ZI_KERNEL_DESCRIPTOR_CACHE_CAPACITY,
                                        &g_descriptor_cache);
  }
  if (ZiFailed(status)) {
    ZiStatus release_status = release_pool_pages(physical_base);
    zi_memory_zero(&g_kernel_pool, sizeof g_kernel_pool);
    zi_memory_zero(&g_descriptor_cache, sizeof g_descriptor_cache);
    if (ZiFailed(release_status)) {
      return ZI_STATUS_MEMORY_CORRUPTION;
    }
    return status;
  }
  g_pool_physical_base = physical_base;
  g_kernel_pool_initialised = true;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_kernel_pool_allocate(size_t size, void** out_allocation) {
  if (!g_kernel_pool_initialised) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiX64InterruptGuard guard = zi_x64_interrupt_guard_acquire(ZI_X64_IRQL_DISPATCH);
  ZiStatus status = zi_pool_allocate(&g_kernel_pool, size, out_allocation);
  zi_x64_interrupt_guard_release(guard);
  return status;
}

ZiStatus zi_kernel_pool_free(void* allocation) {
  if (!g_kernel_pool_initialised) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiX64InterruptGuard guard = zi_x64_interrupt_guard_acquire(ZI_X64_IRQL_DISPATCH);
  ZiStatus status = zi_pool_free(&g_kernel_pool, allocation);
  zi_x64_interrupt_guard_release(guard);
  return status;
}

ZiStatus zi_kernel_pool_validate(void) {
  if (!g_kernel_pool_initialised) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiX64InterruptGuard guard = zi_x64_interrupt_guard_acquire(ZI_X64_IRQL_DISPATCH);
  ZiStatus status = zi_pool_validate(&g_kernel_pool);
  if (ZiSucceeded(status)) {
    status = zi_object_cache_validate(&g_descriptor_cache);
  }
  zi_x64_interrupt_guard_release(guard);
  return status;
}

ZiStatus zi_kernel_pool_statistics(ZiPoolStatistics* out_statistics) {
  if (!g_kernel_pool_initialised) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiX64InterruptGuard guard = zi_x64_interrupt_guard_acquire(ZI_X64_IRQL_DISPATCH);
  ZiStatus status = zi_pool_statistics(&g_kernel_pool, out_statistics);
  zi_x64_interrupt_guard_release(guard);
  return status;
}

ZiStatus zi_kernel_pool_self_test(void) {
  if (!g_kernel_pool_initialised) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiPoolStatistics before = {0};
  ZiStatus status = zi_pool_statistics(&g_kernel_pool, &before);
  if (ZiSucceeded(status)) {
    status = exercise_pool_allocations();
  }
  if (ZiSucceeded(status)) {
    status = exercise_descriptor_cache();
  }

  ZiPoolStatistics after = {0};
  if (ZiSucceeded(status)) {
    status = zi_pool_statistics(&g_kernel_pool, &after);
  }
  if (ZiSucceeded(status) &&
      (after.allocation_count != before.allocation_count ||
       after.allocated_bytes != before.allocated_bytes || g_descriptor_cache.active_objects != 0)) {
    status = ZI_STATUS_MEMORY_CORRUPTION;
  }
  if (ZiSucceeded(status)) {
    status = zi_kernel_pool_validate();
  }
  return status;
}

static ZiStatus preserve_failure(ZiStatus status, ZiStatus clean_up_status) {
  if (ZiSucceeded(status) && ZiFailed(clean_up_status)) {
    return clean_up_status;
  }
  return status;
}

static ZiStatus exercise_pool_allocations(void) {
  const size_t sizes[] = {21, 257, 4096};
  const size_t release_order[] = {1, 0, 2};
  void* allocations[sizeof sizes / sizeof sizes[0]] = {0};
  ZiStatus status = ZI_STATUS_SUCCESS;
  for (size_t index = 0; index < sizeof sizes / sizeof sizes[0]; ++index) {
    status = zi_pool_allocate(&g_kernel_pool, sizes[index], &allocations[index]);
    if (ZiFailed(status)) {
      break;
    }
    zi_memory_zero(allocations[index], sizes[index]);
  }
  for (size_t index = 0; index < sizeof release_order / sizeof release_order[0]; ++index) {
    size_t allocation_index = release_order[index];
    if (allocations[allocation_index] != NULL) {
      ZiStatus free_status = zi_pool_free(&g_kernel_pool, allocations[allocation_index]);
      status = preserve_failure(status, free_status);
    }
  }
  return status;
}

static ZiStatus exercise_descriptor_cache(void) {
  void* objects[2] = {0};
  ZiStatus status = ZI_STATUS_SUCCESS;
  for (size_t index = 0; index < sizeof objects / sizeof objects[0]; ++index) {
    status = zi_object_cache_allocate(&g_descriptor_cache, &objects[index]);
    if (ZiFailed(status)) {
      break;
    }
  }
  if (ZiSucceeded(status)) {
    ZiKernelMemoryDescriptor* first = objects[0];
    ZiKernelMemoryDescriptor* second = objects[1];
    first->physical_base = g_pool_physical_base;
    first->page_count = ZI_KERNEL_POOL_PAGE_COUNT;
    first->owner = ZI_MEMORY_OWNER_KERNEL_POOL;
    first->flags = 0;
    second->physical_base = ZI_KERNEL_POOL_VIRTUAL_BASE;
    second->page_count = ZI_KERNEL_POOL_PAGE_COUNT;
    second->owner = ZI_MEMORY_OWNER_KERNEL_POOL;
    second->flags = ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE;
  }
  for (size_t remaining = sizeof objects / sizeof objects[0]; remaining > 0; --remaining) {
    size_t index = remaining - 1u;
    if (objects[index] != NULL) {
      ZiStatus free_status = zi_object_cache_free(&g_descriptor_cache, objects[index]);
      status = preserve_failure(status, free_status);
    }
  }
  return status;
}

static ZiStatus release_pool_pages(uint64_t physical_base) {
  ZiStatus status = zi_kernel_unmap_pages(ZI_KERNEL_POOL_VIRTUAL_BASE,
                                          ZI_KERNEL_POOL_PAGE_COUNT * ZI_X64_PAGE_SIZE);
  if (ZiFailed(status)) {
    return status;
  }
  return zi_pmm_free(zi_kernel_physical_memory_manager(),
                     physical_base,
                     ZI_KERNEL_POOL_PAGE_COUNT,
                     ZI_MEMORY_OWNER_KERNEL_POOL);
}
