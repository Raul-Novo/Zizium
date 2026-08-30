// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/boot.h"
#include "zi/kernel_memory.h"
#include "zi/memory.h"
#include "zizium/status.h"

static ZiMemoryRange g_range_storage[ZI_BOOT_MAX_MEMORY_RANGES];
static ZiMemoryInventory g_inventory;
static ZiPhysicalMemoryManager g_physical_manager;
static uint64_t g_hhdm_offset;
static bool g_memory_initialised;

static ZiStatus reassign_module_pages(const ZiBootContext* boot_context);
static ZiStatus reserve_zero_guard_page(void);

ZiStatus zi_kernel_memory_initialise(const ZiBootContext* boot_context) {
  if (boot_context == NULL || boot_context->version != ZI_BOOT_CONTEXT_VERSION ||
      boot_context->struct_size < sizeof *boot_context || boot_context->memory_ranges == NULL ||
      boot_context->memory_range_count == 0 || boot_context->hhdm_offset == 0 ||
      boot_context->paging_mode != ZI_BOOT_PAGING_X64_FOUR_LEVEL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (g_memory_initialised) {
    return ZI_STATUS_INVALID_STATE;
  }

  ZiStatus status = zi_memory_inventory_build(boot_context->memory_ranges,
                                              boot_context->memory_range_count,
                                              g_range_storage,
                                              ZI_BOOT_MAX_MEMORY_RANGES,
                                              &g_inventory);
  if (ZiFailed(status)) {
    return status;
  }
  size_t metadata_size = 0;
  status = zi_pmm_metadata_size(g_inventory.managed_page_count, &metadata_size);
  if (ZiFailed(status)) {
    return status;
  }
  uint64_t metadata_pages =
      ((uint64_t)metadata_size + ZI_MEMORY_PAGE_SIZE - 1) >> ZI_MEMORY_PAGE_SHIFT;
  uint64_t metadata_physical_base = 0;
  status =
      zi_memory_inventory_find_usable(&g_inventory, metadata_pages, 1, &metadata_physical_base);
  if (ZiFailed(status)) {
    return status;
  }
  if (boot_context->hhdm_offset > UINT64_MAX - metadata_physical_base) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  void* metadata = (void*)(uintptr_t)(boot_context->hhdm_offset + metadata_physical_base);
  status = zi_pmm_initialise(&g_inventory, metadata, metadata_size, &g_physical_manager);
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_pmm_reserve(&g_physical_manager,
                          metadata_physical_base,
                          metadata_pages,
                          ZI_MEMORY_OWNER_ALLOCATOR_METADATA);
  if (ZiFailed(status)) {
    return status;
  }
  status = reserve_zero_guard_page();
  if (ZiFailed(status)) {
    return status;
  }

  g_hhdm_offset = boot_context->hhdm_offset;
  status = reassign_module_pages(boot_context);
  if (ZiFailed(status)) {
    return status;
  }
  g_memory_initialised = true;
  return ZI_STATUS_SUCCESS;
}

ZiPhysicalMemoryManager* zi_kernel_physical_memory_manager(void) {
  if (!g_memory_initialised) {
    return NULL;
  }
  return &g_physical_manager;
}

ZiPhysicalMemoryStatistics zi_kernel_memory_statistics(void) {
  return zi_pmm_statistics(zi_kernel_physical_memory_manager());
}

ZiStatus zi_kernel_physical_pointer(uint64_t physical_base, size_t size, void** out_pointer) {
  if (!g_memory_initialised || out_pointer == NULL || size == 0 ||
      physical_base >= g_inventory.maximum_physical_address ||
      size > g_inventory.maximum_physical_address - physical_base ||
      g_hhdm_offset > UINT64_MAX - physical_base) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t end = physical_base + (uint64_t)size - 1;
  uint64_t cursor = physical_base;
  for (;;) {
    ZiPhysicalPageMetadata metadata = {0};
    ZiStatus status = zi_pmm_query(&g_physical_manager, cursor, &metadata);
    if (ZiFailed(status)) {
      return status;
    }
    if (metadata.state == ZI_MEMORY_PAGE_UNMANAGED) {
      return ZI_STATUS_OUT_OF_BOUNDS;
    }
    uint64_t page_end = cursor | (ZI_MEMORY_PAGE_SIZE - 1);
    if (page_end >= end) {
      break;
    }
    cursor = page_end + 1;
  }
  *out_pointer = (void*)(uintptr_t)(g_hhdm_offset + physical_base);
  return ZI_STATUS_SUCCESS;
}

static ZiStatus reassign_module_pages(const ZiBootContext* boot_context) {
  for (size_t index = 0; index < boot_context->module_count; ++index) {
    const ZiBootModule* module = &boot_context->modules[index];
    if (module->size == 0 || module->physical_base > UINT64_MAX - module->size) {
      return ZI_STATUS_INVALID_STATE;
    }
    uint64_t first_page = module->physical_base & ~(ZI_MEMORY_PAGE_SIZE - 1);
    uint64_t end = module->physical_base + module->size;
    if (end > UINT64_MAX - (ZI_MEMORY_PAGE_SIZE - 1)) {
      return ZI_STATUS_OUT_OF_BOUNDS;
    }
    uint64_t page_count =
        (((end + ZI_MEMORY_PAGE_SIZE - 1) & ~(ZI_MEMORY_PAGE_SIZE - 1)) - first_page) >>
        ZI_MEMORY_PAGE_SHIFT;
    ZiStatus status = zi_pmm_reassign_reserved(&g_physical_manager,
                                               first_page,
                                               page_count,
                                               ZI_MEMORY_OWNER_KERNEL,
                                               ZI_MEMORY_OWNER_MODULE);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus reserve_zero_guard_page(void) {
  ZiPhysicalPageMetadata page = {0};
  ZiStatus status = zi_pmm_query(&g_physical_manager, 0, &page);
  if (status == ZI_STATUS_OUT_OF_BOUNDS) {
    return ZI_STATUS_SUCCESS;
  }
  if (ZiFailed(status)) {
    return status;
  }
  if (page.state == ZI_MEMORY_PAGE_RESERVED) {
    return ZI_STATUS_SUCCESS;
  }
  if (page.state != ZI_MEMORY_PAGE_FREE) {
    return ZI_STATUS_INVALID_STATE;
  }
  return zi_pmm_reserve(&g_physical_manager, 0, 1, ZI_MEMORY_OWNER_ZERO_GUARD);
}
