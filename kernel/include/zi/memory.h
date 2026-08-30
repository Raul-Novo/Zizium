// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/boot.h"
#include "zizium/status.h"

#define ZI_MEMORY_PAGE_SHIFT 12u
#define ZI_MEMORY_PAGE_SIZE (UINT64_C(1) << ZI_MEMORY_PAGE_SHIFT)

enum ZiMemoryPageState {
  ZI_MEMORY_PAGE_UNMANAGED = 0,
  ZI_MEMORY_PAGE_FREE = 1,
  ZI_MEMORY_PAGE_RESERVED = 2,
  ZI_MEMORY_PAGE_ALLOCATED = 3,
};

enum ZiMemoryOwner {
  ZI_MEMORY_OWNER_NONE = 0,
  ZI_MEMORY_OWNER_FIRMWARE = 1,
  ZI_MEMORY_OWNER_BOOTLOADER = 2,
  ZI_MEMORY_OWNER_KERNEL = 3,
  ZI_MEMORY_OWNER_MODULE = 4,
  ZI_MEMORY_OWNER_FRAMEBUFFER = 5,
  ZI_MEMORY_OWNER_ALLOCATOR_METADATA = 6,
  ZI_MEMORY_OWNER_PAGE_TABLE = 7,
  ZI_MEMORY_OWNER_KERNEL_STACK = 8,
  ZI_MEMORY_OWNER_KERNEL_POOL = 9,
  ZI_MEMORY_OWNER_TEMPORARY_MAPPING = 10,
  ZI_MEMORY_OWNER_TEST = 11,
  ZI_MEMORY_OWNER_ZERO_GUARD = 12,
  ZI_MEMORY_OWNER_PROCESS_IMAGE = 13,
  ZI_MEMORY_OWNER_USER_STACK = 14,
  ZI_MEMORY_OWNER_PROCESS_DATA = 15,
  ZI_MEMORY_OWNER_DMA = 16,
};

typedef struct ZiMemoryRange {
  uint64_t physical_base;
  uint64_t page_count;
  uint32_t type;
  uint32_t owner;
} ZiMemoryRange;

typedef struct ZiMemoryInventory {
  ZiMemoryRange* ranges;
  size_t range_count;
  size_t range_capacity;
  uint64_t maximum_physical_address;
  uint64_t managed_page_count;
  uint64_t initially_usable_page_count;
} ZiMemoryInventory;

typedef struct ZiPhysicalPageMetadata {
  uint8_t state;
  uint8_t owner;
} ZiPhysicalPageMetadata;

typedef struct ZiPhysicalMemoryStatistics {
  uint64_t managed_pages;
  uint64_t free_pages;
  uint64_t reserved_pages;
  uint64_t allocated_pages;
} ZiPhysicalMemoryStatistics;

typedef struct ZiPhysicalMemoryManager {
  const ZiMemoryInventory* inventory;
  ZiPhysicalPageMetadata* pages;
  uint64_t metadata_page_count;
  ZiPhysicalMemoryStatistics statistics;
} ZiPhysicalMemoryManager;

ZiStatus zi_memory_inventory_build(const ZiBootMemoryRange* boot_ranges,
                                   size_t boot_range_count,
                                   ZiMemoryRange* storage,
                                   size_t storage_capacity,
                                   ZiMemoryInventory* out_inventory);
ZiStatus zi_memory_inventory_find_usable(const ZiMemoryInventory* inventory,
                                         uint64_t page_count,
                                         uint64_t alignment_pages,
                                         uint64_t* out_physical_base);
ZiStatus zi_pmm_metadata_size(uint64_t page_count, size_t* out_size);
ZiStatus zi_pmm_initialise(const ZiMemoryInventory* inventory,
                           void* metadata_storage,
                           size_t metadata_size,
                           ZiPhysicalMemoryManager* out_manager);
ZiStatus zi_pmm_reserve(ZiPhysicalMemoryManager* manager,
                        uint64_t physical_base,
                        uint64_t page_count,
                        uint32_t owner);
ZiStatus zi_pmm_reassign_reserved(ZiPhysicalMemoryManager* manager,
                                  uint64_t physical_base,
                                  uint64_t page_count,
                                  uint32_t expected_owner,
                                  uint32_t new_owner);
ZiStatus zi_pmm_allocate(ZiPhysicalMemoryManager* manager,
                         uint64_t page_count,
                         uint64_t alignment_pages,
                         uint32_t owner,
                         uint64_t* out_physical_base);
ZiStatus zi_pmm_allocate_below(ZiPhysicalMemoryManager* manager,
                               uint64_t page_count,
                               uint64_t alignment_pages,
                               uint64_t maximum_physical_address,
                               uint32_t owner,
                               uint64_t* out_physical_base);
ZiStatus zi_pmm_free(ZiPhysicalMemoryManager* manager,
                     uint64_t physical_base,
                     uint64_t page_count,
                     uint32_t expected_owner);
ZiStatus zi_pmm_query(const ZiPhysicalMemoryManager* manager,
                      uint64_t physical_address,
                      ZiPhysicalPageMetadata* out_metadata);
ZiPhysicalMemoryStatistics zi_pmm_statistics(const ZiPhysicalMemoryManager* manager);
