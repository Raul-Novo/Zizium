// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/boot.h"
#include "zi/byte_order.h"
#include "zi/memory.h"
#include "zizium/status.h"

typedef struct ZiMemoryInventoryTotals {
  size_t output_count;
  uint64_t managed_pages;
  uint64_t usable_pages;
  uint64_t maximum_address;
} ZiMemoryInventoryTotals;

typedef struct ZiPmmAllocationRequest {
  uint64_t page_count;
  uint64_t alignment_pages;
  uint64_t maximum_physical_address;
  uint32_t owner;
  uint64_t* out_physical_base;
} ZiPmmAllocationRequest;

static ZiStatus copy_boot_ranges(const ZiBootMemoryRange* boot_ranges,
                                 size_t boot_range_count,
                                 ZiMemoryRange* storage);
static ZiStatus
append_inventory_range(ZiMemoryRange* storage, ZiMemoryRange range, size_t* in_out_count);
static ZiStatus account_inventory_range(ZiMemoryRange range, ZiMemoryInventoryTotals* totals);
static ZiStatus
merge_inventory_ranges(ZiMemoryRange* storage, size_t count, ZiMemoryInventoryTotals* out_totals);
static ZiStatus locate_page_interval(const ZiPhysicalMemoryManager* manager,
                                     uint64_t physical_base,
                                     uint64_t page_count,
                                     uint64_t* out_metadata_index);
static ZiStatus locate_page(const ZiPhysicalMemoryManager* manager,
                            uint64_t physical_address,
                            uint64_t* out_metadata_index);
static uint64_t range_metadata_start(const ZiMemoryInventory* inventory, size_t range_index);
static uint32_t owner_for_boot_type(uint32_t type);
static void sort_ranges(ZiMemoryRange* ranges, size_t count);
static bool allocation_owner_is_valid(uint32_t owner);
static bool reservation_owner_is_valid(uint32_t owner);
static bool
run_is_free(const ZiPhysicalMemoryManager* manager, uint64_t first_page, uint64_t page_count);
static ZiStatus allocate_from_range(ZiPhysicalMemoryManager* manager,
                                    const ZiMemoryRange* range,
                                    uint64_t metadata_start,
                                    const ZiPmmAllocationRequest* request);

ZiStatus zi_memory_inventory_build(const ZiBootMemoryRange* boot_ranges,
                                   size_t boot_range_count,
                                   ZiMemoryRange* storage,
                                   size_t storage_capacity,
                                   ZiMemoryInventory* out_inventory) {
  if (boot_ranges == NULL || boot_range_count == 0 || storage == NULL ||
      storage_capacity < boot_range_count || out_inventory == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = copy_boot_ranges(boot_ranges, boot_range_count, storage);
  if (ZiFailed(status)) {
    return status;
  }
  sort_ranges(storage, boot_range_count);
  ZiMemoryInventoryTotals totals = {0};
  status = merge_inventory_ranges(storage, boot_range_count, &totals);
  if (ZiFailed(status)) {
    return status;
  }

  out_inventory->ranges = storage;
  out_inventory->range_count = totals.output_count;
  out_inventory->range_capacity = storage_capacity;
  out_inventory->maximum_physical_address = totals.maximum_address;
  out_inventory->managed_page_count = totals.managed_pages;
  out_inventory->initially_usable_page_count = totals.usable_pages;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus copy_boot_ranges(const ZiBootMemoryRange* boot_ranges,
                                 size_t boot_range_count,
                                 ZiMemoryRange* storage) {
  for (size_t index = 0; index < boot_range_count; ++index) {
    const ZiBootMemoryRange* source = &boot_ranges[index];
    if (source->size == 0 || source->type > ZI_BOOT_MEMORY_RESERVED_MAPPED ||
        (source->physical_base & (ZI_MEMORY_PAGE_SIZE - 1)) != 0 ||
        (source->size & (ZI_MEMORY_PAGE_SIZE - 1)) != 0 ||
        source->physical_base > UINT64_MAX - source->size) {
      return ZI_STATUS_INVALID_ARGUMENT;
    }
    storage[index].physical_base = source->physical_base;
    storage[index].page_count = source->size >> ZI_MEMORY_PAGE_SHIFT;
    storage[index].type = source->type;
    storage[index].owner = owner_for_boot_type(source->type);
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus
append_inventory_range(ZiMemoryRange* storage, ZiMemoryRange range, size_t* in_out_count) {
  if (*in_out_count == 0) {
    storage[0] = range;
    *in_out_count = 1;
    return ZI_STATUS_SUCCESS;
  }
  ZiMemoryRange* previous = &storage[*in_out_count - 1u];
  uint64_t previous_end = previous->physical_base + (previous->page_count << ZI_MEMORY_PAGE_SHIFT);
  if (range.physical_base < previous_end) {
    return ZI_STATUS_ADDRESS_CONFLICT;
  }
  if (range.physical_base == previous_end && range.type == previous->type) {
    if (previous->page_count > UINT64_MAX - range.page_count) {
      return ZI_STATUS_OUT_OF_BOUNDS;
    }
    previous->page_count += range.page_count;
    return ZI_STATUS_SUCCESS;
  }
  storage[*in_out_count] = range;
  ++*in_out_count;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus account_inventory_range(ZiMemoryRange range, ZiMemoryInventoryTotals* totals) {
  if (totals->managed_pages > UINT64_MAX - range.page_count) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  totals->managed_pages += range.page_count;
  if (range.type == ZI_BOOT_MEMORY_USABLE) {
    if (totals->usable_pages > UINT64_MAX - range.page_count) {
      return ZI_STATUS_OUT_OF_BOUNDS;
    }
    totals->usable_pages += range.page_count;
  }
  uint64_t range_end = range.physical_base + (range.page_count << ZI_MEMORY_PAGE_SHIFT);
  if (range_end > totals->maximum_address) {
    totals->maximum_address = range_end;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus
merge_inventory_ranges(ZiMemoryRange* storage, size_t count, ZiMemoryInventoryTotals* out_totals) {
  ZiMemoryInventoryTotals totals = {0};
  for (size_t index = 0; index < count; ++index) {
    ZiMemoryRange range = storage[index];
    ZiStatus status = append_inventory_range(storage, range, &totals.output_count);
    if (ZiSucceeded(status)) {
      status = account_inventory_range(range, &totals);
    }
    if (ZiFailed(status)) {
      return status;
    }
  }
  *out_totals = totals;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_memory_inventory_find_usable(const ZiMemoryInventory* inventory,
                                         uint64_t page_count,
                                         uint64_t alignment_pages,
                                         uint64_t* out_physical_base) {
  if (inventory == NULL || inventory->ranges == NULL || page_count == 0 || alignment_pages == 0 ||
      (alignment_pages & (alignment_pages - 1)) != 0 || out_physical_base == NULL ||
      alignment_pages > UINT64_MAX / ZI_MEMORY_PAGE_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_physical_base = 0;
  uint64_t alignment = alignment_pages * ZI_MEMORY_PAGE_SIZE;
  for (size_t index = 0; index < inventory->range_count; ++index) {
    const ZiMemoryRange* range = &inventory->ranges[index];
    if (range->type != ZI_BOOT_MEMORY_USABLE) {
      continue;
    }
    uint64_t mask = alignment - 1;
    if (range->physical_base > UINT64_MAX - mask) {
      continue;
    }
    uint64_t candidate = (range->physical_base + mask) & ~mask;
    uint64_t range_size = range->page_count << ZI_MEMORY_PAGE_SHIFT;
    uint64_t range_end = range->physical_base + range_size;
    if (candidate <= range_end && page_count <= (range_end - candidate) / ZI_MEMORY_PAGE_SIZE) {
      *out_physical_base = candidate;
      return ZI_STATUS_SUCCESS;
    }
  }
  return ZI_STATUS_NO_MEMORY;
}

ZiStatus zi_pmm_metadata_size(uint64_t page_count, size_t* out_size) {
  if (page_count == 0 || out_size == NULL ||
      page_count > SIZE_MAX / sizeof(ZiPhysicalPageMetadata)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_size = (size_t)page_count * sizeof(ZiPhysicalPageMetadata);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_pmm_initialise(const ZiMemoryInventory* inventory,
                           void* metadata_storage,
                           size_t metadata_size,
                           ZiPhysicalMemoryManager* out_manager) {
  if (inventory == NULL || inventory->ranges == NULL || inventory->range_count == 0 ||
      inventory->managed_page_count == 0 || metadata_storage == NULL || out_manager == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  size_t required_size = 0;
  ZiStatus status = zi_pmm_metadata_size(inventory->managed_page_count, &required_size);
  if (ZiFailed(status)) {
    return status;
  }
  if (metadata_size < required_size) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }

  zi_memory_zero(metadata_storage, required_size);
  ZiPhysicalPageMetadata* pages = metadata_storage;
  ZiPhysicalMemoryStatistics statistics = {0};
  uint64_t metadata_index = 0;
  for (size_t range_index = 0; range_index < inventory->range_count; ++range_index) {
    const ZiMemoryRange* range = &inventory->ranges[range_index];
    uint8_t state = ZI_MEMORY_PAGE_RESERVED;
    uint8_t owner = (uint8_t)range->owner;
    if (range->type == ZI_BOOT_MEMORY_USABLE) {
      state = ZI_MEMORY_PAGE_FREE;
      owner = ZI_MEMORY_OWNER_NONE;
      statistics.free_pages += range->page_count;
    } else {
      statistics.reserved_pages += range->page_count;
    }
    statistics.managed_pages += range->page_count;
    for (uint64_t offset = 0; offset < range->page_count; ++offset) {
      pages[metadata_index + offset].state = state;
      pages[metadata_index + offset].owner = owner;
    }
    metadata_index += range->page_count;
  }

  out_manager->inventory = inventory;
  out_manager->pages = pages;
  out_manager->metadata_page_count = inventory->managed_page_count;
  out_manager->statistics = statistics;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_pmm_reserve(ZiPhysicalMemoryManager* manager,
                        uint64_t physical_base,
                        uint64_t page_count,
                        uint32_t owner) {
  if (manager == NULL || manager->pages == NULL || !reservation_owner_is_valid(owner)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t first_page = 0;
  ZiStatus status = locate_page_interval(manager, physical_base, page_count, &first_page);
  if (ZiFailed(status)) {
    return status;
  }
  if (!run_is_free(manager, first_page, page_count)) {
    return ZI_STATUS_RESOURCE_IN_USE;
  }
  for (uint64_t offset = 0; offset < page_count; ++offset) {
    manager->pages[first_page + offset].state = ZI_MEMORY_PAGE_RESERVED;
    manager->pages[first_page + offset].owner = (uint8_t)owner;
  }
  manager->statistics.free_pages -= page_count;
  manager->statistics.reserved_pages += page_count;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_pmm_reassign_reserved(ZiPhysicalMemoryManager* manager,
                                  uint64_t physical_base,
                                  uint64_t page_count,
                                  uint32_t expected_owner,
                                  uint32_t new_owner) {
  if (manager == NULL || manager->pages == NULL || expected_owner == ZI_MEMORY_OWNER_NONE ||
      expected_owner > ZI_MEMORY_OWNER_TEST || new_owner == ZI_MEMORY_OWNER_NONE ||
      new_owner > ZI_MEMORY_OWNER_TEST) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t first_page = 0;
  ZiStatus status = locate_page_interval(manager, physical_base, page_count, &first_page);
  if (ZiFailed(status)) {
    return status;
  }
  for (uint64_t offset = 0; offset < page_count; ++offset) {
    const ZiPhysicalPageMetadata* page = &manager->pages[first_page + offset];
    if (page->state != ZI_MEMORY_PAGE_RESERVED || page->owner != expected_owner) {
      return ZI_STATUS_INVALID_STATE;
    }
  }
  for (uint64_t offset = 0; offset < page_count; ++offset) {
    manager->pages[first_page + offset].owner = (uint8_t)new_owner;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_pmm_allocate(ZiPhysicalMemoryManager* manager,
                         uint64_t page_count,
                         uint64_t alignment_pages,
                         uint32_t owner,
                         uint64_t* out_physical_base) {
  return zi_pmm_allocate_below(manager,
                               page_count,
                               alignment_pages,
                               UINT64_MAX,
                               owner,
                               out_physical_base);
}

ZiStatus zi_pmm_allocate_below(ZiPhysicalMemoryManager* manager,
                               uint64_t page_count,
                               uint64_t alignment_pages,
                               uint64_t maximum_physical_address,
                               uint32_t owner,
                               uint64_t* out_physical_base) {
  if (manager == NULL || manager->pages == NULL || page_count == 0 || alignment_pages == 0 ||
      (alignment_pages & (alignment_pages - 1)) != 0 || !allocation_owner_is_valid(owner) ||
      out_physical_base == NULL || maximum_physical_address < ZI_MEMORY_PAGE_SIZE - 1) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_physical_base = 0;
  if (page_count > manager->statistics.free_pages || page_count > manager->metadata_page_count) {
    return ZI_STATUS_NO_MEMORY;
  }

  ZiPmmAllocationRequest request = {
      page_count,
      alignment_pages,
      maximum_physical_address,
      owner,
      out_physical_base,
  };
  uint64_t metadata_start = 0;
  for (size_t range_index = 0; range_index < manager->inventory->range_count; ++range_index) {
    const ZiMemoryRange* range = &manager->inventory->ranges[range_index];
    ZiStatus status = allocate_from_range(manager, range, metadata_start, &request);
    if (status != ZI_STATUS_NOT_FOUND) {
      return status;
    }
    metadata_start += range->page_count;
  }
  return ZI_STATUS_NO_MEMORY;
}

static ZiStatus allocate_from_range(ZiPhysicalMemoryManager* manager,
                                    const ZiMemoryRange* range,
                                    uint64_t metadata_start,
                                    const ZiPmmAllocationRequest* request) {
  if (range->type != ZI_BOOT_MEMORY_USABLE || request->page_count > range->page_count) {
    return ZI_STATUS_NOT_FOUND;
  }
  uint64_t first_physical_page = range->physical_base >> ZI_MEMORY_PAGE_SHIFT;
  uint64_t mask = request->alignment_pages - 1u;
  if (first_physical_page > UINT64_MAX - mask) {
    return ZI_STATUS_NOT_FOUND;
  }
  uint64_t candidate_physical_page = (first_physical_page + mask) & ~mask;
  uint64_t candidate_offset = candidate_physical_page - first_physical_page;
  while (candidate_offset < range->page_count &&
         request->page_count <= range->page_count - candidate_offset) {
    uint64_t candidate_metadata = metadata_start + candidate_offset;
    uint64_t candidate_base = candidate_physical_page << ZI_MEMORY_PAGE_SHIFT;
    uint64_t allocation_size = request->page_count << ZI_MEMORY_PAGE_SHIFT;
    if (candidate_base > request->maximum_physical_address ||
        allocation_size - 1 > request->maximum_physical_address - candidate_base) {
      return ZI_STATUS_NOT_FOUND;
    }
    if (run_is_free(manager, candidate_metadata, request->page_count)) {
      for (uint64_t offset = 0; offset < request->page_count; ++offset) {
        manager->pages[candidate_metadata + offset].state = ZI_MEMORY_PAGE_ALLOCATED;
        manager->pages[candidate_metadata + offset].owner = (uint8_t)request->owner;
      }
      manager->statistics.free_pages -= request->page_count;
      manager->statistics.allocated_pages += request->page_count;
      *request->out_physical_base = candidate_physical_page << ZI_MEMORY_PAGE_SHIFT;
      return ZI_STATUS_SUCCESS;
    }
    candidate_offset += request->alignment_pages;
    candidate_physical_page += request->alignment_pages;
  }
  return ZI_STATUS_NOT_FOUND;
}

ZiStatus zi_pmm_free(ZiPhysicalMemoryManager* manager,
                     uint64_t physical_base,
                     uint64_t page_count,
                     uint32_t expected_owner) {
  if (manager == NULL || manager->pages == NULL || !allocation_owner_is_valid(expected_owner)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t first_page = 0;
  ZiStatus status = locate_page_interval(manager, physical_base, page_count, &first_page);
  if (ZiFailed(status)) {
    return status;
  }
  for (uint64_t offset = 0; offset < page_count; ++offset) {
    const ZiPhysicalPageMetadata* page = &manager->pages[first_page + offset];
    if (page->state != ZI_MEMORY_PAGE_ALLOCATED || page->owner != expected_owner) {
      return ZI_STATUS_INVALID_STATE;
    }
  }
  for (uint64_t offset = 0; offset < page_count; ++offset) {
    manager->pages[first_page + offset].state = ZI_MEMORY_PAGE_FREE;
    manager->pages[first_page + offset].owner = ZI_MEMORY_OWNER_NONE;
  }
  manager->statistics.allocated_pages -= page_count;
  manager->statistics.free_pages += page_count;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_pmm_query(const ZiPhysicalMemoryManager* manager,
                      uint64_t physical_address,
                      ZiPhysicalPageMetadata* out_metadata) {
  if (manager == NULL || manager->pages == NULL || out_metadata == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t metadata_index = 0;
  ZiStatus status = locate_page(manager, physical_address, &metadata_index);
  if (ZiFailed(status)) {
    return status;
  }
  *out_metadata = manager->pages[metadata_index];
  return ZI_STATUS_SUCCESS;
}

ZiPhysicalMemoryStatistics zi_pmm_statistics(const ZiPhysicalMemoryManager* manager) {
  ZiPhysicalMemoryStatistics statistics = {0};
  if (manager != NULL) {
    statistics = manager->statistics;
  }
  return statistics;
}

static ZiStatus locate_page_interval(const ZiPhysicalMemoryManager* manager,
                                     uint64_t physical_base,
                                     uint64_t page_count,
                                     uint64_t* out_metadata_index) {
  if (manager == NULL || manager->inventory == NULL || page_count == 0 ||
      out_metadata_index == NULL || (physical_base & (ZI_MEMORY_PAGE_SIZE - 1)) != 0 ||
      page_count > UINT64_MAX / ZI_MEMORY_PAGE_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t size = page_count * ZI_MEMORY_PAGE_SIZE;
  if (physical_base > UINT64_MAX - size) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  for (size_t index = 0; index < manager->inventory->range_count; ++index) {
    const ZiMemoryRange* range = &manager->inventory->ranges[index];
    uint64_t range_size = range->page_count << ZI_MEMORY_PAGE_SHIFT;
    if (physical_base >= range->physical_base &&
        physical_base - range->physical_base <= range_size &&
        size <= range_size - (physical_base - range->physical_base)) {
      *out_metadata_index = range_metadata_start(manager->inventory, index) +
                            ((physical_base - range->physical_base) >> ZI_MEMORY_PAGE_SHIFT);
      return ZI_STATUS_SUCCESS;
    }
  }
  return ZI_STATUS_OUT_OF_BOUNDS;
}

static ZiStatus locate_page(const ZiPhysicalMemoryManager* manager,
                            uint64_t physical_address,
                            uint64_t* out_metadata_index) {
  if (manager == NULL || manager->inventory == NULL || out_metadata_index == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  for (size_t index = 0; index < manager->inventory->range_count; ++index) {
    const ZiMemoryRange* range = &manager->inventory->ranges[index];
    uint64_t range_size = range->page_count << ZI_MEMORY_PAGE_SHIFT;
    if (physical_address >= range->physical_base &&
        physical_address - range->physical_base < range_size) {
      *out_metadata_index = range_metadata_start(manager->inventory, index) +
                            ((physical_address - range->physical_base) >> ZI_MEMORY_PAGE_SHIFT);
      return ZI_STATUS_SUCCESS;
    }
  }
  return ZI_STATUS_OUT_OF_BOUNDS;
}

static uint64_t range_metadata_start(const ZiMemoryInventory* inventory, size_t range_index) {
  uint64_t metadata_start = 0;
  for (size_t index = 0; index < range_index; ++index) {
    metadata_start += inventory->ranges[index].page_count;
  }
  return metadata_start;
}

static uint32_t owner_for_boot_type(uint32_t type) {
  switch (type) {
    case ZI_BOOT_MEMORY_USABLE:
      return ZI_MEMORY_OWNER_NONE;
    case ZI_BOOT_MEMORY_BOOT_RECLAIMABLE:
      return ZI_MEMORY_OWNER_BOOTLOADER;
    case ZI_BOOT_MEMORY_KERNEL_AND_MODULES:
      return ZI_MEMORY_OWNER_KERNEL;
    case ZI_BOOT_MEMORY_FRAMEBUFFER:
      return ZI_MEMORY_OWNER_FRAMEBUFFER;
    default:
      return ZI_MEMORY_OWNER_FIRMWARE;
  }
}

static void sort_ranges(ZiMemoryRange* ranges, size_t count) {
  for (size_t index = 1; index < count; ++index) {
    ZiMemoryRange value = ranges[index];
    size_t destination = index;
    while (destination != 0 && ranges[destination - 1].physical_base > value.physical_base) {
      ranges[destination] = ranges[destination - 1];
      --destination;
    }
    ranges[destination] = value;
  }
}

static bool allocation_owner_is_valid(uint32_t owner) {
  return (bool)((owner >= ZI_MEMORY_OWNER_ALLOCATOR_METADATA && owner <= ZI_MEMORY_OWNER_TEST) ||
                (owner >= ZI_MEMORY_OWNER_PROCESS_IMAGE && owner <= ZI_MEMORY_OWNER_DMA));
}

static bool reservation_owner_is_valid(uint32_t owner) {
  return (bool)(allocation_owner_is_valid(owner) || owner == ZI_MEMORY_OWNER_ZERO_GUARD);
}

static bool
run_is_free(const ZiPhysicalMemoryManager* manager, uint64_t first_page, uint64_t page_count) {
  for (uint64_t offset = 0; offset < page_count; ++offset) {
    if (manager->pages[first_page + offset].state != ZI_MEMORY_PAGE_FREE) {
      return false;
    }
  }
  return true;
}
