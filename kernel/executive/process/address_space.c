// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/address_space.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/byte_order.h"
#include "zi/x64_paging.h"
#include "zizium/status.h"

static bool backing_is_valid(const ZiAddressSpaceBacking* backing);
static bool address_space_is_active(const ZiAddressSpace* address_space);
static ZiStatus validate_owned_mapping(uint64_t virtual_base, size_t size, uint32_t protection);
static bool
regions_overlap(uint64_t left_base, uint64_t left_size, uint64_t right_base, uint64_t right_size);
static bool align_up_u64(uint64_t value, uint64_t alignment, uint64_t* out_value);
static ZiAddressSpaceRegion*
find_exact_region(ZiAddressSpace* address_space, uint64_t virtual_base, uint64_t page_count);
static ZiAddressSpaceRegion*
find_containing_region(ZiAddressSpace* address_space, uint64_t virtual_base, uint64_t page_count);
static ZiStatus zero_physical_pages(const ZiAddressSpace* address_space,
                                    uint64_t physical_base,
                                    uint64_t page_count);
static ZiStatus release_region(ZiAddressSpace* address_space, size_t index);
static ZiStatus copy_user_bytes(const ZiAddressSpace* address_space,
                                uint64_t user_address,
                                void* kernel_buffer,
                                size_t size,
                                bool to_user);

bool zi_user_range_is_valid(uint64_t address, size_t size) {
  if (size == 0 || address < ZI_USER_ADDRESS_MIN || address >= ZI_USER_ADDRESS_MAX_EXCLUSIVE) {
    return false;
  }
  uint64_t byte_count = (uint64_t)size;
  return (bool)(byte_count <= ZI_USER_ADDRESS_MAX_EXCLUSIVE - address);
}

ZiStatus zi_address_space_initialise(const ZiX64PagingContext* kernel_template,
                                     const ZiAddressSpaceBacking* backing,
                                     ZiAddressSpace* out_address_space) {
  if (kernel_template == NULL || !backing_is_valid(backing) || out_address_space == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiAddressSpace address_space = {0};
  address_space.struct_size = sizeof address_space;
  address_space.version = ZI_ADDRESS_SPACE_VERSION;
  address_space.state = ZI_ADDRESS_SPACE_ACTIVE;
  address_space.kernel_template = kernel_template;
  address_space.backing = *backing;
  ZiStatus status = zi_x64_paging_clone_kernel_half(kernel_template, &address_space.paging);
  if (ZiFailed(status)) {
    return status;
  }
  *out_address_space = address_space;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_address_space_map_owned(ZiAddressSpace* address_space,
                                    uint64_t virtual_base,
                                    size_t size,
                                    uint32_t protection,
                                    uint32_t owner) {
  if (!address_space_is_active(address_space) || owner == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_owned_mapping(virtual_base, size, protection);
  if (ZiFailed(status)) {
    return status;
  }
  if (address_space->region_count >= ZI_ADDRESS_SPACE_REGION_CAPACITY) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  for (size_t index = 0; index < address_space->region_count; ++index) {
    const ZiAddressSpaceRegion* region = &address_space->regions[index];
    uint64_t region_size = region->page_count * ZI_X64_PAGE_SIZE;
    if (regions_overlap(virtual_base, (uint64_t)size, region->virtual_base, region_size)) {
      return ZI_STATUS_ADDRESS_CONFLICT;
    }
  }

  uint64_t page_count = (uint64_t)size / ZI_X64_PAGE_SIZE;
  uint64_t physical_base = 0;
  status = address_space->backing.allocate_pages(address_space->backing.context,
                                                 page_count,
                                                 owner,
                                                 &physical_base);
  if (ZiFailed(status)) {
    return status;
  }
  if (physical_base == 0 || (physical_base & (ZI_X64_PAGE_SIZE - 1)) != 0) {
    (void)address_space->backing.release_pages(address_space->backing.context,
                                               physical_base,
                                               page_count,
                                               owner);
    return ZI_STATUS_INVALID_STATE;
  }
  status = zero_physical_pages(address_space, physical_base, page_count);
  if (ZiSucceeded(status)) {
    status = zi_x64_paging_map_range(&address_space->paging,
                                     virtual_base,
                                     physical_base,
                                     (uint64_t)size,
                                     protection);
  }
  if (ZiFailed(status)) {
    ZiStatus release_status = address_space->backing.release_pages(address_space->backing.context,
                                                                   physical_base,
                                                                   page_count,
                                                                   owner);
    if (ZiFailed(release_status)) {
      return ZI_STATUS_MEMORY_CORRUPTION;
    }
    return status;
  }

  ZiAddressSpaceRegion* region = &address_space->regions[address_space->region_count++];
  region->virtual_base = virtual_base;
  region->physical_base = physical_base;
  region->page_count = page_count;
  region->protection = protection;
  region->owner = owner;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_address_space_find_free_range(const ZiAddressSpace* address_space,
                                          uint64_t search_base,
                                          uint64_t search_end_exclusive,
                                          size_t size,
                                          uint64_t alignment,
                                          uint64_t* out_virtual_base) {
  if (!address_space_is_active(address_space) || out_virtual_base == NULL || size == 0 ||
      alignment < ZI_X64_PAGE_SIZE || (alignment & (alignment - 1u)) != 0 ||
      (alignment & (ZI_X64_PAGE_SIZE - 1u)) != 0 || (size & (size_t)(ZI_X64_PAGE_SIZE - 1u)) != 0 ||
      search_base < ZI_USER_ADDRESS_MIN || search_end_exclusive > ZI_USER_ADDRESS_MAX_EXCLUSIVE ||
      search_base >= search_end_exclusive || (uint64_t)size > search_end_exclusive - search_base) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  uint64_t candidate = 0;
  if (!align_up_u64(search_base, alignment, &candidate)) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  while (candidate < search_end_exclusive && (uint64_t)size <= search_end_exclusive - candidate) {
    uint64_t next_candidate = candidate;
    bool is_free = true;
    for (size_t index = 0; index < address_space->region_count; ++index) {
      const ZiAddressSpaceRegion* region = &address_space->regions[index];
      uint64_t region_size = region->page_count * ZI_X64_PAGE_SIZE;
      if (!regions_overlap(candidate, (uint64_t)size, region->virtual_base, region_size)) {
        continue;
      }
      is_free = false;
      uint64_t region_end = region->virtual_base + region_size;
      uint64_t aligned_end = 0;
      if (!align_up_u64(region_end, alignment, &aligned_end)) {
        return ZI_STATUS_OUT_OF_BOUNDS;
      }
      if (aligned_end > next_candidate) {
        next_candidate = aligned_end;
      }
    }
    if (is_free) {
      *out_virtual_base = candidate;
      return ZI_STATUS_SUCCESS;
    }
    if (next_candidate <= candidate) {
      return ZI_STATUS_INVALID_STATE;
    }
    candidate = next_candidate;
  }
  return ZI_STATUS_NOT_FOUND;
}

ZiStatus zi_address_space_protect_owned(ZiAddressSpace* address_space,
                                        uint64_t virtual_base,
                                        size_t size,
                                        uint32_t protection) {
  if (!address_space_is_active(address_space)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_owned_mapping(virtual_base, size, protection);
  if (ZiFailed(status)) {
    return status;
  }
  uint64_t page_count = (uint64_t)size / ZI_X64_PAGE_SIZE;
  ZiAddressSpaceRegion* region = find_containing_region(address_space, virtual_base, page_count);
  if (region == NULL) {
    return ZI_STATUS_NOT_FOUND;
  }
  status =
      zi_x64_paging_protect_range(&address_space->paging, virtual_base, (uint64_t)size, protection);
  if (ZiSucceeded(status)) {
    if (region->virtual_base == virtual_base && region->page_count == page_count) {
      region->protection = protection;
    } else {
      region->protection = 0;
    }
  }
  return status;
}

ZiStatus
zi_address_space_unmap_owned(ZiAddressSpace* address_space, uint64_t virtual_base, size_t size) {
  if (!address_space_is_active(address_space) || size == 0 ||
      (size & (size_t)(ZI_X64_PAGE_SIZE - 1)) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t page_count = (uint64_t)size / ZI_X64_PAGE_SIZE;
  ZiAddressSpaceRegion* region = find_exact_region(address_space, virtual_base, page_count);
  if (region == NULL) {
    return ZI_STATUS_NOT_FOUND;
  }
  return release_region(address_space, (size_t)(region - address_space->regions));
}

ZiStatus zi_address_space_destroy(ZiAddressSpace* address_space) {
  if (!address_space_is_active(address_space)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  while (address_space->region_count != 0) {
    ZiStatus status = release_region(address_space, address_space->region_count - 1u);
    if (ZiFailed(status)) {
      return status;
    }
  }
  ZiStatus status = zi_x64_paging_release_empty_address_space(&address_space->paging,
                                                              address_space->kernel_template);
  if (ZiFailed(status)) {
    return status;
  }
  zi_memory_zero(address_space, sizeof *address_space);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_address_space_query(const ZiAddressSpace* address_space,
                                uint64_t user_address,
                                uint32_t required_access,
                                ZiX64PageMapping* out_mapping) {
  const uint32_t valid_access = ZI_USER_ACCESS_READ | ZI_USER_ACCESS_WRITE | ZI_USER_ACCESS_EXECUTE;
  if (!address_space_is_active(address_space) || out_mapping == NULL || required_access == 0 ||
      (required_access & ~valid_access) != 0 || !zi_user_range_is_valid(user_address, 1)) {
    return ZI_STATUS_INVALID_USER_BUFFER;
  }
  ZiStatus status = zi_x64_paging_query(&address_space->paging, user_address, out_mapping);
  if (ZiFailed(status) || (out_mapping->protection & ZI_X64_PAGE_USER) == 0 ||
      ((required_access & ZI_USER_ACCESS_READ) != 0 &&
       (out_mapping->protection & ZI_X64_PAGE_READ) == 0) ||
      ((required_access & ZI_USER_ACCESS_WRITE) != 0 &&
       (out_mapping->protection & ZI_X64_PAGE_WRITE) == 0) ||
      ((required_access & ZI_USER_ACCESS_EXECUTE) != 0 &&
       (out_mapping->protection & ZI_X64_PAGE_EXECUTE) == 0)) {
    return ZI_STATUS_INVALID_USER_BUFFER;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_copy_from_user(const ZiAddressSpace* address_space,
                           void* kernel_destination,
                           uint64_t user_source,
                           size_t size) {
  if (kernel_destination == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return copy_user_bytes(address_space, user_source, kernel_destination, size, false);
}

ZiStatus zi_copy_to_user(const ZiAddressSpace* address_space,
                         uint64_t user_destination,
                         const void* kernel_source,
                         size_t size) {
  if (kernel_source == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return copy_user_bytes(address_space,
                         user_destination,
                         (void*)(uintptr_t)kernel_source,
                         size,
                         true);
}

static bool backing_is_valid(const ZiAddressSpaceBacking* backing) {
  return (bool)(backing != NULL && backing->struct_size == sizeof *backing &&
                backing->version == ZI_ADDRESS_SPACE_BACKING_VERSION &&
                backing->allocate_pages != NULL && backing->release_pages != NULL &&
                backing->physical_pointer != NULL);
}

static bool address_space_is_active(const ZiAddressSpace* address_space) {
  return (bool)(address_space != NULL && address_space->struct_size == sizeof *address_space &&
                address_space->version == ZI_ADDRESS_SPACE_VERSION &&
                address_space->state == ZI_ADDRESS_SPACE_ACTIVE &&
                backing_is_valid(&address_space->backing) &&
                address_space->kernel_template != NULL &&
                address_space->paging.root_physical_base != 0 &&
                address_space->region_count <= ZI_ADDRESS_SPACE_REGION_CAPACITY);
}

static ZiStatus validate_owned_mapping(uint64_t virtual_base, size_t size, uint32_t protection) {
  if (!zi_user_range_is_valid(virtual_base, size)) {
    return ZI_STATUS_INVALID_USER_BUFFER;
  }
  if ((virtual_base & (ZI_X64_PAGE_SIZE - 1)) != 0 ||
      (size & (size_t)(ZI_X64_PAGE_SIZE - 1)) != 0) {
    return ZI_STATUS_ALIGNMENT_ERROR;
  }
  const uint32_t allowed =
      ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE | ZI_X64_PAGE_EXECUTE | ZI_X64_PAGE_USER;
  if ((protection & (ZI_X64_PAGE_READ | ZI_X64_PAGE_USER)) !=
          (ZI_X64_PAGE_READ | ZI_X64_PAGE_USER) ||
      (protection & ~allowed) != 0 ||
      ((protection & ZI_X64_PAGE_WRITE) != 0 && (protection & ZI_X64_PAGE_EXECUTE) != 0)) {
    return ZI_STATUS_ACCESS_DENIED;
  }
  return ZI_STATUS_SUCCESS;
}

static bool
regions_overlap(uint64_t left_base, uint64_t left_size, uint64_t right_base, uint64_t right_size) {
  return (bool)(left_base < right_base + right_size && right_base < left_base + left_size);
}

static bool align_up_u64(uint64_t value, uint64_t alignment, uint64_t* out_value) {
  if (out_value == NULL || alignment == 0 || (alignment & (alignment - 1u)) != 0) {
    return false;
  }
  uint64_t mask = alignment - 1u;
  if (value > UINT64_MAX - mask) {
    return false;
  }
  *out_value = (value + mask) & ~mask;
  return true;
}

static ZiAddressSpaceRegion*
find_exact_region(ZiAddressSpace* address_space, uint64_t virtual_base, uint64_t page_count) {
  for (size_t index = 0; index < address_space->region_count; ++index) {
    ZiAddressSpaceRegion* region = &address_space->regions[index];
    if (region->virtual_base == virtual_base && region->page_count == page_count) {
      return region;
    }
  }
  return NULL;
}

static ZiAddressSpaceRegion*
find_containing_region(ZiAddressSpace* address_space, uint64_t virtual_base, uint64_t page_count) {
  uint64_t size = page_count * ZI_X64_PAGE_SIZE;
  for (size_t index = 0; index < address_space->region_count; ++index) {
    ZiAddressSpaceRegion* region = &address_space->regions[index];
    uint64_t region_size = region->page_count * ZI_X64_PAGE_SIZE;
    if (virtual_base >= region->virtual_base &&
        virtual_base - region->virtual_base <= region_size &&
        size <= region_size - (virtual_base - region->virtual_base)) {
      return region;
    }
  }
  return NULL;
}

static ZiStatus zero_physical_pages(const ZiAddressSpace* address_space,
                                    uint64_t physical_base,
                                    uint64_t page_count) {
  for (uint64_t index = 0; index < page_count; ++index) {
    if (physical_base > UINT64_MAX - (index * ZI_X64_PAGE_SIZE)) {
      return ZI_STATUS_OUT_OF_BOUNDS;
    }
    void* page = NULL;
    ZiStatus status =
        address_space->backing.physical_pointer(address_space->backing.context,
                                                physical_base + (index * ZI_X64_PAGE_SIZE),
                                                (size_t)ZI_X64_PAGE_SIZE,
                                                &page);
    if (ZiFailed(status)) {
      return status;
    }
    if (page == NULL) {
      return ZI_STATUS_INVALID_STATE;
    }
    zi_memory_zero(page, (size_t)ZI_X64_PAGE_SIZE);
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus release_region(ZiAddressSpace* address_space, size_t index) {
  if (index >= address_space->region_count) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiAddressSpaceRegion region = address_space->regions[index];
  ZiStatus status = zero_physical_pages(address_space, region.physical_base, region.page_count);
  uint64_t size = region.page_count * ZI_X64_PAGE_SIZE;
  if (ZiSucceeded(status)) {
    status = zi_x64_paging_unmap_range(&address_space->paging, region.virtual_base, size);
  }
  if (ZiFailed(status)) {
    return status;
  }
  status = address_space->backing.release_pages(address_space->backing.context,
                                                region.physical_base,
                                                region.page_count,
                                                region.owner);
  if (ZiFailed(status)) {
    if (region.protection == 0) {
      return ZI_STATUS_MEMORY_CORRUPTION;
    }
    ZiStatus restore_status = zi_x64_paging_map_range(&address_space->paging,
                                                      region.virtual_base,
                                                      region.physical_base,
                                                      size,
                                                      region.protection);
    if (ZiFailed(restore_status)) {
      return ZI_STATUS_MEMORY_CORRUPTION;
    }
    return status;
  }
  for (size_t move = index + 1u; move < address_space->region_count; ++move) {
    address_space->regions[move - 1u] = address_space->regions[move];
  }
  --address_space->region_count;
  zi_memory_zero(&address_space->regions[address_space->region_count],
                 sizeof address_space->regions[0]);
  return ZI_STATUS_SUCCESS;
}

static ZiStatus copy_user_bytes(const ZiAddressSpace* address_space,
                                uint64_t user_address,
                                void* kernel_buffer,
                                size_t size,
                                bool to_user) {
  if (!address_space_is_active(address_space) || kernel_buffer == NULL ||
      !zi_user_range_is_valid(user_address, size)) {
    return ZI_STATUS_INVALID_USER_BUFFER;
  }
  unsigned char* kernel_bytes = kernel_buffer;
  size_t copied = 0;
  uint32_t access = ZI_USER_ACCESS_READ;
  if (to_user) {
    access = ZI_USER_ACCESS_WRITE;
  }
  while (copied < size) {
    uint64_t cursor = user_address + (uint64_t)copied;
    ZiX64PageMapping mapping = {0};
    ZiStatus status = zi_address_space_query(address_space, cursor, access, &mapping);
    if (ZiFailed(status)) {
      return status;
    }
    size_t page_offset = (size_t)(mapping.physical_base & (ZI_X64_PAGE_SIZE - 1));
    size_t chunk = (size_t)ZI_X64_PAGE_SIZE - page_offset;
    if (chunk > size - copied) {
      chunk = size - copied;
    }
    uint64_t physical_page = mapping.physical_base & ~(ZI_X64_PAGE_SIZE - 1);
    void* page = NULL;
    status = address_space->backing.physical_pointer(address_space->backing.context,
                                                     physical_page,
                                                     (size_t)ZI_X64_PAGE_SIZE,
                                                     &page);
    if (ZiFailed(status) || page == NULL) {
      return ZI_STATUS_INVALID_USER_BUFFER;
    }
    unsigned char* user_bytes = (unsigned char*)page + page_offset;
    if (to_user) {
      zi_memory_copy(user_bytes, kernel_bytes + copied, chunk);
    } else {
      zi_memory_copy(kernel_bytes + copied, user_bytes, chunk);
    }
    copied += chunk;
  }
  return ZI_STATUS_SUCCESS;
}
