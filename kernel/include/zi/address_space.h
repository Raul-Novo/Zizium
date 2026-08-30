// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/x64_paging.h"
#include "zizium/status.h"

#define ZI_ADDRESS_SPACE_VERSION 1u
#define ZI_ADDRESS_SPACE_BACKING_VERSION 1u
#define ZI_ADDRESS_SPACE_REGION_CAPACITY 32u

#define ZI_USER_ADDRESS_MIN UINT64_C(0x0000000000010000)
#define ZI_USER_ADDRESS_MAX_EXCLUSIVE UINT64_C(0x0000800000000000)
#define ZI_USER_STACK_TOP UINT64_C(0x00007ffffff00000)

enum ZiAddressSpaceState {
  ZI_ADDRESS_SPACE_EMPTY = 0,
  ZI_ADDRESS_SPACE_ACTIVE = 1,
  ZI_ADDRESS_SPACE_TERMINATED = 2,
};

enum ZiUserAccess {
  ZI_USER_ACCESS_READ = 1u << 0,
  ZI_USER_ACCESS_WRITE = 1u << 1,
  ZI_USER_ACCESS_EXECUTE = 1u << 2,
};

typedef ZiStatus (*ZiAddressSpaceAllocatePages)(void* context,
                                                uint64_t page_count,
                                                uint32_t owner,
                                                uint64_t* out_physical_base);
typedef ZiStatus (*ZiAddressSpaceReleasePages)(void* context,
                                               uint64_t physical_base,
                                               uint64_t page_count,
                                               uint32_t expected_owner);

typedef struct ZiAddressSpaceBacking {
  uint32_t struct_size;
  uint32_t version;
  void* context;
  ZiAddressSpaceAllocatePages allocate_pages;
  ZiAddressSpaceReleasePages release_pages;
  ZiX64PhysicalPointerRoutine physical_pointer;
} ZiAddressSpaceBacking;

typedef struct ZiAddressSpaceRegion {
  uint64_t virtual_base;
  uint64_t physical_base;
  uint64_t page_count;
  uint32_t protection;
  uint32_t owner;
} ZiAddressSpaceRegion;

typedef struct ZiAddressSpace {
  uint32_t struct_size;
  uint32_t version;
  uint32_t state;
  uint32_t reserved;
  ZiX64PagingContext paging;
  const ZiX64PagingContext* kernel_template;
  ZiAddressSpaceBacking backing;
  ZiAddressSpaceRegion regions[ZI_ADDRESS_SPACE_REGION_CAPACITY];
  size_t region_count;
} ZiAddressSpace;

bool zi_user_range_is_valid(uint64_t address, size_t size);
ZiStatus zi_address_space_initialise(const ZiX64PagingContext* kernel_template,
                                     const ZiAddressSpaceBacking* backing,
                                     ZiAddressSpace* out_address_space);
ZiStatus zi_address_space_map_owned(ZiAddressSpace* address_space,
                                    uint64_t virtual_base,
                                    size_t size,
                                    uint32_t protection,
                                    uint32_t owner);
ZiStatus zi_address_space_find_free_range(const ZiAddressSpace* address_space,
                                          uint64_t search_base,
                                          uint64_t search_end_exclusive,
                                          size_t size,
                                          uint64_t alignment,
                                          uint64_t* out_virtual_base);
ZiStatus zi_address_space_protect_owned(ZiAddressSpace* address_space,
                                        uint64_t virtual_base,
                                        size_t size,
                                        uint32_t protection);
ZiStatus
zi_address_space_unmap_owned(ZiAddressSpace* address_space, uint64_t virtual_base, size_t size);
ZiStatus zi_address_space_destroy(ZiAddressSpace* address_space);
ZiStatus zi_address_space_query(const ZiAddressSpace* address_space,
                                uint64_t user_address,
                                uint32_t required_access,
                                ZiX64PageMapping* out_mapping);
ZiStatus zi_copy_from_user(const ZiAddressSpace* address_space,
                           void* kernel_destination,
                           uint64_t user_source,
                           size_t size);
ZiStatus zi_copy_to_user(const ZiAddressSpace* address_space,
                         uint64_t user_destination,
                         const void* kernel_source,
                         size_t size);
