// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"

#define ZI_X64_PAGE_SIZE UINT64_C(4096)

enum ZiX64PageProtection {
  ZI_X64_PAGE_READ = 1u << 0,
  ZI_X64_PAGE_WRITE = 1u << 1,
  ZI_X64_PAGE_EXECUTE = 1u << 2,
  ZI_X64_PAGE_USER = 1u << 3,
  ZI_X64_PAGE_GLOBAL = 1u << 4,
  ZI_X64_PAGE_DEVICE = 1u << 5,
};

typedef ZiStatus (*ZiX64PageAllocateRoutine)(void* context, uint64_t* out_physical_base);
typedef void (*ZiX64PageReleaseRoutine)(void* context, uint64_t physical_base);
typedef ZiStatus (*ZiX64PhysicalPointerRoutine)(void* context,
                                                uint64_t physical_base,
                                                size_t size,
                                                void** out_pointer);

typedef struct ZiX64PagingContext {
  uint64_t root_physical_base;
  void* callback_context;
  ZiX64PageAllocateRoutine allocate_page;
  ZiX64PageReleaseRoutine release_page;
  ZiX64PhysicalPointerRoutine physical_pointer;
  bool nx_enabled;
} ZiX64PagingContext;

typedef struct ZiX64PageMapping {
  uint64_t physical_base;
  uint32_t protection;
} ZiX64PageMapping;

ZiStatus zi_x64_paging_create(void* callback_context,
                              ZiX64PageAllocateRoutine allocate_page,
                              ZiX64PageReleaseRoutine release_page,
                              ZiX64PhysicalPointerRoutine physical_pointer,
                              bool nx_enabled,
                              ZiX64PagingContext* out_context);
ZiStatus zi_x64_paging_clone_kernel_half(const ZiX64PagingContext* kernel_context,
                                         ZiX64PagingContext* out_context);
ZiStatus zi_x64_paging_release_empty_address_space(ZiX64PagingContext* context,
                                                   const ZiX64PagingContext* kernel_context);
ZiStatus zi_x64_paging_map_page(ZiX64PagingContext* context,
                                uint64_t virtual_address,
                                uint64_t physical_address,
                                uint32_t protection);
ZiStatus zi_x64_paging_map_range(ZiX64PagingContext* context,
                                 uint64_t virtual_address,
                                 uint64_t physical_address,
                                 uint64_t size,
                                 uint32_t protection);
ZiStatus zi_x64_paging_unmap_page(ZiX64PagingContext* context, uint64_t virtual_address);
ZiStatus
zi_x64_paging_unmap_range(ZiX64PagingContext* context, uint64_t virtual_address, uint64_t size);
ZiStatus zi_x64_paging_protect_page(ZiX64PagingContext* context,
                                    uint64_t virtual_address,
                                    uint32_t protection);
ZiStatus zi_x64_paging_protect_range(ZiX64PagingContext* context,
                                     uint64_t virtual_address,
                                     uint64_t size,
                                     uint32_t protection);
ZiStatus zi_x64_paging_query(const ZiX64PagingContext* context,
                             uint64_t virtual_address,
                             ZiX64PageMapping* out_mapping);
bool zi_x64_address_is_canonical(uint64_t virtual_address);
