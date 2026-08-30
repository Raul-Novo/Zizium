// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/kernel_dma.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/arch_x64.h"
#include "zi/dma.h"
#include "zi/kernel_memory.h"
#include "zi/memory.h"
#include "zizium/status.h"

static ZiDmaAllocator s_dma_allocator;
static bool s_dma_initialised;

static ZiStatus allocate_pages(void* context,
                               uint64_t page_count,
                               uint64_t alignment_pages,
                               uint64_t maximum_physical_address,
                               uint32_t owner,
                               uint64_t* out_physical_address);
static ZiStatus release_pages(void* context,
                              uint64_t physical_address,
                              uint64_t page_count,
                              uint32_t expected_owner);
static ZiStatus
physical_pointer(void* context, uint64_t physical_address, size_t size, void** out_pointer);
static void synchronise(void* context, uint32_t direction);

ZiStatus zi_kernel_dma_initialise(void) {
  if (s_dma_initialised || zi_kernel_physical_memory_manager() == NULL ||
      zi_kernel_paging_context() == NULL) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiDmaAllocator allocator = {
      sizeof(ZiDmaAllocator),
      ZI_DMA_ALLOCATOR_VERSION,
      zi_kernel_physical_memory_manager(),
      allocate_pages,
      release_pages,
      physical_pointer,
      synchronise,
  };
  s_dma_allocator = allocator;
  s_dma_initialised = true;
  return ZI_STATUS_SUCCESS;
}

const ZiDmaAllocator* zi_kernel_dma_allocator(void) {
  if (!s_dma_initialised) {
    return NULL;
  }
  return &s_dma_allocator;
}

static ZiStatus allocate_pages(void* context,
                               uint64_t page_count,
                               uint64_t alignment_pages,
                               uint64_t maximum_physical_address,
                               uint32_t owner,
                               uint64_t* out_physical_address) {
  ZiPhysicalMemoryManager* manager = context;
  if (manager == NULL || manager != zi_kernel_physical_memory_manager()) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return zi_pmm_allocate_below(manager,
                               page_count,
                               alignment_pages,
                               maximum_physical_address,
                               owner,
                               out_physical_address);
}

static ZiStatus release_pages(void* context,
                              uint64_t physical_address,
                              uint64_t page_count,
                              uint32_t expected_owner) {
  ZiPhysicalMemoryManager* manager = context;
  if (manager == NULL || manager != zi_kernel_physical_memory_manager()) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return zi_pmm_free(manager, physical_address, page_count, expected_owner);
}

static ZiStatus
physical_pointer(void* context, uint64_t physical_address, size_t size, void** out_pointer) {
  if (context == NULL || context != zi_kernel_physical_memory_manager()) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return zi_kernel_physical_pointer(physical_address, size, out_pointer);
}

static void synchronise(void* context, uint32_t direction) {
  (void)context;
  (void)direction;
  ZkArchMemoryBarrier();
}
