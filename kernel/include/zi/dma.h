// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"

#define ZI_DMA_ALLOCATOR_VERSION 1u
#define ZI_DMA_BUFFER_VERSION 1u

enum ZiDmaDirection {
  ZI_DMA_TO_DEVICE = 1,
  ZI_DMA_FROM_DEVICE = 2,
  ZI_DMA_BIDIRECTIONAL = 3,
};

typedef ZiStatus (*ZiDmaAllocatePagesRoutine)(void* context,
                                              uint64_t page_count,
                                              uint64_t alignment_pages,
                                              uint64_t maximum_physical_address,
                                              uint32_t owner,
                                              uint64_t* out_physical_address);
typedef ZiStatus (*ZiDmaReleasePagesRoutine)(void* context,
                                             uint64_t physical_address,
                                             uint64_t page_count,
                                             uint32_t expected_owner);
typedef ZiStatus (*ZiDmaPhysicalPointerRoutine)(void* context,
                                                uint64_t physical_address,
                                                size_t size,
                                                void** out_pointer);
typedef void (*ZiDmaSynchroniseRoutine)(void* context, uint32_t direction);

typedef struct ZiDmaAllocator {
  uint32_t struct_size;
  uint32_t version;
  void* context;
  ZiDmaAllocatePagesRoutine allocate_pages;
  ZiDmaReleasePagesRoutine release_pages;
  ZiDmaPhysicalPointerRoutine physical_pointer;
  ZiDmaSynchroniseRoutine synchronise;
} ZiDmaAllocator;

typedef struct ZiDmaBuffer {
  uint32_t struct_size;
  uint32_t version;
  void* virtual_address;
  uint64_t physical_address;
  size_t requested_size;
  uint64_t page_count;
  uint32_t owner;
  uint32_t allocated;
} ZiDmaBuffer;

ZiStatus zi_dma_allocate(const ZiDmaAllocator* allocator,
                         size_t size,
                         size_t alignment,
                         uint64_t maximum_physical_address,
                         uint32_t owner,
                         ZiDmaBuffer* out_buffer);
ZiStatus zi_dma_release(const ZiDmaAllocator* allocator, ZiDmaBuffer* buffer);
ZiStatus zi_dma_synchronise(const ZiDmaAllocator* allocator, uint32_t direction);
