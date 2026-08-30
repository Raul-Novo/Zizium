// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/dma.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/memory.h"
#include "zizium/status.h"

static bool allocator_is_valid(const ZiDmaAllocator* allocator);
static void zero_bytes(void* memory, size_t size);

ZiStatus zi_dma_allocate(const ZiDmaAllocator* allocator,
                         size_t size,
                         size_t alignment,
                         uint64_t maximum_physical_address,
                         uint32_t owner,
                         ZiDmaBuffer* out_buffer) {
  if (!allocator_is_valid(allocator) || size == 0 || alignment < ZI_MEMORY_PAGE_SIZE ||
      (alignment & (alignment - 1)) != 0 || alignment % ZI_MEMORY_PAGE_SIZE != 0 ||
      size > SIZE_MAX - (ZI_MEMORY_PAGE_SIZE - 1) || out_buffer == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t page_count = ((uint64_t)size + ZI_MEMORY_PAGE_SIZE - 1) >> ZI_MEMORY_PAGE_SHIFT;
  uint64_t alignment_pages = alignment >> ZI_MEMORY_PAGE_SHIFT;
  uint64_t physical_address = 0;
  ZiStatus status = allocator->allocate_pages(allocator->context,
                                              page_count,
                                              alignment_pages,
                                              maximum_physical_address,
                                              owner,
                                              &physical_address);
  if (ZiFailed(status)) {
    return status;
  }

  uint64_t allocated_size = page_count * ZI_MEMORY_PAGE_SIZE;
  if ((physical_address & (alignment - 1)) != 0 || physical_address > maximum_physical_address ||
      allocated_size - 1 > maximum_physical_address - physical_address ||
      allocated_size > SIZE_MAX) {
    (void)allocator->release_pages(allocator->context, physical_address, page_count, owner);
    return ZI_STATUS_INVALID_STATE;
  }
  void* pointer = NULL;
  status = allocator->physical_pointer(allocator->context,
                                       physical_address,
                                       (size_t)allocated_size,
                                       &pointer);
  if (ZiFailed(status) || pointer == NULL) {
    (void)allocator->release_pages(allocator->context, physical_address, page_count, owner);
    if (ZiFailed(status)) {
      return status;
    }
    return ZI_STATUS_INVALID_STATE;
  }
  zero_bytes(pointer, (size_t)allocated_size);
  ZiDmaBuffer buffer = {
      sizeof(ZiDmaBuffer),
      ZI_DMA_BUFFER_VERSION,
      pointer,
      physical_address,
      size,
      page_count,
      owner,
      1,
  };
  *out_buffer = buffer;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_dma_release(const ZiDmaAllocator* allocator, ZiDmaBuffer* buffer) {
  if (!allocator_is_valid(allocator) || buffer == NULL || buffer->struct_size < sizeof *buffer ||
      buffer->version != ZI_DMA_BUFFER_VERSION || buffer->allocated == 0 ||
      buffer->virtual_address == NULL || buffer->page_count == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = allocator->release_pages(allocator->context,
                                             buffer->physical_address,
                                             buffer->page_count,
                                             buffer->owner);
  if (ZiFailed(status)) {
    return status;
  }
  ZiDmaBuffer empty = {0};
  *buffer = empty;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_dma_synchronise(const ZiDmaAllocator* allocator, uint32_t direction) {
  if (!allocator_is_valid(allocator) || direction < ZI_DMA_TO_DEVICE ||
      direction > ZI_DMA_BIDIRECTIONAL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  allocator->synchronise(allocator->context, direction);
  return ZI_STATUS_SUCCESS;
}

static bool allocator_is_valid(const ZiDmaAllocator* allocator) {
  return (bool)((allocator != NULL && allocator->struct_size >= sizeof *allocator &&
                 allocator->version == ZI_DMA_ALLOCATOR_VERSION &&
                 allocator->allocate_pages != NULL && allocator->release_pages != NULL &&
                 allocator->physical_pointer != NULL && allocator->synchronise != NULL) != 0);
}

static void zero_bytes(void* memory, size_t size) {
  unsigned char* bytes = memory;
  for (size_t index = 0; index < size; ++index) {
    bytes[index] = 0;
  }
}
