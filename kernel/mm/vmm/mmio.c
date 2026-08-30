// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/executive_lock.h"
#include "zi/kernel_memory.h"
#include "zi/x64_paging.h"
#include "zizium/status.h"

static ZiExecutiveLock s_mmio_lock;
static bool s_mmio_slots[ZI_KERNEL_MMIO_SLOT_COUNT];
static bool s_mmio_initialised;

static ZiStatus reserve_slots(uint32_t slot_count, uint32_t* out_first_slot);
static void release_slots(uint32_t first_slot, uint32_t slot_count);
static void copy_bytes(void* output, const void* input, size_t size);

ZiStatus zi_kernel_mmio_initialise(void) {
  if (s_mmio_initialised || zi_kernel_paging_context() == NULL) {
    return ZI_STATUS_INVALID_STATE;
  }
  for (size_t index = 0; index < ZI_KERNEL_MMIO_SLOT_COUNT; ++index) {
    s_mmio_slots[index] = false;
  }
  zi_executive_lock_initialise(&s_mmio_lock);
  s_mmio_initialised = true;
  return ZI_STATUS_SUCCESS;
}

ZiStatus
zi_kernel_mmio_map(uint64_t physical_address, size_t size, ZiKernelMmioMapping* out_mapping) {
  if (!s_mmio_initialised || size == 0 || out_mapping == NULL ||
      physical_address > UINT64_MAX - size) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t physical_base = physical_address & ~(ZI_X64_PAGE_SIZE - 1);
  uint64_t page_offset = physical_address - physical_base;
  if ((uint64_t)size > UINT64_MAX - page_offset) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  uint64_t required_size = page_offset + (uint64_t)size;
  if (required_size > UINT64_MAX - (ZI_X64_PAGE_SIZE - 1)) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  uint64_t mapped_size = (required_size + ZI_X64_PAGE_SIZE - 1) & ~(ZI_X64_PAGE_SIZE - 1);
  uint64_t slot_count64 = (mapped_size + ZI_KERNEL_MMIO_SLOT_SIZE - 1) / ZI_KERNEL_MMIO_SLOT_SIZE;
  if (slot_count64 == 0 || slot_count64 > ZI_KERNEL_MMIO_SLOT_COUNT) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  uint32_t first_slot = 0;
  ZiStatus status = reserve_slots((uint32_t)slot_count64, &first_slot);
  if (ZiFailed(status)) {
    return status;
  }

  uint64_t virtual_base =
      ZI_KERNEL_MMIO_VIRTUAL_BASE + ((uint64_t)first_slot * ZI_KERNEL_MMIO_SLOT_SIZE);
  status = zi_kernel_map_pages(virtual_base,
                               physical_base,
                               mapped_size,
                               ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE | ZI_X64_PAGE_GLOBAL |
                                   ZI_X64_PAGE_DEVICE);
  if (ZiFailed(status)) {
    release_slots(first_slot, (uint32_t)slot_count64);
    return status;
  }
  ZiKernelMmioMapping mapping = {
      sizeof(ZiKernelMmioMapping),
      ZI_KERNEL_MMIO_MAPPING_VERSION,
      (void*)(uintptr_t)(virtual_base + page_offset),
      virtual_base,
      physical_base,
      mapped_size,
      size,
      first_slot,
      (uint32_t)slot_count64,
      1,
  };
  *out_mapping = mapping;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_kernel_mmio_unmap(ZiKernelMmioMapping* mapping) {
  if (!s_mmio_initialised || mapping == NULL || mapping->struct_size < sizeof *mapping ||
      mapping->version != ZI_KERNEL_MMIO_MAPPING_VERSION || mapping->active == 0 ||
      mapping->slot_count == 0 || mapping->first_slot >= ZI_KERNEL_MMIO_SLOT_COUNT ||
      mapping->slot_count > ZI_KERNEL_MMIO_SLOT_COUNT - mapping->first_slot) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_kernel_unmap_pages(mapping->virtual_base, mapping->mapped_size);
  if (ZiFailed(status)) {
    return status;
  }
  release_slots(mapping->first_slot, mapping->slot_count);
  ZiKernelMmioMapping empty = {0};
  *mapping = empty;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_kernel_read_physical(uint64_t physical_address, void* output, size_t size) {
  if (output == NULL || size == 0 || physical_address > UINT64_MAX - size) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char* destination = output;
  size_t copied = 0;
  while (copied < size) {
    uint64_t current = physical_address + copied;
    size_t page_offset = (size_t)(current & (ZI_X64_PAGE_SIZE - 1));
    size_t chunk = (size_t)ZI_X64_PAGE_SIZE - page_offset;
    if (chunk > size - copied) {
      chunk = size - copied;
    }
    void* mapped = NULL;
    ZiStatus status = zi_kernel_temporary_map_read_only(current, &mapped);
    if (ZiFailed(status)) {
      return status;
    }
    copy_bytes(destination + copied, mapped, chunk);
    status = zi_kernel_temporary_unmap();
    if (ZiFailed(status)) {
      return status;
    }
    copied += chunk;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus reserve_slots(uint32_t slot_count, uint32_t* out_first_slot) {
  if (slot_count == 0 || slot_count > ZI_KERNEL_MMIO_SLOT_COUNT || out_first_slot == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_executive_lock_acquire(&s_mmio_lock);
  for (uint32_t start = 0; start <= ZI_KERNEL_MMIO_SLOT_COUNT - slot_count; ++start) {
    bool available = true;
    for (uint32_t offset = 0; offset < slot_count; ++offset) {
      if (s_mmio_slots[start + offset]) {
        available = false;
        break;
      }
    }
    if (!available) {
      continue;
    }
    for (uint32_t offset = 0; offset < slot_count; ++offset) {
      s_mmio_slots[start + offset] = true;
    }
    zi_executive_lock_release(&s_mmio_lock);
    *out_first_slot = start;
    return ZI_STATUS_SUCCESS;
  }
  zi_executive_lock_release(&s_mmio_lock);
  return ZI_STATUS_NO_MEMORY;
}

static void release_slots(uint32_t first_slot, uint32_t slot_count) {
  zi_executive_lock_acquire(&s_mmio_lock);
  for (uint32_t offset = 0; offset < slot_count; ++offset) {
    s_mmio_slots[first_slot + offset] = false;
  }
  zi_executive_lock_release(&s_mmio_lock);
}

static void copy_bytes(void* output, const void* input, size_t size) {
  unsigned char* destination = output;
  const unsigned char* source = input;
  for (size_t index = 0; index < size; ++index) {
    destination[index] = source[index];
  }
}
