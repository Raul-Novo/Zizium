// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/boot.h"
#include "zi/memory.h"
#include "zi/x64_paging.h"
#include "zizium/status.h"

ZiStatus zi_kernel_memory_initialise(const ZiBootContext* boot_context);
ZiStatus zi_kernel_virtual_memory_initialise(const ZiBootContext* boot_context);
ZiPhysicalMemoryManager* zi_kernel_physical_memory_manager(void);
ZiX64PagingContext* zi_kernel_paging_context(void);
ZiPhysicalMemoryStatistics zi_kernel_memory_statistics(void);
ZiStatus zi_kernel_physical_pointer(uint64_t physical_base, size_t size, void** out_pointer);
ZiStatus zi_kernel_map_pages(uint64_t virtual_address,
                             uint64_t physical_address,
                             uint64_t size,
                             uint32_t protection);
ZiStatus zi_kernel_unmap_pages(uint64_t virtual_address, uint64_t size);
ZiStatus zi_kernel_protect_pages(uint64_t virtual_address, uint64_t size, uint32_t protection);
ZiStatus zi_kernel_temporary_map(uint64_t physical_address, void** out_pointer);
ZiStatus zi_kernel_temporary_map_read_only(uint64_t physical_address, void** out_pointer);
ZiStatus zi_kernel_temporary_unmap(void);
ZiStatus zi_kernel_temporary_mapping_self_test(void);
uint64_t zi_kernel_apic_virtual_address(void);
uint32_t zi_kernel_virtual_memory_stage(void);

#define ZI_KERNEL_POOL_VIRTUAL_BASE UINT64_C(0xffffc00000000000)
#define ZI_KERNEL_STRESS_VIRTUAL_BASE UINT64_C(0xffffb00000000000)
#define ZI_KERNEL_STACK_VIRTUAL_BASE UINT64_C(0xffffd00000000000)
#define ZI_KERNEL_APIC_VIRTUAL_BASE UINT64_C(0xffffe00000000000)
#define ZI_KERNEL_TEMPORARY_VIRTUAL_BASE UINT64_C(0xffffe00000001000)
#define ZI_KERNEL_MMIO_VIRTUAL_BASE UINT64_C(0xffffe10000000000)
#define ZI_KERNEL_MMIO_SLOT_SIZE UINT64_C(0x200000)
#define ZI_KERNEL_MMIO_SLOT_COUNT 64u

typedef struct ZiKernelMmioMapping {
  uint32_t struct_size;
  uint32_t version;
  void* address;
  uint64_t virtual_base;
  uint64_t physical_base;
  uint64_t mapped_size;
  size_t requested_size;
  uint32_t first_slot;
  uint32_t slot_count;
  uint32_t active;
} ZiKernelMmioMapping;

#define ZI_KERNEL_MMIO_MAPPING_VERSION 1u

ZiStatus zi_kernel_mmio_initialise(void);
ZiStatus
zi_kernel_mmio_map(uint64_t physical_address, size_t size, ZiKernelMmioMapping* out_mapping);
ZiStatus zi_kernel_mmio_unmap(ZiKernelMmioMapping* mapping);
ZiStatus zi_kernel_read_physical(uint64_t physical_address, void* output, size_t size);

enum ZiKernelVirtualMemoryStage {
  ZI_KERNEL_VMM_STAGE_NONE = 0,
  ZI_KERNEL_VMM_STAGE_NX = 1,
  ZI_KERNEL_VMM_STAGE_ROOT = 2,
  ZI_KERNEL_VMM_STAGE_KERNEL_PARSE = 3,
  ZI_KERNEL_VMM_STAGE_KERNEL_HEADERS = 4,
  ZI_KERNEL_VMM_STAGE_KERNEL_SECTION = 5,
  ZI_KERNEL_VMM_STAGE_HHDM = 6,
  ZI_KERNEL_VMM_STAGE_APIC = 7,
  ZI_KERNEL_VMM_STAGE_CR3 = 8,
  ZI_KERNEL_VMM_STAGE_VERIFY = 9,
  ZI_KERNEL_VMM_STAGE_READY = 10,
};
