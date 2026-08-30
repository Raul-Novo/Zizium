// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/display.h"
#include "zizium/status.h"

#define ZI_BOOT_CONTEXT_VERSION 3u
#define ZI_BOOT_MAX_MEMORY_RANGES 256u
#define ZI_BOOT_MAX_DISPLAY_OUTPUTS 8u
#define ZI_BOOT_MAX_MODULES 16u

enum ZiBootMemoryType {
  ZI_BOOT_MEMORY_USABLE = 0,
  ZI_BOOT_MEMORY_RESERVED = 1,
  ZI_BOOT_MEMORY_ACPI_RECLAIMABLE = 2,
  ZI_BOOT_MEMORY_ACPI_NVS = 3,
  ZI_BOOT_MEMORY_BAD = 4,
  ZI_BOOT_MEMORY_BOOT_RECLAIMABLE = 5,
  ZI_BOOT_MEMORY_KERNEL_AND_MODULES = 6,
  ZI_BOOT_MEMORY_FRAMEBUFFER = 7,
  ZI_BOOT_MEMORY_RESERVED_MAPPED = 8,
};

enum ZiBootPagingMode {
  ZI_BOOT_PAGING_X64_FOUR_LEVEL = 0,
  ZI_BOOT_PAGING_X64_FIVE_LEVEL = 1,
};

typedef struct ZiBootMemoryRange {
  uint64_t physical_base;
  uint64_t size;
  uint32_t type;
  uint32_t reserved;
} ZiBootMemoryRange;

typedef struct ZiBootModule {
  const void* address;
  uint64_t physical_base;
  uint64_t size;
  const char* path;
  const char* command_line;
} ZiBootModule;

typedef struct ZiBootContext {
  uint32_t struct_size;
  uint32_t version;
  const char* bootloader_name;
  const char* bootloader_version;
  const char* command_line;
  uint32_t paging_mode;
  uint32_t reserved;
  uint64_t hhdm_offset;
  uint64_t kernel_physical_base;
  uint64_t kernel_virtual_base;
  uint64_t kernel_size;
  const ZiBootMemoryRange* memory_ranges;
  size_t memory_range_count;
  ZiDisplayOutput* display_outputs;
  size_t display_output_count;
  const ZiBootModule* modules;
  size_t module_count;
  void* rsdp;
  void* efi_system_table;
  uint64_t rsdp_physical_address;
} ZiBootContext;

ZiStatus zi_boot_context_from_limine(const ZiBootContext** out_context);
