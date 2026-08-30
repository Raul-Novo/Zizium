// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/arch_x64.h"
#include "zi/boot.h"
#include "zi/kernel_memory.h"
#ifdef ZI_DEBUG
#include "zi/log.h"
#endif
#include "zi/memory.h"
#include "zi/pe.h"
#include "zi/x64_paging.h"
#include "zizium/status.h"

#define ZI_X64_MSR_EFER UINT32_C(0xc0000080)
#define ZI_X64_MSR_EFER_NXE (UINT64_C(1) << 11)
#define ZI_X64_MSR_APIC_BASE UINT32_C(0x1b)
#define ZI_X64_MSR_APIC_ADDRESS_MASK UINT64_C(0x000ffffffffff000)
#define ZI_X64_CPUID_EXTENDED_FEATURES UINT32_C(0x80000001)
#define ZI_X64_CPUID_NX (UINT32_C(1) << 20)
#define ZI_X64_CR3_PHYSICAL_MASK UINT64_C(0x000ffffffffff000)
#define ZI_KERNEL_PE_SECTION_CAPACITY 32u

static ZiX64PagingContext g_paging_context;
static bool g_virtual_memory_initialised;
static bool g_temporary_mapping_active;
static bool g_paging_release_failed;
static uint32_t g_virtual_memory_stage;

static ZiStatus paging_allocate(void* context, uint64_t* out_physical_base);
static void paging_release(void* context, uint64_t physical_base);
static ZiStatus
paging_physical_pointer(void* context, uint64_t physical_base, size_t size, void** out_pointer);
static ZiStatus enable_nx(void);
static ZiStatus map_kernel_image(const ZiBootContext* boot_context);
static ZiStatus map_hhdm(const ZiBootContext* boot_context);
static ZiStatus map_hhdm_range(const ZiBootContext* boot_context, const ZiBootMemoryRange* range);
static ZiStatus map_apic(void);
static ZiStatus temporary_map(uint64_t physical_address, uint32_t protection, void** out_pointer);
static ZiStatus section_protection(uint32_t characteristics, uint32_t* out_protection);
static ZiStatus aligned_size(uint64_t size, uint64_t* out_size);
static void invalidate_range(uint64_t virtual_address, uint64_t size);

ZiStatus zi_kernel_virtual_memory_initialise(const ZiBootContext* boot_context) {
  if (boot_context == NULL || zi_kernel_physical_memory_manager() == NULL ||
      boot_context->paging_mode != ZI_BOOT_PAGING_X64_FOUR_LEVEL ||
      boot_context->kernel_physical_base == 0 || boot_context->kernel_virtual_base == 0 ||
      boot_context->kernel_size == 0 || g_virtual_memory_initialised) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  g_virtual_memory_stage = ZI_KERNEL_VMM_STAGE_NX;
  ZiStatus status = enable_nx();
  if (ZiFailed(status)) {
    return status;
  }
  g_paging_release_failed = false;
  g_virtual_memory_stage = ZI_KERNEL_VMM_STAGE_ROOT;
  status = zi_x64_paging_create(NULL,
                                paging_allocate,
                                paging_release,
                                paging_physical_pointer,
                                true,
                                &g_paging_context);
  if (ZiFailed(status)) {
    return status;
  }
#ifdef ZI_DEBUG
  zi_log_write_hex(ZI_LOG_TRACE,
                   "Memory",
                   "New CR3 physical base",
                   g_paging_context.root_physical_base);
#endif
  g_virtual_memory_stage = ZI_KERNEL_VMM_STAGE_KERNEL_PARSE;
  status = map_kernel_image(boot_context);
  if (ZiSucceeded(status)) {
    g_virtual_memory_stage = ZI_KERNEL_VMM_STAGE_HHDM;
    status = map_hhdm(boot_context);
  }
  if (ZiSucceeded(status)) {
    g_virtual_memory_stage = ZI_KERNEL_VMM_STAGE_APIC;
    status = map_apic();
  }
  if (ZiFailed(status)) {
    return status;
  }
  if (g_paging_release_failed) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }

  g_virtual_memory_stage = ZI_KERNEL_VMM_STAGE_CR3;
  ZkArchEnablePagingProtections();
  ZkArchLoadCr3(g_paging_context.root_physical_base);
  if ((ZkArchReadCr3() & ZI_X64_CR3_PHYSICAL_MASK) != g_paging_context.root_physical_base) {
    return ZI_STATUS_INVALID_STATE;
  }
  g_virtual_memory_stage = ZI_KERNEL_VMM_STAGE_VERIFY;
  ZiX64PageMapping kernel_mapping = {0};
  status =
      zi_x64_paging_query(&g_paging_context, boot_context->kernel_virtual_base, &kernel_mapping);
  if (ZiFailed(status)) {
    return status;
  }
  if (kernel_mapping.physical_base != boot_context->kernel_physical_base) {
    return ZI_STATUS_INVALID_STATE;
  }
  g_virtual_memory_initialised = true;
  g_virtual_memory_stage = ZI_KERNEL_VMM_STAGE_READY;
  return ZI_STATUS_SUCCESS;
}

ZiX64PagingContext* zi_kernel_paging_context(void) {
  if (!g_virtual_memory_initialised) {
    return NULL;
  }
  return &g_paging_context;
}

ZiStatus zi_kernel_map_pages(uint64_t virtual_address,
                             uint64_t physical_address,
                             uint64_t size,
                             uint32_t protection) {
  if (!g_virtual_memory_initialised) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiStatus status = zi_x64_paging_map_range(&g_paging_context,
                                            virtual_address,
                                            physical_address,
                                            size,
                                            protection);
  if (ZiSucceeded(status)) {
    invalidate_range(virtual_address, size);
  }
  if (g_paging_release_failed) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  return status;
}

ZiStatus zi_kernel_unmap_pages(uint64_t virtual_address, uint64_t size) {
  if (!g_virtual_memory_initialised) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiStatus status = zi_x64_paging_unmap_range(&g_paging_context, virtual_address, size);
  if (ZiSucceeded(status)) {
    invalidate_range(virtual_address, size);
  }
  if (g_paging_release_failed) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  return status;
}

ZiStatus zi_kernel_protect_pages(uint64_t virtual_address, uint64_t size, uint32_t protection) {
  if (!g_virtual_memory_initialised) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiStatus status =
      zi_x64_paging_protect_range(&g_paging_context, virtual_address, size, protection);
  if (ZiSucceeded(status)) {
    invalidate_range(virtual_address, size);
  }
  return status;
}

ZiStatus zi_kernel_temporary_map(uint64_t physical_address, void** out_pointer) {
  return temporary_map(physical_address,
                       ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE | ZI_X64_PAGE_GLOBAL,
                       out_pointer);
}

ZiStatus zi_kernel_temporary_map_read_only(uint64_t physical_address, void** out_pointer) {
  return temporary_map(physical_address, ZI_X64_PAGE_READ | ZI_X64_PAGE_GLOBAL, out_pointer);
}

static ZiStatus temporary_map(uint64_t physical_address, uint32_t protection, void** out_pointer) {
  if (!g_virtual_memory_initialised || out_pointer == NULL || g_temporary_mapping_active) {
    if (g_temporary_mapping_active) {
      return ZI_STATUS_RESOURCE_IN_USE;
    }
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t physical_page = physical_address & ~(ZI_X64_PAGE_SIZE - 1);
  ZiStatus status = zi_kernel_map_pages(ZI_KERNEL_TEMPORARY_VIRTUAL_BASE,
                                        physical_page,
                                        ZI_X64_PAGE_SIZE,
                                        protection);
  if (ZiFailed(status)) {
    return status;
  }
  g_temporary_mapping_active = true;
  *out_pointer = (void*)(uintptr_t)(ZI_KERNEL_TEMPORARY_VIRTUAL_BASE |
                                    (physical_address & (ZI_X64_PAGE_SIZE - 1)));
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_kernel_temporary_unmap(void) {
  if (!g_virtual_memory_initialised || !g_temporary_mapping_active) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiStatus status = zi_kernel_unmap_pages(ZI_KERNEL_TEMPORARY_VIRTUAL_BASE, ZI_X64_PAGE_SIZE);
  if (ZiSucceeded(status)) {
    g_temporary_mapping_active = false;
  }
  return status;
}

ZiStatus zi_kernel_temporary_mapping_self_test(void) {
  if (!g_virtual_memory_initialised) {
    return ZI_STATUS_INVALID_STATE;
  }
  uint64_t physical_base = 0;
  ZiStatus status = zi_pmm_allocate(zi_kernel_physical_memory_manager(),
                                    1,
                                    1,
                                    ZI_MEMORY_OWNER_TEMPORARY_MAPPING,
                                    &physical_base);
  if (ZiFailed(status)) {
    return status;
  }

  void* direct_pointer = NULL;
  status = zi_kernel_physical_pointer(physical_base, sizeof(uint64_t), &direct_pointer);
  void* temporary_pointer = NULL;
  bool mapped = false;
  if (ZiSucceeded(status)) {
    status = zi_kernel_temporary_map(physical_base, &temporary_pointer);
    mapped = ZiSucceeded(status);
  }
  if (ZiSucceeded(status)) {
    const uint64_t pattern = UINT64_C(0x5a695a69756d0021);
    *(volatile uint64_t*)temporary_pointer = pattern;
    if (*(volatile const uint64_t*)direct_pointer != pattern) {
      status = ZI_STATUS_MEMORY_CORRUPTION;
    }
  }
  if (mapped) {
    ZiStatus unmap_status = zi_kernel_temporary_unmap();
    if (ZiSucceeded(unmap_status)) {
      mapped = false;
    } else if (ZiSucceeded(status)) {
      status = unmap_status;
    }
  }
  if (!mapped) {
    ZiStatus free_status = zi_pmm_free(zi_kernel_physical_memory_manager(),
                                       physical_base,
                                       1,
                                       ZI_MEMORY_OWNER_TEMPORARY_MAPPING);
    if (ZiSucceeded(status) && ZiFailed(free_status)) {
      status = free_status;
    }
  }
  return status;
}

uint64_t zi_kernel_apic_virtual_address(void) {
  if (!g_virtual_memory_initialised) {
    return 0;
  }
  return ZI_KERNEL_APIC_VIRTUAL_BASE;
}

uint32_t zi_kernel_virtual_memory_stage(void) {
  return g_virtual_memory_stage;
}

static ZiStatus paging_allocate(void* context, uint64_t* out_physical_base) {
  (void)context;
  return zi_pmm_allocate(zi_kernel_physical_memory_manager(),
                         1,
                         1,
                         ZI_MEMORY_OWNER_PAGE_TABLE,
                         out_physical_base);
}

static void paging_release(void* context, uint64_t physical_base) {
  (void)context;
  ZiStatus status = zi_pmm_free(zi_kernel_physical_memory_manager(),
                                physical_base,
                                1,
                                ZI_MEMORY_OWNER_PAGE_TABLE);
  if (ZiFailed(status)) {
    g_paging_release_failed = true;
  }
}

static ZiStatus
paging_physical_pointer(void* context, uint64_t physical_base, size_t size, void** out_pointer) {
  (void)context;
  return zi_kernel_physical_pointer(physical_base, size, out_pointer);
}

static ZiStatus enable_nx(void) {
  ZiX64CpuidResult maximum = {0};
  ZkArchCpuid(UINT32_C(0x80000000), 0, &maximum);
  if (maximum.eax < ZI_X64_CPUID_EXTENDED_FEATURES) {
    return ZI_STATUS_NOT_IMPLEMENTED;
  }
  ZiX64CpuidResult features = {0};
  ZkArchCpuid(ZI_X64_CPUID_EXTENDED_FEATURES, 0, &features);
  if ((features.edx & ZI_X64_CPUID_NX) == 0) {
    return ZI_STATUS_NOT_IMPLEMENTED;
  }
  uint64_t efer = ZkArchReadMsr(ZI_X64_MSR_EFER);
  ZkArchWriteMsr(ZI_X64_MSR_EFER, efer | ZI_X64_MSR_EFER_NXE);
  return (ZkArchReadMsr(ZI_X64_MSR_EFER) & ZI_X64_MSR_EFER_NXE) != 0 ? ZI_STATUS_SUCCESS
                                                                     : ZI_STATUS_INVALID_STATE;
}

static ZiStatus map_kernel_image(const ZiBootContext* boot_context) {
  if (boot_context->kernel_size > SIZE_MAX) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  ZiPeSection sections[ZI_KERNEL_PE_SECTION_CAPACITY] = {0};
  ZiPeImage image = {0};
  ZiStatus status = zi_pe_parse((const void*)(uintptr_t)boot_context->kernel_virtual_base,
                                (size_t)boot_context->kernel_size,
                                sections,
                                ZI_KERNEL_PE_SECTION_CAPACITY,
                                &image);
  if (ZiFailed(status)) {
    return status;
  }
  if (image.machine != ZI_PE_MACHINE_AMD64 || image.subsystem != ZI_PE_SUBSYSTEM_NATIVE ||
      image.section_alignment != ZI_X64_PAGE_SIZE || image.image_size > boot_context->kernel_size ||
      zi_pe_has_imports(&image)) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }

  uint64_t header_size = 0;
  g_virtual_memory_stage = ZI_KERNEL_VMM_STAGE_KERNEL_HEADERS;
  status = aligned_size(image.header_size, &header_size);
  if (ZiFailed(status)) {
    return status;
  }
#ifdef ZI_DEBUG
  zi_log_write_hex(ZI_LOG_TRACE,
                   "Memory",
                   "Kernel header virtual base",
                   boot_context->kernel_virtual_base);
  zi_log_write_hex(ZI_LOG_TRACE,
                   "Memory",
                   "Kernel header physical base",
                   boot_context->kernel_physical_base);
  zi_log_write_hex(ZI_LOG_TRACE, "Memory", "Kernel header mapped size", header_size);
#endif
  status = zi_x64_paging_map_range(&g_paging_context,
                                   boot_context->kernel_virtual_base,
                                   boot_context->kernel_physical_base,
                                   header_size,
                                   ZI_X64_PAGE_READ | ZI_X64_PAGE_GLOBAL);
  if (ZiFailed(status)) {
    return status;
  }

  for (uint16_t index = 0; index < image.section_count; ++index) {
    g_virtual_memory_stage = ZI_KERNEL_VMM_STAGE_KERNEL_SECTION;
    const ZiPeSection* section = &sections[index];
    uint64_t mapped_size = section->virtual_size;
    if (section->raw_size > mapped_size) {
      mapped_size = section->raw_size;
    }
    if (mapped_size == 0 || (section->virtual_address & (ZI_X64_PAGE_SIZE - 1)) != 0 ||
        boot_context->kernel_virtual_base > UINT64_MAX - section->virtual_address ||
        boot_context->kernel_physical_base > UINT64_MAX - section->virtual_address) {
      return ZI_STATUS_BAD_IMAGE_FORMAT;
    }
    status = aligned_size(mapped_size, &mapped_size);
    if (ZiFailed(status)) {
      return status;
    }
    uint32_t protection = 0;
    status = section_protection(section->characteristics, &protection);
    if (ZiFailed(status)) {
      return status;
    }
    status = zi_x64_paging_map_range(&g_paging_context,
                                     boot_context->kernel_virtual_base + section->virtual_address,
                                     boot_context->kernel_physical_base + section->virtual_address,
                                     mapped_size,
                                     protection);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus map_hhdm(const ZiBootContext* boot_context) {
  for (size_t index = 0; index < boot_context->memory_range_count; ++index) {
    ZiStatus status = map_hhdm_range(boot_context, &boot_context->memory_ranges[index]);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus map_hhdm_range(const ZiBootContext* boot_context, const ZiBootMemoryRange* range) {
  uint32_t protection = ZI_X64_PAGE_READ | ZI_X64_PAGE_GLOBAL;
  switch (range->type) {
    case ZI_BOOT_MEMORY_USABLE:
      protection |= ZI_X64_PAGE_WRITE;
      break;
    case ZI_BOOT_MEMORY_ACPI_RECLAIMABLE:
    case ZI_BOOT_MEMORY_ACPI_NVS:
    case ZI_BOOT_MEMORY_BOOT_RECLAIMABLE:
    case ZI_BOOT_MEMORY_KERNEL_AND_MODULES:
    case ZI_BOOT_MEMORY_RESERVED_MAPPED:
      break;
    case ZI_BOOT_MEMORY_FRAMEBUFFER:
      protection |= ZI_X64_PAGE_WRITE | ZI_X64_PAGE_DEVICE;
      break;
    case ZI_BOOT_MEMORY_RESERVED:
    case ZI_BOOT_MEMORY_BAD:
      return ZI_STATUS_SUCCESS;
    default:
      return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (boot_context->hhdm_offset > UINT64_MAX - range->physical_base) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  return zi_x64_paging_map_range(&g_paging_context,
                                 boot_context->hhdm_offset + range->physical_base,
                                 range->physical_base,
                                 range->size,
                                 protection);
}

static ZiStatus map_apic(void) {
  uint64_t physical_base = ZkArchReadMsr(ZI_X64_MSR_APIC_BASE) & ZI_X64_MSR_APIC_ADDRESS_MASK;
  if (physical_base == 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  return zi_x64_paging_map_page(&g_paging_context,
                                ZI_KERNEL_APIC_VIRTUAL_BASE,
                                physical_base,
                                ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE | ZI_X64_PAGE_GLOBAL |
                                    ZI_X64_PAGE_DEVICE);
}

static ZiStatus section_protection(uint32_t characteristics, uint32_t* out_protection) {
  if (out_protection == NULL || ((characteristics & ZI_PE_SECTION_WRITE) != 0 &&
                                 (characteristics & ZI_PE_SECTION_EXECUTE) != 0)) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  uint32_t protection = ZI_X64_PAGE_READ | ZI_X64_PAGE_GLOBAL;
  if ((characteristics & ZI_PE_SECTION_WRITE) != 0) {
    protection |= ZI_X64_PAGE_WRITE;
  }
  if ((characteristics & ZI_PE_SECTION_EXECUTE) != 0) {
    protection |= ZI_X64_PAGE_EXECUTE;
  }
  *out_protection = protection;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus aligned_size(uint64_t size, uint64_t* out_size) {
  if (size == 0 || out_size == NULL || size > UINT64_MAX - (ZI_X64_PAGE_SIZE - 1)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_size = (size + ZI_X64_PAGE_SIZE - 1) & ~(ZI_X64_PAGE_SIZE - 1);
  return ZI_STATUS_SUCCESS;
}

static void invalidate_range(uint64_t virtual_address, uint64_t size) {
  for (uint64_t offset = 0; offset < size; offset += ZI_X64_PAGE_SIZE) {
    ZkArchInvalidatePage(virtual_address + offset);
  }
}
