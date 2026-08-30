// SPDX-License-Identifier: GPL-3.0-or-later

#include <stddef.h>
#include <stdint.h>

#include "limine.h"
#include "zi/boot.h"
#include "zi/byte_order.h"
#include "zi/display.h"
#include "zizium/status.h"

#pragma section(".limreq$a", read, write)
#pragma section(".limreq$b", read, write)
#pragma section(".limreq$z", read, write)

// Limine discovery and /include linker roots require externally visible COFF symbols.
// NOLINTBEGIN(misc-use-internal-linkage)
__declspec(allocate(".limreq$a")) volatile uint64_t g_limine_requests_start_marker[4] =
    LIMINE_REQUESTS_START_MARKER;
__declspec(allocate(".limreq$b")) volatile uint64_t g_limine_base_revision[3] =
    LIMINE_BASE_REVISION(6);

__declspec(allocate(".limreq$b")) volatile struct limine_bootloader_info_request
    g_limine_bootloader_info_request = {LIMINE_BOOTLOADER_INFO_REQUEST_ID, 0, NULL};
__declspec(allocate(".limreq$b")) volatile struct limine_executable_cmdline_request
    g_limine_command_line_request = {LIMINE_EXECUTABLE_CMDLINE_REQUEST_ID, 0, NULL};
__declspec(allocate(".limreq$b")) volatile struct limine_memmap_request
    g_limine_memory_map_request = {LIMINE_MEMMAP_REQUEST_ID, 0, NULL};
__declspec(allocate(".limreq$b")) volatile struct limine_hhdm_request g_limine_hhdm_request = {
    LIMINE_HHDM_REQUEST_ID,
    0,
    NULL,
};
__declspec(allocate(
    ".limreq$b")) volatile struct limine_paging_mode_request g_limine_paging_mode_request = {
    LIMINE_PAGING_MODE_REQUEST_ID,
    0,
    NULL,
    LIMINE_PAGING_MODE_X86_64_4LVL,
    LIMINE_PAGING_MODE_X86_64_4LVL,
    LIMINE_PAGING_MODE_X86_64_4LVL,
};
__declspec(allocate(".limreq$b")) volatile struct limine_executable_address_request
    g_limine_executable_address_request = {LIMINE_EXECUTABLE_ADDRESS_REQUEST_ID, 0, NULL};
__declspec(allocate(".limreq$b")) volatile struct limine_framebuffer_request
    g_limine_framebuffer_request = {LIMINE_FRAMEBUFFER_REQUEST_ID, 1, NULL};
__declspec(allocate(".limreq$b")) volatile struct limine_module_request g_limine_module_request = {
    LIMINE_MODULE_REQUEST_ID,
    0,
    NULL,
    0,
    NULL,
};
__declspec(allocate(".limreq$b")) volatile struct limine_rsdp_request g_limine_rsdp_request = {
    LIMINE_RSDP_REQUEST_ID,
    0,
    NULL,
};
__declspec(allocate(".limreq$b")) volatile struct limine_efi_system_table_request
    g_limine_efi_system_table_request = {LIMINE_EFI_SYSTEM_TABLE_REQUEST_ID, 0, NULL};

__declspec(allocate(".limreq$z")) volatile uint64_t g_limine_requests_end_marker[2] =
    LIMINE_REQUESTS_END_MARKER;

void* volatile g_zk_relocation_anchor = (void*)&g_zk_relocation_anchor;
// NOLINTEND(misc-use-internal-linkage)

static ZiBootMemoryRange g_memory_ranges[ZI_BOOT_MAX_MEMORY_RANGES];
static ZiDisplayOutput g_display_outputs[ZI_BOOT_MAX_DISPLAY_OUTPUTS];
static ZiBootModule g_modules[ZI_BOOT_MAX_MODULES];
static ZiBootContext g_boot_context;

static uint32_t translate_memory_type(uint64_t limine_type);
static ZiStatus translate_memory_map(void);
static ZiStatus translate_framebuffers(void);
static ZiStatus translate_modules(void);
static ZiStatus translate_kernel_address(void);

ZiStatus zi_boot_context_from_limine(const ZiBootContext** out_context) {
  if (out_context == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_context = NULL;
  if (!LIMINE_BASE_REVISION_SUPPORTED(g_limine_base_revision)) {
    return ZI_STATUS_INVALID_STATE;
  }

  zi_memory_zero(&g_boot_context, sizeof g_boot_context);
  g_boot_context.struct_size = sizeof g_boot_context;
  g_boot_context.version = ZI_BOOT_CONTEXT_VERSION;

  struct limine_bootloader_info_response* bootloader_response =
      g_limine_bootloader_info_request.response;
  if (bootloader_response != NULL) {
    g_boot_context.bootloader_name = bootloader_response->name;
    g_boot_context.bootloader_version = bootloader_response->version;
  }
  struct limine_executable_cmdline_response* command_line_response =
      g_limine_command_line_request.response;
  if (command_line_response != NULL) {
    g_boot_context.command_line = command_line_response->cmdline;
  }
  struct limine_hhdm_response* hhdm_response = g_limine_hhdm_request.response;
  if (hhdm_response == NULL) {
    return ZI_STATUS_INVALID_STATE;
  }
  g_boot_context.hhdm_offset = hhdm_response->offset;
  struct limine_paging_mode_response* paging_response = g_limine_paging_mode_request.response;
  if (paging_response == NULL || paging_response->mode != LIMINE_PAGING_MODE_X86_64_4LVL) {
    return ZI_STATUS_INVALID_STATE;
  }
  g_boot_context.paging_mode = ZI_BOOT_PAGING_X64_FOUR_LEVEL;
  struct limine_rsdp_response* rsdp_response = g_limine_rsdp_request.response;
  if (rsdp_response != NULL) {
    g_boot_context.rsdp = rsdp_response->address;
    if ((uintptr_t)rsdp_response->address < g_boot_context.hhdm_offset) {
      return ZI_STATUS_INVALID_STATE;
    }
    g_boot_context.rsdp_physical_address =
        (uint64_t)(uintptr_t)rsdp_response->address - g_boot_context.hhdm_offset;
  }
  struct limine_efi_system_table_response* efi_response =
      g_limine_efi_system_table_request.response;
  if (efi_response != NULL) {
    g_boot_context.efi_system_table = efi_response->address;
  }

  ZiStatus status = translate_memory_map();
  if (ZiFailed(status)) {
    return status;
  }
  status = translate_kernel_address();
  if (ZiFailed(status)) {
    return status;
  }
  status = translate_framebuffers();
  if (ZiFailed(status)) {
    return status;
  }
  status = translate_modules();
  if (ZiFailed(status)) {
    return status;
  }
  *out_context = &g_boot_context;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus translate_kernel_address(void) {
  const struct limine_executable_address_response* response =
      g_limine_executable_address_request.response;
  if (response == NULL || response->physical_base == 0 || response->virtual_base == 0 ||
      (response->physical_base & UINT64_C(0xfff)) != 0 ||
      (response->virtual_base & UINT64_C(0xfff)) != 0) {
    return ZI_STATUS_INVALID_STATE;
  }

  uint64_t kernel_size = 0;
  for (size_t index = 0; index < g_boot_context.memory_range_count; ++index) {
    const ZiBootMemoryRange* range = &g_boot_context.memory_ranges[index];
    if (range->type != ZI_BOOT_MEMORY_KERNEL_AND_MODULES ||
        response->physical_base < range->physical_base ||
        response->physical_base - range->physical_base >= range->size) {
      continue;
    }
    kernel_size = range->size - (response->physical_base - range->physical_base);
    break;
  }
  if (kernel_size == 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  g_boot_context.kernel_physical_base = response->physical_base;
  g_boot_context.kernel_virtual_base = response->virtual_base;
  g_boot_context.kernel_size = kernel_size;
  return ZI_STATUS_SUCCESS;
}

static uint32_t translate_memory_type(uint64_t limine_type) {
  switch (limine_type) {
    case LIMINE_MEMMAP_USABLE:
      return ZI_BOOT_MEMORY_USABLE;
    case LIMINE_MEMMAP_ACPI_RECLAIMABLE:
      return ZI_BOOT_MEMORY_ACPI_RECLAIMABLE;
    case LIMINE_MEMMAP_ACPI_NVS:
      return ZI_BOOT_MEMORY_ACPI_NVS;
    case LIMINE_MEMMAP_BAD_MEMORY:
      return ZI_BOOT_MEMORY_BAD;
    case LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE:
      return ZI_BOOT_MEMORY_BOOT_RECLAIMABLE;
    case LIMINE_MEMMAP_EXECUTABLE_AND_MODULES:
      return ZI_BOOT_MEMORY_KERNEL_AND_MODULES;
    case LIMINE_MEMMAP_FRAMEBUFFER:
      return ZI_BOOT_MEMORY_FRAMEBUFFER;
    case LIMINE_MEMMAP_RESERVED_MAPPED:
      return ZI_BOOT_MEMORY_RESERVED_MAPPED;
    default:
      return ZI_BOOT_MEMORY_RESERVED;
  }
}

static ZiStatus translate_memory_map(void) {
  struct limine_memmap_response* response = g_limine_memory_map_request.response;
  if (response == NULL || response->entries == NULL || response->entry_count == 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  if (response->entry_count > ZI_BOOT_MAX_MEMORY_RANGES) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  for (size_t index = 0; index < (size_t)response->entry_count; ++index) {
    const struct limine_memmap_entry* source = response->entries[index];
    if (source == NULL) {
      return ZI_STATUS_INVALID_STATE;
    }
    g_memory_ranges[index].physical_base = source->base;
    g_memory_ranges[index].size = source->length;
    g_memory_ranges[index].type = translate_memory_type(source->type);
    g_memory_ranges[index].reserved = 0;
  }
  g_boot_context.memory_ranges = g_memory_ranges;
  g_boot_context.memory_range_count = (size_t)response->entry_count;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus translate_framebuffers(void) {
  struct limine_framebuffer_response* response = g_limine_framebuffer_request.response;
  if (response == NULL) {
    return ZI_STATUS_SUCCESS;
  }
  if (response->framebuffer_count > ZI_BOOT_MAX_DISPLAY_OUTPUTS ||
      (response->framebuffer_count != 0 && response->framebuffers == NULL)) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  for (size_t index = 0; index < (size_t)response->framebuffer_count; ++index) {
    const struct limine_framebuffer* source = response->framebuffers[index];
    if (source == NULL || source->width == 0 || source->height == 0 || source->width > UINT32_MAX ||
        source->height > UINT32_MAX || source->pitch > UINT32_MAX ||
        source->pitch > SIZE_MAX / source->height) {
      return ZI_STATUS_INVALID_STATE;
    }
    ZiDisplayOutput* output = &g_display_outputs[index];
    zi_memory_zero(output, sizeof *output);
    output->output_id = index;
    output->active_mode.width = (uint32_t)source->width;
    output->active_mode.height = (uint32_t)source->height;
    output->active_mode.bits_per_pixel = source->bpp;
    output->scale = zi_display_default_scale(output->active_mode.height);
    output->framebuffer.address = source->address;
    output->framebuffer.size = (size_t)(source->pitch * source->height);
    output->framebuffer.width = (uint32_t)source->width;
    output->framebuffer.height = (uint32_t)source->height;
    output->framebuffer.pitch = (uint32_t)source->pitch;
    output->framebuffer.bits_per_pixel = source->bpp;
    output->framebuffer.pixel_format = source->memory_model;
    output->framebuffer.red_mask_size = source->red_mask_size;
    output->framebuffer.red_mask_shift = source->red_mask_shift;
    output->framebuffer.green_mask_size = source->green_mask_size;
    output->framebuffer.green_mask_shift = source->green_mask_shift;
    output->framebuffer.blue_mask_size = source->blue_mask_size;
    output->framebuffer.blue_mask_shift = source->blue_mask_shift;
  }
  g_boot_context.display_outputs = g_display_outputs;
  g_boot_context.display_output_count = (size_t)response->framebuffer_count;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus translate_modules(void) {
  struct limine_module_response* response = g_limine_module_request.response;
  if (response == NULL) {
    return ZI_STATUS_SUCCESS;
  }
  if (response->module_count > ZI_BOOT_MAX_MODULES ||
      (response->module_count != 0 && response->modules == NULL)) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  for (size_t index = 0; index < (size_t)response->module_count; ++index) {
    const struct limine_file* source = response->modules[index];
    if (source == NULL || source->address == NULL || source->size == 0) {
      return ZI_STATUS_INVALID_STATE;
    }
    g_modules[index].address = source->address;
    if ((uintptr_t)source->address < g_boot_context.hhdm_offset) {
      return ZI_STATUS_INVALID_STATE;
    }
    g_modules[index].physical_base =
        (uint64_t)(uintptr_t)source->address - g_boot_context.hhdm_offset;
    g_modules[index].size = source->size;
    g_modules[index].path = source->path;
    g_modules[index].command_line = source->string;
  }
  g_boot_context.modules = g_modules;
  g_boot_context.module_count = (size_t)response->module_count;
  return ZI_STATUS_SUCCESS;
}
