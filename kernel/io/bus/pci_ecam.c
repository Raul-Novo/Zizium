// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/pci_ecam.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/acpi.h"
#include "zi/arch_x64.h"
#include "zi/executive_lock.h"
#include "zi/kernel_memory.h"
#include "zi/pci.h"
#include "zizium/status.h"

#define PCI_ECAM_BUS_SIZE UINT64_C(0x100000)

static ZiStatus read32(void* opaque, ZiPciAddress address, uint16_t offset, uint32_t* out_value);
static ZiStatus write32(void* opaque, ZiPciAddress address, uint16_t offset, uint32_t value);
static ZiStatus ensure_bus_mapping(ZiPciEcamContext* context, ZiPciAddress address);
static const ZiAcpiMcfgAllocation* find_allocation(const ZiPciEcamContext* context,
                                                   ZiPciAddress address);
static bool context_is_valid(const ZiPciEcamContext* context);

ZiStatus zi_pci_ecam_initialise(const ZiAcpiMcfgAllocation* allocations,
                                size_t allocation_count,
                                ZiPciEcamContext* context,
                                ZiPciConfigAccess* out_access) {
  if (allocations == NULL || allocation_count == 0 || context == NULL || out_access == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  for (size_t index = 0; index < allocation_count; ++index) {
    if (allocations[index].base_address == 0 ||
        (allocations[index].base_address & (PCI_ECAM_BUS_SIZE - 1)) != 0 ||
        allocations[index].start_bus > allocations[index].end_bus) {
      return ZI_STATUS_INVALID_ARGUMENT;
    }
  }
  ZiPciEcamContext result = {0};
  result.struct_size = sizeof result;
  result.version = ZI_PCI_ECAM_CONTEXT_VERSION;
  result.allocations = allocations;
  result.allocation_count = allocation_count;
  zi_executive_lock_initialise(&result.lock);
  *context = result;
  ZiPciConfigAccess access = {
      sizeof(ZiPciConfigAccess),
      ZI_PCI_CONFIG_ACCESS_VERSION,
      context,
      read32,
      write32,
  };
  *out_access = access;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_pci_ecam_finish(ZiPciEcamContext* context) {
  if (!context_is_valid(context)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_executive_lock_acquire(&context->lock);
  ZiStatus status = ZI_STATUS_SUCCESS;
  if (context->bus_is_mapped != 0) {
    status = zi_kernel_mmio_unmap(&context->bus_mapping);
    if (ZiSucceeded(status)) {
      context->bus_is_mapped = 0;
    }
  }
  zi_executive_lock_release(&context->lock);
  if (ZiSucceeded(status)) {
    ZiPciEcamContext empty = {0};
    *context = empty;
  }
  return status;
}

static ZiStatus read32(void* opaque, ZiPciAddress address, uint16_t offset, uint32_t* out_value) {
  ZiPciEcamContext* context = opaque;
  if (!context_is_valid(context) || out_value == NULL || address.device >= 32 ||
      address.function >= 8 || offset >= 4096 || (offset & 3u) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_executive_lock_acquire(&context->lock);
  ZiStatus status = ensure_bus_mapping(context, address);
  if (ZiSucceeded(status)) {
    uintptr_t register_offset =
        ((uintptr_t)address.device << 15) | ((uintptr_t)address.function << 12) | offset;
    const volatile uint32_t* register_pointer =
        (const volatile uint32_t*)((uintptr_t)context->bus_mapping.address + register_offset);
    *out_value = *register_pointer;
  }
  zi_executive_lock_release(&context->lock);
  return status;
}

static ZiStatus write32(void* opaque, ZiPciAddress address, uint16_t offset, uint32_t value) {
  ZiPciEcamContext* context = opaque;
  if (!context_is_valid(context) || address.device >= 32 || address.function >= 8 ||
      offset >= 4096 || (offset & 3u) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_executive_lock_acquire(&context->lock);
  ZiStatus status = ensure_bus_mapping(context, address);
  if (ZiSucceeded(status)) {
    uintptr_t register_offset =
        ((uintptr_t)address.device << 15) | ((uintptr_t)address.function << 12) | offset;
    volatile uint32_t* register_pointer =
        (volatile uint32_t*)((uintptr_t)context->bus_mapping.address + register_offset);
    *register_pointer = value;
    ZkArchMemoryBarrier();
  }
  zi_executive_lock_release(&context->lock);
  return status;
}

static ZiStatus ensure_bus_mapping(ZiPciEcamContext* context, ZiPciAddress address) {
  if (context->bus_is_mapped != 0 && context->mapped_segment == address.segment &&
      context->mapped_bus == address.bus) {
    return ZI_STATUS_SUCCESS;
  }
  const ZiAcpiMcfgAllocation* allocation = find_allocation(context, address);
  if (allocation == NULL) {
    return ZI_STATUS_NOT_FOUND;
  }
  if (context->bus_is_mapped != 0) {
    ZiStatus status = zi_kernel_mmio_unmap(&context->bus_mapping);
    if (ZiFailed(status)) {
      return status;
    }
    context->bus_is_mapped = 0;
  }
  uint64_t bus_offset = ((uint64_t)address.bus - allocation->start_bus) << 20;
  if (allocation->base_address > UINT64_MAX - bus_offset) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  ZiStatus status = zi_kernel_mmio_map(allocation->base_address + bus_offset,
                                       (size_t)PCI_ECAM_BUS_SIZE,
                                       &context->bus_mapping);
  if (ZiFailed(status)) {
    return status;
  }
  context->mapped_segment = address.segment;
  context->mapped_bus = address.bus;
  context->bus_is_mapped = 1;
  return ZI_STATUS_SUCCESS;
}

static const ZiAcpiMcfgAllocation* find_allocation(const ZiPciEcamContext* context,
                                                   ZiPciAddress address) {
  for (size_t index = 0; index < context->allocation_count; ++index) {
    const ZiAcpiMcfgAllocation* allocation = &context->allocations[index];
    if (allocation->segment_group == address.segment && address.bus >= allocation->start_bus &&
        address.bus <= allocation->end_bus) {
      return allocation;
    }
  }
  return NULL;
}

static bool context_is_valid(const ZiPciEcamContext* context) {
  return (bool)((context != NULL && context->struct_size >= sizeof *context &&
                 context->version == ZI_PCI_ECAM_CONTEXT_VERSION && context->allocations != NULL &&
                 context->allocation_count != 0) != 0);
}
