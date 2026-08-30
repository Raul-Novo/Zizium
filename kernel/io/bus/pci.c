// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/pci.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/acpi.h"
#include "zizium/status.h"

#define PCI_VENDOR_ABSENT UINT16_C(0xffff)
#define PCI_HEADER_MULTIFUNCTION UINT8_C(0x80)
#define PCI_HEADER_TYPE_MASK UINT8_C(0x7f)
#define PCI_HEADER_STANDARD UINT8_C(0)
#define PCI_HEADER_BRIDGE UINT8_C(1)
#define PCI_COMMAND_IO_SPACE UINT16_C(1)
#define PCI_COMMAND_MEMORY_SPACE UINT16_C(2)

static ZiStatus
read_device(const ZiPciConfigAccess* access, ZiPciAddress address, ZiPciDevice* out_device);
static ZiStatus enumerate_slot(const ZiAcpiMcfgAllocation* allocation,
                               uint8_t bus,
                               uint8_t device,
                               const ZiPciConfigAccess* access,
                               ZiPciDevice* devices,
                               size_t device_capacity,
                               size_t* count);
static ZiStatus enumerate_allocation(const ZiAcpiMcfgAllocation* allocation,
                                     const ZiPciConfigAccess* access,
                                     ZiPciDevice* devices,
                                     size_t device_capacity,
                                     size_t* count);
static ZiStatus decode_assigned_bars(const ZiPciConfigAccess* access, ZiPciDevice* device);
static ZiStatus probe_bar(const ZiPciConfigAccess* access,
                          ZiPciDevice* device,
                          uint8_t index,
                          uint8_t bar_count,
                          uint8_t* out_consumed);
static bool access_is_valid(const ZiPciConfigAccess* access, bool require_write);
static bool match_u16(uint16_t rule, uint16_t value);
static bool match_u8(uint8_t rule, uint8_t value);
static uint32_t match_specificity(const ZiPciDriverMatch* match);
static uint64_t bar_size32(uint32_t mask);
static uint64_t bar_size64(uint64_t mask);

ZiStatus zi_pci_ecam_address(const ZiAcpiMcfgAllocation* allocation,
                             ZiPciAddress address,
                             uint16_t offset,
                             uint64_t* out_physical_address) {
  if (allocation == NULL || out_physical_address == NULL || address.device >= 32 ||
      address.function >= 8 || offset >= 4096 || (offset & 3u) != 0 ||
      address.segment != allocation->segment_group || address.bus < allocation->start_bus ||
      address.bus > allocation->end_bus) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t relative_bus = (uint64_t)address.bus - allocation->start_bus;
  uint64_t relative = (relative_bus << 20) | ((uint64_t)address.device << 15) |
                      ((uint64_t)address.function << 12) | offset;
  if (allocation->base_address > UINT64_MAX - relative) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  *out_physical_address = allocation->base_address + relative;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_pci_enumerate(const ZiAcpiMcfgAllocation* allocations,
                          size_t allocation_count,
                          const ZiPciConfigAccess* access,
                          ZiPciDevice* devices,
                          size_t device_capacity,
                          size_t* out_device_count) {
  if (allocations == NULL || allocation_count == 0 || !access_is_valid(access, false) ||
      devices == NULL || device_capacity == 0 || out_device_count == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_device_count = 0;

  size_t count = 0;
  for (size_t segment_index = 0; segment_index < allocation_count; ++segment_index) {
    ZiStatus status =
        enumerate_allocation(&allocations[segment_index], access, devices, device_capacity, &count);
    if (ZiFailed(status)) {
      *out_device_count = count;
      return status;
    }
  }
  *out_device_count = count;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus enumerate_allocation(const ZiAcpiMcfgAllocation* allocation,
                                     const ZiPciConfigAccess* access,
                                     ZiPciDevice* devices,
                                     size_t device_capacity,
                                     size_t* count) {
  for (uint16_t bus_value = allocation->start_bus; bus_value <= allocation->end_bus; ++bus_value) {
    for (uint8_t device_value = 0; device_value < 32; ++device_value) {
      ZiStatus status = enumerate_slot(allocation,
                                       (uint8_t)bus_value,
                                       device_value,
                                       access,
                                       devices,
                                       device_capacity,
                                       count);
      if (ZiFailed(status)) {
        return status;
      }
    }
    if (bus_value == UINT8_MAX) {
      break;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus enumerate_slot(const ZiAcpiMcfgAllocation* allocation,
                               uint8_t bus,
                               uint8_t device,
                               const ZiPciConfigAccess* access,
                               ZiPciDevice* devices,
                               size_t device_capacity,
                               size_t* count) {
  ZiPciAddress address = {allocation->segment_group, bus, device, 0};
  uint32_t identity = 0;
  ZiStatus status = access->read32(access->context, address, 0, &identity);
  if (ZiFailed(status) || (uint16_t)identity == PCI_VENDOR_ABSENT) {
    return status;
  }
  uint32_t header = 0;
  status = access->read32(access->context, address, 0x0c, &header);
  if (ZiFailed(status)) {
    return status;
  }
  uint8_t function_count = ((header >> 16) & PCI_HEADER_MULTIFUNCTION) != 0 ? 8 : 1;
  for (uint8_t function = 0; function < function_count; ++function) {
    address.function = function;
    if (function != 0) {
      status = access->read32(access->context, address, 0, &identity);
      if (ZiFailed(status)) {
        return status;
      }
      if ((uint16_t)identity == PCI_VENDOR_ABSENT) {
        continue;
      }
    }
    if (*count >= device_capacity) {
      return ZI_STATUS_BUFFER_TOO_SMALL;
    }
    status = read_device(access, address, &devices[*count]);
    if (ZiFailed(status)) {
      return status;
    }
    ++*count;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_pci_probe_bars(const ZiPciConfigAccess* access, ZiPciDevice* device) {
  if (!access_is_valid(access, true) || device == NULL || device->struct_size < sizeof *device ||
      device->version != ZI_PCI_DEVICE_VERSION) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint8_t header_type = device->header_type & PCI_HEADER_TYPE_MASK;
  uint8_t bar_count = 0;
  if (header_type == PCI_HEADER_STANDARD) {
    bar_count = 6;
  } else if (header_type == PCI_HEADER_BRIDGE) {
    bar_count = 2;
  } else {
    return ZI_STATUS_NOT_IMPLEMENTED;
  }

  uint32_t command_status = 0;
  ZiStatus status = access->read32(access->context, device->address, 4, &command_status);
  if (ZiFailed(status)) {
    return status;
  }
  uint16_t original_command = (uint16_t)command_status;
  status = access->write32(access->context,
                           device->address,
                           4,
                           original_command & ~(PCI_COMMAND_IO_SPACE | PCI_COMMAND_MEMORY_SPACE));
  if (ZiFailed(status)) {
    return status;
  }

  ZiStatus result = ZI_STATUS_SUCCESS;
  for (uint8_t index = 0; index < bar_count;) {
    uint8_t consumed = 1;
    result = probe_bar(access, device, index, bar_count, &consumed);
    if (ZiFailed(result)) {
      break;
    }
    index = (uint8_t)(index + consumed);
  }
  ZiStatus restore_status = access->write32(access->context, device->address, 4, original_command);
  if (ZiSucceeded(result) && ZiFailed(restore_status)) {
    result = restore_status;
  }
  return result;
}

ZiStatus zi_pci_select_driver(const ZiPciDevice* device,
                              const ZiPciDriverMatch* matches,
                              size_t match_count,
                              const ZiPciDriverMatch** out_match) {
  if (device == NULL || matches == NULL || match_count == 0 || out_match == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_match = NULL;
  uint32_t best_specificity = 0;
  uint8_t best_priority = 0;
  for (size_t index = 0; index < match_count; ++index) {
    const ZiPciDriverMatch* match = &matches[index];
    if (!match_u16(match->vendor_id, device->vendor_id) ||
        !match_u16(match->device_id, device->device_id) ||
        !match_u8(match->class_code, device->class_code) ||
        !match_u8(match->subclass, device->subclass) ||
        !match_u8(match->programming_interface, device->programming_interface)) {
      continue;
    }
    uint32_t specificity = match_specificity(match);
    if (*out_match == NULL || specificity > best_specificity ||
        (specificity == best_specificity && match->priority > best_priority)) {
      *out_match = match;
      best_specificity = specificity;
      best_priority = match->priority;
    }
  }
  return *out_match == NULL ? ZI_STATUS_NOT_FOUND : ZI_STATUS_SUCCESS;
}

ZiStatus zi_pci_set_command_bits(const ZiPciConfigAccess* access,
                                 ZiPciAddress address,
                                 uint16_t set_bits,
                                 uint16_t clear_bits) {
  if (!access_is_valid(access, true) || (set_bits & clear_bits) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint32_t command_status = 0;
  ZiStatus status = access->read32(access->context, address, 4, &command_status);
  if (ZiFailed(status)) {
    return status;
  }
  uint16_t command = (uint16_t)command_status;
  command = (uint16_t)((command | set_bits) & ~clear_bits);
  return access->write32(access->context, address, 4, command);
}

static ZiStatus
read_device(const ZiPciConfigAccess* access, ZiPciAddress address, ZiPciDevice* out_device) {
  uint32_t identity = 0;
  uint32_t class_revision = 0;
  uint32_t header = 0;
  uint32_t subsystem = 0;
  uint32_t interrupt = 0;
  ZiStatus status = access->read32(access->context, address, 0, &identity);
  if (ZiSucceeded(status)) {
    status = access->read32(access->context, address, 8, &class_revision);
  }
  if (ZiSucceeded(status)) {
    status = access->read32(access->context, address, 0x0c, &header);
  }
  if (ZiFailed(status)) {
    return status;
  }
  uint8_t header_type = (uint8_t)(header >> 16);
  if ((header_type & PCI_HEADER_TYPE_MASK) == PCI_HEADER_STANDARD) {
    status = access->read32(access->context, address, 0x2c, &subsystem);
    if (ZiFailed(status)) {
      return status;
    }
  }
  status = access->read32(access->context, address, 0x3c, &interrupt);
  if (ZiFailed(status)) {
    return status;
  }

  ZiPciDevice result = {0};
  result.struct_size = sizeof result;
  result.version = ZI_PCI_DEVICE_VERSION;
  result.address = address;
  result.vendor_id = (uint16_t)identity;
  result.device_id = (uint16_t)(identity >> 16);
  result.revision_id = (uint8_t)class_revision;
  result.programming_interface = (uint8_t)(class_revision >> 8);
  result.subclass = (uint8_t)(class_revision >> 16);
  result.class_code = (uint8_t)(class_revision >> 24);
  result.header_type = header_type;
  result.subsystem_vendor_id = (uint16_t)subsystem;
  result.subsystem_id = (uint16_t)(subsystem >> 16);
  result.interrupt_line = (uint8_t)interrupt;
  result.interrupt_pin = (uint8_t)(interrupt >> 8);
  *out_device = result;
  return decode_assigned_bars(access, out_device);
}

static ZiStatus decode_assigned_bars(const ZiPciConfigAccess* access, ZiPciDevice* device) {
  uint8_t header_type = device->header_type & PCI_HEADER_TYPE_MASK;
  uint8_t bar_count = 0;
  if (header_type == PCI_HEADER_STANDARD) {
    bar_count = 6;
  } else if (header_type == PCI_HEADER_BRIDGE) {
    bar_count = 2;
  }
  for (uint8_t index = 0; index < bar_count; ++index) {
    uint32_t low = 0;
    ZiStatus status =
        access->read32(access->context, device->address, (uint16_t)(0x10 + (index * 4)), &low);
    if (ZiFailed(status)) {
      return status;
    }
    ZiPciBar* bar = &device->bars[index];
    bar->register_index = index;
    if ((low & UINT32_C(1)) != 0) {
      bar->kind = ZI_PCI_BAR_IO;
      bar->base_address = low & ~UINT32_C(3);
      continue;
    }
    bar->kind = ZI_PCI_BAR_MEMORY;
    bar->prefetchable = (uint8_t)((low >> 3) & 1u);
    uint32_t memory_type = (low >> 1) & 3u;
    if (memory_type == 2 && index + 1 < bar_count) {
      uint32_t high = 0;
      status = access->read32(access->context,
                              device->address,
                              (uint16_t)(0x10 + ((index + 1) * 4)),
                              &high);
      if (ZiFailed(status)) {
        return status;
      }
      bar->is_64_bit = 1;
      bar->base_address = ((uint64_t)high << 32) | (low & ~UINT32_C(0x0f));
      device->bars[index + 1].register_index = (uint8_t)(index + 1);
      ++index;
    } else if (memory_type == 0) {
      bar->base_address = low & ~UINT32_C(0x0f);
    } else {
      bar->kind = ZI_PCI_BAR_NONE;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus probe_bar(const ZiPciConfigAccess* access,
                          ZiPciDevice* device,
                          uint8_t index,
                          uint8_t bar_count,
                          uint8_t* out_consumed) {
  uint16_t offset = (uint16_t)(0x10 + (index * 4));
  uint32_t original_low = 0;
  ZiStatus status = access->read32(access->context, device->address, offset, &original_low);
  if (ZiFailed(status)) {
    return status;
  }
  *out_consumed = 1;
  bool is_io = (original_low & UINT32_C(1)) != 0;
  bool is_64_bit = (bool)((!is_io && ((original_low >> 1) & 3u) == 2) != 0);
  if (is_64_bit && index + 1 >= bar_count) {
    return ZI_STATUS_INVALID_STATE;
  }

  uint32_t original_high = 0;
  if (is_64_bit) {
    status = access->read32(access->context, device->address, offset + 4, &original_high);
    if (ZiFailed(status)) {
      return status;
    }
  }
  status = access->write32(access->context, device->address, offset, UINT32_MAX);
  if (ZiFailed(status)) {
    return status;
  }
  if (is_64_bit) {
    status = access->write32(access->context, device->address, offset + 4, UINT32_MAX);
    if (ZiFailed(status)) {
      (void)access->write32(access->context, device->address, offset, original_low);
      return status;
    }
  }

  uint32_t mask_low = 0;
  uint32_t mask_high = 0;
  status = access->read32(access->context, device->address, offset, &mask_low);
  if (ZiSucceeded(status) && is_64_bit) {
    status = access->read32(access->context, device->address, offset + 4, &mask_high);
  }
  ZiStatus restore_status = ZI_STATUS_SUCCESS;
  if (is_64_bit) {
    restore_status = access->write32(access->context, device->address, offset + 4, original_high);
  }
  ZiStatus low_restore_status =
      access->write32(access->context, device->address, offset, original_low);
  if (ZiSucceeded(restore_status) && ZiFailed(low_restore_status)) {
    restore_status = low_restore_status;
  }
  if (ZiFailed(status)) {
    return status;
  }
  if (ZiFailed(restore_status)) {
    return restore_status;
  }

  ZiPciBar* bar = &device->bars[index];
  if (is_io) {
    uint32_t mask = mask_low & ~UINT32_C(3);
    bar->size = bar_size32(mask);
  } else if (is_64_bit) {
    uint64_t mask = ((uint64_t)mask_high << 32) | (mask_low & ~UINT32_C(0x0f));
    bar->size = bar_size64(mask);
    *out_consumed = 2;
  } else {
    uint32_t mask = mask_low & ~UINT32_C(0x0f);
    bar->size = bar_size32(mask);
  }
  return ZI_STATUS_SUCCESS;
}

static bool access_is_valid(const ZiPciConfigAccess* access, bool require_write) {
  return (bool)((access != NULL && access->struct_size >= sizeof *access &&
                 access->version == ZI_PCI_CONFIG_ACCESS_VERSION && access->read32 != NULL &&
                 (!require_write || access->write32 != NULL)) != 0);
}

static bool match_u16(uint16_t rule, uint16_t value) {
  return (bool)((rule == ZI_PCI_MATCH_ANY_U16 || rule == value) != 0);
}

static bool match_u8(uint8_t rule, uint8_t value) {
  return (bool)((rule == ZI_PCI_MATCH_ANY_U8 || rule == value) != 0);
}

static uint32_t match_specificity(const ZiPciDriverMatch* match) {
  uint32_t score = 0;
  score += match->vendor_id == ZI_PCI_MATCH_ANY_U16 ? 0u : 16u;
  score += match->device_id == ZI_PCI_MATCH_ANY_U16 ? 0u : 8u;
  score += match->class_code == ZI_PCI_MATCH_ANY_U8 ? 0u : 4u;
  score += match->subclass == ZI_PCI_MATCH_ANY_U8 ? 0u : 2u;
  score += match->programming_interface == ZI_PCI_MATCH_ANY_U8 ? 0u : 1u;
  return score;
}

static uint64_t bar_size32(uint32_t mask) {
  if (mask == 0) {
    return 0;
  }
  return ~mask + 1u;
}

static uint64_t bar_size64(uint64_t mask) {
  if (mask == 0) {
    return 0;
  }
  return ~mask + 1u;
}
