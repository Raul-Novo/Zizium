// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/acpi.h"
#include "zizium/status.h"

#define ZI_PCI_CONFIG_ACCESS_VERSION 1u
#define ZI_PCI_DEVICE_VERSION 1u
#define ZI_PCI_BAR_COUNT 6u
#define ZI_PCI_MATCH_ANY_U16 UINT16_C(0xffff)
#define ZI_PCI_MATCH_ANY_U8 UINT8_C(0xff)

enum ZiPciBarKind {
  ZI_PCI_BAR_NONE = 0,
  ZI_PCI_BAR_MEMORY = 1,
  ZI_PCI_BAR_IO = 2,
};

typedef struct ZiPciAddress {
  uint16_t segment;
  uint8_t bus;
  uint8_t device;
  uint8_t function;
} ZiPciAddress;

typedef ZiStatus (*ZiPciConfigRead32Routine)(void* context,
                                             ZiPciAddress address,
                                             uint16_t offset,
                                             uint32_t* out_value);
typedef ZiStatus (*ZiPciConfigWrite32Routine)(void* context,
                                              ZiPciAddress address,
                                              uint16_t offset,
                                              uint32_t value);

typedef struct ZiPciConfigAccess {
  uint32_t struct_size;
  uint32_t version;
  void* context;
  ZiPciConfigRead32Routine read32;
  ZiPciConfigWrite32Routine write32;
} ZiPciConfigAccess;

typedef struct ZiPciBar {
  uint64_t base_address;
  uint64_t size;
  uint8_t kind;
  uint8_t is_64_bit;
  uint8_t prefetchable;
  uint8_t register_index;
} ZiPciBar;

typedef struct ZiPciDevice {
  uint32_t struct_size;
  uint32_t version;
  ZiPciAddress address;
  uint16_t vendor_id;
  uint16_t device_id;
  uint16_t subsystem_vendor_id;
  uint16_t subsystem_id;
  uint8_t class_code;
  uint8_t subclass;
  uint8_t programming_interface;
  uint8_t revision_id;
  uint8_t header_type;
  uint8_t interrupt_line;
  uint8_t interrupt_pin;
  ZiPciBar bars[ZI_PCI_BAR_COUNT];
} ZiPciDevice;

typedef struct ZiPciDriverMatch {
  uint16_t vendor_id;
  uint16_t device_id;
  uint8_t class_code;
  uint8_t subclass;
  uint8_t programming_interface;
  uint8_t priority;
  uint32_t driver_id;
} ZiPciDriverMatch;

ZiStatus zi_pci_ecam_address(const ZiAcpiMcfgAllocation* allocation,
                             ZiPciAddress address,
                             uint16_t offset,
                             uint64_t* out_physical_address);
ZiStatus zi_pci_enumerate(const ZiAcpiMcfgAllocation* allocations,
                          size_t allocation_count,
                          const ZiPciConfigAccess* access,
                          ZiPciDevice* devices,
                          size_t device_capacity,
                          size_t* out_device_count);
ZiStatus zi_pci_probe_bars(const ZiPciConfigAccess* access, ZiPciDevice* device);
ZiStatus zi_pci_select_driver(const ZiPciDevice* device,
                              const ZiPciDriverMatch* matches,
                              size_t match_count,
                              const ZiPciDriverMatch** out_match);
ZiStatus zi_pci_set_command_bits(const ZiPciConfigAccess* access,
                                 ZiPciAddress address,
                                 uint16_t set_bits,
                                 uint16_t clear_bits);
