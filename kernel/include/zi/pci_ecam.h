// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/acpi.h"
#include "zi/executive_lock.h"
#include "zi/kernel_memory.h"
#include "zi/pci.h"
#include "zizium/status.h"

#define ZI_PCI_ECAM_CONTEXT_VERSION 1u

typedef struct ZiPciEcamContext {
  uint32_t struct_size;
  uint32_t version;
  const ZiAcpiMcfgAllocation* allocations;
  size_t allocation_count;
  ZiKernelMmioMapping bus_mapping;
  uint16_t mapped_segment;
  uint8_t mapped_bus;
  uint8_t bus_is_mapped;
  ZiExecutiveLock lock;
} ZiPciEcamContext;

ZiStatus zi_pci_ecam_initialise(const ZiAcpiMcfgAllocation* allocations,
                                size_t allocation_count,
                                ZiPciEcamContext* context,
                                ZiPciConfigAccess* out_access);
ZiStatus zi_pci_ecam_finish(ZiPciEcamContext* context);
