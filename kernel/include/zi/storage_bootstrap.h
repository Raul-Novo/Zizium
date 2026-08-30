// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/acpi.h"
#include "zi/block.h"
#include "zi/boot.h"
#include "zi/driver.h"
#include "zi/gpt.h"
#include "zi/nvme.h"
#include "zi/pci.h"
#include "zi/pci_ecam.h"
#include "zizium/status.h"

#define ZI_STORAGE_BOOTSTRAP_VERSION 1u
#define ZI_STORAGE_MAXIMUM_MCFG_ALLOCATIONS 8u
#define ZI_STORAGE_MAXIMUM_PCI_DEVICES 128u
#define ZI_STORAGE_PCI_NAME_CAPACITY 48u

enum ZiStorageInitialiseFlags {
  ZI_STORAGE_INITIALISE_NONE = 0,
  ZI_STORAGE_INITIALISE_FORCE_NVME_TIMEOUT = 1u << 0,
};

enum ZiStorageStage {
  ZI_STORAGE_STAGE_NONE = 0,
  ZI_STORAGE_STAGE_MANAGERS = 1,
  ZI_STORAGE_STAGE_ACPI = 2,
  ZI_STORAGE_STAGE_MCFG = 3,
  ZI_STORAGE_STAGE_PCIE = 4,
  ZI_STORAGE_STAGE_DEVICES = 5,
  ZI_STORAGE_STAGE_NVME = 6,
  ZI_STORAGE_STAGE_GPT = 7,
  ZI_STORAGE_STAGE_PARTITION = 8,
  ZI_STORAGE_STAGE_READ_STRESS = 9,
  ZI_STORAGE_STAGE_READY = 10,
};

enum ZiStorageCompletedFlags {
  ZI_STORAGE_COMPLETED_MANAGERS = 1u << 0,
  ZI_STORAGE_COMPLETED_ACPI = 1u << 1,
  ZI_STORAGE_COMPLETED_PCIE = 1u << 2,
  ZI_STORAGE_COMPLETED_DEVICES = 1u << 3,
  ZI_STORAGE_COMPLETED_NVME = 1u << 4,
  ZI_STORAGE_COMPLETED_GPT = 1u << 5,
  ZI_STORAGE_COMPLETED_PARTITION = 1u << 6,
  ZI_STORAGE_COMPLETED_READ_STRESS = 1u << 7,
};

typedef struct ZiStorageBootstrap {
  uint32_t struct_size;
  uint32_t version;
  uint32_t stage;
  uint32_t completed_flags;
  ZiStatus last_status;
  ZiAcpiContext acpi;
  ZiAcpiMcfgAllocation mcfg[ZI_STORAGE_MAXIMUM_MCFG_ALLOCATIONS];
  size_t mcfg_count;
  ZiPciEcamContext ecam;
  ZiPciConfigAccess pci_access;
  ZiPciDevice pci_devices[ZI_STORAGE_MAXIMUM_PCI_DEVICES];
  size_t pci_device_count;
  ZiDriverObject pci_bus_driver;
  ZiDeviceObject pci_device_objects[ZI_STORAGE_MAXIMUM_PCI_DEVICES];
  char pci_device_names[ZI_STORAGE_MAXIMUM_PCI_DEVICES][ZI_STORAGE_PCI_NAME_CAPACITY];
  size_t published_device_count;
  ZiNvmeController nvme;
  unsigned char gpt_scratch[4096];
  ZiGptPartition gpt_partitions[ZI_STORAGE_MAXIMUM_PCI_DEVICES];
  ZiGptTable gpt;
  ZiPartitionBlockContext partition_context;
  ZiBlockDevice zifs_partition;
  uint32_t read_stress_crc;
} ZiStorageBootstrap;

ZiStatus zi_storage_bootstrap_initialise(const ZiBootContext* boot_context,
                                         uint32_t flags,
                                         ZiStorageBootstrap* bootstrap,
                                         const ZiBlockDevice** out_zifs_partition);
