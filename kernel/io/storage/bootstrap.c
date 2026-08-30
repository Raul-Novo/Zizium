// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/acpi.h"
#include "zi/block.h"
#include "zi/boot.h"
#include "zi/byte_order.h"
#include "zi/crc32.h"
#include "zi/driver.h"
#include "zi/gpt.h"
#include "zi/io.h"
#include "zi/kernel_dma.h"
#include "zi/kernel_memory.h"
#include "zi/nvme.h"
#include "zi/pci.h"
#include "zi/pci_ecam.h"
#include "zi/storage_bootstrap.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define STORAGE_READ_STRESS_ROUNDS 64u

static const char k_pci_driver_name[] = "PCIe";
static const char k_pci_device_prefix[] = "\\System\\Devices\\PCI\\";
static const ZiPciDriverMatch k_driver_matches[] = {
    {ZI_PCI_MATCH_ANY_U16,
     ZI_PCI_MATCH_ANY_U16,
     UINT8_C(0x01),
     UINT8_C(0x08),
     UINT8_C(0x02),
     100,
     1},
};

static ZiStatus read_physical(void* context, uint64_t physical_address, void* output, size_t size);
static ZiStatus initialise_managers(void);
static ZiStatus publish_pci_devices(ZiStorageBootstrap* bootstrap);
static ZiStatus initialise_nvme(ZiStorageBootstrap* bootstrap, uint32_t flags);
static ZiStatus discover_zifs_partition(ZiStorageBootstrap* bootstrap);
static ZiStatus run_read_stress(ZiStorageBootstrap* bootstrap);
static void clean_failed_bootstrap(ZiStorageBootstrap* bootstrap);
static size_t format_pci_name(ZiPciAddress address, char* output, size_t capacity);
static size_t append_text(char* output, size_t capacity, size_t offset, const char* text);
static size_t
append_hex(char* output, size_t capacity, size_t offset, uint32_t value, size_t digits);
static ZiStatus fail_at(ZiStorageBootstrap* bootstrap, uint32_t stage, ZiStatus status);

ZiStatus zi_storage_bootstrap_initialise(const ZiBootContext* boot_context,
                                         uint32_t flags,
                                         ZiStorageBootstrap* bootstrap,
                                         const ZiBlockDevice** out_zifs_partition) {
  if (boot_context == NULL || boot_context->struct_size < sizeof *boot_context ||
      boot_context->version != ZI_BOOT_CONTEXT_VERSION ||
      boot_context->rsdp_physical_address == 0 || bootstrap == NULL || out_zifs_partition == NULL ||
      (flags & ~ZI_STORAGE_INITIALISE_FORCE_NVME_TIMEOUT) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_zifs_partition = NULL;
  zi_memory_zero(bootstrap, sizeof *bootstrap);
  bootstrap->struct_size = sizeof *bootstrap;
  bootstrap->version = ZI_STORAGE_BOOTSTRAP_VERSION;

  ZiStatus status = initialise_managers();
  if (ZiFailed(status)) {
    return fail_at(bootstrap, ZI_STORAGE_STAGE_MANAGERS, status);
  }
  bootstrap->completed_flags |= ZI_STORAGE_COMPLETED_MANAGERS;

  ZiAcpiPhysicalReader reader = {
      sizeof(ZiAcpiPhysicalReader),
      ZI_ACPI_PHYSICAL_READER_VERSION,
      NULL,
      read_physical,
  };
  status = zi_acpi_initialise(boot_context->rsdp_physical_address, &reader, &bootstrap->acpi);
  if (ZiFailed(status)) {
    return fail_at(bootstrap, ZI_STORAGE_STAGE_ACPI, status);
  }
  bootstrap->completed_flags |= ZI_STORAGE_COMPLETED_ACPI;

  status = zi_acpi_parse_mcfg(&bootstrap->acpi,
                              bootstrap->mcfg,
                              ZI_STORAGE_MAXIMUM_MCFG_ALLOCATIONS,
                              &bootstrap->mcfg_count);
  if (ZiFailed(status)) {
    return fail_at(bootstrap, ZI_STORAGE_STAGE_MCFG, status);
  }
  status = zi_pci_ecam_initialise(bootstrap->mcfg,
                                  bootstrap->mcfg_count,
                                  &bootstrap->ecam,
                                  &bootstrap->pci_access);
  if (ZiFailed(status)) {
    return fail_at(bootstrap, ZI_STORAGE_STAGE_PCIE, status);
  }
  status = zi_pci_enumerate(bootstrap->mcfg,
                            bootstrap->mcfg_count,
                            &bootstrap->pci_access,
                            bootstrap->pci_devices,
                            ZI_STORAGE_MAXIMUM_PCI_DEVICES,
                            &bootstrap->pci_device_count);
  if (ZiFailed(status)) {
    clean_failed_bootstrap(bootstrap);
    return fail_at(bootstrap, ZI_STORAGE_STAGE_PCIE, status);
  }
  bootstrap->completed_flags |= ZI_STORAGE_COMPLETED_PCIE;

  status = publish_pci_devices(bootstrap);
  if (ZiFailed(status)) {
    clean_failed_bootstrap(bootstrap);
    return fail_at(bootstrap, ZI_STORAGE_STAGE_DEVICES, status);
  }
  bootstrap->completed_flags |= ZI_STORAGE_COMPLETED_DEVICES;

  status = initialise_nvme(bootstrap, flags);
  if (ZiFailed(status)) {
    clean_failed_bootstrap(bootstrap);
    return fail_at(bootstrap, ZI_STORAGE_STAGE_NVME, status);
  }
  bootstrap->completed_flags |= ZI_STORAGE_COMPLETED_NVME;

  status = discover_zifs_partition(bootstrap);
  if (ZiFailed(status)) {
    clean_failed_bootstrap(bootstrap);
    return fail_at(bootstrap, ZI_STORAGE_STAGE_GPT, status);
  }
  bootstrap->completed_flags |= ZI_STORAGE_COMPLETED_GPT | ZI_STORAGE_COMPLETED_PARTITION;

  status = run_read_stress(bootstrap);
  if (ZiFailed(status)) {
    clean_failed_bootstrap(bootstrap);
    return fail_at(bootstrap, ZI_STORAGE_STAGE_READ_STRESS, status);
  }
  bootstrap->completed_flags |= ZI_STORAGE_COMPLETED_READ_STRESS;
  bootstrap->stage = ZI_STORAGE_STAGE_READY;
  bootstrap->last_status = ZI_STATUS_SUCCESS;
  *out_zifs_partition = &bootstrap->zifs_partition;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus read_physical(void* context, uint64_t physical_address, void* output, size_t size) {
  (void)context;
  return zi_kernel_read_physical(physical_address, output, size);
}

static ZiStatus initialise_managers(void) {
  ZiStatus status = zi_kernel_mmio_initialise();
  if (ZiSucceeded(status)) {
    status = zi_io_initialise();
  }
  if (ZiSucceeded(status)) {
    status = zi_kernel_dma_initialise();
  }
  return status;
}

static ZiStatus publish_pci_devices(ZiStorageBootstrap* bootstrap) {
  bootstrap->pci_bus_driver.struct_size = sizeof bootstrap->pci_bus_driver;
  bootstrap->pci_bus_driver.version = ZI_DRIVER_OBJECT_VERSION;
  bootstrap->pci_bus_driver.name = (ZiStringView){k_pci_driver_name, sizeof k_pci_driver_name - 1u};
  bootstrap->pci_bus_driver.driver_kind = ZI_DRIVER_BUS;
  for (size_t index = 0; index < bootstrap->pci_device_count; ++index) {
    ZiPciDevice* pci_device = &bootstrap->pci_devices[index];
    ZiStatus status = zi_pci_probe_bars(&bootstrap->pci_access, pci_device);
    if (status == ZI_STATUS_NOT_IMPLEMENTED) {
      status = ZI_STATUS_SUCCESS;
    }
    if (ZiFailed(status)) {
      return status;
    }
    size_t name_size = format_pci_name(pci_device->address,
                                       bootstrap->pci_device_names[index],
                                       ZI_STORAGE_PCI_NAME_CAPACITY);
    if (name_size == 0) {
      return ZI_STATUS_BUFFER_TOO_SMALL;
    }
    ZiDeviceObject* device = &bootstrap->pci_device_objects[index];
    device->struct_size = sizeof *device;
    device->version = ZI_DEVICE_OBJECT_VERSION;
    device->name = (ZiStringView){bootstrap->pci_device_names[index], name_size};
    device->driver = &bootstrap->pci_bus_driver;
    device->power_state = ZI_DEVICE_POWER_ON;
    device->device_extension = pci_device;
    if (index + 1u < bootstrap->pci_device_count) {
      device->next_driver_device = &bootstrap->pci_device_objects[index + 1u];
    }
    status = zi_io_publish_device(device);
    if (ZiFailed(status)) {
      return status;
    }
    ++bootstrap->published_device_count;
  }
  if (bootstrap->pci_device_count != 0) {
    bootstrap->pci_bus_driver.devices = &bootstrap->pci_device_objects[0];
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus initialise_nvme(ZiStorageBootstrap* bootstrap, uint32_t flags) {
  const ZiPciDriverMatch* selected_match = NULL;
  size_t selected_index = bootstrap->pci_device_count;
  for (size_t index = 0; index < bootstrap->pci_device_count; ++index) {
    const ZiPciDriverMatch* match = NULL;
    ZiStatus status = zi_pci_select_driver(&bootstrap->pci_devices[index],
                                           k_driver_matches,
                                           sizeof k_driver_matches / sizeof k_driver_matches[0],
                                           &match);
    if (status == ZI_STATUS_NOT_FOUND) {
      continue;
    }
    if (ZiFailed(status)) {
      return status;
    }
    selected_match = match;
    selected_index = index;
    break;
  }
  if (selected_match == NULL || selected_match->driver_id != 1 ||
      selected_index >= bootstrap->pci_device_count) {
    return ZI_STATUS_NOT_FOUND;
  }
  uint32_t nvme_flags = (flags & ZI_STORAGE_INITIALISE_FORCE_NVME_TIMEOUT) != 0
                            ? ZI_NVME_INITIALISE_FORCE_TIMEOUT
                            : ZI_NVME_INITIALISE_NONE;
  return zi_nvme_initialise(&bootstrap->pci_access,
                            &bootstrap->pci_devices[selected_index],
                            &bootstrap->pci_device_objects[selected_index],
                            zi_kernel_dma_allocator(),
                            nvme_flags,
                            &bootstrap->nvme);
}

static ZiStatus discover_zifs_partition(ZiStorageBootstrap* bootstrap) {
  const ZiBlockDevice* device = zi_nvme_block_device(&bootstrap->nvme);
  if (device == NULL || device->block_size > sizeof bootstrap->gpt_scratch) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiStatus status = zi_gpt_read(device,
                                bootstrap->gpt_scratch,
                                sizeof bootstrap->gpt_scratch,
                                bootstrap->gpt_partitions,
                                ZI_STORAGE_MAXIMUM_PCI_DEVICES,
                                &bootstrap->gpt);
  if (ZiFailed(status)) {
    return status;
  }
  const ZiGptPartition* partition = NULL;
  status = zi_gpt_find_partition_by_type(&bootstrap->gpt, &ZiGptZiFsTypeGuid, &partition);
  if (ZiFailed(status) || partition == NULL || partition->last_lba == UINT64_MAX) {
    if (ZiFailed(status)) {
      return status;
    }
    return ZI_STATUS_INVALID_STATE;
  }
  uint64_t parent_block_count = partition->last_lba - partition->first_lba + 1u;
  status = zi_partition_block_initialise(device,
                                         partition->first_lba,
                                         parent_block_count,
                                         4096,
                                         &bootstrap->partition_context,
                                         &bootstrap->zifs_partition);
  return status;
}

static ZiStatus run_read_stress(ZiStorageBootstrap* bootstrap) {
  if (bootstrap->zifs_partition.read_blocks == NULL || bootstrap->zifs_partition.block_count == 0 ||
      bootstrap->zifs_partition.block_size > sizeof bootstrap->gpt_scratch) {
    return ZI_STATUS_INVALID_STATE;
  }
  uint32_t first_crc = 0;
  uint32_t second_crc = 0;
  for (uint32_t pass = 0; pass < 2; ++pass) {
    uint32_t crc = 0;
    for (uint32_t round = 0; round < STORAGE_READ_STRESS_ROUNDS; ++round) {
      uint64_t block = ((uint64_t)round * UINT64_C(7919)) % bootstrap->zifs_partition.block_count;
      ZiStatus status = bootstrap->zifs_partition.read_blocks(bootstrap->zifs_partition.context,
                                                              block,
                                                              1,
                                                              bootstrap->gpt_scratch,
                                                              sizeof bootstrap->gpt_scratch);
      if (ZiFailed(status)) {
        return status;
      }
      crc = zi_crc32(crc, bootstrap->gpt_scratch, bootstrap->zifs_partition.block_size);
    }
    if (pass == 0) {
      first_crc = crc;
    } else {
      second_crc = crc;
    }
  }
  if (first_crc != second_crc) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  bootstrap->read_stress_crc = first_crc;
  return ZI_STATUS_SUCCESS;
}

static void clean_failed_bootstrap(ZiStorageBootstrap* bootstrap) {
  if (bootstrap->nvme.initialised != 0) {
    (void)zi_nvme_shutdown(&bootstrap->nvme);
  }
  while (bootstrap->published_device_count != 0) {
    --bootstrap->published_device_count;
    (void)zi_io_unpublish_device(&bootstrap->pci_device_objects[bootstrap->published_device_count]);
  }
  if (bootstrap->ecam.struct_size != 0) {
    (void)zi_pci_ecam_finish(&bootstrap->ecam);
  }
}

static size_t format_pci_name(ZiPciAddress address, char* output, size_t capacity) {
  size_t offset = append_text(output, capacity, 0, k_pci_device_prefix);
  if (offset == SIZE_MAX) {
    return 0;
  }
  offset = append_hex(output, capacity, offset, address.segment, 4);
  if (offset == SIZE_MAX) {
    return 0;
  }
  offset = append_text(output, capacity, offset, ":");
  if (offset == SIZE_MAX) {
    return 0;
  }
  offset = append_hex(output, capacity, offset, address.bus, 2);
  if (offset == SIZE_MAX) {
    return 0;
  }
  offset = append_text(output, capacity, offset, ":");
  if (offset == SIZE_MAX) {
    return 0;
  }
  offset = append_hex(output, capacity, offset, address.device, 2);
  if (offset == SIZE_MAX) {
    return 0;
  }
  offset = append_text(output, capacity, offset, ".");
  if (offset == SIZE_MAX) {
    return 0;
  }
  offset = append_hex(output, capacity, offset, address.function, 1);
  if (offset == SIZE_MAX || offset == 0 || offset >= capacity) {
    return 0;
  }
  output[offset] = '\0';
  return offset;
}

static size_t append_text(char* output, size_t capacity, size_t offset, const char* text) {
  if (output == NULL || text == NULL || offset >= capacity) {
    return SIZE_MAX;
  }
  size_t index = 0;
  while (text[index] != '\0') {
    if (offset >= capacity - 1u) {
      return SIZE_MAX;
    }
    output[offset++] = text[index++];
  }
  return offset;
}

static size_t
append_hex(char* output, size_t capacity, size_t offset, uint32_t value, size_t digits) {
  static const char k_hexadecimal[] = "0123456789ABCDEF";
  if (output == NULL || digits == 0 || offset >= capacity || digits > 8 ||
      digits > capacity - offset - 1u) {
    return SIZE_MAX;
  }
  for (size_t index = 0; index < digits; ++index) {
    size_t shift = (digits - index - 1u) * 4u;
    output[offset++] = k_hexadecimal[(value >> shift) & 0x0fu];
  }
  return offset;
}

static ZiStatus fail_at(ZiStorageBootstrap* bootstrap, uint32_t stage, ZiStatus status) {
  bootstrap->stage = stage;
  bootstrap->last_status = status;
  return status;
}
