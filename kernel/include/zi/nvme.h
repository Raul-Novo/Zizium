// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/block.h"
#include "zi/dma.h"
#include "zi/driver.h"
#include "zi/executive_lock.h"
#include "zi/kernel_memory.h"
#include "zi/pci.h"
#include "zizium/status.h"

#define ZI_NVME_CONTROLLER_VERSION 1u
#define ZI_NVME_QUEUE_DEPTH 16u
#define ZI_NVME_TRANSFER_SIZE 4096u
#define ZI_NVME_DEFAULT_POLL_LIMIT UINT32_C(50000000)

enum ZiNvmeInitialiseFlags {
  ZI_NVME_INITIALISE_NONE = 0,
  ZI_NVME_INITIALISE_FORCE_TIMEOUT = 1u << 0,
};

typedef struct ZiNvmeSubmission {
  uint8_t opcode;
  uint8_t flags;
  uint16_t command_id;
  uint32_t namespace_id;
  uint32_t reserved2[2];
  uint64_t metadata_pointer;
  uint64_t data_pointer1;
  uint64_t data_pointer2;
  uint32_t command10;
  uint32_t command11;
  uint32_t command12;
  uint32_t command13;
  uint32_t command14;
  uint32_t command15;
} ZiNvmeSubmission;

typedef struct ZiNvmeCompletion {
  uint32_t result;
  uint32_t reserved;
  uint16_t submission_head;
  uint16_t submission_queue_id;
  uint16_t command_id;
  uint16_t status;
} ZiNvmeCompletion;

typedef struct ZiNvmeController {
  uint32_t struct_size;
  uint32_t version;
  const ZiPciConfigAccess* pci_access;
  ZiPciDevice pci_device;
  ZiKernelMmioMapping register_mapping;
  volatile unsigned char* registers;
  const ZiDmaAllocator* dma_allocator;
  ZiDmaBuffer admin_submission;
  ZiDmaBuffer admin_completion;
  ZiDmaBuffer io_submission;
  ZiDmaBuffer io_completion;
  ZiDmaBuffer identify;
  ZiDmaBuffer transfer;
  ZiDriverObject driver;
  ZiDeviceObject device;
  ZiDeviceObject* pci_device_object;
  ZiBlockDevice block_device;
  ZiExecutiveLock lock;
  uint64_t namespace_block_count;
  uint32_t namespace_id;
  uint32_t namespace_block_size;
  uint32_t doorbell_stride;
  uint32_t queue_depth;
  uint32_t poll_limit;
  uint16_t next_command_id;
  uint16_t admin_submission_tail;
  uint16_t admin_completion_head;
  uint16_t io_submission_tail;
  uint16_t io_completion_head;
  uint8_t admin_completion_phase;
  uint8_t io_completion_phase;
  uint8_t controller_enabled;
  uint8_t initialised;
} ZiNvmeController;

_Static_assert(sizeof(ZiNvmeSubmission) == 64, "NVMe submissions must be 64 bytes");
_Static_assert(sizeof(ZiNvmeCompletion) == 16, "NVMe completions must be 16 bytes");

ZiStatus zi_nvme_initialise(const ZiPciConfigAccess* pci_access,
                            const ZiPciDevice* pci_device,
                            ZiDeviceObject* pci_device_object,
                            const ZiDmaAllocator* dma_allocator,
                            uint32_t flags,
                            ZiNvmeController* out_controller);
ZiStatus zi_nvme_shutdown(ZiNvmeController* controller);
const ZiBlockDevice* zi_nvme_block_device(const ZiNvmeController* controller);
