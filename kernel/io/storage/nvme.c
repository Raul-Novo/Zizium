// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/nvme.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/arch_x64.h"
#include "zi/block.h"
#include "zi/byte_order.h"
#include "zi/dma.h"
#include "zi/driver.h"
#include "zi/executive_lock.h"
#include "zi/io.h"
#include "zi/kernel_memory.h"
#include "zi/memory.h"
#include "zi/pci.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define NVME_REGISTER_CAP 0x00u
#define NVME_REGISTER_VERSION 0x08u
#define NVME_REGISTER_CC 0x14u
#define NVME_REGISTER_CSTS 0x1cu
#define NVME_REGISTER_AQA 0x24u
#define NVME_REGISTER_ASQ 0x28u
#define NVME_REGISTER_ACQ 0x30u
#define NVME_REGISTER_DOORBELL 0x1000u
#define NVME_CC_ENABLE UINT32_C(1)
#define NVME_CC_IO_SUBMISSION_ENTRY_SIZE (UINT32_C(6) << 16)
#define NVME_CC_IO_COMPLETION_ENTRY_SIZE (UINT32_C(4) << 20)
#define NVME_CSTS_READY UINT32_C(1)
#define NVME_CSTS_FATAL UINT32_C(2)
#define NVME_ADMIN_DELETE_IO_SUBMISSION_QUEUE UINT8_C(0x00)
#define NVME_ADMIN_CREATE_IO_SUBMISSION_QUEUE UINT8_C(0x01)
#define NVME_ADMIN_DELETE_IO_COMPLETION_QUEUE UINT8_C(0x04)
#define NVME_ADMIN_CREATE_IO_COMPLETION_QUEUE UINT8_C(0x05)
#define NVME_ADMIN_IDENTIFY UINT8_C(0x06)
#define NVME_IO_FLUSH UINT8_C(0x00)
#define NVME_IO_WRITE UINT8_C(0x01)
#define NVME_IO_READ UINT8_C(0x02)
#define NVME_IDENTIFY_NAMESPACE UINT32_C(0)
#define NVME_IDENTIFY_CONTROLLER UINT32_C(1)
#define NVME_IDENTIFY_ACTIVE_NAMESPACE_LIST UINT32_C(2)
#define NVME_PCI_COMMAND_MEMORY_AND_MASTER UINT16_C(0x0006)
#define NVME_PCI_CLASS_STORAGE UINT8_C(0x01)
#define NVME_PCI_SUBCLASS_NVM UINT8_C(0x08)
#define NVME_PCI_INTERFACE UINT8_C(0x02)
#define NVME_MINIMUM_REGISTER_SIZE UINT64_C(0x2000)
#define NVME_MAXIMUM_REGISTER_SIZE (UINT64_C(128) * 1024 * 1024)
#define NVME_QUEUE_IDENTIFIER UINT16_C(1)
#define NVME_NAMESPACE_LIST_COUNT 1024u
#define NVME_IDENTIFY_CONTROLLER_NAMESPACE_COUNT_OFFSET 516u
#define NVME_IDENTIFY_NAMESPACE_FORMAT_OFFSET 26u
#define NVME_IDENTIFY_NAMESPACE_FORMATS_OFFSET 128u

typedef struct ZiNvmeQueueView {
  ZiNvmeSubmission* submissions;
  ZiNvmeCompletion* completions;
  uint16_t* submission_tail;
  uint16_t* completion_head;
  uint8_t* completion_phase;
  uint16_t queue_id;
} ZiNvmeQueueView;

static const char k_nvme_driver_name[] = "NVMe";
static const char k_nvme_device_name[] = "\\System\\Devices\\Storage\\NVMe0";

static uint32_t register_read32(const ZiNvmeController* controller, uint32_t offset);
static uint64_t register_read64(const ZiNvmeController* controller, uint32_t offset);
static void register_write32(ZiNvmeController* controller, uint32_t offset, uint32_t value);
static void register_write64(ZiNvmeController* controller, uint32_t offset, uint64_t value);
static ZiStatus wait_ready(ZiNvmeController* controller, bool expected_ready);
static ZiStatus allocate_dma_buffers(ZiNvmeController* controller);
static void release_dma_buffers(ZiNvmeController* controller);
static ZiStatus configure_admin_queues(ZiNvmeController* controller);
static ZiStatus identify_namespace(ZiNvmeController* controller);
static ZiStatus create_io_queues(ZiNvmeController* controller);
static ZiStatus submit_admin(ZiNvmeController* controller, ZiNvmeSubmission* command);
static ZiStatus submit_io(ZiNvmeController* controller, ZiNvmeSubmission* command);
static ZiStatus
submit_command(ZiNvmeController* controller, ZiNvmeQueueView queue, ZiNvmeSubmission* command);
static ZiStatus read_blocks_internal(ZiNvmeController* controller,
                                     uint64_t first_block,
                                     uint32_t block_count,
                                     void* output,
                                     size_t output_size);
static ZiStatus write_blocks_internal(ZiNvmeController* controller,
                                      uint64_t first_block,
                                      uint32_t block_count,
                                      const void* input,
                                      size_t input_size);
static ZiStatus block_read(void* context,
                           uint64_t first_block,
                           uint32_t block_count,
                           void* output,
                           size_t output_size);
static ZiStatus block_write(void* context,
                            uint64_t first_block,
                            uint32_t block_count,
                            const void* input,
                            size_t input_size);
static ZiStatus block_flush(void* context);
static ZiStatus dispatch_read(ZiDeviceObject* device, ZiIrp* request);
static ZiStatus dispatch_write(ZiDeviceObject* device, ZiIrp* request);
static ZiStatus dispatch_flush(ZiDeviceObject* device, ZiIrp* request);
static ZiStatus initialise_driver_objects(ZiNvmeController* controller,
                                          ZiDeviceObject* pci_device_object);
static ZiStatus validate_capabilities(ZiNvmeController* controller, uint64_t capabilities);
static uint16_t next_command_id(ZiNvmeController* controller);
static uint32_t
doorbell_offset(const ZiNvmeController* controller, uint16_t queue_id, bool completion);
static bool controller_is_valid(const ZiNvmeController* controller);

ZiStatus zi_nvme_initialise(const ZiPciConfigAccess* pci_access,
                            const ZiPciDevice* pci_device,
                            ZiDeviceObject* pci_device_object,
                            const ZiDmaAllocator* dma_allocator,
                            uint32_t flags,
                            ZiNvmeController* out_controller) {
  if (pci_access == NULL || pci_access->read32 == NULL || pci_access->write32 == NULL ||
      pci_device == NULL || pci_device->struct_size < sizeof *pci_device ||
      pci_device->version != ZI_PCI_DEVICE_VERSION || pci_device_object == NULL ||
      dma_allocator == NULL || out_controller == NULL ||
      (flags & ~ZI_NVME_INITIALISE_FORCE_TIMEOUT) != 0 ||
      pci_device->class_code != NVME_PCI_CLASS_STORAGE ||
      pci_device->subclass != NVME_PCI_SUBCLASS_NVM ||
      pci_device->programming_interface != NVME_PCI_INTERFACE ||
      pci_device->bars[0].kind != ZI_PCI_BAR_MEMORY || pci_device->bars[0].base_address == 0 ||
      pci_device->bars[0].size < NVME_MINIMUM_REGISTER_SIZE ||
      pci_device->bars[0].size > NVME_MAXIMUM_REGISTER_SIZE ||
      pci_device->bars[0].size > SIZE_MAX) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  ZiNvmeController controller = {0};
  controller.struct_size = sizeof controller;
  controller.version = ZI_NVME_CONTROLLER_VERSION;
  controller.pci_access = pci_access;
  controller.pci_device = *pci_device;
  controller.dma_allocator = dma_allocator;
  controller.queue_depth = ZI_NVME_QUEUE_DEPTH;
  controller.poll_limit = ZI_NVME_DEFAULT_POLL_LIMIT;
  controller.admin_completion_phase = 1;
  controller.io_completion_phase = 1;
  zi_executive_lock_initialise(&controller.lock);

  ZiStatus status = zi_pci_set_command_bits(pci_access,
                                            pci_device->address,
                                            NVME_PCI_COMMAND_MEMORY_AND_MASTER,
                                            0);
  if (ZiSucceeded(status)) {
    status = zi_kernel_mmio_map(pci_device->bars[0].base_address,
                                (size_t)pci_device->bars[0].size,
                                &controller.register_mapping);
  }
  if (ZiFailed(status)) {
    return status;
  }
  controller.registers = controller.register_mapping.address;
  uint64_t capabilities = register_read64(&controller, NVME_REGISTER_CAP);
  status = validate_capabilities(&controller, capabilities);
  if (ZiSucceeded(status) && (flags & ZI_NVME_INITIALISE_FORCE_TIMEOUT) != 0) {
    controller.poll_limit = 1;
    status = ZI_STATUS_TIMEOUT;
  }
  if (ZiSucceeded(status)) {
    status = allocate_dma_buffers(&controller);
  }
  if (ZiSucceeded(status)) {
    status = configure_admin_queues(&controller);
  }
  if (ZiSucceeded(status)) {
    status = identify_namespace(&controller);
  }
  if (ZiSucceeded(status)) {
    status = create_io_queues(&controller);
  }
  if (ZiFailed(status)) {
    if (controller.controller_enabled != 0) {
      uint32_t configuration = register_read32(&controller, NVME_REGISTER_CC);
      register_write32(&controller, NVME_REGISTER_CC, configuration & ~NVME_CC_ENABLE);
      ZiStatus stop_status = wait_ready(&controller, false);
      if (ZiFailed(stop_status)) {
        // Keep DMA pages and the MMIO aperture quarantined while the device may still own them.
        return stop_status;
      }
    }
    release_dma_buffers(&controller);
    (void)zi_kernel_mmio_unmap(&controller.register_mapping);
    return status;
  }
  *out_controller = controller;
  status = initialise_driver_objects(out_controller, pci_device_object);
  if (ZiFailed(status)) {
    uint32_t configuration = register_read32(out_controller, NVME_REGISTER_CC);
    register_write32(out_controller, NVME_REGISTER_CC, configuration & ~NVME_CC_ENABLE);
    ZiStatus stop_status = wait_ready(out_controller, false);
    if (ZiFailed(stop_status)) {
      // A controller that may still perform DMA must retain its backing pages.
      return stop_status;
    }
    release_dma_buffers(out_controller);
    (void)zi_kernel_mmio_unmap(&out_controller->register_mapping);
    ZiNvmeController empty = {0};
    *out_controller = empty;
    return status;
  }
  out_controller->initialised = 1;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_nvme_shutdown(ZiNvmeController* controller) {
  if (!controller_is_valid(controller)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus result = zi_io_unpublish_device(&controller->device);
  if (ZiSucceeded(result)) {
    result = zi_driver_detach_device(&controller->device, controller->pci_device_object);
  }
  uint32_t configuration = register_read32(controller, NVME_REGISTER_CC);
  register_write32(controller, NVME_REGISTER_CC, configuration & ~NVME_CC_ENABLE);
  ZiStatus status = wait_ready(controller, false);
  if (ZiSucceeded(result) && ZiFailed(status)) {
    result = status;
  }
  if (ZiFailed(status)) {
    // Fail closed: unpublished devices may leak quarantined resources, but cannot DMA into reuse.
    return result;
  }
  controller->controller_enabled = 0;
  release_dma_buffers(controller);
  status = zi_kernel_mmio_unmap(&controller->register_mapping);
  if (ZiSucceeded(result) && ZiFailed(status)) {
    result = status;
  }
  if (ZiSucceeded(result)) {
    ZiNvmeController empty = {0};
    *controller = empty;
  }
  return result;
}

const ZiBlockDevice* zi_nvme_block_device(const ZiNvmeController* controller) {
  if (!controller_is_valid(controller)) {
    return NULL;
  }
  return &controller->block_device;
}

static uint32_t register_read32(const ZiNvmeController* controller, uint32_t offset) {
  const volatile uint32_t* pointer = (const volatile uint32_t*)(controller->registers + offset);
  return *pointer;
}

static uint64_t register_read64(const ZiNvmeController* controller, uint32_t offset) {
  const volatile uint64_t* pointer = (const volatile uint64_t*)(controller->registers + offset);
  return *pointer;
}

static void register_write32(ZiNvmeController* controller, uint32_t offset, uint32_t value) {
  volatile uint32_t* pointer = (volatile uint32_t*)(controller->registers + offset);
  *pointer = value;
  ZkArchMemoryBarrier();
}

static void register_write64(ZiNvmeController* controller, uint32_t offset, uint64_t value) {
  volatile uint64_t* pointer = (volatile uint64_t*)(controller->registers + offset);
  *pointer = value;
  ZkArchMemoryBarrier();
}

static ZiStatus wait_ready(ZiNvmeController* controller, bool expected_ready) {
  for (uint32_t poll = 0; poll < controller->poll_limit; ++poll) {
    uint32_t status = register_read32(controller, NVME_REGISTER_CSTS);
    if ((status & NVME_CSTS_FATAL) != 0) {
      return ZI_STATUS_DEVICE_ERROR;
    }
    bool ready = (bool)(((status & NVME_CSTS_READY) != 0) != 0);
    if (ready == expected_ready) {
      return ZI_STATUS_SUCCESS;
    }
    ZkArchPause();
  }
  return ZI_STATUS_TIMEOUT;
}

static ZiStatus allocate_dma_buffers(ZiNvmeController* controller) {
  ZiDmaBuffer* buffers[] = {&controller->admin_submission,
                            &controller->admin_completion,
                            &controller->io_submission,
                            &controller->io_completion,
                            &controller->identify,
                            &controller->transfer};
  for (size_t index = 0; index < sizeof buffers / sizeof buffers[0]; ++index) {
    ZiStatus status = zi_dma_allocate(controller->dma_allocator,
                                      ZI_NVME_TRANSFER_SIZE,
                                      ZI_MEMORY_PAGE_SIZE,
                                      UINT64_MAX,
                                      ZI_MEMORY_OWNER_DMA,
                                      buffers[index]);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static void release_dma_buffers(ZiNvmeController* controller) {
  ZiDmaBuffer* buffers[] = {&controller->transfer,
                            &controller->identify,
                            &controller->io_completion,
                            &controller->io_submission,
                            &controller->admin_completion,
                            &controller->admin_submission};
  for (size_t index = 0; index < sizeof buffers / sizeof buffers[0]; ++index) {
    if (buffers[index]->allocated != 0) {
      (void)zi_dma_release(controller->dma_allocator, buffers[index]);
    }
  }
}

static ZiStatus configure_admin_queues(ZiNvmeController* controller) {
  uint32_t configuration = register_read32(controller, NVME_REGISTER_CC);
  if ((configuration & NVME_CC_ENABLE) != 0) {
    register_write32(controller, NVME_REGISTER_CC, configuration & ~NVME_CC_ENABLE);
    ZiStatus status = wait_ready(controller, false);
    if (ZiFailed(status)) {
      return status;
    }
  }
  uint32_t queue_attributes =
      ((controller->queue_depth - 1u) << 16) | (controller->queue_depth - 1u);
  register_write32(controller, NVME_REGISTER_AQA, queue_attributes);
  register_write64(controller, NVME_REGISTER_ASQ, controller->admin_submission.physical_address);
  register_write64(controller, NVME_REGISTER_ACQ, controller->admin_completion.physical_address);
  register_write32(controller,
                   NVME_REGISTER_CC,
                   NVME_CC_ENABLE | NVME_CC_IO_SUBMISSION_ENTRY_SIZE |
                       NVME_CC_IO_COMPLETION_ENTRY_SIZE);
  ZiStatus status = wait_ready(controller, true);
  if (ZiSucceeded(status)) {
    controller->controller_enabled = 1;
  }
  return status;
}

static ZiStatus block_flush(void* context) {
  ZiNvmeController* controller = context;
  if (!controller_is_valid(controller)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiIoRequestInitialiser initialiser = {0};
  initialiser.struct_size = sizeof initialiser;
  initialiser.version = ZI_IO_REQUEST_INITIALISER_VERSION;
  initialiser.major_operation = ZI_IRP_FLUSH;
  ZiIrp request = {0};
  ZiStatus status = zi_io_request_initialise(&request, &initialiser);
  if (ZiSucceeded(status)) {
    status = zi_io_submit(controller->pci_device_object, &request);
  }
  return status;
}

static ZiStatus identify_namespace(ZiNvmeController* controller) {
  ZiNvmeSubmission command = {0};
  command.opcode = NVME_ADMIN_IDENTIFY;
  command.data_pointer1 = controller->identify.physical_address;
  command.command10 = NVME_IDENTIFY_CONTROLLER;
  ZiStatus status = submit_admin(controller, &command);
  if (ZiFailed(status)) {
    return status;
  }
  const unsigned char* identify = controller->identify.virtual_address;
  uint32_t namespace_count =
      zi_read_u32_le(identify + NVME_IDENTIFY_CONTROLLER_NAMESPACE_COUNT_OFFSET);
  if (namespace_count == 0) {
    return ZI_STATUS_NOT_FOUND;
  }

  zi_memory_zero(controller->identify.virtual_address, ZI_NVME_TRANSFER_SIZE);
  command = (ZiNvmeSubmission){0};
  command.opcode = NVME_ADMIN_IDENTIFY;
  command.data_pointer1 = controller->identify.physical_address;
  command.command10 = NVME_IDENTIFY_ACTIVE_NAMESPACE_LIST;
  status = submit_admin(controller, &command);
  if (ZiFailed(status)) {
    return status;
  }
  identify = controller->identify.virtual_address;
  uint32_t namespace_id = zi_read_u32_le(identify);
  if (namespace_id == 0) {
    return ZI_STATUS_INVALID_STATE;
  }

  zi_memory_zero(controller->identify.virtual_address, ZI_NVME_TRANSFER_SIZE);
  command = (ZiNvmeSubmission){0};
  command.opcode = NVME_ADMIN_IDENTIFY;
  command.namespace_id = namespace_id;
  command.data_pointer1 = controller->identify.physical_address;
  command.command10 = NVME_IDENTIFY_NAMESPACE;
  status = submit_admin(controller, &command);
  if (ZiFailed(status)) {
    return status;
  }
  identify = controller->identify.virtual_address;
  uint64_t block_count = zi_read_u64_le(identify);
  uint8_t format_index = identify[NVME_IDENTIFY_NAMESPACE_FORMAT_OFFSET] & UINT8_C(0x0f);
  size_t format_offset = NVME_IDENTIFY_NAMESPACE_FORMATS_OFFSET + ((size_t)format_index * 4u);
  uint16_t metadata_size = zi_read_u16_le(identify + format_offset);
  uint8_t block_shift = identify[format_offset + 2u];
  if (block_count == 0 || metadata_size != 0 || block_shift < 9 || block_shift > 12) {
    return ZI_STATUS_NOT_IMPLEMENTED;
  }
  controller->namespace_id = namespace_id;
  controller->namespace_block_count = block_count;
  controller->namespace_block_size = UINT32_C(1) << block_shift;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus create_io_queues(ZiNvmeController* controller) {
  ZiNvmeSubmission command = {0};
  command.opcode = NVME_ADMIN_CREATE_IO_COMPLETION_QUEUE;
  command.data_pointer1 = controller->io_completion.physical_address;
  command.command10 = ((controller->queue_depth - 1u) << 16) | NVME_QUEUE_IDENTIFIER;
  command.command11 = 1;
  ZiStatus status = submit_admin(controller, &command);
  if (ZiFailed(status)) {
    return status;
  }
  command = (ZiNvmeSubmission){0};
  command.opcode = NVME_ADMIN_CREATE_IO_SUBMISSION_QUEUE;
  command.data_pointer1 = controller->io_submission.physical_address;
  command.command10 = ((controller->queue_depth - 1u) << 16) | NVME_QUEUE_IDENTIFIER;
  command.command11 = ((uint32_t)NVME_QUEUE_IDENTIFIER << 16) | 1u;
  return submit_admin(controller, &command);
}

static ZiStatus submit_admin(ZiNvmeController* controller, ZiNvmeSubmission* command) {
  ZiNvmeQueueView queue = {controller->admin_submission.virtual_address,
                           controller->admin_completion.virtual_address,
                           &controller->admin_submission_tail,
                           &controller->admin_completion_head,
                           &controller->admin_completion_phase,
                           0};
  return submit_command(controller, queue, command);
}

static ZiStatus submit_io(ZiNvmeController* controller, ZiNvmeSubmission* command) {
  ZiNvmeQueueView queue = {controller->io_submission.virtual_address,
                           controller->io_completion.virtual_address,
                           &controller->io_submission_tail,
                           &controller->io_completion_head,
                           &controller->io_completion_phase,
                           NVME_QUEUE_IDENTIFIER};
  return submit_command(controller, queue, command);
}

static ZiStatus
submit_command(ZiNvmeController* controller, ZiNvmeQueueView queue, ZiNvmeSubmission* command) {
  if (queue.submissions == NULL || queue.completions == NULL || queue.submission_tail == NULL ||
      queue.completion_head == NULL || queue.completion_phase == NULL || command == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  command->command_id = next_command_id(controller);
  queue.submissions[*queue.submission_tail] = *command;
  ZiStatus status = zi_dma_synchronise(controller->dma_allocator, ZI_DMA_TO_DEVICE);
  if (ZiFailed(status)) {
    return status;
  }
  *queue.submission_tail = (uint16_t)((*queue.submission_tail + 1u) % controller->queue_depth);
  register_write32(controller,
                   doorbell_offset(controller, queue.queue_id, false),
                   *queue.submission_tail);

  ZiNvmeCompletion completion = {0};
  bool completed = false;
  for (uint32_t poll = 0; poll < controller->poll_limit; ++poll) {
    uint16_t completion_status = queue.completions[*queue.completion_head].status;
    if ((completion_status & 1u) == *queue.completion_phase) {
      ZkArchMemoryBarrier();
      completion = queue.completions[*queue.completion_head];
      completed = true;
      break;
    }
    if ((register_read32(controller, NVME_REGISTER_CSTS) & NVME_CSTS_FATAL) != 0) {
      return ZI_STATUS_DEVICE_ERROR;
    }
    ZkArchPause();
  }
  if (!completed) {
    return ZI_STATUS_TIMEOUT;
  }
  if (completion.command_id != command->command_id ||
      completion.submission_queue_id != queue.queue_id || (completion.status >> 1) != 0) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  *queue.completion_head = (uint16_t)(*queue.completion_head + 1u);
  if (*queue.completion_head == controller->queue_depth) {
    *queue.completion_head = 0;
    *queue.completion_phase ^= 1u;
  }
  register_write32(controller,
                   doorbell_offset(controller, queue.queue_id, true),
                   *queue.completion_head);
  return zi_dma_synchronise(controller->dma_allocator, ZI_DMA_FROM_DEVICE);
}

static ZiStatus read_blocks_internal(ZiNvmeController* controller,
                                     uint64_t first_block,
                                     uint32_t block_count,
                                     void* output,
                                     size_t output_size) {
  if (!controller_is_valid(controller) || output == NULL || block_count == 0 ||
      first_block >= controller->namespace_block_count ||
      block_count > controller->namespace_block_count - first_block ||
      block_count > SIZE_MAX / controller->namespace_block_size ||
      output_size < (size_t)block_count * controller->namespace_block_size) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char* destination = output;
  uint32_t remaining = block_count;
  uint64_t current_block = first_block;
  size_t output_offset = 0;
  uint32_t maximum_blocks = ZI_NVME_TRANSFER_SIZE / controller->namespace_block_size;
  while (remaining != 0) {
    uint32_t transfer_blocks = remaining < maximum_blocks ? remaining : maximum_blocks;
    zi_memory_zero(controller->transfer.virtual_address, ZI_NVME_TRANSFER_SIZE);
    ZiNvmeSubmission command = {0};
    command.opcode = NVME_IO_READ;
    command.namespace_id = controller->namespace_id;
    command.data_pointer1 = controller->transfer.physical_address;
    command.command10 = (uint32_t)current_block;
    command.command11 = (uint32_t)(current_block >> 32);
    command.command12 = transfer_blocks - 1u;
    ZiStatus status = submit_io(controller, &command);
    if (ZiFailed(status)) {
      return status;
    }
    size_t byte_count = (size_t)transfer_blocks * controller->namespace_block_size;
    zi_memory_copy(destination + output_offset, controller->transfer.virtual_address, byte_count);
    remaining -= transfer_blocks;
    current_block += transfer_blocks;
    output_offset += byte_count;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus write_blocks_internal(ZiNvmeController* controller,
                                      uint64_t first_block,
                                      uint32_t block_count,
                                      const void* input,
                                      size_t input_size) {
  if (!controller_is_valid(controller) || input == NULL || block_count == 0 ||
      first_block >= controller->namespace_block_count ||
      block_count > controller->namespace_block_count - first_block ||
      block_count > SIZE_MAX / controller->namespace_block_size ||
      input_size != (size_t)block_count * controller->namespace_block_size) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const unsigned char* source = input;
  uint32_t remaining = block_count;
  uint64_t current_block = first_block;
  size_t input_offset = 0;
  uint32_t maximum_blocks = ZI_NVME_TRANSFER_SIZE / controller->namespace_block_size;
  while (remaining != 0) {
    uint32_t transfer_blocks = remaining < maximum_blocks ? remaining : maximum_blocks;
    size_t byte_count = (size_t)transfer_blocks * controller->namespace_block_size;
    zi_memory_zero(controller->transfer.virtual_address, ZI_NVME_TRANSFER_SIZE);
    zi_memory_copy(controller->transfer.virtual_address, source + input_offset, byte_count);
    ZiNvmeSubmission command = {0};
    command.opcode = NVME_IO_WRITE;
    command.namespace_id = controller->namespace_id;
    command.data_pointer1 = controller->transfer.physical_address;
    command.command10 = (uint32_t)current_block;
    command.command11 = (uint32_t)(current_block >> 32);
    command.command12 = transfer_blocks - 1u;
    ZiStatus status = submit_io(controller, &command);
    if (ZiFailed(status)) {
      return status;
    }
    remaining -= transfer_blocks;
    current_block += transfer_blocks;
    input_offset += byte_count;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus block_read(void* context,
                           uint64_t first_block,
                           uint32_t block_count,
                           void* output,
                           size_t output_size) {
  ZiNvmeController* controller = context;
  if (!controller_is_valid(controller) || output == NULL || block_count == 0 ||
      first_block > UINT64_MAX / controller->namespace_block_size ||
      block_count > SIZE_MAX / controller->namespace_block_size) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiIoRequestInitialiser initialiser = {0};
  initialiser.struct_size = sizeof initialiser;
  initialiser.version = ZI_IO_REQUEST_INITIALISER_VERSION;
  initialiser.major_operation = ZI_IRP_READ;
  size_t expected_size = (size_t)block_count * controller->namespace_block_size;
  if (output_size < expected_size) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  initialiser.buffer = (ZiMutableBuffer){output, expected_size};
  initialiser.offset = first_block * controller->namespace_block_size;
  ZiIrp request = {0};
  ZiStatus status = zi_io_request_initialise(&request, &initialiser);
  if (ZiSucceeded(status)) {
    status = zi_io_submit(controller->pci_device_object, &request);
  }
  if (ZiSucceeded(status) && request.io_status.information != expected_size) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  return status;
}

static ZiStatus block_write(void* context,
                            uint64_t first_block,
                            uint32_t block_count,
                            const void* input,
                            size_t input_size) {
  ZiNvmeController* controller = context;
  if (!controller_is_valid(controller) || input == NULL || block_count == 0 ||
      first_block > UINT64_MAX / controller->namespace_block_size ||
      block_count > SIZE_MAX / controller->namespace_block_size) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  size_t expected_size = (size_t)block_count * controller->namespace_block_size;
  if (input_size != expected_size) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  ZiIoRequestInitialiser initialiser = {0};
  initialiser.struct_size = sizeof initialiser;
  initialiser.version = ZI_IO_REQUEST_INITIALISER_VERSION;
  initialiser.major_operation = ZI_IRP_WRITE;
  initialiser.input_buffer = (ZiConstBuffer){input, expected_size};
  initialiser.offset = first_block * controller->namespace_block_size;
  ZiIrp request = {0};
  ZiStatus status = zi_io_request_initialise(&request, &initialiser);
  if (ZiSucceeded(status)) {
    status = zi_io_submit(controller->pci_device_object, &request);
  }
  if (ZiSucceeded(status) && request.io_status.information != expected_size) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  return status;
}

static ZiStatus dispatch_read(ZiDeviceObject* device, ZiIrp* request) {
  if (device == NULL || request == NULL || device->device_extension == NULL ||
      request->buffer.data == NULL || request->buffer.size == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiNvmeController* controller = device->device_extension;
  if (!controller_is_valid(controller) || request->offset % controller->namespace_block_size != 0 ||
      request->buffer.size % controller->namespace_block_size != 0 ||
      request->buffer.size / controller->namespace_block_size > UINT32_MAX) {
    return ZI_STATUS_ALIGNMENT_ERROR;
  }
  uint64_t first_block = request->offset / controller->namespace_block_size;
  uint32_t block_count = (uint32_t)(request->buffer.size / controller->namespace_block_size);
  zi_executive_lock_acquire(&controller->lock);
  ZiStatus status = read_blocks_internal(controller,
                                         first_block,
                                         block_count,
                                         request->buffer.data,
                                         request->buffer.size);
  zi_executive_lock_release(&controller->lock);
  if (ZiSucceeded(status)) {
    request->io_status.information = request->buffer.size;
  }
  return status;
}

static ZiStatus dispatch_write(ZiDeviceObject* device, ZiIrp* request) {
  if (device == NULL || request == NULL || device->device_extension == NULL ||
      request->input_buffer.data == NULL || request->input_buffer.size == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiNvmeController* controller = device->device_extension;
  if (!controller_is_valid(controller) || request->offset % controller->namespace_block_size != 0 ||
      request->input_buffer.size % controller->namespace_block_size != 0 ||
      request->input_buffer.size / controller->namespace_block_size > UINT32_MAX) {
    return ZI_STATUS_ALIGNMENT_ERROR;
  }
  uint64_t first_block = request->offset / controller->namespace_block_size;
  uint32_t block_count = (uint32_t)(request->input_buffer.size / controller->namespace_block_size);
  zi_executive_lock_acquire(&controller->lock);
  ZiStatus status = write_blocks_internal(controller,
                                          first_block,
                                          block_count,
                                          request->input_buffer.data,
                                          request->input_buffer.size);
  zi_executive_lock_release(&controller->lock);
  if (ZiSucceeded(status)) {
    request->io_status.information = request->input_buffer.size;
  }
  return status;
}

static ZiStatus dispatch_flush(ZiDeviceObject* device, ZiIrp* request) {
  if (device == NULL || request == NULL || device->device_extension == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiNvmeController* controller = device->device_extension;
  if (!controller_is_valid(controller)) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiNvmeSubmission command = {0};
  command.opcode = NVME_IO_FLUSH;
  command.namespace_id = controller->namespace_id;
  zi_executive_lock_acquire(&controller->lock);
  ZiStatus status = submit_io(controller, &command);
  zi_executive_lock_release(&controller->lock);
  return status;
}

static ZiStatus initialise_driver_objects(ZiNvmeController* controller,
                                          ZiDeviceObject* pci_device_object) {
  controller->driver.struct_size = sizeof controller->driver;
  controller->driver.version = ZI_DRIVER_OBJECT_VERSION;
  controller->driver.name = (ZiStringView){k_nvme_driver_name, sizeof k_nvme_driver_name - 1u};
  controller->driver.driver_kind = ZI_DRIVER_FUNCTION;
  controller->driver.driver_extension = controller;
  controller->driver.dispatch[ZI_IRP_READ] = dispatch_read;
  controller->driver.dispatch[ZI_IRP_WRITE] = dispatch_write;
  controller->driver.dispatch[ZI_IRP_FLUSH] = dispatch_flush;
  controller->device.struct_size = sizeof controller->device;
  controller->device.version = ZI_DEVICE_OBJECT_VERSION;
  controller->device.name = (ZiStringView){k_nvme_device_name, sizeof k_nvme_device_name - 1u};
  controller->device.driver = &controller->driver;
  controller->device.power_state = ZI_DEVICE_POWER_ON;
  controller->device.device_extension = controller;
  controller->pci_device_object = pci_device_object;
  ZiStatus status = zi_driver_attach_device(&controller->device, pci_device_object);
  if (ZiSucceeded(status)) {
    status = zi_io_publish_device(&controller->device);
  }
  if (ZiFailed(status) && controller->device.attached_below == pci_device_object) {
    (void)zi_driver_detach_device(&controller->device, pci_device_object);
  }
  if (ZiFailed(status)) {
    return status;
  }
  controller->block_device =
      (ZiBlockDevice){sizeof(ZiBlockDevice),
                      ZI_BLOCK_DEVICE_VERSION,
                      controller,
                      controller->namespace_block_size,
                      controller->namespace_block_count,
                      block_read,
                      block_flush,
                      ZI_BLOCK_DEVICE_FLUSH_SUPPORTED | ZI_BLOCK_DEVICE_WRITE_SUPPORTED,
                      block_write};
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_capabilities(ZiNvmeController* controller, uint64_t capabilities) {
  uint32_t maximum_queue_entries = (uint32_t)(capabilities & UINT16_MAX) + 1u;
  uint32_t minimum_page_shift = 12u + (uint32_t)((capabilities >> 48) & 0x0fu);
  uint32_t maximum_page_shift = 12u + (uint32_t)((capabilities >> 52) & 0x0fu);
  if (maximum_queue_entries < ZI_NVME_QUEUE_DEPTH || minimum_page_shift > 12 ||
      maximum_page_shift < 12 || ((capabilities >> 37) & 1u) == 0) {
    return ZI_STATUS_NOT_IMPLEMENTED;
  }
  uint32_t stride_shift = (uint32_t)((capabilities >> 32) & 0x0fu) + 2u;
  if (stride_shift >= 32) {
    return ZI_STATUS_INVALID_STATE;
  }
  controller->doorbell_stride = UINT32_C(1) << stride_shift;
  uint32_t version = register_read32(controller, NVME_REGISTER_VERSION);
  return version == 0 ? ZI_STATUS_INVALID_STATE : ZI_STATUS_SUCCESS;
}

static uint16_t next_command_id(ZiNvmeController* controller) {
  ++controller->next_command_id;
  if (controller->next_command_id == 0) {
    ++controller->next_command_id;
  }
  return controller->next_command_id;
}

static uint32_t
doorbell_offset(const ZiNvmeController* controller, uint16_t queue_id, bool completion) {
  uint32_t index = ((uint32_t)queue_id * 2u) + (uint32_t)completion;
  return NVME_REGISTER_DOORBELL + (index * controller->doorbell_stride);
}

static bool controller_is_valid(const ZiNvmeController* controller) {
  return (bool)((controller != NULL && controller->struct_size >= sizeof *controller &&
                 controller->version == ZI_NVME_CONTROLLER_VERSION &&
                 controller->initialised != 0 && controller->registers != NULL &&
                 controller->namespace_block_size != 0 && controller->namespace_block_count != 0) !=
                0);
}
