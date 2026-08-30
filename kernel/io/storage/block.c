// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/block.h"

#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"

static ZiStatus partition_read(void* context,
                               uint64_t first_block,
                               uint32_t block_count,
                               void* output,
                               size_t output_size);
static ZiStatus partition_flush(void* context);
static ZiStatus partition_write(void* context,
                                uint64_t first_block,
                                uint32_t block_count,
                                const void* input,
                                size_t input_size);
static ZiStatus translate_partition_range(const ZiPartitionBlockContext* partition,
                                          uint64_t first_block,
                                          uint32_t block_count,
                                          uint64_t* out_parent_first_block,
                                          uint32_t* out_parent_block_count);

ZiStatus zi_partition_block_initialise(const ZiBlockDevice* parent,
                                       uint64_t first_parent_block,
                                       uint64_t parent_block_count,
                                       uint32_t exposed_block_size,
                                       ZiPartitionBlockContext* context,
                                       ZiBlockDevice* out_device) {
  if (parent == NULL || parent->struct_size < sizeof *parent ||
      parent->version != ZI_BLOCK_DEVICE_VERSION || parent->read_blocks == NULL ||
      parent->block_size == 0 || parent->block_count == 0 || context == NULL ||
      out_device == NULL ||
      ((parent->flags & ZI_BLOCK_DEVICE_FLUSH_SUPPORTED) != 0) != (parent->flush != NULL) ||
      ((parent->flags & ZI_BLOCK_DEVICE_WRITE_SUPPORTED) != 0) != (parent->write_blocks != NULL) ||
      ((parent->flags & ZI_BLOCK_DEVICE_READ_ONLY) != 0 &&
       (parent->flags & ZI_BLOCK_DEVICE_WRITE_SUPPORTED) != 0) ||
      exposed_block_size < parent->block_size || exposed_block_size % parent->block_size != 0 ||
      first_parent_block >= parent->block_count || parent_block_count == 0 ||
      parent_block_count > parent->block_count - first_parent_block) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint32_t ratio = exposed_block_size / parent->block_size;
  if (parent_block_count % ratio != 0) {
    return ZI_STATUS_ALIGNMENT_ERROR;
  }

  ZiPartitionBlockContext result = {
      parent,
      first_parent_block,
      parent_block_count,
      ratio,
  };
  *context = result;
  ZiBlockDevice device = {
      sizeof(ZiBlockDevice),
      ZI_BLOCK_DEVICE_VERSION,
      context,
      exposed_block_size,
      parent_block_count / ratio,
      partition_read,
      parent->flush == NULL ? NULL : partition_flush,
      parent->flags,
      parent->write_blocks == NULL ? NULL : partition_write,
  };
  *out_device = device;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_block_flush(const ZiBlockDevice* device) {
  if (device == NULL || device->struct_size < sizeof *device ||
      device->version != ZI_BLOCK_DEVICE_VERSION) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (device->flush == NULL || (device->flags & ZI_BLOCK_DEVICE_FLUSH_SUPPORTED) == 0) {
    return ZI_STATUS_NOT_IMPLEMENTED;
  }
  return device->flush(device->context);
}

ZiStatus zi_block_barrier(const ZiBlockDevice* device) {
  return zi_block_flush(device);
}

ZiStatus zi_block_write(const ZiBlockDevice* device,
                        uint64_t first_block,
                        uint32_t block_count,
                        const void* input,
                        size_t input_size) {
  if (device == NULL || device->struct_size < sizeof *device ||
      device->version != ZI_BLOCK_DEVICE_VERSION || input == NULL || block_count == 0 ||
      device->block_size == 0 || device->block_count == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if ((device->flags & ZI_BLOCK_DEVICE_READ_ONLY) != 0) {
    return ZI_STATUS_READ_ONLY_FILESYSTEM;
  }
  if (device->write_blocks == NULL || (device->flags & ZI_BLOCK_DEVICE_WRITE_SUPPORTED) == 0) {
    return ZI_STATUS_NOT_IMPLEMENTED;
  }
  if (first_block >= device->block_count || block_count > device->block_count - first_block ||
      block_count > SIZE_MAX / device->block_size ||
      input_size != (size_t)block_count * device->block_size) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  return device->write_blocks(device->context, first_block, block_count, input, input_size);
}

static ZiStatus partition_read(void* context,
                               uint64_t first_block,
                               uint32_t block_count,
                               void* output,
                               size_t output_size) {
  if (context == NULL || output == NULL || block_count == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const ZiPartitionBlockContext* partition = context;
  uint64_t parent_first_block = 0;
  uint32_t parent_block_count = 0;
  ZiStatus status = translate_partition_range(partition,
                                              first_block,
                                              block_count,
                                              &parent_first_block,
                                              &parent_block_count);
  if (ZiFailed(status)) {
    return status;
  }
  return partition->parent->read_blocks(partition->parent->context,
                                        parent_first_block,
                                        parent_block_count,
                                        output,
                                        output_size);
}

static ZiStatus partition_flush(void* context) {
  if (context == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const ZiPartitionBlockContext* partition = context;
  return zi_block_flush(partition->parent);
}

static ZiStatus partition_write(void* context,
                                uint64_t first_block,
                                uint32_t block_count,
                                const void* input,
                                size_t input_size) {
  if (context == NULL || input == NULL || block_count == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const ZiPartitionBlockContext* partition = context;
  uint64_t parent_first_block = 0;
  uint32_t parent_block_count = 0;
  ZiStatus status = translate_partition_range(partition,
                                              first_block,
                                              block_count,
                                              &parent_first_block,
                                              &parent_block_count);
  if (ZiFailed(status)) {
    return status;
  }
  return zi_block_write(partition->parent,
                        parent_first_block,
                        parent_block_count,
                        input,
                        input_size);
}

static ZiStatus translate_partition_range(const ZiPartitionBlockContext* partition,
                                          uint64_t first_block,
                                          uint32_t block_count,
                                          uint64_t* out_parent_first_block,
                                          uint32_t* out_parent_block_count) {
  if (partition == NULL || partition->parent == NULL || partition->parent_blocks_per_block == 0 ||
      block_count == 0 || out_parent_first_block == NULL || out_parent_block_count == NULL ||
      first_block > UINT64_MAX / partition->parent_blocks_per_block ||
      block_count > UINT32_MAX / partition->parent_blocks_per_block) {
    return ZI_STATUS_INVALID_STATE;
  }
  uint64_t parent_offset = first_block * partition->parent_blocks_per_block;
  uint32_t parent_count = block_count * partition->parent_blocks_per_block;
  if (parent_offset >= partition->parent_block_count ||
      parent_count > partition->parent_block_count - parent_offset ||
      partition->first_parent_block > UINT64_MAX - parent_offset) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  *out_parent_first_block = partition->first_parent_block + parent_offset;
  *out_parent_block_count = parent_count;
  return ZI_STATUS_SUCCESS;
}
