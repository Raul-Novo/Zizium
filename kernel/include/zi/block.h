// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"

#define ZI_BLOCK_DEVICE_VERSION 3u

typedef ZiStatus (*ZiBlockReadRoutine)(void* context,
                                       uint64_t first_block,
                                       uint32_t block_count,
                                       void* output,
                                       size_t output_size);
typedef ZiStatus (*ZiBlockFlushRoutine)(void* context);
typedef ZiStatus (*ZiBlockWriteRoutine)(void* context,
                                        uint64_t first_block,
                                        uint32_t block_count,
                                        const void* input,
                                        size_t input_size);

enum ZiBlockDeviceFlags {
  ZI_BLOCK_DEVICE_READ_ONLY = 1u << 0,
  ZI_BLOCK_DEVICE_FLUSH_SUPPORTED = 1u << 1,
  ZI_BLOCK_DEVICE_WRITE_SUPPORTED = 1u << 2,
};

typedef struct ZiBlockDevice {
  uint32_t struct_size;
  uint32_t version;
  void* context;
  uint32_t block_size;
  uint64_t block_count;
  ZiBlockReadRoutine read_blocks;
  ZiBlockFlushRoutine flush;
  uint32_t flags;
  ZiBlockWriteRoutine write_blocks;
} ZiBlockDevice;

typedef struct ZiPartitionBlockContext {
  const ZiBlockDevice* parent;
  uint64_t first_parent_block;
  uint64_t parent_block_count;
  uint32_t parent_blocks_per_block;
} ZiPartitionBlockContext;

ZiStatus zi_partition_block_initialise(const ZiBlockDevice* parent,
                                       uint64_t first_parent_block,
                                       uint64_t parent_block_count,
                                       uint32_t exposed_block_size,
                                       ZiPartitionBlockContext* context,
                                       ZiBlockDevice* out_device);
ZiStatus zi_block_flush(const ZiBlockDevice* device);
ZiStatus zi_block_barrier(const ZiBlockDevice* device);
ZiStatus zi_block_write(const ZiBlockDevice* device,
                        uint64_t first_block,
                        uint32_t block_count,
                        const void* input,
                        size_t input_size);
