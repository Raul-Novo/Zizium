// SPDX-License-Identifier: GPL-3.0-or-later

#include "source.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#include <io.h>
#include <share.h>

#include "zi/block.h"
#include "zi/byte_order.h"
#include "zi/gpt.h"
#include "zi/zifs.h"
#include "zizium/status.h"

static ZiStatus configure_raw_source(ZiFsRepairSource* source);
static ZiStatus configure_gpt_source(ZiFsRepairSource* source);
static enum ZiFsRepairSourceMode detect_mode(FILE* file, uint64_t file_size);
static bool read_signature(FILE* file, uint64_t offset, void* output, size_t output_size);
static ZiStatus file_read_blocks(void* context,
                                 uint64_t first_block,
                                 uint32_t block_count,
                                 void* output,
                                 size_t output_size);
static ZiStatus file_write_blocks(void* context,
                                  uint64_t first_block,
                                  uint32_t block_count,
                                  const void* input,
                                  size_t input_size);
static ZiStatus file_flush(void* context);
static bool range_to_bytes(const ZiFsRepairFileContext* file,
                           uint64_t first_block,
                           uint32_t block_count,
                           uint64_t* out_offset,
                           size_t* out_size);

ZiStatus zifs_repair_source_open(const wchar_t* path,
                                 enum ZiFsRepairSourceMode requested_mode,
                                 bool writable,
                                 ZiFsRepairSource* out_source) {
  if (path == NULL || out_source == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_memory_zero(out_source, sizeof *out_source);
  const wchar_t* mode = L"rb";
  int share_mode = _SH_DENYWR;
  if (writable) {
    mode = L"r+b";
    share_mode = _SH_DENYRW;
  }
  FILE* file = _wfsopen(path, mode, share_mode);
  if (file == NULL) {
    return ZI_STATUS_NOT_FOUND;
  }
  if (_fseeki64(file, 0, SEEK_END) != 0) {
    (void)fclose(file);
    return ZI_STATUS_DEVICE_ERROR;
  }
  int64_t signed_size = _ftelli64(file);
  if (signed_size <= 0 || _fseeki64(file, 0, SEEK_SET) != 0) {
    (void)fclose(file);
    return ZI_STATUS_DEVICE_ERROR;
  }

  ZiFsRepairSource source = {0};
  source.file = file;
  source.file_context.file = file;
  source.file_context.file_size = (uint64_t)signed_size;
  source.is_writable = writable;
  enum ZiFsRepairSourceMode mode_value = requested_mode;
  if (mode_value == ZIFS_REPAIR_SOURCE_AUTO) {
    mode_value = detect_mode(file, source.file_context.file_size);
  }
  ZiStatus status = ZI_STATUS_INVALID_ARGUMENT;
  if (mode_value == ZIFS_REPAIR_SOURCE_RAW) {
    status = configure_raw_source(&source);
  } else if (mode_value == ZIFS_REPAIR_SOURCE_GPT) {
    status = configure_gpt_source(&source);
  }
  if (ZiFailed(status)) {
    (void)fclose(file);
    return status;
  }

  *out_source = source;
  out_source->file_context.file = out_source->file;
  out_source->file_device.context = &out_source->file_context;
  if (out_source->partition_lba_count == 0) {
    out_source->volume_device.context = &out_source->file_context;
  } else {
    out_source->partition_context.parent = &out_source->file_device;
    out_source->volume_device.context = &out_source->partition_context;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zifs_repair_source_close(ZiFsRepairSource* source) {
  if (source == NULL || source->file == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  FILE* file = source->file;
  zi_memory_zero(source, sizeof *source);
  return fclose(file) == 0 ? ZI_STATUS_SUCCESS : ZI_STATUS_DEVICE_ERROR;
}

static ZiStatus configure_raw_source(ZiFsRepairSource* source) {
  if (source->file_context.file_size % ZI_FS_BLOCK_SIZE != 0 ||
      source->file_context.file_size / ZI_FS_BLOCK_SIZE < 2) {
    return ZI_STATUS_ALIGNMENT_ERROR;
  }
  source->file_context.block_size = ZI_FS_BLOCK_SIZE;
  source->file_device = (ZiBlockDevice){
      sizeof(ZiBlockDevice),
      ZI_BLOCK_DEVICE_VERSION,
      &source->file_context,
      ZI_FS_BLOCK_SIZE,
      source->file_context.file_size / ZI_FS_BLOCK_SIZE,
      file_read_blocks,
      NULL,
      ZI_BLOCK_DEVICE_READ_ONLY,
      NULL,
  };
  if (source->is_writable) {
    source->file_device.flush = file_flush;
    source->file_device.flags = ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED;
    source->file_device.write_blocks = file_write_blocks;
  }
  source->volume_device = source->file_device;
  source->container_name = "raw ZiFS volume";
  return ZI_STATUS_SUCCESS;
}

static ZiStatus configure_gpt_source(ZiFsRepairSource* source) {
  if (source->file_context.file_size % 512u != 0 || source->file_context.file_size / 512u < 3) {
    return ZI_STATUS_ALIGNMENT_ERROR;
  }
  source->file_context.block_size = 512;
  source->file_device = (ZiBlockDevice){
      sizeof(ZiBlockDevice),
      ZI_BLOCK_DEVICE_VERSION,
      &source->file_context,
      512,
      source->file_context.file_size / 512u,
      file_read_blocks,
      NULL,
      ZI_BLOCK_DEVICE_READ_ONLY,
      NULL,
  };
  if (source->is_writable) {
    source->file_device.flush = file_flush;
    source->file_device.flags = ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED;
    source->file_device.write_blocks = file_write_blocks;
  }

  ZiGptPartition* partitions = calloc(ZI_GPT_MAXIMUM_ENTRY_COUNT, sizeof *partitions);
  if (partitions == NULL) {
    return ZI_STATUS_NO_MEMORY;
  }
  unsigned char block_buffer[4096] = {0};
  ZiGptTable table = {0};
  ZiStatus status = zi_gpt_read(&source->file_device,
                                block_buffer,
                                sizeof block_buffer,
                                partitions,
                                ZI_GPT_MAXIMUM_ENTRY_COUNT,
                                &table);
  const ZiGptPartition* partition = NULL;
  if (ZiSucceeded(status)) {
    status = zi_gpt_find_partition_by_type(&table, &ZiGptZiFsTypeGuid, &partition);
  }
  if (ZiSucceeded(status) && partition != NULL) {
    uint64_t lba_count = partition->last_lba - partition->first_lba + 1u;
    status = zi_partition_block_initialise(&source->file_device,
                                           partition->first_lba,
                                           lba_count,
                                           ZI_FS_BLOCK_SIZE,
                                           &source->partition_context,
                                           &source->volume_device);
    if (ZiSucceeded(status)) {
      source->container_name = "GPT image with ZiFS partition";
      source->partition_first_lba = partition->first_lba;
      source->partition_lba_count = lba_count;
      source->gpt_from_backup = table.mounted_from_backup;
    }
  }
  free(partitions);
  return status;
}

static enum ZiFsRepairSourceMode detect_mode(FILE* file, uint64_t file_size) {
  static const unsigned char k_zifs_magic[8] = {'Z', 'i', 'F', 'S', '\r', '\n', 0x1a, '\n'};
  static const unsigned char k_gpt_magic[8] = {'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T'};
  unsigned char signature[8] = {0};
  if (read_signature(file, 0, signature, sizeof signature) &&
      zi_memory_compare(signature, k_zifs_magic, sizeof signature) == 0) {
    return ZIFS_REPAIR_SOURCE_RAW;
  }
  if (file_size >= 520u && read_signature(file, 512, signature, sizeof signature) &&
      zi_memory_compare(signature, k_gpt_magic, sizeof signature) == 0) {
    return ZIFS_REPAIR_SOURCE_GPT;
  }
  return file_size % ZI_FS_BLOCK_SIZE == 0 ? ZIFS_REPAIR_SOURCE_RAW : ZIFS_REPAIR_SOURCE_GPT;
}

static bool read_signature(FILE* file, uint64_t offset, void* output, size_t output_size) {
  if (offset > INT64_MAX || _fseeki64(file, (int64_t)offset, SEEK_SET) != 0) {
    return false;
  }
  return (bool)(fread(output, 1, output_size, file) == output_size);
}

static ZiStatus file_read_blocks(void* context,
                                 uint64_t first_block,
                                 uint32_t block_count,
                                 void* output,
                                 size_t output_size) {
  if (context == NULL || output == NULL || block_count == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiFsRepairFileContext* file = context;
  uint64_t byte_offset = 0;
  size_t byte_count = 0;
  if (!range_to_bytes(file, first_block, block_count, &byte_offset, &byte_count) ||
      output_size < byte_count || byte_offset > INT64_MAX ||
      _fseeki64(file->file, (int64_t)byte_offset, SEEK_SET) != 0) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  return fread(output, 1, byte_count, file->file) == byte_count ? ZI_STATUS_SUCCESS
                                                                : ZI_STATUS_DEVICE_ERROR;
}

static ZiStatus file_write_blocks(void* context,
                                  uint64_t first_block,
                                  uint32_t block_count,
                                  const void* input,
                                  size_t input_size) {
  if (context == NULL || input == NULL || block_count == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiFsRepairFileContext* file = context;
  uint64_t byte_offset = 0;
  size_t byte_count = 0;
  if (!range_to_bytes(file, first_block, block_count, &byte_offset, &byte_count) ||
      input_size != byte_count || byte_offset > INT64_MAX ||
      _fseeki64(file->file, (int64_t)byte_offset, SEEK_SET) != 0) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  return fwrite(input, 1, byte_count, file->file) == byte_count ? ZI_STATUS_SUCCESS
                                                                : ZI_STATUS_DEVICE_ERROR;
}

static ZiStatus file_flush(void* context) {
  if (context == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiFsRepairFileContext* file = context;
  if (file->file == NULL || fflush(file->file) != 0) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  int descriptor = _fileno(file->file);
  if (descriptor < 0 || _commit(descriptor) != 0) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  return ZI_STATUS_SUCCESS;
}

static bool range_to_bytes(const ZiFsRepairFileContext* file,
                           uint64_t first_block,
                           uint32_t block_count,
                           uint64_t* out_offset,
                           size_t* out_size) {
  if (file == NULL || file->file == NULL || file->block_size == 0 || out_offset == NULL ||
      out_size == NULL || block_count == 0 || first_block > UINT64_MAX / file->block_size ||
      block_count > SIZE_MAX / file->block_size) {
    return false;
  }
  uint64_t byte_offset = first_block * file->block_size;
  size_t byte_count = (size_t)block_count * file->block_size;
  if (byte_offset > file->file_size || byte_count > file->file_size - byte_offset) {
    return false;
  }
  *out_offset = byte_offset;
  *out_size = byte_count;
  return true;
}
