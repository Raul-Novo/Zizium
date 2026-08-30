// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/zifs_image_source.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/byte_order.h"
#include "zi/path.h"
#include "zi/pe.h"
#include "zi/unicode.h"
#include "zi/zifs.h"
#include "zizium/status.h"
#include "zizium/types.h"

static bool allocator_is_valid(const ZiFsImageSourceAllocator* allocator);
static bool module_name_is_valid(ZiStringView module_name);
static bool string_views_equal(ZiStringView left, ZiStringView right);
static ZiStatus validate_requests(const ZiFsImageSourceRequest* requests, size_t request_count);
static ZiStatus load_one_source(const ZiFsVolume* volume,
                                const ZiFsImageSourceRequest* request,
                                const ZiFsImageSourceAllocator* allocator,
                                void* block_buffer,
                                size_t block_buffer_size,
                                ZiFsImageSourceSet* source_set);

ZiStatus zi_zifs_image_source_set_load(const ZiFsVolume* volume,
                                       const ZiFsImageSourceRequest* requests,
                                       size_t request_count,
                                       const ZiFsImageSourceAllocator* allocator,
                                       void* block_buffer,
                                       size_t block_buffer_size,
                                       ZiFsImageSourceSet* out_source_set) {
  if (volume == NULL || !allocator_is_valid(allocator) || block_buffer == NULL ||
      block_buffer_size < ZI_FS_BLOCK_SIZE || out_source_set == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_requests(requests, request_count);
  if (ZiFailed(status)) {
    return status;
  }

  ZiFsImageSourceSet source_set = {0};
  source_set.struct_size = sizeof source_set;
  source_set.version = ZI_FS_IMAGE_SOURCE_SET_VERSION;
  for (size_t index = 0; index < request_count; ++index) {
    status = load_one_source(volume,
                             &requests[index],
                             allocator,
                             block_buffer,
                             block_buffer_size,
                             &source_set);
    if (ZiFailed(status)) {
      ZiStatus release_status = zi_zifs_image_source_set_release(allocator, &source_set);
      if (ZiFailed(release_status)) {
        return ZI_STATUS_MEMORY_CORRUPTION;
      }
      return status;
    }
  }
  *out_source_set = source_set;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_zifs_image_source_set_release(const ZiFsImageSourceAllocator* allocator,
                                          ZiFsImageSourceSet* source_set) {
  if (!allocator_is_valid(allocator) || source_set == NULL ||
      source_set->struct_size != sizeof *source_set ||
      source_set->version != ZI_FS_IMAGE_SOURCE_SET_VERSION ||
      source_set->source_count > ZI_FS_IMAGE_SOURCE_CAPACITY) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus result = ZI_STATUS_SUCCESS;
  while (source_set->source_count != 0) {
    size_t index = --source_set->source_count;
    if (source_set->allocations[index] != NULL) {
      ZiStatus status = allocator->release(allocator->context, source_set->allocations[index]);
      if (ZiSucceeded(result) && ZiFailed(status)) {
        result = status;
      }
    }
    source_set->allocations[index] = NULL;
    zi_memory_zero(&source_set->sources[index], sizeof source_set->sources[index]);
  }
  zi_memory_zero(source_set, sizeof *source_set);
  return result;
}

static bool allocator_is_valid(const ZiFsImageSourceAllocator* allocator) {
  return (bool)(allocator != NULL && allocator->struct_size == sizeof *allocator &&
                allocator->version == ZI_FS_IMAGE_SOURCE_ALLOCATOR_VERSION &&
                allocator->maximum_file_size != 0 && allocator->maximum_total_size != 0 &&
                allocator->allocate != NULL && allocator->release != NULL);
}

static bool module_name_is_valid(ZiStringView module_name) {
  if (module_name.data == NULL || module_name.size == 0 ||
      module_name.size > ZI_PE_MODULE_NAME_LIMIT ||
      ZiFailed(zi_utf8_validate(module_name.data, module_name.size))) {
    return false;
  }
  for (size_t index = 0; index < module_name.size; ++index) {
    char character = module_name.data[index];
    if (character == '\0' || character == '\\' || character == '/' || character == ':') {
      return false;
    }
  }
  return true;
}

static bool string_views_equal(ZiStringView left, ZiStringView right) {
  if (left.data == NULL || right.data == NULL || left.size != right.size) {
    return false;
  }
  return zi_memory_compare(left.data, right.data, left.size) == 0;
}

static ZiStatus validate_requests(const ZiFsImageSourceRequest* requests, size_t request_count) {
  if (requests == NULL || request_count == 0 || request_count > ZI_FS_IMAGE_SOURCE_CAPACITY) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  for (size_t index = 0; index < request_count; ++index) {
    if (!module_name_is_valid(requests[index].module_name) ||
        requests[index].file_path.data == NULL || requests[index].file_path.size == 0) {
      return ZI_STATUS_INVALID_ARGUMENT;
    }
    for (size_t previous = 0; previous < index; ++previous) {
      if (string_views_equal(requests[index].module_name, requests[previous].module_name)) {
        return ZI_STATUS_INVALID_ARGUMENT;
      }
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus load_one_source(const ZiFsVolume* volume,
                                const ZiFsImageSourceRequest* request,
                                const ZiFsImageSourceAllocator* allocator,
                                void* block_buffer,
                                size_t block_buffer_size,
                                ZiFsImageSourceSet* source_set) {
  ZiStringView components[ZI_FS_IMAGE_PATH_COMPONENT_CAPACITY] = {0};
  ZiParsedPath path = {0};
  ZiStatus status = zi_path_parse_absolute(request->file_path.data,
                                           request->file_path.size,
                                           components,
                                           ZI_FS_IMAGE_PATH_COMPONENT_CAPACITY,
                                           &path);
  ZiFsFileRecord record = {0};
  if (ZiSucceeded(status)) {
    status = ZiFsLookupPath(volume, &path, block_buffer, block_buffer_size, &record);
  }
  if (ZiFailed(status)) {
    return status;
  }
  if (record.file_type != ZI_FS_FILE_TYPE_REGULAR || record.file_size == 0) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  if (record.file_size > SIZE_MAX || record.file_size > allocator->maximum_file_size ||
      source_set->total_size > allocator->maximum_total_size ||
      record.file_size > allocator->maximum_total_size - source_set->total_size) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }

  void* allocation = NULL;
  status = allocator->allocate(allocator->context, (size_t)record.file_size, &allocation);
  if (ZiFailed(status)) {
    return status;
  }
  if (allocation == NULL) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }

  size_t bytes_read = 0;
  status = ZiFsReadFile(volume,
                        &record,
                        0,
                        allocation,
                        (size_t)record.file_size,
                        &bytes_read,
                        block_buffer,
                        block_buffer_size);
  if (ZiFailed(status) || bytes_read != record.file_size) {
    ZiStatus release_status = allocator->release(allocator->context, allocation);
    if (ZiFailed(release_status)) {
      return ZI_STATUS_MEMORY_CORRUPTION;
    }
    if (ZiFailed(status)) {
      return status;
    }
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }

  size_t index = source_set->source_count++;
  source_set->sources[index].module_name = request->module_name;
  source_set->sources[index].file_data = allocation;
  source_set->sources[index].file_size = bytes_read;
  source_set->allocations[index] = allocation;
  source_set->total_size += bytes_read;
  return ZI_STATUS_SUCCESS;
}
