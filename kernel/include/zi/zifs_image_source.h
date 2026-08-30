// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/user_image.h"
#include "zi/zifs.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_FS_IMAGE_SOURCE_ALLOCATOR_VERSION 1u
#define ZI_FS_IMAGE_SOURCE_SET_VERSION 1u
#define ZI_FS_IMAGE_SOURCE_CAPACITY ZI_USER_IMAGE_SET_CAPACITY
#define ZI_FS_IMAGE_PATH_COMPONENT_CAPACITY 32u

typedef ZiStatus (*ZiFsImageSourceAllocate)(void* context, size_t size, void** out_allocation);
typedef ZiStatus (*ZiFsImageSourceRelease)(void* context, void* allocation);

typedef struct ZiFsImageSourceAllocator {
  uint32_t struct_size;
  uint32_t version;
  void* context;
  size_t maximum_file_size;
  size_t maximum_total_size;
  ZiFsImageSourceAllocate allocate;
  ZiFsImageSourceRelease release;
} ZiFsImageSourceAllocator;

typedef struct ZiFsImageSourceRequest {
  ZiStringView module_name;
  ZiStringView file_path;
} ZiFsImageSourceRequest;

typedef struct ZiFsImageSourceSet {
  uint32_t struct_size;
  uint32_t version;
  ZiUserModuleSource sources[ZI_FS_IMAGE_SOURCE_CAPACITY];
  void* allocations[ZI_FS_IMAGE_SOURCE_CAPACITY];
  size_t source_count;
  size_t total_size;
} ZiFsImageSourceSet;

ZiStatus zi_zifs_image_source_set_load(const ZiFsVolume* volume,
                                       const ZiFsImageSourceRequest* requests,
                                       size_t request_count,
                                       const ZiFsImageSourceAllocator* allocator,
                                       void* block_buffer,
                                       size_t block_buffer_size,
                                       ZiFsImageSourceSet* out_source_set);
ZiStatus zi_zifs_image_source_set_release(const ZiFsImageSourceAllocator* allocator,
                                          ZiFsImageSourceSet* source_set);
