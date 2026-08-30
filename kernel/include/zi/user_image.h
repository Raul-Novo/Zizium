// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/address_space.h"
#include "zi/pe.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_USER_IMAGE_VERSION 2u
#define ZI_USER_IMAGE_SET_VERSION 1u
#define ZI_USER_IMAGE_LOAD_OPTIONS_VERSION 1u
#define ZI_USER_IMAGE_SET_CAPACITY 8u

#define ZI_USER_IMAGE_LOAD_FORCE_RELOCATION UINT32_C(0x00000001)

#define ZI_USER_IMAGE_FLAG_MAIN UINT32_C(0x00000001)
#define ZI_USER_IMAGE_FLAG_LIBRARY UINT32_C(0x00000002)
#define ZI_USER_IMAGE_FLAG_RELOCATED UINT32_C(0x00000004)

enum ZiUserImageState {
  ZI_USER_IMAGE_EMPTY = 0,
  ZI_USER_IMAGE_LOADING = 1,
  ZI_USER_IMAGE_READY = 2,
};

typedef struct ZiUserModuleSource {
  ZiStringView module_name;
  const void* file_data;
  size_t file_size;
} ZiUserModuleSource;

typedef struct ZiUserImageLoadOptions {
  uint32_t struct_size;
  uint32_t version;
  uint32_t flags;
  uint32_t reserved;
  uint64_t search_base;
  uint64_t search_end_exclusive;
  uint64_t search_alignment;
  const ZiUserModuleSource* module_sources;
  size_t module_source_count;
} ZiUserImageLoadOptions;

typedef struct ZiUserImage {
  uint32_t struct_size;
  uint32_t version;
  uint32_t state;
  uint32_t flags;
  uint64_t preferred_base;
  uint64_t image_base;
  uint64_t image_size;
  uint64_t entry_point;
  const void* file_data;
  size_t file_size;
  char module_name[ZI_PE_MODULE_NAME_LIMIT + 1u];
  size_t module_name_size;
} ZiUserImage;

typedef struct ZiUserImageSet {
  uint32_t struct_size;
  uint32_t version;
  ZiUserImage images[ZI_USER_IMAGE_SET_CAPACITY];
  size_t image_count;
} ZiUserImageSet;

ZiStatus zi_pe_load_user_image(const void* file_data,
                               size_t file_size,
                               ZiStringView module_name,
                               const ZiUserImageLoadOptions* options,
                               ZiAddressSpace* address_space,
                               ZiUserImageSet* out_image_set);
ZiStatus zi_user_image_set_unload(ZiAddressSpace* address_space, ZiUserImageSet* image_set);
