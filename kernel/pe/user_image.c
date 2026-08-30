// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/user_image.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/address_space.h"
#include "zi/byte_order.h"
#include "zi/memory.h"
#include "zi/pe.h"
#include "zi/x64_paging.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_USER_PE_SECTION_CAPACITY 32u
#define ZI_USER_IMAGE_DEFAULT_SEARCH_BASE UINT64_C(0x0000000150000000)
#define ZI_USER_IMAGE_DEFAULT_SEARCH_END UINT64_C(0x0000000300000000)
#define ZI_USER_IMAGE_DEFAULT_ALIGNMENT UINT64_C(0x0000000000010000)

typedef struct UserImageAccessContext {
  ZiAddressSpace* address_space;
  uint64_t image_base;
  uint64_t image_size;
} UserImageAccessContext;

typedef struct UserImageLoader {
  ZiAddressSpace* address_space;
  const ZiUserImageLoadOptions* options;
  ZiUserImageSet* image_set;
} UserImageLoader;

static bool load_options_are_valid(const ZiUserImageLoadOptions* options);
static bool module_name_is_valid(ZiStringView module_name);
static bool module_names_equal(ZiStringView left, ZiStringView right);
static bool image_contract_is_valid(const ZiPeImage* image, bool is_main);
static ZiStatus select_image_base(const ZiPeImage* image,
                                  const ZiUserImageLoadOptions* options,
                                  const ZiAddressSpace* address_space,
                                  bool is_main,
                                  uint64_t* out_image_base);
static ZiStatus load_image(UserImageLoader* loader,
                           const void* file_data,
                           size_t file_size,
                           ZiStringView module_name,
                           bool is_main,
                           ZiUserImage** out_image);
static ZiStatus
copy_image_contents(const ZiPeImage* image, uint64_t image_base, ZiAddressSpace* address_space);
static ZiStatus
protect_image_contents(const ZiPeImage* image, uint64_t image_base, ZiAddressSpace* address_space);
static ZiStatus section_protection(const ZiPeSection* section, uint32_t* out_protection);
static ZiStatus align_page_size(uint32_t size, size_t* out_size);
static ZiStatus
user_image_read(void* context, uint32_t relative_address, void* output, size_t output_size);
static ZiStatus
user_image_write(void* context, uint32_t relative_address, const void* data, size_t data_size);
static ZiStatus resolve_import(void* context,
                               const char* module_name,
                               size_t module_name_size,
                               const char* symbol_name,
                               size_t symbol_name_size,
                               uint16_t ordinal,
                               bool is_ordinal,
                               uint64_t* out_address);
static ZiUserImage* find_loaded_image(ZiUserImageSet* image_set, ZiStringView module_name);
static const ZiUserModuleSource* find_module_source(const ZiUserImageLoadOptions* options,
                                                    ZiStringView module_name);
static ZiStatus validate_module_sources(const ZiUserImageLoadOptions* options,
                                        ZiStringView main_module_name);
static ZiStatus parse_loaded_image(const ZiUserImage* loaded,
                                   ZiPeSection* sections,
                                   size_t section_capacity,
                                   ZiPeImage* out_image);
static void clear_source_views(ZiUserImageSet* image_set);

ZiStatus zi_pe_load_user_image(const void* file_data,
                               size_t file_size,
                               ZiStringView module_name,
                               const ZiUserImageLoadOptions* options,
                               ZiAddressSpace* address_space,
                               ZiUserImageSet* out_image_set) {
  if (file_data == NULL || file_size == 0 || !module_name_is_valid(module_name) ||
      address_space == NULL || out_image_set == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiUserImageLoadOptions default_options = {
      sizeof(ZiUserImageLoadOptions),
      ZI_USER_IMAGE_LOAD_OPTIONS_VERSION,
      0,
      0,
      ZI_USER_IMAGE_DEFAULT_SEARCH_BASE,
      ZI_USER_IMAGE_DEFAULT_SEARCH_END,
      ZI_USER_IMAGE_DEFAULT_ALIGNMENT,
      NULL,
      0,
  };
  if (options == NULL) {
    options = &default_options;
  }
  if (!load_options_are_valid(options)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_module_sources(options, module_name);
  if (ZiFailed(status)) {
    return status;
  }

  ZiUserImageSet image_set = {0};
  image_set.struct_size = sizeof image_set;
  image_set.version = ZI_USER_IMAGE_SET_VERSION;
  UserImageLoader loader = {address_space, options, &image_set};
  ZiUserImage* main_image = NULL;
  status = load_image(&loader, file_data, file_size, module_name, true, &main_image);
  if (ZiFailed(status)) {
    ZiStatus unload_status = zi_user_image_set_unload(address_space, &image_set);
    if (ZiFailed(unload_status)) {
      return ZI_STATUS_MEMORY_CORRUPTION;
    }
    return status;
  }
  if (main_image == NULL || main_image != &image_set.images[0]) {
    (void)zi_user_image_set_unload(address_space, &image_set);
    return ZI_STATUS_INVALID_STATE;
  }
  clear_source_views(&image_set);
  *out_image_set = image_set;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_user_image_set_unload(ZiAddressSpace* address_space, ZiUserImageSet* image_set) {
  if (address_space == NULL || image_set == NULL || image_set->struct_size != sizeof *image_set ||
      image_set->version != ZI_USER_IMAGE_SET_VERSION ||
      image_set->image_count > ZI_USER_IMAGE_SET_CAPACITY) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  while (image_set->image_count != 0) {
    ZiUserImage* image = &image_set->images[image_set->image_count - 1u];
    if (image->image_base != 0 && image->image_size != 0) {
      if (image->image_size > SIZE_MAX) {
        return ZI_STATUS_OUT_OF_BOUNDS;
      }
      ZiStatus status =
          zi_address_space_unmap_owned(address_space, image->image_base, (size_t)image->image_size);
      if (ZiFailed(status)) {
        return status;
      }
    }
    --image_set->image_count;
    zi_memory_zero(image, sizeof *image);
  }
  zi_memory_zero(image_set, sizeof *image_set);
  return ZI_STATUS_SUCCESS;
}

static bool load_options_are_valid(const ZiUserImageLoadOptions* options) {
  const uint32_t known_flags = ZI_USER_IMAGE_LOAD_FORCE_RELOCATION;
  return (bool)(options != NULL && options->struct_size == sizeof *options &&
                options->version == ZI_USER_IMAGE_LOAD_OPTIONS_VERSION &&
                (options->flags & ~known_flags) == 0 &&
                options->search_base >= ZI_USER_ADDRESS_MIN &&
                options->search_end_exclusive <= ZI_USER_ADDRESS_MAX_EXCLUSIVE &&
                options->search_base < options->search_end_exclusive &&
                options->search_alignment >= ZI_X64_PAGE_SIZE &&
                (options->search_alignment & (options->search_alignment - 1u)) == 0 &&
                (options->module_sources != NULL || options->module_source_count == 0));
}

static bool module_name_is_valid(ZiStringView module_name) {
  if (module_name.data == NULL || module_name.size == 0 ||
      module_name.size > ZI_PE_MODULE_NAME_LIMIT) {
    return false;
  }
  for (size_t index = 0; index < module_name.size; ++index) {
    if (module_name.data[index] == '\0') {
      return false;
    }
  }
  return true;
}

static bool module_names_equal(ZiStringView left, ZiStringView right) {
  if (left.size != right.size || left.data == NULL || right.data == NULL) {
    return false;
  }
  for (size_t index = 0; index < left.size; ++index) {
    if (left.data[index] != right.data[index]) {
      return false;
    }
  }
  return true;
}

static bool image_contract_is_valid(const ZiPeImage* image, bool is_main) {
  if (image == NULL || image->machine != ZI_PE_MACHINE_AMD64 ||
      image->subsystem != ZI_PE_SUBSYSTEM_NATIVE || image->section_alignment != ZI_X64_PAGE_SIZE ||
      image->image_size == 0 || (image->image_size & (ZI_X64_PAGE_SIZE - 1u)) != 0 ||
      (image->image_base & (ZI_X64_PAGE_SIZE - 1u)) != 0 ||
      !zi_user_range_is_valid(image->image_base, image->image_size)) {
    return false;
  }
  bool is_library = (image->characteristics & ZI_PE_CHARACTERISTIC_DLL) != 0;
  if (is_main == is_library || (!is_main && !zi_pe_has_exports(image))) {
    return false;
  }
  uint64_t header_end =
      ((uint64_t)image->header_size + (ZI_X64_PAGE_SIZE - 1u)) & ~(ZI_X64_PAGE_SIZE - 1u);
  if (header_end == 0 || header_end > image->image_size) {
    return false;
  }
  for (uint16_t index = 0; index < image->section_count; ++index) {
    const ZiPeSection* section = &image->sections[index];
    uint32_t mapped_size =
        section->virtual_size > section->raw_size ? section->virtual_size : section->raw_size;
    uint64_t mapped_end =
        ((uint64_t)section->virtual_address + mapped_size + (ZI_X64_PAGE_SIZE - 1u)) &
        ~(ZI_X64_PAGE_SIZE - 1u);
    if (mapped_size == 0 || (section->virtual_address & (ZI_X64_PAGE_SIZE - 1u)) != 0 ||
        section->virtual_address < header_end || mapped_end > image->image_size) {
      return false;
    }
    for (uint16_t previous_index = 0; previous_index < index; ++previous_index) {
      const ZiPeSection* previous = &image->sections[previous_index];
      uint32_t previous_size =
          previous->virtual_size > previous->raw_size ? previous->virtual_size : previous->raw_size;
      uint64_t previous_end =
          ((uint64_t)previous->virtual_address + previous_size + (ZI_X64_PAGE_SIZE - 1u)) &
          ~(ZI_X64_PAGE_SIZE - 1u);
      if (section->virtual_address < previous_end && previous->virtual_address < mapped_end) {
        return false;
      }
    }
  }
  return true;
}

static ZiStatus select_image_base(const ZiPeImage* image,
                                  const ZiUserImageLoadOptions* options,
                                  const ZiAddressSpace* address_space,
                                  bool is_main,
                                  uint64_t* out_image_base) {
  if (image == NULL || options == NULL || address_space == NULL || out_image_base == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  bool force_relocation =
      (bool)(is_main && (options->flags & ZI_USER_IMAGE_LOAD_FORCE_RELOCATION) != 0);
  if (!force_relocation) {
    uint64_t preferred_end = image->image_base + image->image_size;
    ZiStatus preferred_status = zi_address_space_find_free_range(address_space,
                                                                 image->image_base,
                                                                 preferred_end,
                                                                 (size_t)image->image_size,
                                                                 ZI_X64_PAGE_SIZE,
                                                                 out_image_base);
    if (ZiSucceeded(preferred_status)) {
      return ZI_STATUS_SUCCESS;
    }
    if (preferred_status != ZI_STATUS_NOT_FOUND) {
      return preferred_status;
    }
  }
  if (image->relocation_directory.virtual_address == 0 || image->relocation_directory.size == 0) {
    return ZI_STATUS_IMAGE_RELOCATION_FAILED;
  }
  ZiStatus status = zi_address_space_find_free_range(address_space,
                                                     options->search_base,
                                                     options->search_end_exclusive,
                                                     (size_t)image->image_size,
                                                     options->search_alignment,
                                                     out_image_base);
  if (ZiFailed(status)) {
    return status;
  }
  if (*out_image_base == image->image_base) {
    uint64_t next = *out_image_base + options->search_alignment;
    status = zi_address_space_find_free_range(address_space,
                                              next,
                                              options->search_end_exclusive,
                                              (size_t)image->image_size,
                                              options->search_alignment,
                                              out_image_base);
  }
  return status;
}

// Recursive dependency loading is bounded by ZI_USER_IMAGE_SET_CAPACITY.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static ZiStatus load_image(UserImageLoader* loader,
                           const void* file_data,
                           size_t file_size,
                           ZiStringView module_name,
                           bool is_main,
                           ZiUserImage** out_image) {
  if (loader == NULL || loader->address_space == NULL || loader->options == NULL ||
      loader->image_set == NULL || file_data == NULL || file_size == 0 ||
      !module_name_is_valid(module_name) || out_image == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiUserImage* existing = find_loaded_image(loader->image_set, module_name);
  if (existing != NULL) {
    if (existing->state == ZI_USER_IMAGE_LOADING) {
      return ZI_STATUS_IMAGE_DEPENDENCY_CYCLE;
    }
    *out_image = existing;
    return existing->state == ZI_USER_IMAGE_READY ? ZI_STATUS_SUCCESS : ZI_STATUS_INVALID_STATE;
  }
  if (loader->image_set->image_count >= ZI_USER_IMAGE_SET_CAPACITY) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }

  ZiPeSection sections[ZI_USER_PE_SECTION_CAPACITY] = {0};
  ZiPeImage image = {0};
  ZiStatus status =
      zi_pe_parse(file_data, file_size, sections, ZI_USER_PE_SECTION_CAPACITY, &image);
  if (ZiFailed(status)) {
    return status;
  }
  if (!image_contract_is_valid(&image, is_main)) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }

  ZiUserImage* loaded = &loader->image_set->images[loader->image_set->image_count++];
  loaded->struct_size = sizeof *loaded;
  loaded->version = ZI_USER_IMAGE_VERSION;
  loaded->state = ZI_USER_IMAGE_LOADING;
  loaded->flags = ZI_USER_IMAGE_FLAG_LIBRARY;
  if (is_main) {
    loaded->flags = ZI_USER_IMAGE_FLAG_MAIN;
  }
  loaded->preferred_base = image.image_base;
  loaded->image_size = image.image_size;
  loaded->file_data = file_data;
  loaded->file_size = file_size;
  loaded->module_name_size = module_name.size;
  for (size_t index = 0; index < module_name.size; ++index) {
    loaded->module_name[index] = module_name.data[index];
  }
  loaded->module_name[module_name.size] = '\0';

  status = select_image_base(&image,
                             loader->options,
                             loader->address_space,
                             is_main,
                             &loaded->image_base);
  if (ZiFailed(status)) {
    return status;
  }
  if (loaded->image_base != loaded->preferred_base) {
    loaded->flags |= ZI_USER_IMAGE_FLAG_RELOCATED;
  }
  status = zi_address_space_map_owned(loader->address_space,
                                      loaded->image_base,
                                      (size_t)loaded->image_size,
                                      ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE | ZI_X64_PAGE_USER,
                                      ZI_MEMORY_OWNER_PROCESS_IMAGE);
  if (ZiFailed(status)) {
    loaded->image_base = 0;
    return status;
  }
  status = copy_image_contents(&image, loaded->image_base, loader->address_space);

  UserImageAccessContext access_context = {
      loader->address_space,
      loaded->image_base,
      loaded->image_size,
  };
  ZiPeImageAccess access = {
      sizeof(ZiPeImageAccess),
      ZI_PE_IMAGE_ACCESS_VERSION,
      &access_context,
      user_image_read,
      user_image_write,
  };
  if (ZiSucceeded(status)) {
    status = zi_pe_apply_relocations_with_access(&image, &access, loaded->image_base);
  }
  if (ZiSucceeded(status)) {
    ZiPeImportResolver resolver = {
        sizeof(ZiPeImportResolver),
        ZI_PE_IMPORT_RESOLVER_VERSION,
        loader,
        resolve_import,
    };
    status = zi_pe_resolve_imports(&image, &access, &resolver);
  }
  if (ZiSucceeded(status)) {
    status = protect_image_contents(&image, loaded->image_base, loader->address_space);
  }
  if (ZiSucceeded(status) && is_main) {
    loaded->entry_point = loaded->image_base + image.entry_point_rva;
    ZiX64PageMapping entry_mapping = {0};
    status = zi_address_space_query(loader->address_space,
                                    loaded->entry_point,
                                    ZI_USER_ACCESS_EXECUTE,
                                    &entry_mapping);
    if (status == ZI_STATUS_INVALID_USER_BUFFER) {
      status = ZI_STATUS_BAD_IMAGE_FORMAT;
    }
  }
  if (ZiFailed(status)) {
    return status;
  }
  loaded->state = ZI_USER_IMAGE_READY;
  *out_image = loaded;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus
copy_image_contents(const ZiPeImage* image, uint64_t image_base, ZiAddressSpace* address_space) {
  ZiStatus status =
      zi_copy_to_user(address_space, image_base, image->file_data, image->header_size);
  for (uint16_t index = 0; ZiSucceeded(status) && index < image->section_count; ++index) {
    const ZiPeSection* section = &image->sections[index];
    if (section->raw_size != 0) {
      status = zi_copy_to_user(address_space,
                               image_base + section->virtual_address,
                               image->file_data + section->raw_offset,
                               section->raw_size);
    }
  }
  return status;
}

static ZiStatus
protect_image_contents(const ZiPeImage* image, uint64_t image_base, ZiAddressSpace* address_space) {
  ZiStatus status = zi_address_space_protect_owned(address_space,
                                                   image_base,
                                                   image->image_size,
                                                   ZI_X64_PAGE_READ | ZI_X64_PAGE_USER);
  for (uint16_t index = 0; ZiSucceeded(status) && index < image->section_count; ++index) {
    const ZiPeSection* section = &image->sections[index];
    uint32_t mapped_size =
        section->virtual_size > section->raw_size ? section->virtual_size : section->raw_size;
    size_t aligned_size = 0;
    status = align_page_size(mapped_size, &aligned_size);
    uint32_t protection = 0;
    if (ZiSucceeded(status)) {
      status = section_protection(section, &protection);
    }
    if (ZiSucceeded(status)) {
      status = zi_address_space_protect_owned(address_space,
                                              image_base + section->virtual_address,
                                              aligned_size,
                                              protection);
    }
  }
  return status;
}

static ZiStatus section_protection(const ZiPeSection* section, uint32_t* out_protection) {
  if (section == NULL || out_protection == NULL ||
      ((section->characteristics & ZI_PE_SECTION_WRITE) != 0 &&
       (section->characteristics & ZI_PE_SECTION_EXECUTE) != 0)) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  uint32_t protection = ZI_X64_PAGE_READ | ZI_X64_PAGE_USER;
  if ((section->characteristics & ZI_PE_SECTION_WRITE) != 0) {
    protection |= ZI_X64_PAGE_WRITE;
  }
  if ((section->characteristics & ZI_PE_SECTION_EXECUTE) != 0) {
    protection |= ZI_X64_PAGE_EXECUTE;
  }
  *out_protection = protection;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus align_page_size(uint32_t size, size_t* out_size) {
  if (size == 0 || out_size == NULL || size > UINT32_MAX - (uint32_t)(ZI_X64_PAGE_SIZE - 1u)) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  *out_size =
      (size_t)((size + (uint32_t)ZI_X64_PAGE_SIZE - 1u) & ~(uint32_t)(ZI_X64_PAGE_SIZE - 1u));
  return ZI_STATUS_SUCCESS;
}

static ZiStatus
user_image_read(void* context, uint32_t relative_address, void* output, size_t output_size) {
  UserImageAccessContext* access = context;
  if (access == NULL || access->address_space == NULL || output == NULL || output_size == 0 ||
      relative_address > access->image_size ||
      output_size > access->image_size - relative_address) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  return zi_copy_from_user(access->address_space,
                           output,
                           access->image_base + relative_address,
                           output_size);
}

static ZiStatus
user_image_write(void* context, uint32_t relative_address, const void* data, size_t data_size) {
  UserImageAccessContext* access = context;
  if (access == NULL || access->address_space == NULL || data == NULL || data_size == 0 ||
      relative_address > access->image_size || data_size > access->image_size - relative_address) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  return zi_copy_to_user(access->address_space,
                         access->image_base + relative_address,
                         data,
                         data_size);
}

// The import-resolver callback shape is a public PE contract with eight parameters.
// NOLINTNEXTLINE(readability-function-size)
static ZiStatus resolve_import(void* context,
                               const char* module_name,
                               size_t module_name_size,
                               const char* symbol_name,
                               size_t symbol_name_size,
                               uint16_t ordinal,
                               bool is_ordinal,
                               uint64_t* out_address) {
  UserImageLoader* loader = context;
  ZiStringView requested_module = {module_name, module_name_size};
  if (loader == NULL || !module_name_is_valid(requested_module) || out_address == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiUserImage* loaded = find_loaded_image(loader->image_set, requested_module);
  if (loaded != NULL && loaded->state == ZI_USER_IMAGE_LOADING) {
    return ZI_STATUS_IMAGE_DEPENDENCY_CYCLE;
  }
  if (loaded == NULL) {
    const ZiUserModuleSource* source = find_module_source(loader->options, requested_module);
    if (source == NULL) {
      return ZI_STATUS_IMAGE_IMPORT_NOT_FOUND;
    }
    ZiStatus status = load_image(loader,
                                 source->file_data,
                                 source->file_size,
                                 source->module_name,
                                 false,
                                 &loaded);
    if (ZiFailed(status)) {
      return status;
    }
  }
  if (loaded == NULL || loaded->state != ZI_USER_IMAGE_READY) {
    return ZI_STATUS_INVALID_STATE;
  }

  ZiPeSection sections[ZI_USER_PE_SECTION_CAPACITY] = {0};
  ZiPeImage image = {0};
  ZiStatus status = parse_loaded_image(loaded, sections, ZI_USER_PE_SECTION_CAPACITY, &image);
  if (ZiFailed(status)) {
    return status;
  }
  UserImageAccessContext access_context = {
      loader->address_space,
      loaded->image_base,
      loaded->image_size,
  };
  ZiPeImageAccess access = {
      sizeof(ZiPeImageAccess),
      ZI_PE_IMAGE_ACCESS_VERSION,
      &access_context,
      user_image_read,
      NULL,
  };
  uint32_t relative_address = 0;
  if (is_ordinal) {
    status = zi_pe_find_export_by_ordinal(&image, &access, ordinal, &relative_address);
  } else {
    status = zi_pe_find_export(&image, &access, symbol_name, symbol_name_size, &relative_address);
  }
  if (status == ZI_STATUS_NOT_FOUND) {
    return ZI_STATUS_IMAGE_IMPORT_NOT_FOUND;
  }
  if (ZiFailed(status) || loaded->image_base > UINT64_MAX - relative_address) {
    if (ZiFailed(status)) {
      return status;
    }
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  uint64_t resolved = loaded->image_base + relative_address;
  ZiX64PageMapping mapping = {0};
  status =
      zi_address_space_query(loader->address_space, resolved, ZI_USER_ACCESS_EXECUTE, &mapping);
  if (ZiFailed(status)) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  *out_address = resolved;
  return ZI_STATUS_SUCCESS;
}

static ZiUserImage* find_loaded_image(ZiUserImageSet* image_set, ZiStringView module_name) {
  if (image_set == NULL) {
    return NULL;
  }
  for (size_t index = 0; index < image_set->image_count; ++index) {
    ZiUserImage* image = &image_set->images[index];
    ZiStringView loaded_name = {image->module_name, image->module_name_size};
    if (module_names_equal(loaded_name, module_name)) {
      return image;
    }
  }
  return NULL;
}

static const ZiUserModuleSource* find_module_source(const ZiUserImageLoadOptions* options,
                                                    ZiStringView module_name) {
  for (size_t index = 0; index < options->module_source_count; ++index) {
    if (module_names_equal(options->module_sources[index].module_name, module_name)) {
      return &options->module_sources[index];
    }
  }
  return NULL;
}

static ZiStatus validate_module_sources(const ZiUserImageLoadOptions* options,
                                        ZiStringView main_module_name) {
  for (size_t index = 0; index < options->module_source_count; ++index) {
    const ZiUserModuleSource* source = &options->module_sources[index];
    if (!module_name_is_valid(source->module_name) || source->file_data == NULL ||
        source->file_size == 0 || module_names_equal(source->module_name, main_module_name)) {
      return ZI_STATUS_INVALID_ARGUMENT;
    }
    for (size_t previous = 0; previous < index; ++previous) {
      if (module_names_equal(source->module_name, options->module_sources[previous].module_name)) {
        return ZI_STATUS_INVALID_ARGUMENT;
      }
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus parse_loaded_image(const ZiUserImage* loaded,
                                   ZiPeSection* sections,
                                   size_t section_capacity,
                                   ZiPeImage* out_image) {
  if (loaded == NULL || loaded->file_data == NULL || loaded->file_size == 0 || sections == NULL ||
      out_image == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return zi_pe_parse(loaded->file_data, loaded->file_size, sections, section_capacity, out_image);
}

static void clear_source_views(ZiUserImageSet* image_set) {
  for (size_t index = 0; index < image_set->image_count; ++index) {
    image_set->images[index].file_data = NULL;
    image_set->images[index].file_size = 0;
  }
}
