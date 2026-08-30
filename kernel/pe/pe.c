// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/pe.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/byte_order.h"
#include "zizium/status.h"

enum {
  PE_DOS_MINIMUM_SIZE = 64,
  PE_COFF_HEADER_SIZE = 20,
  PE_SECTION_HEADER_SIZE = 40,
  PE_OPTIONAL_MINIMUM_SIZE = 112,
  PE_EXPORT_DIRECTORY_SIZE = 40,
  PE_IMPORT_DESCRIPTOR_SIZE = 20,
  PE_IMPORT_DESCRIPTOR_LIMIT = 64,
  PE_IMPORT_THUNK_LIMIT = 4096,
  PE_EXPORT_ENTRY_LIMIT = 4096,
  PE_DIRECTORY_EXPORT = 0,
  PE_DIRECTORY_IMPORT = 1,
  PE_DIRECTORY_RELOCATION = 5,
};

#define PE_IMPORT_ORDINAL_FLAG UINT64_C(0x8000000000000000)

typedef struct PeMemoryAccess {
  unsigned char* data;
  size_t size;
} PeMemoryAccess;

typedef struct PeImportDescriptor {
  uint32_t original_thunk;
  uint32_t time_stamp;
  uint32_t forwarder_chain;
  uint32_t name_relative_address;
  uint32_t first_thunk;
} PeImportDescriptor;

typedef struct PeImportBindingContext {
  const ZiPeImage* image;
  const ZiPeImageAccess* access;
  const ZiPeImportResolver* resolver;
  const char* module_name;
  size_t module_name_size;
  char* symbol_name;
  size_t symbol_name_capacity;
} PeImportBindingContext;

static bool range_is_valid(size_t offset, size_t length, size_t total_size);
static bool virtual_range_is_valid(uint32_t address, uint32_t size, uint32_t image_size);
static bool directories_are_valid(const ZiPeImage* image);
static bool sections_are_disjoint(const ZiPeSection* sections, uint16_t section_count);
static ZiPeDataDirectory read_directory(const unsigned char* optional_header,
                                        size_t optional_size,
                                        uint32_t directory_count,
                                        uint32_t index);
static bool access_is_valid(const ZiPeImageAccess* access, bool needs_write);
static ZiStatus access_read(const ZiPeImage* image,
                            const ZiPeImageAccess* access,
                            uint32_t relative_address,
                            void* output,
                            size_t output_size);
static ZiStatus access_write(const ZiPeImage* image,
                             const ZiPeImageAccess* access,
                             uint32_t relative_address,
                             const void* data,
                             size_t data_size);
static ZiStatus access_read_u16(const ZiPeImage* image,
                                const ZiPeImageAccess* access,
                                uint32_t relative_address,
                                uint16_t* out_value);
static ZiStatus access_read_u32(const ZiPeImage* image,
                                const ZiPeImageAccess* access,
                                uint32_t relative_address,
                                uint32_t* out_value);
static ZiStatus access_read_u64(const ZiPeImage* image,
                                const ZiPeImageAccess* access,
                                uint32_t relative_address,
                                uint64_t* out_value);
static ZiStatus access_write_u64(const ZiPeImage* image,
                                 const ZiPeImageAccess* access,
                                 uint32_t relative_address,
                                 uint64_t value);
static ZiStatus access_read_string(const ZiPeImage* image,
                                   const ZiPeImageAccess* access,
                                   uint32_t relative_address,
                                   char* output,
                                   size_t output_capacity,
                                   size_t* out_size);
static ZiStatus
memory_access_read(void* context, uint32_t relative_address, void* output, size_t output_size);
static ZiStatus
memory_access_write(void* context, uint32_t relative_address, const void* data, size_t data_size);
static bool bytes_equal(const char* left, const char* right, size_t size);
static ZiStatus export_function_by_index(const ZiPeImage* image,
                                         const ZiPeImageAccess* access,
                                         uint32_t function_table,
                                         uint32_t function_count,
                                         uint32_t function_index,
                                         uint32_t* out_relative_address);
static ZiStatus apply_relocation_block(const ZiPeImage* image,
                                       const ZiPeImageAccess* access,
                                       uint32_t cursor,
                                       uint32_t end,
                                       uint64_t delta,
                                       uint32_t* out_block_size);
static ZiStatus read_import_descriptor(const ZiPeImage* image,
                                       const ZiPeImageAccess* access,
                                       uint32_t relative_address,
                                       PeImportDescriptor* out_descriptor);
static bool import_descriptor_is_null(const PeImportDescriptor* descriptor);
static ZiStatus resolve_import_lookup(const PeImportBindingContext* context,
                                      uint64_t lookup,
                                      uint64_t* out_address);
static ZiStatus resolve_import_thunks(const PeImportBindingContext* context,
                                      uint32_t lookup_thunk,
                                      uint32_t first_thunk);

// NOLINTNEXTLINE(readability-function-cognitive-complexity) -- image bounds checks are explicit.
ZiStatus zi_pe_parse(const void* data,
                     size_t data_size,
                     ZiPeSection* section_storage,
                     size_t section_capacity,
                     ZiPeImage* out_image) {
  if (data == NULL || section_storage == NULL || out_image == NULL ||
      data_size < PE_DOS_MINIMUM_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  const unsigned char* bytes = data;
  if (bytes[0] != 'M' || bytes[1] != 'Z') {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  uint32_t pe_offset = zi_read_u32_le(bytes + 0x3c);
  if (!range_is_valid(pe_offset, 4u + PE_COFF_HEADER_SIZE, data_size)) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  if (bytes[pe_offset] != 'P' || bytes[pe_offset + 1] != 'E' || bytes[pe_offset + 2] != 0 ||
      bytes[pe_offset + 3] != 0) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }

  const unsigned char* coff = bytes + pe_offset + 4;
  uint16_t section_count = zi_read_u16_le(coff + 2);
  uint16_t optional_size = zi_read_u16_le(coff + 16);
  if (section_count == 0 || section_count > section_capacity ||
      optional_size < PE_OPTIONAL_MINIMUM_SIZE) {
    return section_count > section_capacity ? ZI_STATUS_BUFFER_TOO_SMALL
                                            : ZI_STATUS_BAD_IMAGE_FORMAT;
  }

  size_t optional_offset = (size_t)pe_offset + 4u + PE_COFF_HEADER_SIZE;
  if (!range_is_valid(optional_offset, optional_size, data_size)) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  const unsigned char* optional = bytes + optional_offset;
  if (zi_read_u16_le(optional) != ZI_PE_OPTIONAL_MAGIC_PE32_PLUS) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }

  uint32_t directory_count = zi_read_u32_le(optional + 108);
  size_t section_offset = optional_offset + optional_size;
  size_t section_bytes = (size_t)section_count * PE_SECTION_HEADER_SIZE;
  if (!range_is_valid(section_offset, section_bytes, data_size)) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }

  uint32_t image_size = zi_read_u32_le(optional + 56);
  for (uint16_t index = 0; index < section_count; ++index) {
    const unsigned char* source = bytes + section_offset + ((size_t)index * PE_SECTION_HEADER_SIZE);
    ZiPeSection* section = &section_storage[index];
    for (size_t name_index = 0; name_index < 8; ++name_index) {
      section->name[name_index] = (char)source[name_index];
    }
    section->name[8] = '\0';
    section->virtual_size = zi_read_u32_le(source + 8);
    section->virtual_address = zi_read_u32_le(source + 12);
    section->raw_size = zi_read_u32_le(source + 16);
    section->raw_offset = zi_read_u32_le(source + 20);
    section->characteristics = zi_read_u32_le(source + 36);

    if (section->raw_size != 0 &&
        !range_is_valid(section->raw_offset, section->raw_size, data_size)) {
      return ZI_STATUS_BAD_IMAGE_FORMAT;
    }
    uint32_t mapped_size =
        section->virtual_size > section->raw_size ? section->virtual_size : section->raw_size;
    if (section->virtual_address > image_size ||
        mapped_size > image_size - section->virtual_address) {
      return ZI_STATUS_BAD_IMAGE_FORMAT;
    }
  }

  out_image->machine = zi_read_u16_le(coff);
  out_image->section_count = section_count;
  out_image->characteristics = zi_read_u16_le(coff + 18);
  out_image->subsystem = zi_read_u16_le(optional + 68);
  out_image->entry_point_rva = zi_read_u32_le(optional + 16);
  out_image->image_base = zi_read_u64_le(optional + 24);
  out_image->section_alignment = zi_read_u32_le(optional + 32);
  out_image->file_alignment = zi_read_u32_le(optional + 36);
  out_image->image_size = image_size;
  out_image->header_size = zi_read_u32_le(optional + 60);
  out_image->export_directory =
      read_directory(optional, optional_size, directory_count, PE_DIRECTORY_EXPORT);
  out_image->import_directory =
      read_directory(optional, optional_size, directory_count, PE_DIRECTORY_IMPORT);
  out_image->relocation_directory =
      read_directory(optional, optional_size, directory_count, PE_DIRECTORY_RELOCATION);
  out_image->sections = section_storage;
  out_image->file_data = bytes;
  out_image->file_size = data_size;

  if (out_image->header_size > data_size || out_image->header_size > image_size ||
      out_image->entry_point_rva >= image_size || out_image->section_alignment == 0 ||
      out_image->file_alignment == 0 || !directories_are_valid(out_image) ||
      !sections_are_disjoint(section_storage, section_count)) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  return ZI_STATUS_SUCCESS;
}

bool zi_pe_has_imports(const ZiPeImage* image) {
  return (bool)(image != NULL && image->import_directory.virtual_address != 0 &&
                image->import_directory.size != 0);
}

bool zi_pe_has_exports(const ZiPeImage* image) {
  return (bool)(image != NULL && image->export_directory.virtual_address != 0 &&
                image->export_directory.size != 0);
}

ZiStatus zi_pe_map_image(const ZiPeImage* image, void* destination, size_t destination_size) {
  if (image == NULL || destination == NULL || image->file_data == NULL || image->sections == NULL ||
      image->image_size == 0 || destination_size < image->image_size ||
      image->header_size > image->file_size || image->header_size > image->image_size) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char* mapped = destination;
  zi_memory_zero(mapped, image->image_size);
  zi_memory_copy(mapped, image->file_data, image->header_size);
  for (uint16_t index = 0; index < image->section_count; ++index) {
    const ZiPeSection* section = &image->sections[index];
    if (section->raw_size == 0) {
      continue;
    }
    if (!range_is_valid(section->raw_offset, section->raw_size, image->file_size) ||
        !range_is_valid(section->virtual_address, section->raw_size, image->image_size)) {
      zi_memory_zero(mapped, image->image_size);
      return ZI_STATUS_BAD_IMAGE_FORMAT;
    }
    zi_memory_copy(mapped + section->virtual_address,
                   image->file_data + section->raw_offset,
                   section->raw_size);
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_pe_apply_relocations(const ZiPeImage* image,
                                 void* mapped_image,
                                 size_t mapped_size,
                                 uint64_t new_image_base) {
  if (image == NULL || mapped_image == NULL || mapped_size < image->image_size) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  PeMemoryAccess memory = {mapped_image, mapped_size};
  ZiPeImageAccess access = {
      sizeof(ZiPeImageAccess),
      ZI_PE_IMAGE_ACCESS_VERSION,
      &memory,
      memory_access_read,
      memory_access_write,
  };
  return zi_pe_apply_relocations_with_access(image, &access, new_image_base);
}

ZiStatus zi_pe_apply_relocations_with_access(const ZiPeImage* image,
                                             const ZiPeImageAccess* access,
                                             uint64_t new_image_base) {
  if (image == NULL || !access_is_valid(access, true)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (new_image_base == image->image_base) {
    return ZI_STATUS_SUCCESS;
  }
  ZiPeDataDirectory directory = image->relocation_directory;
  if (directory.virtual_address == 0 || directory.size == 0 ||
      !range_is_valid(directory.virtual_address, directory.size, image->image_size)) {
    return ZI_STATUS_IMAGE_RELOCATION_FAILED;
  }

  uint64_t delta = new_image_base - image->image_base;
  uint32_t cursor = directory.virtual_address;
  uint32_t end = cursor + directory.size;
  while (cursor < end) {
    uint32_t block_size = 0;
    ZiStatus status = apply_relocation_block(image, access, cursor, end, delta, &block_size);
    if (ZiFailed(status)) {
      return status;
    }
    cursor += block_size;
  }
  if (cursor != end) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_pe_find_export(const ZiPeImage* image,
                           const ZiPeImageAccess* access,
                           const char* symbol_name,
                           size_t symbol_name_size,
                           uint32_t* out_relative_address) {
  if (image == NULL || !access_is_valid(access, false) || symbol_name == NULL ||
      symbol_name_size == 0 || symbol_name_size > ZI_PE_SYMBOL_NAME_LIMIT ||
      out_relative_address == NULL || !zi_pe_has_exports(image)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint32_t directory = image->export_directory.virtual_address;
  if (image->export_directory.size < PE_EXPORT_DIRECTORY_SIZE ||
      !range_is_valid(directory, PE_EXPORT_DIRECTORY_SIZE, image->image_size)) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  uint32_t function_count = 0;
  uint32_t name_count = 0;
  uint32_t function_table = 0;
  uint32_t name_table = 0;
  uint32_t ordinal_table = 0;
  ZiStatus status = access_read_u32(image, access, directory + 20u, &function_count);
  if (ZiSucceeded(status)) {
    status = access_read_u32(image, access, directory + 24u, &name_count);
  }
  if (ZiSucceeded(status)) {
    status = access_read_u32(image, access, directory + 28u, &function_table);
  }
  if (ZiSucceeded(status)) {
    status = access_read_u32(image, access, directory + 32u, &name_table);
  }
  if (ZiSucceeded(status)) {
    status = access_read_u32(image, access, directory + 36u, &ordinal_table);
  }
  if (ZiFailed(status)) {
    return status;
  }
  if (function_count == 0 || function_count > PE_EXPORT_ENTRY_LIMIT ||
      name_count > function_count || name_count > PE_EXPORT_ENTRY_LIMIT ||
      !range_is_valid(function_table, (size_t)function_count * 4u, image->image_size) ||
      !range_is_valid(name_table, (size_t)name_count * 4u, image->image_size) ||
      !range_is_valid(ordinal_table, (size_t)name_count * 2u, image->image_size)) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }

  char candidate[ZI_PE_SYMBOL_NAME_LIMIT + 1u] = {0};
  for (uint32_t index = 0; index < name_count; ++index) {
    uint32_t name_relative_address = 0;
    status = access_read_u32(image, access, name_table + (index * 4u), &name_relative_address);
    size_t candidate_size = 0;
    if (ZiSucceeded(status)) {
      status = access_read_string(image,
                                  access,
                                  name_relative_address,
                                  candidate,
                                  sizeof candidate,
                                  &candidate_size);
    }
    if (ZiFailed(status)) {
      return status;
    }
    if (candidate_size != symbol_name_size ||
        !bytes_equal(candidate, symbol_name, symbol_name_size)) {
      continue;
    }
    uint16_t ordinal_index = 0;
    status = access_read_u16(image, access, ordinal_table + (index * 2u), &ordinal_index);
    if (ZiFailed(status) || ordinal_index >= function_count) {
      return ZI_STATUS_BAD_IMAGE_FORMAT;
    }
    return export_function_by_index(image,
                                    access,
                                    function_table,
                                    function_count,
                                    ordinal_index,
                                    out_relative_address);
  }
  return ZI_STATUS_NOT_FOUND;
}

ZiStatus zi_pe_find_export_by_ordinal(const ZiPeImage* image,
                                      const ZiPeImageAccess* access,
                                      uint16_t ordinal,
                                      uint32_t* out_relative_address) {
  if (image == NULL || !access_is_valid(access, false) || out_relative_address == NULL ||
      !zi_pe_has_exports(image)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint32_t directory = image->export_directory.virtual_address;
  if (image->export_directory.size < PE_EXPORT_DIRECTORY_SIZE ||
      !range_is_valid(directory, PE_EXPORT_DIRECTORY_SIZE, image->image_size)) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  uint32_t ordinal_base = 0;
  uint32_t function_count = 0;
  uint32_t function_table = 0;
  ZiStatus status = access_read_u32(image, access, directory + 16u, &ordinal_base);
  if (ZiSucceeded(status)) {
    status = access_read_u32(image, access, directory + 20u, &function_count);
  }
  if (ZiSucceeded(status)) {
    status = access_read_u32(image, access, directory + 28u, &function_table);
  }
  if (ZiFailed(status)) {
    return status;
  }
  if (function_count == 0 || function_count > PE_EXPORT_ENTRY_LIMIT || ordinal < ordinal_base ||
      (uint32_t)ordinal - ordinal_base >= function_count ||
      !range_is_valid(function_table, (size_t)function_count * 4u, image->image_size)) {
    return ZI_STATUS_NOT_FOUND;
  }
  return export_function_by_index(image,
                                  access,
                                  function_table,
                                  function_count,
                                  (uint32_t)ordinal - ordinal_base,
                                  out_relative_address);
}

ZiStatus zi_pe_resolve_imports(const ZiPeImage* image,
                               const ZiPeImageAccess* access,
                               const ZiPeImportResolver* resolver) {
  if (image == NULL || !access_is_valid(access, true) || resolver == NULL ||
      resolver->struct_size != sizeof *resolver ||
      resolver->version != ZI_PE_IMPORT_RESOLVER_VERSION || resolver->resolve == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (!zi_pe_has_imports(image)) {
    return ZI_STATUS_SUCCESS;
  }
  ZiPeDataDirectory directory = image->import_directory;
  if (directory.size < PE_IMPORT_DESCRIPTOR_SIZE * 2u ||
      directory.size % PE_IMPORT_DESCRIPTOR_SIZE != 0) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  size_t descriptor_capacity = directory.size / PE_IMPORT_DESCRIPTOR_SIZE;
  if (descriptor_capacity == 0 || descriptor_capacity > PE_IMPORT_DESCRIPTOR_LIMIT) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }

  char module_name[ZI_PE_MODULE_NAME_LIMIT + 1u] = {0};
  char symbol_name[ZI_PE_SYMBOL_NAME_LIMIT + 1u] = {0};
  for (size_t descriptor_index = 0; descriptor_index < descriptor_capacity; ++descriptor_index) {
    uint32_t descriptor_address =
        directory.virtual_address + (uint32_t)(descriptor_index * PE_IMPORT_DESCRIPTOR_SIZE);
    PeImportDescriptor descriptor = {0};
    ZiStatus status = read_import_descriptor(image, access, descriptor_address, &descriptor);
    if (ZiFailed(status)) {
      return status;
    }
    if (import_descriptor_is_null(&descriptor)) {
      return ZI_STATUS_SUCCESS;
    }
    if (descriptor.name_relative_address == 0 || descriptor.first_thunk == 0) {
      return ZI_STATUS_BAD_IMAGE_FORMAT;
    }
    uint32_t lookup_thunk = descriptor.original_thunk;
    if (lookup_thunk == 0) {
      lookup_thunk = descriptor.first_thunk;
    }
    size_t module_name_size = 0;
    status = access_read_string(image,
                                access,
                                descriptor.name_relative_address,
                                module_name,
                                sizeof module_name,
                                &module_name_size);
    if (ZiFailed(status) || module_name_size == 0) {
      return ZI_STATUS_BAD_IMAGE_FORMAT;
    }
    PeImportBindingContext binding = {
        image,
        access,
        resolver,
        module_name,
        module_name_size,
        symbol_name,
        sizeof symbol_name,
    };
    status = resolve_import_thunks(&binding, lookup_thunk, descriptor.first_thunk);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_BAD_IMAGE_FORMAT;
}

static ZiStatus apply_relocation_block(const ZiPeImage* image,
                                       const ZiPeImageAccess* access,
                                       uint32_t cursor,
                                       uint32_t end,
                                       uint64_t delta,
                                       uint32_t* out_block_size) {
  if (out_block_size == NULL || !range_is_valid(cursor, 8, end)) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  uint32_t page_rva = 0;
  uint32_t block_size = 0;
  ZiStatus status = access_read_u32(image, access, cursor, &page_rva);
  if (ZiSucceeded(status)) {
    status = access_read_u32(image, access, cursor + 4u, &block_size);
  }
  if (ZiFailed(status)) {
    return status;
  }
  if (block_size < 8u || (block_size & 1u) != 0 || block_size > end - cursor) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }

  size_t entry_count = (block_size - 8u) / 2u;
  for (size_t index = 0; index < entry_count; ++index) {
    uint16_t entry = 0;
    status = access_read_u16(image, access, cursor + 8u + (uint32_t)(index * 2u), &entry);
    if (ZiFailed(status)) {
      return status;
    }
    uint16_t type = entry >> 12;
    uint32_t offset = entry & UINT16_C(0x0fff);
    if (type == ZI_PE_RELOCATION_ABSOLUTE) {
      continue;
    }
    if (type != ZI_PE_RELOCATION_DIR64 || page_rva > UINT32_MAX - offset) {
      return ZI_STATUS_IMAGE_RELOCATION_FAILED;
    }
    uint32_t target_rva = page_rva + offset;
    if (!range_is_valid(target_rva, sizeof(uint64_t), image->image_size)) {
      return ZI_STATUS_BAD_IMAGE_FORMAT;
    }
    uint64_t value = 0;
    status = access_read_u64(image, access, target_rva, &value);
    if (ZiSucceeded(status)) {
      status = access_write_u64(image, access, target_rva, value + delta);
    }
    if (ZiFailed(status)) {
      return status;
    }
  }
  *out_block_size = block_size;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus read_import_descriptor(const ZiPeImage* image,
                                       const ZiPeImageAccess* access,
                                       uint32_t relative_address,
                                       PeImportDescriptor* out_descriptor) {
  if (out_descriptor == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status =
      access_read_u32(image, access, relative_address, &out_descriptor->original_thunk);
  if (ZiSucceeded(status)) {
    status = access_read_u32(image, access, relative_address + 4u, &out_descriptor->time_stamp);
  }
  if (ZiSucceeded(status)) {
    status =
        access_read_u32(image, access, relative_address + 8u, &out_descriptor->forwarder_chain);
  }
  if (ZiSucceeded(status)) {
    status = access_read_u32(image,
                             access,
                             relative_address + 12u,
                             &out_descriptor->name_relative_address);
  }
  if (ZiSucceeded(status)) {
    status = access_read_u32(image, access, relative_address + 16u, &out_descriptor->first_thunk);
  }
  return status;
}

static bool import_descriptor_is_null(const PeImportDescriptor* descriptor) {
  return (bool)(descriptor != NULL && descriptor->original_thunk == 0 &&
                descriptor->time_stamp == 0 && descriptor->forwarder_chain == 0 &&
                descriptor->name_relative_address == 0 && descriptor->first_thunk == 0);
}

static ZiStatus resolve_import_lookup(const PeImportBindingContext* context,
                                      uint64_t lookup,
                                      uint64_t* out_address) {
  if (context == NULL || out_address == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  bool is_ordinal = (lookup & PE_IMPORT_ORDINAL_FLAG) != 0;
  uint16_t ordinal = 0;
  size_t symbol_name_size = 0;
  if (is_ordinal) {
    if ((lookup & ~(PE_IMPORT_ORDINAL_FLAG | UINT64_C(0xffff))) != 0) {
      return ZI_STATUS_BAD_IMAGE_FORMAT;
    }
    ordinal = (uint16_t)lookup;
  } else {
    if (lookup > UINT32_MAX - 2u) {
      return ZI_STATUS_BAD_IMAGE_FORMAT;
    }
    ZiStatus status = access_read_string(context->image,
                                         context->access,
                                         (uint32_t)lookup + 2u,
                                         context->symbol_name,
                                         context->symbol_name_capacity,
                                         &symbol_name_size);
    if (ZiFailed(status) || symbol_name_size == 0) {
      return ZI_STATUS_BAD_IMAGE_FORMAT;
    }
  }
  ZiStatus status = context->resolver->resolve(context->resolver->context,
                                               context->module_name,
                                               context->module_name_size,
                                               context->symbol_name,
                                               symbol_name_size,
                                               ordinal,
                                               is_ordinal,
                                               out_address);
  if (ZiFailed(status)) {
    return status;
  }
  if (*out_address == 0) {
    return ZI_STATUS_IMAGE_IMPORT_NOT_FOUND;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus resolve_import_thunks(const PeImportBindingContext* context,
                                      uint32_t lookup_thunk,
                                      uint32_t first_thunk) {
  if (context == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  for (uint32_t thunk_index = 0; thunk_index < PE_IMPORT_THUNK_LIMIT; ++thunk_index) {
    uint32_t offset = thunk_index * 8u;
    if (lookup_thunk > UINT32_MAX - offset || first_thunk > UINT32_MAX - offset) {
      return ZI_STATUS_BAD_IMAGE_FORMAT;
    }
    uint32_t lookup_address = lookup_thunk + offset;
    uint32_t write_address = first_thunk + offset;
    uint64_t lookup = 0;
    ZiStatus status = access_read_u64(context->image, context->access, lookup_address, &lookup);
    if (ZiFailed(status)) {
      return status;
    }
    if (lookup == 0) {
      return ZI_STATUS_SUCCESS;
    }
    uint64_t resolved_address = 0;
    status = resolve_import_lookup(context, lookup, &resolved_address);
    if (ZiFailed(status)) {
      return status;
    }
    status = access_write_u64(context->image, context->access, write_address, resolved_address);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_BAD_IMAGE_FORMAT;
}

static bool access_is_valid(const ZiPeImageAccess* access, bool needs_write) {
  return (bool)(access != NULL && access->struct_size == sizeof *access &&
                access->version == ZI_PE_IMAGE_ACCESS_VERSION && access->read != NULL &&
                (!needs_write || access->write != NULL));
}

static ZiStatus access_read(const ZiPeImage* image,
                            const ZiPeImageAccess* access,
                            uint32_t relative_address,
                            void* output,
                            size_t output_size) {
  if (image == NULL || !access_is_valid(access, false) || output == NULL || output_size == 0 ||
      !range_is_valid(relative_address, output_size, image->image_size)) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  return access->read(access->context, relative_address, output, output_size);
}

static ZiStatus access_write(const ZiPeImage* image,
                             const ZiPeImageAccess* access,
                             uint32_t relative_address,
                             const void* data,
                             size_t data_size) {
  if (image == NULL || !access_is_valid(access, true) || data == NULL || data_size == 0 ||
      !range_is_valid(relative_address, data_size, image->image_size)) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  return access->write(access->context, relative_address, data, data_size);
}

static ZiStatus access_read_u16(const ZiPeImage* image,
                                const ZiPeImageAccess* access,
                                uint32_t relative_address,
                                uint16_t* out_value) {
  if (out_value == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char bytes[2] = {0};
  ZiStatus status = access_read(image, access, relative_address, bytes, sizeof bytes);
  if (ZiSucceeded(status)) {
    *out_value = zi_read_u16_le(bytes);
  }
  return status;
}

static ZiStatus access_read_u32(const ZiPeImage* image,
                                const ZiPeImageAccess* access,
                                uint32_t relative_address,
                                uint32_t* out_value) {
  if (out_value == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char bytes[4] = {0};
  ZiStatus status = access_read(image, access, relative_address, bytes, sizeof bytes);
  if (ZiSucceeded(status)) {
    *out_value = zi_read_u32_le(bytes);
  }
  return status;
}

static ZiStatus access_read_u64(const ZiPeImage* image,
                                const ZiPeImageAccess* access,
                                uint32_t relative_address,
                                uint64_t* out_value) {
  if (out_value == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char bytes[8] = {0};
  ZiStatus status = access_read(image, access, relative_address, bytes, sizeof bytes);
  if (ZiSucceeded(status)) {
    *out_value = zi_read_u64_le(bytes);
  }
  return status;
}

static ZiStatus access_write_u64(const ZiPeImage* image,
                                 const ZiPeImageAccess* access,
                                 uint32_t relative_address,
                                 uint64_t value) {
  unsigned char bytes[8] = {0};
  zi_write_u64_le(bytes, value);
  return access_write(image, access, relative_address, bytes, sizeof bytes);
}

static ZiStatus access_read_string(const ZiPeImage* image,
                                   const ZiPeImageAccess* access,
                                   uint32_t relative_address,
                                   char* output,
                                   size_t output_capacity,
                                   size_t* out_size) {
  if (image == NULL || output == NULL || output_capacity < 2 || out_size == NULL ||
      relative_address >= image->image_size) {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  size_t maximum = image->image_size - relative_address;
  if (maximum >= output_capacity) {
    maximum = output_capacity - 1u;
  }
  for (size_t index = 0; index < maximum; ++index) {
    ZiStatus status =
        access_read(image, access, relative_address + (uint32_t)index, &output[index], 1);
    if (ZiFailed(status)) {
      return status;
    }
    if (output[index] == '\0') {
      *out_size = index;
      return ZI_STATUS_SUCCESS;
    }
  }
  output[0] = '\0';
  return ZI_STATUS_BAD_IMAGE_FORMAT;
}

static ZiStatus
memory_access_read(void* context, uint32_t relative_address, void* output, size_t output_size) {
  PeMemoryAccess* memory = context;
  if (memory == NULL || memory->data == NULL || output == NULL ||
      !range_is_valid(relative_address, output_size, memory->size)) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  zi_memory_copy(output, memory->data + relative_address, output_size);
  return ZI_STATUS_SUCCESS;
}

static ZiStatus
memory_access_write(void* context, uint32_t relative_address, const void* data, size_t data_size) {
  PeMemoryAccess* memory = context;
  if (memory == NULL || memory->data == NULL || data == NULL ||
      !range_is_valid(relative_address, data_size, memory->size)) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  zi_memory_copy(memory->data + relative_address, data, data_size);
  return ZI_STATUS_SUCCESS;
}

static bool bytes_equal(const char* left, const char* right, size_t size) {
  for (size_t index = 0; index < size; ++index) {
    if (left[index] != right[index]) {
      return false;
    }
  }
  return true;
}

static ZiStatus export_function_by_index(const ZiPeImage* image,
                                         const ZiPeImageAccess* access,
                                         uint32_t function_table,
                                         uint32_t function_count,
                                         uint32_t function_index,
                                         uint32_t* out_relative_address) {
  if (function_index >= function_count || out_relative_address == NULL) {
    return ZI_STATUS_NOT_FOUND;
  }
  uint32_t function_relative_address = 0;
  ZiStatus status = access_read_u32(image,
                                    access,
                                    function_table + (function_index * 4u),
                                    &function_relative_address);
  if (ZiFailed(status)) {
    return status;
  }
  uint32_t export_start = image->export_directory.virtual_address;
  uint32_t export_end = export_start + image->export_directory.size;
  if (function_relative_address == 0 || function_relative_address >= image->image_size) {
    return ZI_STATUS_NOT_FOUND;
  }
  if (function_relative_address >= export_start && function_relative_address < export_end) {
    return ZI_STATUS_NOT_IMPLEMENTED;
  }
  *out_relative_address = function_relative_address;
  return ZI_STATUS_SUCCESS;
}

static bool range_is_valid(size_t offset, size_t length, size_t total_size) {
  return (bool)(offset <= total_size && length <= total_size - offset);
}

static bool virtual_range_is_valid(uint32_t address, uint32_t size, uint32_t image_size) {
  if ((address == 0) != (size == 0)) {
    return false;
  }
  return (bool)(address == 0 || (address <= image_size && size <= image_size - address));
}

static bool directories_are_valid(const ZiPeImage* image) {
  bool export_shape_is_valid = (bool)(image->export_directory.size == 0 ||
                                      image->export_directory.size >= PE_EXPORT_DIRECTORY_SIZE);
  bool import_shape_is_valid =
      (bool)(image->import_directory.size == 0 ||
             (image->import_directory.size >= PE_IMPORT_DESCRIPTOR_SIZE * 2u &&
              image->import_directory.size % PE_IMPORT_DESCRIPTOR_SIZE == 0));
  return (bool)(export_shape_is_valid && import_shape_is_valid &&
                virtual_range_is_valid(image->export_directory.virtual_address,
                                       image->export_directory.size,
                                       image->image_size) &&
                virtual_range_is_valid(image->import_directory.virtual_address,
                                       image->import_directory.size,
                                       image->image_size) &&
                virtual_range_is_valid(image->relocation_directory.virtual_address,
                                       image->relocation_directory.size,
                                       image->image_size));
}

static bool sections_are_disjoint(const ZiPeSection* sections, uint16_t section_count) {
  for (uint16_t left_index = 0; left_index < section_count; ++left_index) {
    const ZiPeSection* left = &sections[left_index];
    uint32_t left_size = left->virtual_size > left->raw_size ? left->virtual_size : left->raw_size;
    for (uint16_t right_index = left_index + 1u; right_index < section_count; ++right_index) {
      const ZiPeSection* right = &sections[right_index];
      uint32_t right_size =
          right->virtual_size > right->raw_size ? right->virtual_size : right->raw_size;
      if (left_size != 0 && right_size != 0 &&
          left->virtual_address < right->virtual_address + right_size &&
          right->virtual_address < left->virtual_address + left_size) {
        return false;
      }
    }
  }
  return true;
}

static ZiPeDataDirectory read_directory(const unsigned char* optional_header,
                                        size_t optional_size,
                                        uint32_t directory_count,
                                        uint32_t index) {
  ZiPeDataDirectory directory = {0};
  size_t offset = 112u + ((size_t)index * 8u);
  if (index >= directory_count || !range_is_valid(offset, 8, optional_size)) {
    return directory;
  }
  directory.virtual_address = zi_read_u32_le(optional_header + offset);
  directory.size = zi_read_u32_le(optional_header + offset + 4);
  return directory;
}
