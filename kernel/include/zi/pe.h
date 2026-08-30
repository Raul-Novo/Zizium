// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"

#define ZI_PE_MACHINE_AMD64 UINT16_C(0x8664)
#define ZI_PE_OPTIONAL_MAGIC_PE32_PLUS UINT16_C(0x020b)
#define ZI_PE_SUBSYSTEM_NATIVE UINT16_C(1)
#define ZI_PE_SUBSYSTEM_EFI_APPLICATION UINT16_C(10)
#define ZI_PE_SECTION_EXECUTE UINT32_C(0x20000000)
#define ZI_PE_SECTION_READ UINT32_C(0x40000000)
#define ZI_PE_SECTION_WRITE UINT32_C(0x80000000)
#define ZI_PE_CHARACTERISTIC_DLL UINT16_C(0x2000)
#define ZI_PE_RELOCATION_ABSOLUTE UINT16_C(0)
#define ZI_PE_RELOCATION_DIR64 UINT16_C(10)
#define ZI_PE_IMAGE_ACCESS_VERSION 1u
#define ZI_PE_IMPORT_RESOLVER_VERSION 1u
#define ZI_PE_MODULE_NAME_LIMIT 63u
#define ZI_PE_SYMBOL_NAME_LIMIT 127u

typedef struct ZiPeDataDirectory {
  uint32_t virtual_address;
  uint32_t size;
} ZiPeDataDirectory;

typedef struct ZiPeSection {
  char name[9];
  uint32_t virtual_size;
  uint32_t virtual_address;
  uint32_t raw_size;
  uint32_t raw_offset;
  uint32_t characteristics;
} ZiPeSection;

typedef struct ZiPeImage {
  uint16_t machine;
  uint16_t section_count;
  uint16_t characteristics;
  uint16_t subsystem;
  uint32_t entry_point_rva;
  uint32_t section_alignment;
  uint32_t file_alignment;
  uint32_t image_size;
  uint32_t header_size;
  uint64_t image_base;
  ZiPeDataDirectory export_directory;
  ZiPeDataDirectory import_directory;
  ZiPeDataDirectory relocation_directory;
  ZiPeSection* sections;
  const unsigned char* file_data;
  size_t file_size;
} ZiPeImage;

typedef ZiStatus (*ZiPeImageRead)(void* context,
                                  uint32_t relative_address,
                                  void* output,
                                  size_t output_size);
typedef ZiStatus (*ZiPeImageWrite)(void* context,
                                   uint32_t relative_address,
                                   const void* data,
                                   size_t data_size);

typedef struct ZiPeImageAccess {
  uint32_t struct_size;
  uint32_t version;
  void* context;
  ZiPeImageRead read;
  ZiPeImageWrite write;
} ZiPeImageAccess;

typedef ZiStatus (*ZiPeImportResolve)(void* context,
                                      const char* module_name,
                                      size_t module_name_size,
                                      const char* symbol_name,
                                      size_t symbol_name_size,
                                      uint16_t ordinal,
                                      bool is_ordinal,
                                      uint64_t* out_address);

typedef struct ZiPeImportResolver {
  uint32_t struct_size;
  uint32_t version;
  void* context;
  ZiPeImportResolve resolve;
} ZiPeImportResolver;

ZiStatus zi_pe_parse(const void* data,
                     size_t data_size,
                     ZiPeSection* section_storage,
                     size_t section_capacity,
                     ZiPeImage* out_image);
bool zi_pe_has_imports(const ZiPeImage* image);
bool zi_pe_has_exports(const ZiPeImage* image);
ZiStatus zi_pe_map_image(const ZiPeImage* image, void* destination, size_t destination_size);
ZiStatus zi_pe_apply_relocations(const ZiPeImage* image,
                                 void* mapped_image,
                                 size_t mapped_size,
                                 uint64_t new_image_base);
ZiStatus zi_pe_apply_relocations_with_access(const ZiPeImage* image,
                                             const ZiPeImageAccess* access,
                                             uint64_t new_image_base);
ZiStatus zi_pe_find_export(const ZiPeImage* image,
                           const ZiPeImageAccess* access,
                           const char* symbol_name,
                           size_t symbol_name_size,
                           uint32_t* out_relative_address);
ZiStatus zi_pe_find_export_by_ordinal(const ZiPeImage* image,
                                      const ZiPeImageAccess* access,
                                      uint16_t ordinal,
                                      uint32_t* out_relative_address);
ZiStatus zi_pe_resolve_imports(const ZiPeImage* image,
                               const ZiPeImageAccess* access,
                               const ZiPeImportResolver* resolver);
