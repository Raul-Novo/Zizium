// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "phase3_tests.h"
#include "zi/byte_order.h"
#include "zi/pe.h"
#include "zizium/status.h"

#define PE_TEST_BUFFER_SIZE 0x2000u

typedef struct PeTestMemory {
  unsigned char data[PE_TEST_BUFFER_SIZE];
} PeTestMemory;

typedef struct PeResolvedSymbol {
  const char* module_name;
  size_t module_name_size;
  const char* symbol_name;
  size_t symbol_name_size;
  uint16_t ordinal;
  bool is_ordinal;
  uint64_t address;
  size_t call_count;
} PeResolvedSymbol;

#define PHASE3_ASSERT(expression)                                                                  \
  do {                                                                                             \
    ++assertions;                                                                                  \
    if (!(expression)) {                                                                           \
      (void)fprintf_s(stderr, "%s:%d: assertion failed: %s\n", __FILE__, __LINE__, #expression);   \
      *out_assertion_count = assertions;                                                           \
      return false;                                                                                \
    }                                                                                              \
  } while (false)

static ZiStatus
pe_test_read(void* context, uint32_t relative_address, void* output, size_t output_size);
static ZiStatus
pe_test_write(void* context, uint32_t relative_address, const void* data, size_t data_size);
static ZiStatus pe_test_resolve(void* context,
                                const char* module_name,
                                size_t module_name_size,
                                const char* symbol_name,
                                size_t symbol_name_size,
                                uint16_t ordinal,
                                bool is_ordinal,
                                uint64_t* out_address);
static void create_export_fixture(PeTestMemory* memory, ZiPeImage* image);
static void create_import_fixture(PeTestMemory* memory, ZiPeImage* image);
static bool bytes_equal(const char* left, const char* right, size_t size);

// Export/import tables are hostile binary contracts, so positive and malformed forms stay paired.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
bool phase3_pe_linking_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  size_t assertions = 0;
  *out_assertion_count = 0;
  PeTestMemory export_memory = {0};
  ZiPeImage export_image = {0};
  create_export_fixture(&export_memory, &export_image);
  ZiPeImageAccess export_access = {
      sizeof(ZiPeImageAccess),
      ZI_PE_IMAGE_ACCESS_VERSION,
      &export_memory,
      pe_test_read,
      pe_test_write,
  };
  uint32_t relative_address = 0;
  PHASE3_ASSERT(ZiSucceeded(zi_pe_find_export(&export_image,
                                              &export_access,
                                              "ZiExample",
                                              sizeof "ZiExample" - 1u,
                                              &relative_address)));
  PHASE3_ASSERT(relative_address == UINT32_C(0x1000));
  PHASE3_ASSERT(ZiSucceeded(
      zi_pe_find_export_by_ordinal(&export_image, &export_access, 21, &relative_address)));
  PHASE3_ASSERT(relative_address == UINT32_C(0x1000));
  PHASE3_ASSERT(zi_pe_find_export(&export_image,
                                  &export_access,
                                  "ziexample",
                                  sizeof "ziexample" - 1u,
                                  &relative_address) == ZI_STATUS_NOT_FOUND);
  PHASE3_ASSERT(
      zi_pe_find_export_by_ordinal(&export_image, &export_access, 22, &relative_address) ==
      ZI_STATUS_NOT_FOUND);
  zi_write_u32_le(export_memory.data + 0x300, 0x250);
  PHASE3_ASSERT(zi_pe_find_export(&export_image,
                                  &export_access,
                                  "ZiExample",
                                  sizeof "ZiExample" - 1u,
                                  &relative_address) == ZI_STATUS_NOT_IMPLEMENTED);
  export_image.export_directory.size = 20;
  PHASE3_ASSERT(zi_pe_find_export(&export_image,
                                  &export_access,
                                  "ZiExample",
                                  sizeof "ZiExample" - 1u,
                                  &relative_address) == ZI_STATUS_BAD_IMAGE_FORMAT);

  PeTestMemory import_memory = {0};
  ZiPeImage import_image = {0};
  create_import_fixture(&import_memory, &import_image);
  ZiPeImageAccess import_access = {
      sizeof(ZiPeImageAccess),
      ZI_PE_IMAGE_ACCESS_VERSION,
      &import_memory,
      pe_test_read,
      pe_test_write,
  };
  PeResolvedSymbol expected = {
      "zx.dll",
      sizeof "zx.dll" - 1u,
      "ZxDebugWrite",
      sizeof "ZxDebugWrite" - 1u,
      0,
      false,
      UINT64_C(0x180001021),
      0,
  };
  ZiPeImportResolver resolver = {
      sizeof(ZiPeImportResolver),
      ZI_PE_IMPORT_RESOLVER_VERSION,
      &expected,
      pe_test_resolve,
  };
  PHASE3_ASSERT(ZiSucceeded(zi_pe_resolve_imports(&import_image, &import_access, &resolver)));
  PHASE3_ASSERT(expected.call_count == 1);
  PHASE3_ASSERT(zi_read_u64_le(import_memory.data + 0x380) == expected.address);

  create_import_fixture(&import_memory, &import_image);
  zi_write_u64_le(import_memory.data + 0x360, UINT64_C(0x8000000000000015));
  expected.is_ordinal = true;
  expected.ordinal = 21;
  expected.call_count = 0;
  expected.address = UINT64_C(0x180001000);
  PHASE3_ASSERT(ZiSucceeded(zi_pe_resolve_imports(&import_image, &import_access, &resolver)));
  PHASE3_ASSERT(expected.call_count == 1 &&
                zi_read_u64_le(import_memory.data + 0x380) == expected.address);

  create_import_fixture(&import_memory, &import_image);
  expected.is_ordinal = false;
  expected.ordinal = 0;
  expected.call_count = 0;
  expected.address = 0;
  PHASE3_ASSERT(zi_pe_resolve_imports(&import_image, &import_access, &resolver) ==
                ZI_STATUS_IMAGE_IMPORT_NOT_FOUND);
  create_import_fixture(&import_memory, &import_image);
  import_image.import_directory.size = 20;
  PHASE3_ASSERT(zi_pe_resolve_imports(&import_image, &import_access, &resolver) ==
                ZI_STATUS_BAD_IMAGE_FORMAT);
  create_import_fixture(&import_memory, &import_image);
  zi_write_u32_le(import_memory.data + 0x200 + 12u, 0);
  PHASE3_ASSERT(zi_pe_resolve_imports(&import_image, &import_access, &resolver) ==
                ZI_STATUS_BAD_IMAGE_FORMAT);
  create_import_fixture(&import_memory, &import_image);
  zi_write_u64_le(import_memory.data + 0x360, UINT64_C(0x8001000000000015));
  PHASE3_ASSERT(zi_pe_resolve_imports(&import_image, &import_access, &resolver) ==
                ZI_STATUS_BAD_IMAGE_FORMAT);
  create_import_fixture(&import_memory, &import_image);
  import_memory.data[0x3a2] = 'X';
  for (size_t index = 0x3a3; index < PE_TEST_BUFFER_SIZE; ++index) {
    import_memory.data[index] = 'Y';
  }
  PHASE3_ASSERT(zi_pe_resolve_imports(&import_image, &import_access, &resolver) ==
                ZI_STATUS_BAD_IMAGE_FORMAT);

  *out_assertion_count = assertions;
  return true;
}

static ZiStatus
pe_test_read(void* context, uint32_t relative_address, void* output, size_t output_size) {
  PeTestMemory* memory = context;
  if (memory == NULL || output == NULL || output_size == 0 ||
      relative_address > PE_TEST_BUFFER_SIZE ||
      output_size > PE_TEST_BUFFER_SIZE - relative_address) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  zi_memory_copy(output, memory->data + relative_address, output_size);
  return ZI_STATUS_SUCCESS;
}

static ZiStatus
pe_test_write(void* context, uint32_t relative_address, const void* data, size_t data_size) {
  PeTestMemory* memory = context;
  if (memory == NULL || data == NULL || data_size == 0 || relative_address > PE_TEST_BUFFER_SIZE ||
      data_size > PE_TEST_BUFFER_SIZE - relative_address) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  zi_memory_copy(memory->data + relative_address, data, data_size);
  return ZI_STATUS_SUCCESS;
}

// The import-resolver callback shape is a public PE contract with eight parameters.
// NOLINTNEXTLINE(readability-function-size)
static ZiStatus pe_test_resolve(void* context,
                                const char* module_name,
                                size_t module_name_size,
                                const char* symbol_name,
                                size_t symbol_name_size,
                                uint16_t ordinal,
                                bool is_ordinal,
                                uint64_t* out_address) {
  PeResolvedSymbol* expected = context;
  if (expected == NULL || module_name == NULL || out_address == NULL ||
      module_name_size != expected->module_name_size ||
      !bytes_equal(module_name, expected->module_name, module_name_size) ||
      is_ordinal != expected->is_ordinal) {
    return ZI_STATUS_IMAGE_IMPORT_NOT_FOUND;
  }
  if (is_ordinal) {
    if (ordinal != expected->ordinal) {
      return ZI_STATUS_IMAGE_IMPORT_NOT_FOUND;
    }
  } else if (symbol_name == NULL || symbol_name_size != expected->symbol_name_size ||
             !bytes_equal(symbol_name, expected->symbol_name, symbol_name_size)) {
    return ZI_STATUS_IMAGE_IMPORT_NOT_FOUND;
  }
  ++expected->call_count;
  *out_address = expected->address;
  return ZI_STATUS_SUCCESS;
}

static void create_export_fixture(PeTestMemory* memory, ZiPeImage* image) {
  zi_memory_zero(memory, sizeof *memory);
  zi_memory_zero(image, sizeof *image);
  image->image_size = PE_TEST_BUFFER_SIZE;
  image->export_directory.virtual_address = UINT32_C(0x200);
  image->export_directory.size = UINT32_C(0x100);
  zi_write_u32_le(memory->data + 0x200 + 16u, 21);
  zi_write_u32_le(memory->data + 0x200 + 20u, 1);
  zi_write_u32_le(memory->data + 0x200 + 24u, 1);
  zi_write_u32_le(memory->data + 0x200 + 28u, 0x300);
  zi_write_u32_le(memory->data + 0x200 + 32u, 0x320);
  zi_write_u32_le(memory->data + 0x200 + 36u, 0x340);
  zi_write_u32_le(memory->data + 0x300, 0x1000);
  zi_write_u32_le(memory->data + 0x320, 0x350);
  zi_write_u16_le(memory->data + 0x340, 0);
  zi_memory_copy(memory->data + 0x350, "ZiExample", sizeof "ZiExample");
}

static void create_import_fixture(PeTestMemory* memory, ZiPeImage* image) {
  zi_memory_zero(memory, sizeof *memory);
  zi_memory_zero(image, sizeof *image);
  image->image_size = PE_TEST_BUFFER_SIZE;
  image->import_directory.virtual_address = UINT32_C(0x200);
  image->import_directory.size = 40;
  zi_write_u32_le(memory->data + 0x200, 0x360);
  zi_write_u32_le(memory->data + 0x200 + 12u, 0x340);
  zi_write_u32_le(memory->data + 0x200 + 16u, 0x380);
  zi_memory_copy(memory->data + 0x340, "zx.dll", sizeof "zx.dll");
  zi_write_u64_le(memory->data + 0x360, 0x3a0);
  zi_write_u64_le(memory->data + 0x368, 0);
  zi_write_u64_le(memory->data + 0x380, 0x3a0);
  zi_write_u64_le(memory->data + 0x388, 0);
  zi_write_u16_le(memory->data + 0x3a0, 0);
  zi_memory_copy(memory->data + 0x3a2, "ZxDebugWrite", sizeof "ZxDebugWrite");
}

static bool bytes_equal(const char* left, const char* right, size_t size) {
  if (left == NULL || right == NULL) {
    return false;
  }
  for (size_t index = 0; index < size; ++index) {
    if (left[index] != right[index]) {
      return false;
    }
  }
  return true;
}
