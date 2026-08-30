// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "phase3_tests.h"
#include "phase4_tests.h"
#include "phase5_tests.h"
#include "phase6_tests.h"
#include "phase7_tests.h"
#include "zi/address_space.h"
#include "zi/block.h"
#include "zi/boot.h"
#include "zi/byte_order.h"
#include "zi/display.h"
#include "zi/font.h"
#include "zi/luma.h"
#include "zi/memory.h"
#include "zi/object.h"
#include "zi/path.h"
#include "zi/pe.h"
#include "zi/pool.h"
#include "zi/scheduler.h"
#include "zi/security.h"
#include "zi/syscall.h"
#include "zi/terminal.h"
#include "zi/unicode.h"
#include "zi/user_image.h"
#include "zi/x64_descriptor.h"
#include "zi/x64_interrupt.h"
#include "zi/x64_paging.h"
#include "zi/zifs.h"
#include "zi/zifs_security.h"
#include "zizium/status.h"
#include "zizium/theme.h"
#include "zizium/types.h"

#define ARRAY_COUNT(array) (sizeof(array) / sizeof((array)[0]))

typedef bool (*TestRoutine)(void);

typedef struct TestDefinition {
  const char* name;
  TestRoutine routine;
} TestDefinition;

typedef struct MemoryBlockDevice {
  unsigned char* data;
  size_t size;
} MemoryBlockDevice;

#define TEST_PAGE_POOL_CAPACITY 64u

typedef struct TestPagePool {
  uint64_t pages[TEST_PAGE_POOL_CAPACITY][ZI_X64_PAGE_SIZE / sizeof(uint64_t)];
  bool used[TEST_PAGE_POOL_CAPACITY];
  size_t allocation_calls;
  size_t fail_on_call;
} TestPagePool;

static size_t g_assertion_count;
static size_t g_destructor_calls;

static bool test_utf8(void);
static bool test_paths(void);
static bool test_physical_memory(void);
static bool test_pool_and_object_cache(void);
static bool test_x64_paging(void);
static bool test_process_address_space(void);
static bool test_zifs_encoding(void);
static bool test_zifs_mount_and_lookup(void);
static bool test_acl(void);
static bool test_objects(void);
static bool test_x64_architecture(void);
static bool test_syscall_frames(void);
static bool test_scheduler(void);
static bool test_pe(void);
static bool test_terminal(void);
static bool test_display_scale(void);
static bool test_luma(void);
static bool test_phase3_process_parameters(void);
static bool test_phase3_process_lifecycle(void);
static bool test_phase3_pe_linking(void);
static bool test_phase4_object_namespace(void);
static bool test_phase4_handle_table(void);
static bool test_phase4_dispatcher(void);
static bool test_phase4_ipc(void);
static bool test_phase5_acpi(void);
static bool test_phase5_pci(void);
static bool test_phase5_dma(void);
static bool test_phase5_gpt(void);
static bool test_phase5_io(void);
static bool test_phase6_zifs_files(void);
static bool test_phase6_service_manifests(void);
static bool test_phase7_zifs_wire(void);
static bool test_phase7_zifs_security(void);
static ZiStatus memory_read_blocks(void* context,
                                   uint64_t first_block,
                                   uint32_t block_count,
                                   void* output,
                                   size_t output_size);
static ZiStatus test_page_allocate(void* context, uint64_t* out_physical_base);
static void test_page_release(void* context, uint64_t physical_base);
static ZiStatus
test_page_pointer(void* context, uint64_t physical_base, size_t size, void** out_pointer);
static ZiStatus test_page_run_allocate(void* context,
                                       uint64_t page_count,
                                       uint32_t owner,
                                       uint64_t* out_physical_base);
static ZiStatus test_page_run_release(void* context,
                                      uint64_t physical_base,
                                      uint64_t page_count,
                                      uint32_t expected_owner);
static size_t test_page_used_count(const TestPagePool* pool);
static void configure_dependency_fixture(unsigned char* image_data,
                                         size_t image_size,
                                         uint64_t image_base,
                                         bool is_library,
                                         const char* dependency_name,
                                         const char* symbol_name);
static bool initialise_test_volume(unsigned char* volume, size_t volume_size);
static bool initialise_test_security_table(void* block, size_t block_size);
static void test_object_destroy(ZiObjectHeader* object);
static bool string_view_equal(ZiStringView view, const char* text, size_t text_size);
static bool assert_true(bool condition, const char* expression, const char* file, int line);

#define TEST_ASSERT(expression)                                                                    \
  do {                                                                                             \
    if (!assert_true((expression), #expression, __FILE__, __LINE__)) {                             \
      return false;                                                                                \
    }                                                                                              \
  } while (false)

int main(void) {
  const TestDefinition tests[] = {
      {"UTF-8 validation and conversion", test_utf8},
      {"case-sensitive paths and spaces", test_paths},
      {"physical memory inventory and allocation", test_physical_memory},
      {"kernel pool and object cache", test_pool_and_object_cache},
      {"x64 page-table mapping and rollback", test_x64_paging},
      {"process address spaces and user copies", test_process_address_space},
      {"ZiFS serialisation", test_zifs_encoding},
      {"ZiFS mount and exact lookup", test_zifs_mount_and_lookup},
      {"ACL access checks", test_acl},
      {"object lifecycle", test_objects},
      {"x64 descriptors and interrupt frames", test_x64_architecture},
      {"x64 syscall frames and return validation", test_syscall_frames},
      {"scheduler priority queues", test_scheduler},
      {"PE/COFF parser", test_pe},
      {"Phase 3 PE imports and exports", test_phase3_pe_linking},
      {"Phase 3 process parameters", test_phase3_process_parameters},
      {"Phase 3 process lifecycle and tokens", test_phase3_process_lifecycle},
      {"Phase 4 object namespace", test_phase4_object_namespace},
      {"Phase 4 generational handle tables", test_phase4_handle_table},
      {"Phase 4 dispatcher waits", test_phase4_dispatcher},
      {"Phase 4 bounded IPC and handle transfer", test_phase4_ipc},
      {"Phase 5 ACPI table discovery", test_phase5_acpi},
      {"Phase 5 PCIe enumeration and matching", test_phase5_pci},
      {"Phase 5 DMA ownership", test_phase5_dma},
      {"Phase 5 GPT and partition blocks", test_phase5_gpt},
      {"Phase 5 I/O request lifecycle", test_phase5_io},
      {"Phase 6 ZiFS bounded file reads", test_phase6_zifs_files},
      {"Phase 6 service manifests and dependency graph", test_phase6_service_manifests},
      {"Phase 7 ZiFS allocation, journal, and staged create", test_phase7_zifs_wire},
      {"Phase 7 ZiFS durable security descriptors", test_phase7_zifs_security},
      {"terminal scrollback and history", test_terminal},
      {"display scaling", test_display_scale},
      {"Luma tokenisation", test_luma},
  };

  size_t passed = 0;
  for (size_t index = 0; index < ARRAY_COUNT(tests); ++index) {
    bool result = tests[index].routine();
    const char* result_name = "FAIL";
    if (result) {
      result_name = "PASS";
      ++passed;
    }
    printf("[%s] %s\n", result_name, tests[index].name);
  }

  printf("%zu/%zu test groups passed; %zu assertions checked.\n",
         passed,
         ARRAY_COUNT(tests),
         g_assertion_count);
  return passed == ARRAY_COUNT(tests) ? 0 : 1;
}

// Assertion macros deliberately make focused test routines appear branch-heavy.
// NOLINTBEGIN(readability-function-cognitive-complexity)
static bool test_utf8(void) {
  const char valid[] = {'A',
                        (char)0xc2,
                        (char)0xa2,
                        (char)0xe2,
                        (char)0x82,
                        (char)0xac,
                        (char)0xf0,
                        (char)0x9f,
                        (char)0x8c,
                        (char)0x8a};
  const char overlong[] = {(char)0xc0, (char)0xaf};
  const char surrogate[] = {(char)0xed, (char)0xa0, (char)0x80};
  const char truncated[] = {(char)0xf0, (char)0x9f, (char)0x8c};
  const char maximum[] = {(char)0xf4, (char)0x8f, (char)0xbf, (char)0xbf};
  const char too_large[] = {(char)0xf4, (char)0x90, (char)0x80, (char)0x80};

  TEST_ASSERT(ZiSucceeded(zi_utf8_validate(valid, sizeof valid)));
  TEST_ASSERT(zi_utf8_validate(overlong, sizeof overlong) == ZI_STATUS_INVALID_ENCODING);
  TEST_ASSERT(zi_utf8_validate(surrogate, sizeof surrogate) == ZI_STATUS_INVALID_ENCODING);
  TEST_ASSERT(zi_utf8_validate(truncated, sizeof truncated) == ZI_STATUS_INVALID_ENCODING);
  TEST_ASSERT(ZiSucceeded(zi_utf8_validate(maximum, sizeof maximum)));
  TEST_ASSERT(zi_utf8_validate(too_large, sizeof too_large) == ZI_STATUS_INVALID_ENCODING);

  ZiUtf8DecodeResult decoded = {0};
  TEST_ASSERT(ZiSucceeded(zi_utf8_decode(maximum, sizeof maximum, &decoded)));
  TEST_ASSERT(decoded.scalar == UINT32_C(0x10ffff));
  TEST_ASSERT(decoded.consumed == 4);

  char encoded[4] = {0};
  size_t encoded_size = 0;
  TEST_ASSERT(ZiSucceeded(
      zi_utf8_encode(ZI_UNICODE_REPLACEMENT_CHARACTER, encoded, sizeof encoded, &encoded_size)));
  TEST_ASSERT(encoded_size == 3);
  TEST_ASSERT((unsigned char)encoded[0] == 0xefu && (unsigned char)encoded[1] == 0xbfu &&
              (unsigned char)encoded[2] == 0xbdu);
  TEST_ASSERT(zi_utf8_encode(UINT32_C(0xd800), encoded, sizeof encoded, &encoded_size) ==
              ZI_STATUS_INVALID_ARGUMENT);

  const char supplementary[] = {(char)0xf0, (char)0x9f, (char)0x8c, (char)0x8a};
  uint16_t utf16[2] = {0};
  size_t utf16_size = 0;
  TEST_ASSERT(ZiSucceeded(zi_utf8_to_utf16(supplementary,
                                           sizeof supplementary,
                                           utf16,
                                           ARRAY_COUNT(utf16),
                                           &utf16_size)));
  TEST_ASSERT(utf16_size == 2 && utf16[0] == 0xd83c && utf16[1] == 0xdf0a);
  TEST_ASSERT(zi_utf8_to_utf16(supplementary, sizeof supplementary, utf16, 1, &utf16_size) ==
              ZI_STATUS_BUFFER_TOO_SMALL);
  TEST_ASSERT(zi_unicode_is_combining(UINT32_C(0x0301)));
  TEST_ASSERT(zi_unicode_cell_width(UINT32_C(0x754c)) == 2);
  return true;
}

static bool test_paths(void) {
  const char path[] = "C:\\Users\\Raul\\My Projects\\hello.c";
  ZiStringView components[8] = {0};
  ZiParsedPath parsed = {0};
  TEST_ASSERT(ZiSucceeded(
      zi_path_parse_absolute(path, sizeof path - 1, components, ARRAY_COUNT(components), &parsed)));
  TEST_ASSERT(parsed.drive_letter == 'C' && parsed.component_count == 4);
  TEST_ASSERT(string_view_equal(parsed.components[2], "My Projects", 11));

  ZiStringView upper = {"Temp", 4};
  ZiStringView lower = {"temp", 4};
  int comparison = 0;
  TEST_ASSERT(ZiSucceeded(zi_path_compare_component(upper, lower, &comparison)));
  TEST_ASSERT(comparison != 0);

  const char composed_data[] = {(char)0xc3, (char)0xa9};
  const char decomposed_data[] = {'e', (char)0xcc, (char)0x81};
  ZiStringView composed = {composed_data, sizeof composed_data};
  ZiStringView decomposed = {decomposed_data, sizeof decomposed_data};
  TEST_ASSERT(ZiSucceeded(zi_path_compare_component(composed, decomposed, &comparison)));
  TEST_ASSERT(comparison != 0);

  const char forward_slash[] = "C:/Temp";
  TEST_ASSERT(zi_path_parse_absolute(forward_slash,
                                     sizeof forward_slash - 1,
                                     components,
                                     ARRAY_COUNT(components),
                                     &parsed) == ZI_STATUS_INVALID_PATH);
  const char parent_path[] = "C:\\Temp\\..\\Secret";
  TEST_ASSERT(zi_path_parse_absolute(parent_path,
                                     sizeof parent_path - 1,
                                     components,
                                     ARRAY_COUNT(components),
                                     &parsed) == ZI_STATUS_INVALID_PATH);
  return true;
}

// The scenarios share one allocator fixture; splitting them would obscure state transitions.
// NOLINTNEXTLINE(readability-function-size)
static bool test_physical_memory(void) {
  const ZiBootMemoryRange boot_ranges[] = {
      {UINT64_C(0x9000), UINT64_C(0x3000), ZI_BOOT_MEMORY_USABLE, 0},
      {UINT64_C(0x0000), UINT64_C(0x1000), ZI_BOOT_MEMORY_RESERVED, 0},
      {UINT64_C(0x4000), UINT64_C(0x5000), ZI_BOOT_MEMORY_USABLE, 0},
      {UINT64_C(0x1000), UINT64_C(0x3000), ZI_BOOT_MEMORY_KERNEL_AND_MODULES, 0},
      {UINT64_C(0xc000), UINT64_C(0x4000), ZI_BOOT_MEMORY_BOOT_RECLAIMABLE, 0},
  };
  ZiMemoryRange range_storage[ARRAY_COUNT(boot_ranges)] = {0};
  ZiMemoryInventory inventory = {0};
  TEST_ASSERT(ZiSucceeded(zi_memory_inventory_build(boot_ranges,
                                                    ARRAY_COUNT(boot_ranges),
                                                    range_storage,
                                                    ARRAY_COUNT(range_storage),
                                                    &inventory)));
  TEST_ASSERT(inventory.range_count == 4);
  TEST_ASSERT(inventory.ranges[0].physical_base == 0);
  TEST_ASSERT(inventory.ranges[2].physical_base == UINT64_C(0x4000));
  TEST_ASSERT(inventory.ranges[2].page_count == 8);
  TEST_ASSERT(inventory.maximum_physical_address == UINT64_C(0x10000));
  TEST_ASSERT(inventory.managed_page_count == 16);
  TEST_ASSERT(inventory.initially_usable_page_count == 8);

  uint64_t usable_base = 0;
  TEST_ASSERT(ZiSucceeded(zi_memory_inventory_find_usable(&inventory, 2, 4, &usable_base)));
  TEST_ASSERT(usable_base == UINT64_C(0x4000));
  TEST_ASSERT(zi_memory_inventory_find_usable(&inventory, 9, 1, &usable_base) ==
              ZI_STATUS_NO_MEMORY);

  ZiPhysicalPageMetadata metadata[16] = {0};
  ZiPhysicalMemoryManager manager = {0};
  size_t metadata_size = 0;
  TEST_ASSERT(ZiSucceeded(zi_pmm_metadata_size(ARRAY_COUNT(metadata), &metadata_size)));
  TEST_ASSERT(metadata_size == sizeof metadata);
  TEST_ASSERT(ZiSucceeded(zi_pmm_initialise(&inventory, metadata, sizeof metadata, &manager)));
  ZiPhysicalMemoryStatistics statistics = zi_pmm_statistics(&manager);
  TEST_ASSERT(statistics.managed_pages == 16);
  TEST_ASSERT(statistics.free_pages == 8);
  TEST_ASSERT(statistics.reserved_pages == 8);
  TEST_ASSERT(statistics.allocated_pages == 0);

  TEST_ASSERT(ZiSucceeded(
      zi_pmm_reserve(&manager, UINT64_C(0x4000), 1, ZI_MEMORY_OWNER_ALLOCATOR_METADATA)));
  uint64_t allocation = 0;
  TEST_ASSERT(ZiSucceeded(zi_pmm_allocate(&manager, 2, 2, ZI_MEMORY_OWNER_TEST, &allocation)));
  TEST_ASSERT(allocation == UINT64_C(0x6000));
  ZiPhysicalPageMetadata page = {0};
  TEST_ASSERT(ZiSucceeded(zi_pmm_query(&manager, allocation, &page)));
  TEST_ASSERT(page.state == ZI_MEMORY_PAGE_ALLOCATED && page.owner == ZI_MEMORY_OWNER_TEST);
  TEST_ASSERT(zi_pmm_free(&manager, allocation, 2, ZI_MEMORY_OWNER_KERNEL_POOL) ==
              ZI_STATUS_INVALID_STATE);
  TEST_ASSERT(ZiSucceeded(zi_pmm_query(&manager, allocation, &page)));
  TEST_ASSERT(page.state == ZI_MEMORY_PAGE_ALLOCATED);
  TEST_ASSERT(ZiSucceeded(zi_pmm_free(&manager, allocation, 2, ZI_MEMORY_OWNER_TEST)));
  TEST_ASSERT(ZiSucceeded(zi_pmm_query(&manager, allocation, &page)));
  TEST_ASSERT(page.state == ZI_MEMORY_PAGE_FREE && page.owner == ZI_MEMORY_OWNER_NONE);
  TEST_ASSERT(zi_pmm_reserve(&manager, UINT64_C(0x1000), 1, ZI_MEMORY_OWNER_ALLOCATOR_METADATA) ==
              ZI_STATUS_RESOURCE_IN_USE);
  TEST_ASSERT(ZiSucceeded(zi_pmm_reassign_reserved(&manager,
                                                   UINT64_C(0x1000),
                                                   1,
                                                   ZI_MEMORY_OWNER_KERNEL,
                                                   ZI_MEMORY_OWNER_MODULE)));
  TEST_ASSERT(ZiSucceeded(zi_pmm_query(&manager, UINT64_C(0x1000), &page)));
  TEST_ASSERT(page.state == ZI_MEMORY_PAGE_RESERVED && page.owner == ZI_MEMORY_OWNER_MODULE);
  TEST_ASSERT(zi_pmm_allocate(&manager, 8, 1, ZI_MEMORY_OWNER_TEST, &allocation) ==
              ZI_STATUS_NO_MEMORY);

  const ZiBootMemoryRange overlap[] = {
      {UINT64_C(0x1000), UINT64_C(0x3000), ZI_BOOT_MEMORY_USABLE, 0},
      {UINT64_C(0x2000), UINT64_C(0x1000), ZI_BOOT_MEMORY_RESERVED, 0},
  };
  ZiMemoryRange overlap_storage[ARRAY_COUNT(overlap)] = {0};
  TEST_ASSERT(zi_memory_inventory_build(overlap,
                                        ARRAY_COUNT(overlap),
                                        overlap_storage,
                                        ARRAY_COUNT(overlap_storage),
                                        &inventory) == ZI_STATUS_ADDRESS_CONFLICT);
  const ZiBootMemoryRange unaligned[] = {
      {UINT64_C(0x1001), UINT64_C(0x1000), ZI_BOOT_MEMORY_USABLE, 0},
  };
  TEST_ASSERT(zi_memory_inventory_build(unaligned,
                                        ARRAY_COUNT(unaligned),
                                        overlap_storage,
                                        ARRAY_COUNT(overlap_storage),
                                        &inventory) == ZI_STATUS_INVALID_ARGUMENT);

  const ZiBootMemoryRange sparse[] = {
      {UINT64_C(0x1000), UINT64_C(0x2000), ZI_BOOT_MEMORY_USABLE, 0},
      {UINT64_C(0x8000000000), UINT64_C(0x1000), ZI_BOOT_MEMORY_FRAMEBUFFER, 0},
  };
  ZiMemoryRange sparse_storage[ARRAY_COUNT(sparse)] = {0};
  TEST_ASSERT(ZiSucceeded(zi_memory_inventory_build(sparse,
                                                    ARRAY_COUNT(sparse),
                                                    sparse_storage,
                                                    ARRAY_COUNT(sparse_storage),
                                                    &inventory)));
  TEST_ASSERT(inventory.managed_page_count == 3);
  ZiPhysicalPageMetadata sparse_metadata[3] = {0};
  TEST_ASSERT(ZiSucceeded(
      zi_pmm_initialise(&inventory, sparse_metadata, sizeof sparse_metadata, &manager)));
  TEST_ASSERT(manager.metadata_page_count == 3);
  TEST_ASSERT(ZiSucceeded(zi_pmm_query(&manager, UINT64_C(0x8000000000), &page)));
  TEST_ASSERT(page.owner == ZI_MEMORY_OWNER_FRAMEBUFFER);

  const ZiBootMemoryRange zero_guard_range[] = {
      {0, UINT64_C(0x3000), ZI_BOOT_MEMORY_USABLE, 0},
  };
  ZiMemoryRange zero_guard_storage[ARRAY_COUNT(zero_guard_range)] = {0};
  TEST_ASSERT(ZiSucceeded(zi_memory_inventory_build(zero_guard_range,
                                                    ARRAY_COUNT(zero_guard_range),
                                                    zero_guard_storage,
                                                    ARRAY_COUNT(zero_guard_storage),
                                                    &inventory)));
  ZiPhysicalPageMetadata zero_guard_metadata[3] = {0};
  TEST_ASSERT(ZiSucceeded(
      zi_pmm_initialise(&inventory, zero_guard_metadata, sizeof zero_guard_metadata, &manager)));
  TEST_ASSERT(ZiSucceeded(zi_pmm_reserve(&manager, 0, 1, ZI_MEMORY_OWNER_ZERO_GUARD)));
  TEST_ASSERT(ZiSucceeded(zi_pmm_allocate(&manager, 1, 1, ZI_MEMORY_OWNER_TEST, &allocation)));
  TEST_ASSERT(allocation == ZI_MEMORY_PAGE_SIZE);
  uint64_t process_allocation = 0;
  TEST_ASSERT(ZiSucceeded(
      zi_pmm_allocate(&manager, 1, 1, ZI_MEMORY_OWNER_PROCESS_IMAGE, &process_allocation)));
  TEST_ASSERT(process_allocation == UINT64_C(2) * ZI_MEMORY_PAGE_SIZE);
  TEST_ASSERT(ZiSucceeded(zi_pmm_query(&manager, process_allocation, &page)));
  TEST_ASSERT(page.state == ZI_MEMORY_PAGE_ALLOCATED &&
              page.owner == ZI_MEMORY_OWNER_PROCESS_IMAGE);
  uint64_t invalid_allocation = UINT64_MAX;
  TEST_ASSERT(zi_pmm_allocate(&manager, 1, 1, ZI_MEMORY_OWNER_ZERO_GUARD, &invalid_allocation) ==
              ZI_STATUS_INVALID_ARGUMENT);
  TEST_ASSERT(invalid_allocation == UINT64_MAX);
  TEST_ASSERT(
      ZiSucceeded(zi_pmm_free(&manager, process_allocation, 1, ZI_MEMORY_OWNER_PROCESS_IMAGE)));
  return true;
}

// This cohesive corruption-and-lifecycle matrix deliberately exceeds the line review threshold.
// NOLINTNEXTLINE(readability-function-size)
static bool test_pool_and_object_cache(void) {
  _Alignas(ZI_POOL_ALIGNMENT) unsigned char arena[4096] = {0};
  ZiPool pool = {0};
  TEST_ASSERT(ZiSucceeded(zi_pool_initialise(arena, sizeof arena, &pool)));
  TEST_ASSERT(ZiSucceeded(zi_pool_validate(&pool)));
  TEST_ASSERT(zi_pool_allocate(&pool, 0, NULL) == ZI_STATUS_INVALID_ARGUMENT);

  void* first = NULL;
  void* middle = NULL;
  void* last = NULL;
  TEST_ASSERT(ZiSucceeded(zi_pool_allocate(&pool, 1, &first)));
  TEST_ASSERT(ZiSucceeded(zi_pool_allocate(&pool, 37, &middle)));
  TEST_ASSERT(ZiSucceeded(zi_pool_allocate(&pool, 128, &last)));
  TEST_ASSERT(((uintptr_t)first & (ZI_POOL_ALIGNMENT - 1u)) == 0);
  TEST_ASSERT(((uintptr_t)middle & (ZI_POOL_ALIGNMENT - 1u)) == 0);
  TEST_ASSERT(((uintptr_t)last & (ZI_POOL_ALIGNMENT - 1u)) == 0);
  zi_memory_zero(first, 1);
  zi_memory_zero(middle, 37);
  zi_memory_zero(last, 128);

  ZiPoolStatistics statistics = {0};
  TEST_ASSERT(ZiSucceeded(zi_pool_statistics(&pool, &statistics)));
  TEST_ASSERT(statistics.allocation_count == 3 && statistics.allocated_bytes == 166);
  TEST_ASSERT(statistics.block_count == 4 && statistics.peak_allocated_bytes == 166);
  TEST_ASSERT(zi_pool_free(&pool, (unsigned char*)first + ZI_POOL_ALIGNMENT) ==
              ZI_STATUS_INVALID_ARGUMENT);
  TEST_ASSERT(ZiSucceeded(zi_pool_free(&pool, middle)));
  TEST_ASSERT(zi_pool_free(&pool, middle) == ZI_STATUS_INVALID_STATE);
  void* reused = NULL;
  TEST_ASSERT(ZiSucceeded(zi_pool_allocate(&pool, 32, &reused)));
  TEST_ASSERT(reused == middle);
  TEST_ASSERT(zi_pool_allocate(&pool, sizeof arena, &middle) == ZI_STATUS_NO_MEMORY);
  TEST_ASSERT(ZiSucceeded(zi_pool_free(&pool, reused)));
  TEST_ASSERT(ZiSucceeded(zi_pool_free(&pool, first)));
  TEST_ASSERT(ZiSucceeded(zi_pool_free(&pool, last)));
  TEST_ASSERT(ZiSucceeded(zi_pool_statistics(&pool, &statistics)));
  TEST_ASSERT(statistics.allocation_count == 0 && statistics.block_count == 1);
  TEST_ASSERT(statistics.free_span_bytes == sizeof arena);

  _Alignas(ZI_POOL_ALIGNMENT) unsigned char tail_arena[512] = {0};
  ZiPool tail_pool = {0};
  void* tail_allocation = NULL;
  TEST_ASSERT(ZiSucceeded(zi_pool_initialise(tail_arena, sizeof tail_arena, &tail_pool)));
  TEST_ASSERT(ZiSucceeded(zi_pool_allocate(&tail_pool, 17, &tail_allocation)));
  ((unsigned char*)tail_allocation)[17] ^= UINT8_C(0x01);
  TEST_ASSERT(zi_pool_validate(&tail_pool) == ZI_STATUS_MEMORY_CORRUPTION);

  _Alignas(ZI_POOL_ALIGNMENT) unsigned char header_arena[512] = {0};
  ZiPool header_pool = {0};
  TEST_ASSERT(ZiSucceeded(zi_pool_initialise(header_arena, sizeof header_arena, &header_pool)));
  header_arena[0] ^= UINT8_C(0x01);
  TEST_ASSERT(zi_pool_validate(&header_pool) == ZI_STATUS_MEMORY_CORRUPTION);

  _Alignas(ZI_POOL_ALIGNMENT) unsigned char cache_arena[8192] = {0};
  ZiPool cache_pool = {0};
  ZiObjectCache cache = {0};
  TEST_ASSERT(ZiSucceeded(zi_pool_initialise(cache_arena, sizeof cache_arena, &cache_pool)));
  TEST_ASSERT(ZiSucceeded(zi_object_cache_initialise(&cache_pool, 24, 3, &cache)));
  void* object_a = NULL;
  void* object_b = NULL;
  void* object_c = NULL;
  void* object_d = NULL;
  TEST_ASSERT(ZiSucceeded(zi_object_cache_allocate(&cache, &object_a)));
  TEST_ASSERT(ZiSucceeded(zi_object_cache_allocate(&cache, &object_b)));
  TEST_ASSERT(ZiSucceeded(zi_object_cache_allocate(&cache, &object_c)));
  TEST_ASSERT(zi_object_cache_allocate(&cache, &object_d) == ZI_STATUS_NO_MEMORY);
  TEST_ASSERT(((uintptr_t)object_a & (ZI_POOL_ALIGNMENT - 1u)) == 0);
  TEST_ASSERT(zi_object_cache_destroy(&cache) == ZI_STATUS_RESOURCE_IN_USE);
  TEST_ASSERT(zi_object_cache_free(&cache, (unsigned char*)object_a + 1) ==
              ZI_STATUS_INVALID_ARGUMENT);
  TEST_ASSERT(ZiSucceeded(zi_object_cache_free(&cache, object_b)));
  TEST_ASSERT(zi_object_cache_free(&cache, object_b) == ZI_STATUS_INVALID_STATE);
  TEST_ASSERT(ZiSucceeded(zi_object_cache_allocate(&cache, &object_d)));
  TEST_ASSERT(object_d == object_b);
  TEST_ASSERT(ZiSucceeded(zi_object_cache_free(&cache, object_a)));
  TEST_ASSERT(ZiSucceeded(zi_object_cache_free(&cache, object_c)));
  TEST_ASSERT(ZiSucceeded(zi_object_cache_free(&cache, object_d)));
  TEST_ASSERT(ZiSucceeded(zi_object_cache_validate(&cache)));
  TEST_ASSERT(ZiSucceeded(zi_object_cache_destroy(&cache)));
  TEST_ASSERT(ZiSucceeded(zi_pool_statistics(&cache_pool, &statistics)));
  TEST_ASSERT(statistics.allocation_count == 0 && statistics.block_count == 1);

  _Alignas(ZI_POOL_ALIGNMENT) unsigned char cache_tail_arena[1024] = {0};
  ZiPool cache_tail_pool = {0};
  ZiObjectCache tail_cache = {0};
  void* tail_object = NULL;
  TEST_ASSERT(
      ZiSucceeded(zi_pool_initialise(cache_tail_arena, sizeof cache_tail_arena, &cache_tail_pool)));
  TEST_ASSERT(ZiSucceeded(zi_object_cache_initialise(&cache_tail_pool, 21, 2, &tail_cache)));
  TEST_ASSERT(ZiSucceeded(zi_object_cache_allocate(&tail_cache, &tail_object)));
  ((unsigned char*)tail_object)[21] ^= UINT8_C(0x01);
  TEST_ASSERT(zi_object_cache_validate(&tail_cache) == ZI_STATUS_MEMORY_CORRUPTION);

  _Alignas(ZI_POOL_ALIGNMENT) unsigned char stale_arena[1024] = {0};
  ZiPool stale_pool = {0};
  ZiObjectCache stale_cache = {0};
  void* stale_object = NULL;
  TEST_ASSERT(ZiSucceeded(zi_pool_initialise(stale_arena, sizeof stale_arena, &stale_pool)));
  TEST_ASSERT(ZiSucceeded(zi_object_cache_initialise(&stale_pool, 16, 2, &stale_cache)));
  TEST_ASSERT(ZiSucceeded(zi_object_cache_allocate(&stale_cache, &stale_object)));
  TEST_ASSERT(ZiSucceeded(zi_object_cache_free(&stale_cache, stale_object)));
  ((unsigned char*)stale_object)[0] = UINT8_C(0x01);
  TEST_ASSERT(zi_object_cache_validate(&stale_cache) == ZI_STATUS_MEMORY_CORRUPTION);
  return true;
}

static bool test_x64_paging(void) {
  TestPagePool pool = {0};
  pool.fail_on_call = SIZE_MAX;
  ZiX64PagingContext paging = {0};
  TEST_ASSERT(ZiSucceeded(zi_x64_paging_create(&pool,
                                               test_page_allocate,
                                               test_page_release,
                                               test_page_pointer,
                                               true,
                                               &paging)));
  TEST_ASSERT(test_page_used_count(&pool) == 1);

  const uint64_t virtual_address = UINT64_C(0xffff900000000000);
  const uint64_t physical_address = UINT64_C(0x00200000);
  uint32_t read_write = ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE | ZI_X64_PAGE_GLOBAL;
  TEST_ASSERT(
      ZiSucceeded(zi_x64_paging_map_page(&paging, virtual_address, physical_address, read_write)));
  TEST_ASSERT(test_page_used_count(&pool) == 4);
  ZiX64PageMapping mapping = {0};
  TEST_ASSERT(ZiSucceeded(zi_x64_paging_query(&paging, virtual_address + 21, &mapping)));
  TEST_ASSERT(mapping.physical_base == physical_address + 21);
  TEST_ASSERT(mapping.protection == read_write);
  TEST_ASSERT(zi_x64_paging_map_page(&paging, virtual_address, physical_address, read_write) ==
              ZI_STATUS_ALREADY_EXISTS);

  size_t pml4_index = (size_t)((virtual_address >> 39) & UINT64_C(0x1ff));
  TEST_ASSERT((pool.pages[0][pml4_index] & (UINT64_C(1) << 2)) == 0);
  pool.fail_on_call = pool.allocation_calls;
  TEST_ASSERT(zi_x64_paging_map_page(&paging,
                                     virtual_address + (UINT64_C(1) << 30),
                                     physical_address + ZI_X64_PAGE_SIZE,
                                     ZI_X64_PAGE_READ | ZI_X64_PAGE_USER) == ZI_STATUS_NO_MEMORY);
  TEST_ASSERT((pool.pages[0][pml4_index] & (UINT64_C(1) << 2)) == 0);
  pool.fail_on_call = SIZE_MAX;
  TEST_ASSERT(zi_x64_paging_protect_page(&paging,
                                         virtual_address,
                                         ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE |
                                             ZI_X64_PAGE_EXECUTE) == ZI_STATUS_INVALID_ARGUMENT);
  uint32_t read_execute = ZI_X64_PAGE_READ | ZI_X64_PAGE_EXECUTE | ZI_X64_PAGE_GLOBAL;
  TEST_ASSERT(ZiSucceeded(zi_x64_paging_protect_page(&paging, virtual_address, read_execute)));
  TEST_ASSERT(ZiSucceeded(zi_x64_paging_query(&paging, virtual_address, &mapping)));
  TEST_ASSERT(mapping.protection == read_execute);

  TEST_ASSERT(ZiSucceeded(zi_x64_paging_map_range(&paging,
                                                  virtual_address + UINT64_C(0x2000),
                                                  physical_address + UINT64_C(0x2000),
                                                  UINT64_C(0x2000),
                                                  read_write)));
  TEST_ASSERT(ZiSucceeded(
      zi_x64_paging_unmap_range(&paging, virtual_address + UINT64_C(0x2000), UINT64_C(0x2000))));
  TEST_ASSERT(zi_x64_paging_query(&paging, virtual_address + UINT64_C(0x2000), &mapping) ==
              ZI_STATUS_PAGE_NOT_MAPPED);
  TEST_ASSERT(ZiSucceeded(zi_x64_paging_unmap_page(&paging, virtual_address)));
  TEST_ASSERT(test_page_used_count(&pool) == 1);

  pool.fail_on_call = pool.allocation_calls + 2;
  const uint64_t rollback_address = UINT64_C(0xffffa00000000000);
  TEST_ASSERT(
      zi_x64_paging_map_page(&paging, rollback_address, physical_address, ZI_X64_PAGE_READ) ==
      ZI_STATUS_NO_MEMORY);
  TEST_ASSERT(test_page_used_count(&pool) == 1);
  TEST_ASSERT(zi_x64_paging_query(&paging, rollback_address, &mapping) ==
              ZI_STATUS_PAGE_NOT_MAPPED);
  TEST_ASSERT(!zi_x64_address_is_canonical(UINT64_C(0x0000800000000000)));
  TEST_ASSERT(zi_x64_paging_map_page(&paging,
                                     UINT64_C(0x0000800000000000),
                                     physical_address,
                                     ZI_X64_PAGE_READ) == ZI_STATUS_INVALID_ARGUMENT);
  TEST_ASSERT(zi_x64_paging_unmap_page(&paging, virtual_address) == ZI_STATUS_PAGE_NOT_MAPPED);

  pool.fail_on_call = SIZE_MAX;
  ZiX64PagingContext process_paging = {0};
  TEST_ASSERT(ZiSucceeded(zi_x64_paging_clone_kernel_half(&paging, &process_paging)));
  TEST_ASSERT(test_page_used_count(&pool) == 2);
  TEST_ASSERT(zi_x64_paging_query(&process_paging, rollback_address, &mapping) ==
              ZI_STATUS_PAGE_NOT_MAPPED);
  const uint64_t user_address = UINT64_C(0x0000000000400000);
  TEST_ASSERT(ZiSucceeded(zi_x64_paging_map_page(&process_paging,
                                                 user_address,
                                                 physical_address,
                                                 ZI_X64_PAGE_READ | ZI_X64_PAGE_USER)));
  TEST_ASSERT(zi_x64_paging_release_empty_address_space(&process_paging, &paging) ==
              ZI_STATUS_RESOURCE_IN_USE);
  TEST_ASSERT(ZiSucceeded(zi_x64_paging_unmap_page(&process_paging, user_address)));
  TEST_ASSERT(ZiSucceeded(zi_x64_paging_release_empty_address_space(&process_paging, &paging)));
  TEST_ASSERT(process_paging.root_physical_base == 0);
  TEST_ASSERT(test_page_used_count(&pool) == 1);
  return true;
}

// The shared page-pool fixture makes these address-space transitions clearest as one matrix.
// NOLINTNEXTLINE(readability-function-size)
static bool test_process_address_space(void) {
  TestPagePool pool = {0};
  pool.fail_on_call = SIZE_MAX;
  ZiX64PagingContext kernel_paging = {0};
  TEST_ASSERT(ZiSucceeded(zi_x64_paging_create(&pool,
                                               test_page_allocate,
                                               test_page_release,
                                               test_page_pointer,
                                               true,
                                               &kernel_paging)));
  const uint64_t kernel_virtual = UINT64_C(0xffff900000000000);
  TEST_ASSERT(ZiSucceeded(
      zi_x64_paging_map_page(&kernel_paging,
                             kernel_virtual,
                             UINT64_C(0x00200000),
                             ZI_X64_PAGE_READ | ZI_X64_PAGE_EXECUTE | ZI_X64_PAGE_GLOBAL)));
  size_t kernel_page_count = test_page_used_count(&pool);
  TEST_ASSERT(kernel_page_count == 4);

  ZiAddressSpaceBacking backing = {
      sizeof(ZiAddressSpaceBacking),
      ZI_ADDRESS_SPACE_BACKING_VERSION,
      &pool,
      test_page_run_allocate,
      test_page_run_release,
      test_page_pointer,
  };
  ZiAddressSpace address_space = {0};
  TEST_ASSERT(ZiSucceeded(zi_address_space_initialise(&kernel_paging, &backing, &address_space)));
  TEST_ASSERT(address_space.paging.root_physical_base != kernel_paging.root_physical_base);
  ZiX64PageMapping mapping = {0};
  TEST_ASSERT(ZiSucceeded(zi_x64_paging_query(&address_space.paging, kernel_virtual, &mapping)));
  TEST_ASSERT((mapping.protection & ZI_X64_PAGE_USER) == 0);

  const uint64_t user_base = UINT64_C(0x0000000000400000);
  const size_t user_size = (size_t)(2u * ZI_X64_PAGE_SIZE);
  const uint32_t user_read_write = ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE | ZI_X64_PAGE_USER;
  TEST_ASSERT(ZiSucceeded(zi_address_space_map_owned(&address_space,
                                                     user_base,
                                                     user_size,
                                                     user_read_write,
                                                     ZI_MEMORY_OWNER_PROCESS_DATA)));
  TEST_ASSERT(address_space.region_count == 1);
  TEST_ASSERT(ZiSucceeded(
      zi_address_space_query(&address_space, user_base, ZI_USER_ACCESS_WRITE, &mapping)));
  TEST_ASSERT((mapping.protection & ZI_X64_PAGE_USER) != 0);
  uint64_t free_base = 0;
  TEST_ASSERT(ZiSucceeded(zi_address_space_find_free_range(&address_space,
                                                           user_base,
                                                           user_base + UINT64_C(0x10000),
                                                           (size_t)ZI_X64_PAGE_SIZE,
                                                           ZI_X64_PAGE_SIZE,
                                                           &free_base)));
  TEST_ASSERT(free_base == user_base + user_size);
  TEST_ASSERT(zi_address_space_find_free_range(&address_space,
                                               user_base,
                                               user_base + user_size,
                                               (size_t)ZI_X64_PAGE_SIZE,
                                               ZI_X64_PAGE_SIZE,
                                               &free_base) == ZI_STATUS_NOT_FOUND);
  TEST_ASSERT(zi_address_space_find_free_range(&address_space,
                                               user_base,
                                               user_base + UINT64_C(0x10000),
                                               (size_t)ZI_X64_PAGE_SIZE,
                                               3,
                                               &free_base) == ZI_STATUS_INVALID_ARGUMENT);

  const unsigned char source[] = {0x21,
                                  0x64,
                                  0x96,
                                  0xe6,
                                  0xd1,
                                  0xec,
                                  0xfc,
                                  0x17,
                                  0x20,
                                  0x33,
                                  0x5f,
                                  0x6f,
                                  0x8a,
                                  0x63,
                                  0xc7,
                                  0x85};
  unsigned char destination[sizeof source] = {0};
  uint64_t crossing_address = user_base + ZI_X64_PAGE_SIZE - 7u;
  TEST_ASSERT(
      ZiSucceeded(zi_copy_to_user(&address_space, crossing_address, source, sizeof source)));
  TEST_ASSERT(ZiSucceeded(
      zi_copy_from_user(&address_space, destination, crossing_address, sizeof destination)));
  TEST_ASSERT(zi_memory_compare(source, destination, sizeof source) == 0);

  TEST_ASSERT(zi_address_space_map_owned(&address_space,
                                         user_base + ZI_X64_PAGE_SIZE,
                                         (size_t)ZI_X64_PAGE_SIZE,
                                         user_read_write,
                                         ZI_MEMORY_OWNER_PROCESS_DATA) ==
              ZI_STATUS_ADDRESS_CONFLICT);
  TEST_ASSERT(zi_address_space_map_owned(&address_space,
                                         user_base + user_size,
                                         (size_t)ZI_X64_PAGE_SIZE,
                                         user_read_write | ZI_X64_PAGE_EXECUTE,
                                         ZI_MEMORY_OWNER_PROCESS_DATA) == ZI_STATUS_ACCESS_DENIED);
  TEST_ASSERT(zi_address_space_map_owned(&address_space,
                                         user_base + user_size,
                                         (size_t)ZI_X64_PAGE_SIZE,
                                         user_read_write | ZI_X64_PAGE_GLOBAL,
                                         ZI_MEMORY_OWNER_PROCESS_DATA) == ZI_STATUS_ACCESS_DENIED);
  TEST_ASSERT(!zi_user_range_is_valid(0, 1));
  TEST_ASSERT(!zi_user_range_is_valid(ZI_USER_ADDRESS_MIN - 1u, 1));
  TEST_ASSERT(!zi_user_range_is_valid(ZI_USER_ADDRESS_MAX_EXCLUSIVE - 1u, 2));
  TEST_ASSERT(zi_copy_from_user(&address_space, destination, 0, sizeof destination) ==
              ZI_STATUS_INVALID_USER_BUFFER);

  const uint32_t user_read_execute = ZI_X64_PAGE_READ | ZI_X64_PAGE_EXECUTE | ZI_X64_PAGE_USER;
  TEST_ASSERT(ZiSucceeded(
      zi_address_space_protect_owned(&address_space, user_base, user_size, user_read_execute)));
  TEST_ASSERT(zi_copy_to_user(&address_space, user_base, source, sizeof source) ==
              ZI_STATUS_INVALID_USER_BUFFER);
  TEST_ASSERT(ZiSucceeded(
      zi_address_space_query(&address_space, user_base, ZI_USER_ACCESS_EXECUTE, &mapping)));

  TEST_ASSERT(ZiSucceeded(zi_address_space_destroy(&address_space)));
  TEST_ASSERT(address_space.version == 0);
  TEST_ASSERT(test_page_used_count(&pool) == kernel_page_count);
  TEST_ASSERT(ZiSucceeded(zi_x64_paging_unmap_page(&kernel_paging, kernel_virtual)));
  TEST_ASSERT(test_page_used_count(&pool) == 1);
  return true;
}

static bool test_zifs_encoding(void) {
  ZiFsSuperblock superblock = {0};
  superblock.format_major = ZI_FS_FORMAT_MAJOR;
  superblock.format_minor = ZI_FS_FORMAT_MINOR;
  superblock.block_shift = ZI_FS_BLOCK_SHIFT;
  superblock.checksum_type = 1;
  superblock.generation = 21;
  superblock.total_blocks = 16;
  superblock.root_record_index = 0;
  superblock.record_table_start = 1;
  superblock.record_table_blocks = 1;
  superblock.allocation_bitmap_start = 2;
  superblock.allocation_bitmap_blocks = 1;
  superblock.journal_start = 3;
  superblock.journal_blocks = 1;
  superblock.security_table_start = 4;
  superblock.security_table_blocks = 1;
  superblock.directory_table_start = 5;
  superblock.directory_table_blocks = 2;
  superblock.backup_superblock = 15;
  superblock.volume_name_size = 6;
  zi_memory_copy(superblock.volume_name, "Zizium", 6);

  unsigned char block[ZI_FS_BLOCK_SIZE] = {0};
  TEST_ASSERT(ZiSucceeded(ZiFsEncodeSuperblock(&superblock, block, sizeof block)));
  const unsigned char golden_magic[] = {'Z', 'i', 'F', 'S', '\r', '\n', 0x1a, '\n'};
  TEST_ASSERT(zi_memory_compare(block, golden_magic, sizeof golden_magic) == 0);
  TEST_ASSERT(zi_read_u16_le(block + 8) == ZI_FS_FORMAT_MAJOR);
  TEST_ASSERT(zi_read_u64_le(block + 64) == 16);

  ZiFsSuperblock decoded = {0};
  TEST_ASSERT(ZiSucceeded(ZiFsDecodeSuperblock(block, sizeof block, &decoded)));
  TEST_ASSERT(decoded.generation == 21 && decoded.backup_superblock == 15);
  block[80] ^= 1u;
  TEST_ASSERT(ZiFsDecodeSuperblock(block, sizeof block, &decoded) == ZI_STATUS_CHECKSUM_MISMATCH);

  ZiFsFileRecord record = {0};
  record.file_id = 21;
  record.parent_file_id = 1;
  record.security_id = 1;
  record.file_type = ZI_FS_FILE_TYPE_REGULAR;
  record.file_size = ZI_FS_BLOCK_SIZE + 21u;
  record.allocated_size = UINT64_C(2) * ZI_FS_BLOCK_SIZE;
  record.extent_count = 1;
  record.extents[0].logical_block = 0;
  record.extents[0].physical_block = 7;
  record.extents[0].block_count = 2;
  TEST_ASSERT(ZiSucceeded(ZiFsEncodeFileRecord(&record, block, sizeof block)));
  ZiFsFileRecord decoded_record = {0};
  TEST_ASSERT(ZiSucceeded(ZiFsDecodeFileRecord(block, sizeof block, &decoded_record)));
  TEST_ASSERT(decoded_record.file_id == 21 && decoded_record.file_size == record.file_size);
  TEST_ASSERT(decoded_record.extents[0].physical_block == 7);

  TEST_ASSERT(ZiSucceeded(ZiFsInitialiseDirectoryBlock(block, sizeof block, 1, 1)));
  ZiFsDirectoryEntry entry = {0};
  entry.file_id = 2;
  entry.record_index = 1;
  entry.file_type = ZI_FS_FILE_TYPE_DIRECTORY;
  entry.name.data = "Temp";
  entry.name.size = 4;
  TEST_ASSERT(ZiSucceeded(ZiFsAddDirectoryEntry(block, sizeof block, &entry)));
  ZiFsDirectoryEntry found = {0};
  TEST_ASSERT(
      ZiSucceeded(ZiFsFindDirectoryEntry(block, sizeof block, (ZiStringView){"Temp", 4}, &found)));
  TEST_ASSERT(found.file_id == 2);
  TEST_ASSERT(ZiFsFindDirectoryEntry(block, sizeof block, (ZiStringView){"temp", 4}, &found) ==
              ZI_STATUS_NOT_FOUND);
  block[100] ^= 1u;
  TEST_ASSERT(ZiFsFindDirectoryEntry(block, sizeof block, (ZiStringView){"Temp", 4}, &found) ==
              ZI_STATUS_CHECKSUM_MISMATCH);
  return true;
}

static bool test_zifs_mount_and_lookup(void) {
  unsigned char volume_data[16u * ZI_FS_BLOCK_SIZE] = {0};
  TEST_ASSERT(initialise_test_volume(volume_data, sizeof volume_data));
  MemoryBlockDevice memory = {volume_data, sizeof volume_data};
  ZiBlockDevice device = {
      sizeof(ZiBlockDevice),
      ZI_BLOCK_DEVICE_VERSION,
      &memory,
      ZI_FS_BLOCK_SIZE,
      16,
      memory_read_blocks,
      NULL,
      ZI_BLOCK_DEVICE_READ_ONLY,
      NULL,
  };
  unsigned char block[ZI_FS_BLOCK_SIZE] = {0};
  ZiFsVolume volume = {0};
  TEST_ASSERT(ZiSucceeded(ZiFsMountVolume(&device, block, sizeof block, &volume)));
  TEST_ASSERT(volume.is_read_only == 1 && volume.mounted_from_backup == 0);

  ZiStringView components[2] = {0};
  ZiParsedPath path = {0};
  const char temp_path[] = "C:\\Temp";
  TEST_ASSERT(ZiSucceeded(zi_path_parse_absolute(temp_path,
                                                 sizeof temp_path - 1,
                                                 components,
                                                 ARRAY_COUNT(components),
                                                 &path)));
  ZiFsFileRecord record = {0};
  TEST_ASSERT(ZiSucceeded(ZiFsLookupPath(&volume, &path, block, sizeof block, &record)));
  TEST_ASSERT(record.file_id == 2);

  const char wrong_case[] = "C:\\temp";
  TEST_ASSERT(ZiSucceeded(zi_path_parse_absolute(wrong_case,
                                                 sizeof wrong_case - 1,
                                                 components,
                                                 ARRAY_COUNT(components),
                                                 &path)));
  TEST_ASSERT(ZiFsLookupPath(&volume, &path, block, sizeof block, &record) == ZI_STATUS_NOT_FOUND);

  volume_data[80] ^= 1u;
  TEST_ASSERT(ZiSucceeded(ZiFsMountVolume(&device, block, sizeof block, &volume)));
  TEST_ASSERT(volume.mounted_from_backup == 1);
  volume_data[sizeof volume_data - ZI_FS_BLOCK_SIZE + 80] ^= 1u;
  TEST_ASSERT(ZiFsMountVolume(&device, block, sizeof block, &volume) ==
              ZI_STATUS_CHECKSUM_MISMATCH);
  return true;
}

static bool test_acl(void) {
  const ZiSecurityId user = {ZI_SECURITY_AUTHORITY_USER, 21};
  const ZiSecurityId group = {ZI_SECURITY_AUTHORITY_GROUP, 7};
  const ZiSecurityId groups[] = {group};
  ZiAccessToken token = {sizeof(ZiAccessToken), 1, user, groups, ARRAY_COUNT(groups), 0};
  const ZiAce entries[] = {
      {ZI_ACE_DENY, 0, 0, ZI_ACCESS_DELETE, group},
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_READ | ZI_ACCESS_WRITE, user},
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_EXECUTE, group},
  };
  ZiAcl acl = {sizeof(ZiAcl), 1, entries, ARRAY_COUNT(entries)};
  ZiSecurityDescriptor descriptor = {
      sizeof(ZiSecurityDescriptor),
      1,
      user,
      group,
      &acl,
      0,
  };
  ZiAccessMask granted = 0;
  TEST_ASSERT(ZiSucceeded(
      zi_security_access_check(&descriptor, &token, ZI_ACCESS_READ | ZI_ACCESS_EXECUTE, &granted)));
  TEST_ASSERT(granted == (ZI_ACCESS_READ | ZI_ACCESS_EXECUTE));
  TEST_ASSERT(zi_security_access_check(&descriptor, &token, ZI_ACCESS_DELETE, &granted) ==
              ZI_STATUS_ACCESS_DENIED);
  TEST_ASSERT(granted == 0);
  TEST_ASSERT(
      zi_security_access_check(&descriptor, &token, ZI_ACCESS_READ | ZI_ACCESS_CREATE, &granted) ==
      ZI_STATUS_ACCESS_DENIED);
  TEST_ASSERT(granted == ZI_ACCESS_READ);
  descriptor.dacl = NULL;
  TEST_ASSERT(zi_security_access_check(&descriptor, &token, ZI_ACCESS_READ, &granted) ==
              ZI_STATUS_ACCESS_DENIED);
  TEST_ASSERT(ZiSucceeded(zi_security_access_check(&descriptor, &token, 0, &granted)));
  return true;
}

static bool test_objects(void) {
  const ZiObjectOperations operations = {sizeof(ZiObjectOperations),
                                         ZI_OBJECT_OPERATIONS_VERSION,
                                         test_object_destroy,
                                         NULL};
  const ZiObjectType type = {21, {"TestObject", 10}, &operations, 0};
  ZiObjectHeader object = {0};
  g_destructor_calls = 0;
  TEST_ASSERT(ZiSucceeded(zi_object_initialise(&object,
                                               &type,
                                               (ZiStringView){"Object21", 8},
                                               NULL,
                                               NULL,
                                               "test object")));
  TEST_ASSERT(object.reference_count == 1 && object.handle_count == 0);
  TEST_ASSERT(ZiSucceeded(zi_object_reference(&object)));
  TEST_ASSERT(ZiSucceeded(zi_object_add_handle(&object)));
  TEST_ASSERT(object.reference_count == 3 && object.handle_count == 1);
  TEST_ASSERT(ZiSucceeded(zi_object_remove_handle(&object)));
  TEST_ASSERT(object.reference_count == 2 && object.handle_count == 0);
  TEST_ASSERT(zi_object_remove_handle(&object) == ZI_STATUS_INVALID_STATE);
  TEST_ASSERT(ZiSucceeded(zi_object_dereference(&object)));
  TEST_ASSERT(ZiSucceeded(zi_object_dereference(&object)));
  TEST_ASSERT(object.is_destroyed == 1 && g_destructor_calls == 1);
  TEST_ASSERT(zi_object_dereference(&object) == ZI_STATUS_INVALID_STATE);
  TEST_ASSERT(g_destructor_calls == 1);
  return true;
}

static bool test_scheduler(void) {
  ZxThread idle = {0};
  idle.thread_id = 0;
  idle.priority = 0;
  idle.affinity_mask = UINT64_MAX;
  idle.state = ZI_THREAD_RUNNING;
  ZxScheduler scheduler = {0};
  zi_scheduler_initialise(&scheduler, 1, &idle);
  TEST_ASSERT(zi_scheduler_select_next(&scheduler) == &idle);

  ZxThread low = {0};
  low.thread_id = 1;
  low.priority = 5;
  low.base_priority = 5;
  low.affinity_mask = UINT64_MAX;
  ZxThread high_first = {0};
  high_first.thread_id = 2;
  high_first.priority = 21;
  high_first.base_priority = 21;
  high_first.affinity_mask = UINT64_MAX;
  ZxThread high_second = high_first;
  high_second.thread_id = 3;
  ZxThread wrong_cpu = high_first;
  wrong_cpu.thread_id = 4;
  wrong_cpu.priority = 31;
  wrong_cpu.base_priority = 31;
  wrong_cpu.affinity_mask = UINT64_C(1);

  TEST_ASSERT(ZiSucceeded(zi_scheduler_enqueue(&scheduler, &low)));
  TEST_ASSERT(ZiSucceeded(zi_scheduler_enqueue(&scheduler, &high_first)));
  TEST_ASSERT(ZiSucceeded(zi_scheduler_enqueue(&scheduler, &high_second)));
  TEST_ASSERT(ZiSucceeded(zi_scheduler_enqueue(&scheduler, &wrong_cpu)));
  TEST_ASSERT(zi_scheduler_select_next(&scheduler) == &high_first);
  TEST_ASSERT(zi_scheduler_select_next(&scheduler) == &high_second);
  TEST_ASSERT(zi_scheduler_select_next(&scheduler) == &low);
  TEST_ASSERT(zi_scheduler_select_next(&scheduler) == &idle);
  TEST_ASSERT(wrong_cpu.is_queued == 1);
  TEST_ASSERT(ZiSucceeded(zi_scheduler_remove(&scheduler, &wrong_cpu)));

  low.priority = 10;
  low.base_priority = 10;
  zi_scheduler_boost_priority(&low, 20);
  TEST_ASSERT(low.priority == ZI_SCHEDULER_DYNAMIC_PRIORITY_MAX);
  zi_scheduler_decay_priority(&low);
  TEST_ASSERT(low.priority == 14);

  ZxThread tick_idle = {0};
  tick_idle.thread_id = 10;
  tick_idle.priority = 0;
  tick_idle.affinity_mask = UINT64_C(1);
  tick_idle.quantum = 1;
  ZxThread boot = {0};
  boot.thread_id = 11;
  boot.priority = 8;
  boot.base_priority = 8;
  boot.affinity_mask = UINT64_C(1);
  boot.quantum = 2;
  boot.quantum_remaining = 2;
  boot.state = ZI_THREAD_RUNNING;
  ZxThread worker_first = boot;
  worker_first.thread_id = 12;
  worker_first.state = ZI_THREAD_INITIALISED;
  ZxThread worker_second = worker_first;
  worker_second.thread_id = 13;
  ZxScheduler tick_scheduler = {0};
  zi_scheduler_initialise(&tick_scheduler, 0, &tick_idle);
  tick_scheduler.current_thread = &boot;
  TEST_ASSERT(ZiSucceeded(zi_scheduler_enqueue(&tick_scheduler, &worker_first)));
  TEST_ASSERT(ZiSucceeded(zi_scheduler_enqueue(&tick_scheduler, &worker_second)));

  ZiSchedulerDispatch dispatch = {0};
  TEST_ASSERT(ZiSucceeded(zi_scheduler_on_tick(&tick_scheduler, &dispatch)));
  TEST_ASSERT(dispatch.next_thread == &boot && dispatch.did_switch == 0);
  TEST_ASSERT(boot.quantum_remaining == 1 && tick_scheduler.tick_count == 1);
  TEST_ASSERT(ZiSucceeded(zi_scheduler_on_tick(&tick_scheduler, &dispatch)));
  TEST_ASSERT(dispatch.previous_thread == &boot && dispatch.next_thread == &worker_first);
  TEST_ASSERT(dispatch.quantum_expired == 1 && dispatch.did_switch == 1);
  TEST_ASSERT(boot.is_queued == 1 && tick_scheduler.quantum_expiry_count == 1);
  TEST_ASSERT(ZiSucceeded(zi_scheduler_on_tick(&tick_scheduler, &dispatch)));
  TEST_ASSERT(dispatch.next_thread == &worker_first && dispatch.did_switch == 0);
  TEST_ASSERT(ZiSucceeded(zi_scheduler_on_tick(&tick_scheduler, &dispatch)));
  TEST_ASSERT(dispatch.next_thread == &worker_second && dispatch.did_switch == 1);

  ZxThread urgent = {0};
  urgent.thread_id = 14;
  urgent.priority = 20;
  urgent.base_priority = 20;
  urgent.affinity_mask = UINT64_C(1);
  urgent.quantum = 2;
  urgent.quantum_remaining = 2;
  TEST_ASSERT(ZiSucceeded(zi_scheduler_enqueue(&tick_scheduler, &urgent)));
  TEST_ASSERT(ZiSucceeded(zi_scheduler_on_tick(&tick_scheduler, &dispatch)));
  TEST_ASSERT(dispatch.next_thread == &urgent && dispatch.quantum_expired == 0);
  TEST_ASSERT(tick_scheduler.context_switch_count == 3);
  TEST_ASSERT(zi_scheduler_on_tick(NULL, &dispatch) == ZI_STATUS_INVALID_ARGUMENT);
  return true;
}

static bool test_x64_architecture(void) {
  TEST_ASSERT(zi_x64_encode_segment_descriptor(UINT32_C(0xfffff), UINT8_C(0x9a), UINT8_C(0x0a)) ==
              UINT64_C(0x00af9a000000ffff));
  TEST_ASSERT(zi_x64_encode_segment_descriptor(UINT32_C(0xfffff), UINT8_C(0x92), UINT8_C(0x0c)) ==
              UINT64_C(0x00cf92000000ffff));

  ZiX64SystemDescriptor tss =
      zi_x64_encode_tss_descriptor(UINT64_C(0x1122334455667788), UINT32_C(0x67));
  TEST_ASSERT(tss.low == UINT64_C(0x5500896677880067));
  TEST_ASSERT(tss.high == UINT64_C(0x11223344));

  ZiX64IdtGate gate = zi_x64_encode_idt_gate(UINT64_C(0x1122334455667788),
                                             ZI_X64_GDT_KERNEL_CODE_SELECTOR,
                                             UINT8_C(3),
                                             UINT8_C(0x8e));
  TEST_ASSERT(gate.offset_low == UINT16_C(0x7788));
  TEST_ASSERT(gate.selector == ZI_X64_GDT_KERNEL_CODE_SELECTOR && gate.ist == 3);
  TEST_ASSERT(gate.attributes == UINT8_C(0x8e));
  TEST_ASSERT(gate.offset_middle == UINT16_C(0x5566));
  TEST_ASSERT(gate.offset_high == UINT32_C(0x11223344) && gate.reserved == 0);

  TEST_ASSERT(!zi_x64_exception_uses_error_code(0));
  TEST_ASSERT(zi_x64_exception_uses_error_code(8));
  TEST_ASSERT(zi_x64_exception_uses_error_code(14));
  TEST_ASSERT(zi_x64_exception_uses_error_code(21));
  TEST_ASSERT(zi_x64_exception_uses_error_code(30));
  TEST_ASSERT(!zi_x64_exception_uses_error_code(31));
  TEST_ASSERT(zi_memory_compare(zi_x64_exception_name(6), "Invalid opcode", 14) == 0);
  TEST_ASSERT(zi_memory_compare(zi_x64_exception_name(14), "Page fault", 10) == 0);
  TEST_ASSERT(sizeof(ZiX64InterruptFrame) == 176);
  TEST_ASSERT(offsetof(ZiX64InterruptFrame, rsp) == 160);
  TEST_ASSERT(offsetof(ZiX64InterruptFrame, ss) == 168);
  TEST_ASSERT(ZI_X64_INTERRUPT_RETURN_USER_TERMINATED == UINT64_MAX);
  TEST_ASSERT(_Alignof(ZiX64ThreadContext) >= 16);
  return true;
}

static bool test_syscall_frames(void) {
  TEST_ASSERT(sizeof(ZiSyscallFrame) == 208);
  TEST_ASSERT(offsetof(ZiSyscallFrame, r15) == 16);
  TEST_ASSERT(offsetof(ZiSyscallFrame, rax) == 128);
  TEST_ASSERT(offsetof(ZiSyscallFrame, number) == 136);
  TEST_ASSERT(offsetof(ZiSyscallFrame, argument_1) == 144);
  TEST_ASSERT(offsetof(ZiSyscallFrame, user_instruction_pointer) == 176);
  TEST_ASSERT(offsetof(ZiSyscallFrame, user_stack_pointer) == 184);
  TEST_ASSERT(offsetof(ZiSyscallFrame, user_flags) == 192);
  TEST_ASSERT(offsetof(ZiSyscallFrame, result) == 200);
  TEST_ASSERT(sizeof(ZiX64SyscallCpuState) == 64);
  TEST_ASSERT(offsetof(ZiX64SyscallCpuState, kernel_stack_top) == 8);
  TEST_ASSERT(offsetof(ZiX64SyscallCpuState, kernel_cr3) == 16);
  TEST_ASSERT(offsetof(ZiX64SyscallCpuState, resume_stack_pointer) == 24);
  TEST_ASSERT(offsetof(ZiX64SyscallCpuState, resume_instruction_pointer) == 32);
  TEST_ASSERT(offsetof(ZiX64SyscallCpuState, user_stack_scratch) == 48);
  TEST_ASSERT(offsetof(ZiX64SyscallCpuState, termination_value) == 56);

  ZiSyscallFrame frame = {0};
  frame.struct_size = sizeof frame;
  frame.version = ZI_X64_SYSCALL_FRAME_VERSION;
  frame.user_instruction_pointer = UINT64_C(0x0000000140001000);
  frame.user_stack_pointer = ZI_USER_STACK_TOP - 8u;
  frame.user_flags = UINT64_C(0x202);
  TEST_ASSERT(zi_x64_syscall_return_is_safe(&frame));
  frame.user_instruction_pointer = ZI_USER_ADDRESS_MAX_EXCLUSIVE;
  TEST_ASSERT(!zi_x64_syscall_return_is_safe(&frame));
  frame.user_instruction_pointer = UINT64_C(0x0000000140001000);
  frame.user_stack_pointer = ZI_USER_ADDRESS_MIN - 1u;
  TEST_ASSERT(!zi_x64_syscall_return_is_safe(&frame));
  frame.user_stack_pointer = ZI_USER_STACK_TOP - 8u;
  frame.user_flags |= UINT64_C(3) << 12;
  TEST_ASSERT(!zi_x64_syscall_return_is_safe(&frame));
  frame.user_flags = UINT64_C(0x202) | (UINT64_C(1) << 17);
  TEST_ASSERT(!zi_x64_syscall_return_is_safe(&frame));
  frame.user_flags = UINT64_C(0x200);
  TEST_ASSERT(!zi_x64_syscall_return_is_safe(&frame));
  frame.user_flags = UINT64_C(2);
  TEST_ASSERT(!zi_x64_syscall_return_is_safe(&frame));
  return true;
}

// Parsing, relocation, mapping, and malformed-image cases intentionally share one PE fixture.
// NOLINTNEXTLINE(readability-function-size)
static bool test_pe(void) {
  unsigned char image_data[1024] = {0};
  image_data[0] = 'M';
  image_data[1] = 'Z';
  zi_write_u32_le(image_data + 0x3c, 0x80);
  unsigned char* pe = image_data + 0x80;
  pe[0] = 'P';
  pe[1] = 'E';
  unsigned char* coff = pe + 4;
  zi_write_u16_le(coff, ZI_PE_MACHINE_AMD64);
  zi_write_u16_le(coff + 2, 1);
  zi_write_u16_le(coff + 16, 240);
  zi_write_u16_le(coff + 18, UINT16_C(0x0022));
  unsigned char* optional = coff + 20;
  zi_write_u16_le(optional, ZI_PE_OPTIONAL_MAGIC_PE32_PLUS);
  zi_write_u32_le(optional + 16, 0x1000);
  zi_write_u64_le(optional + 24, UINT64_C(0x0000000140000000));
  zi_write_u32_le(optional + 32, 0x1000);
  zi_write_u32_le(optional + 36, 0x200);
  zi_write_u32_le(optional + 56, 0x2000);
  zi_write_u32_le(optional + 60, 0x200);
  zi_write_u16_le(optional + 68, ZI_PE_SUBSYSTEM_NATIVE);
  zi_write_u32_le(optional + 108, 16);
  zi_write_u32_le(optional + (size_t)112 + ((size_t)5 * 8), 0x1100);
  zi_write_u32_le(optional + (size_t)112 + ((size_t)5 * 8) + 4, 12);
  unsigned char* section = optional + 240;
  section[0] = '.';
  section[1] = 't';
  section[2] = 'e';
  section[3] = 'x';
  section[4] = 't';
  zi_write_u32_le(section + 8, 16);
  zi_write_u32_le(section + 12, 0x1000);
  zi_write_u32_le(section + 16, 0x200);
  zi_write_u32_le(section + 20, 0x200);
  zi_write_u32_le(section + 36, ZI_PE_SECTION_READ | ZI_PE_SECTION_EXECUTE);
  zi_write_u64_le(image_data + 0x280, UINT64_C(0x0000000140001080));
  zi_write_u32_le(image_data + 0x300, 0x1000);
  zi_write_u32_le(image_data + 0x304, 12);
  zi_write_u16_le(image_data + 0x308, (uint16_t)((ZI_PE_RELOCATION_DIR64 << 12) | UINT16_C(0x080)));
  zi_write_u16_le(image_data + 0x30a, ZI_PE_RELOCATION_ABSOLUTE);

  ZiPeSection sections[2] = {0};
  ZiPeImage image = {0};
  TEST_ASSERT(ZiSucceeded(
      zi_pe_parse(image_data, sizeof image_data, sections, ARRAY_COUNT(sections), &image)));
  TEST_ASSERT(image.machine == ZI_PE_MACHINE_AMD64 && image.section_count == 1);
  TEST_ASSERT(image.relocation_directory.virtual_address == 0x1100);
  TEST_ASSERT(!zi_pe_has_imports(&image));
  unsigned char mapped_image[8192] = {0};
  TEST_ASSERT(ZiSucceeded(zi_pe_map_image(&image, mapped_image, sizeof mapped_image)));
  TEST_ASSERT(zi_read_u64_le(mapped_image + 0x1080) == UINT64_C(0x0000000140001080));
  TEST_ASSERT(ZiSucceeded(zi_pe_apply_relocations(&image,
                                                  mapped_image,
                                                  sizeof mapped_image,
                                                  UINT64_C(0x0000000150000000))));
  TEST_ASSERT(zi_read_u64_le(mapped_image + 0x1080) == UINT64_C(0x0000000150001080));
  mapped_image[0x1109] = UINT8_C(0x90);
  TEST_ASSERT(zi_pe_apply_relocations(&image,
                                      mapped_image,
                                      sizeof mapped_image,
                                      UINT64_C(0x0000000160000000)) ==
              ZI_STATUS_IMAGE_RELOCATION_FAILED);

  TestPagePool pool = {0};
  pool.fail_on_call = SIZE_MAX;
  ZiX64PagingContext kernel_paging = {0};
  TEST_ASSERT(ZiSucceeded(zi_x64_paging_create(&pool,
                                               test_page_allocate,
                                               test_page_release,
                                               test_page_pointer,
                                               true,
                                               &kernel_paging)));
  ZiAddressSpaceBacking backing = {
      sizeof(ZiAddressSpaceBacking),
      ZI_ADDRESS_SPACE_BACKING_VERSION,
      &pool,
      test_page_run_allocate,
      test_page_run_release,
      test_page_pointer,
  };
  ZiAddressSpace address_space = {0};
  TEST_ASSERT(ZiSucceeded(zi_address_space_initialise(&kernel_paging, &backing, &address_space)));
  ZiStringView module_name = {"fixture.exe", 11};
  ZiUserImageLoadOptions load_options = {
      sizeof(ZiUserImageLoadOptions),
      ZI_USER_IMAGE_LOAD_OPTIONS_VERSION,
      ZI_USER_IMAGE_LOAD_FORCE_RELOCATION,
      0,
      UINT64_C(0x0000000150000000),
      UINT64_C(0x0000000160000000),
      UINT64_C(0x10000),
      NULL,
      0,
  };
  ZiUserImageSet image_set = {0};
  TEST_ASSERT(ZiSucceeded(zi_pe_load_user_image(image_data,
                                                sizeof image_data,
                                                module_name,
                                                &load_options,
                                                &address_space,
                                                &image_set)));
  TEST_ASSERT(image_set.image_count == 1);
  const ZiUserImage* user_image = &image_set.images[0];
  TEST_ASSERT(user_image->image_base == UINT64_C(0x0000000150000000));
  TEST_ASSERT(user_image->entry_point == UINT64_C(0x0000000150001000));
  TEST_ASSERT((user_image->flags & ZI_USER_IMAGE_FLAG_RELOCATED) != 0);
  TEST_ASSERT(user_image->file_data == NULL && user_image->file_size == 0);
  ZiX64PageMapping user_mapping = {0};
  TEST_ASSERT(ZiSucceeded(zi_address_space_query(&address_space,
                                                 user_image->entry_point,
                                                 ZI_USER_ACCESS_EXECUTE,
                                                 &user_mapping)));
  TEST_ASSERT(zi_address_space_query(&address_space,
                                     user_image->image_base,
                                     ZI_USER_ACCESS_WRITE,
                                     &user_mapping) == ZI_STATUS_INVALID_USER_BUFFER);
  TEST_ASSERT(ZiSucceeded(zi_user_image_set_unload(&address_space, &image_set)));
  TEST_ASSERT(ZiSucceeded(zi_address_space_destroy(&address_space)));
  TEST_ASSERT(test_page_used_count(&pool) == 1);

  unsigned char cycle_main[sizeof image_data] = {0};
  unsigned char cycle_a[sizeof image_data] = {0};
  unsigned char cycle_b[sizeof image_data] = {0};
  zi_memory_copy(cycle_main, image_data, sizeof cycle_main);
  zi_memory_copy(cycle_a, image_data, sizeof cycle_a);
  zi_memory_copy(cycle_b, image_data, sizeof cycle_b);
  configure_dependency_fixture(cycle_main,
                               sizeof cycle_main,
                               UINT64_C(0x0000000140000000),
                               false,
                               "a.dll",
                               "A");
  configure_dependency_fixture(cycle_a,
                               sizeof cycle_a,
                               UINT64_C(0x0000000141000000),
                               true,
                               "b.dll",
                               "B");
  configure_dependency_fixture(cycle_b,
                               sizeof cycle_b,
                               UINT64_C(0x0000000142000000),
                               true,
                               "a.dll",
                               "A");
  const ZiUserModuleSource cycle_sources[] = {
      {{"a.dll", sizeof "a.dll" - 1u}, cycle_a, sizeof cycle_a},
      {{"b.dll", sizeof "b.dll" - 1u}, cycle_b, sizeof cycle_b},
  };
  load_options.flags = 0;
  load_options.module_sources = cycle_sources;
  load_options.module_source_count = ARRAY_COUNT(cycle_sources);
  module_name = (ZiStringView){"cycle.exe", sizeof "cycle.exe" - 1u};
  TEST_ASSERT(ZiSucceeded(zi_address_space_initialise(&kernel_paging, &backing, &address_space)));
  TEST_ASSERT(zi_pe_load_user_image(cycle_main,
                                    sizeof cycle_main,
                                    module_name,
                                    &load_options,
                                    &address_space,
                                    &image_set) == ZI_STATUS_IMAGE_DEPENDENCY_CYCLE);
  TEST_ASSERT(address_space.region_count == 0);
  TEST_ASSERT(ZiSucceeded(zi_address_space_destroy(&address_space)));
  TEST_ASSERT(test_page_used_count(&pool) == 1);

  load_options.module_sources = NULL;
  load_options.module_source_count = 0;
  TEST_ASSERT(ZiSucceeded(zi_address_space_initialise(&kernel_paging, &backing, &address_space)));
  TEST_ASSERT(zi_pe_load_user_image(cycle_main,
                                    sizeof cycle_main,
                                    module_name,
                                    &load_options,
                                    &address_space,
                                    &image_set) == ZI_STATUS_IMAGE_IMPORT_NOT_FOUND);
  TEST_ASSERT(address_space.region_count == 0);
  TEST_ASSERT(ZiSucceeded(zi_address_space_destroy(&address_space)));
  TEST_ASSERT(test_page_used_count(&pool) == 1);

  zi_write_u32_le(optional + 112 + 8, 0x1200);
  zi_write_u32_le(optional + 112 + 12, 40);
  TEST_ASSERT(ZiSucceeded(
      zi_pe_parse(image_data, sizeof image_data, sections, ARRAY_COUNT(sections), &image)));
  TEST_ASSERT(zi_pe_has_imports(&image));
  image_data[0] = 'N';
  TEST_ASSERT(zi_pe_parse(image_data, sizeof image_data, sections, ARRAY_COUNT(sections), &image) ==
              ZI_STATUS_BAD_IMAGE_FORMAT);
  image_data[0] = 'M';
  zi_write_u32_le(section + 20, 900);
  TEST_ASSERT(zi_pe_parse(image_data, sizeof image_data, sections, ARRAY_COUNT(sections), &image) ==
              ZI_STATUS_BAD_IMAGE_FORMAT);
  return true;
}

static bool test_terminal(void) {
  ZiTerminalCell cells[3 * 4] = {0};
  size_t used_columns[3] = {0};
  ZiTerminalBuffer terminal = {0};
  TEST_ASSERT(ZiSucceeded(zi_terminal_initialise(&terminal,
                                                 cells,
                                                 used_columns,
                                                 4,
                                                 3,
                                                 ZI_COLOUR_TEXT,
                                                 ZI_COLOUR_BACKGROUND)));
  TEST_ASSERT(ZiSucceeded(zi_terminal_write_utf8(&terminal, "abcde", 5)));
  TEST_ASSERT(terminal.line_count == 2 && terminal.cursor_column == 1);
  size_t used = 0;
  const ZiTerminalCell* line = zi_terminal_get_line(&terminal, 0, &used);
  TEST_ASSERT(line != NULL && used == 4 && line[0].scalar == 'a' && line[3].scalar == 'd');
  TEST_ASSERT(ZiSucceeded(zi_terminal_write_scalar(&terminal, UINT32_C(0x0301))));
  line = zi_terminal_get_line(&terminal, 1, &used);
  TEST_ASSERT(line != NULL && line[0].combining_count == 1);
  TEST_ASSERT(ZiSucceeded(zi_terminal_write_utf8(&terminal, "\nline2\nline3", 12)));
  TEST_ASSERT(terminal.line_count == 3);
  line = zi_terminal_get_line(&terminal, 0, &used);
  TEST_ASSERT(line != NULL && line[0].scalar != 'a');
  zi_terminal_page_up(&terminal, 2);
  TEST_ASSERT(terminal.viewport_offset == 2);
  zi_terminal_page_down(&terminal, 1);
  TEST_ASSERT(terminal.viewport_offset == 1);
  zi_terminal_page_down(&terminal, 2);
  TEST_ASSERT(terminal.viewport_offset == 0);

  char history_storage[3 * 16] = {0};
  ZiCommandHistory history = {0};
  TEST_ASSERT(ZiSucceeded(zi_history_initialise(&history, history_storage, 3, 16)));
  TEST_ASSERT(ZiSucceeded(zi_history_add(&history, "one", 3)));
  TEST_ASSERT(ZiSucceeded(zi_history_add(&history, "two", 3)));
  TEST_ASSERT(ZiSucceeded(zi_history_add(&history, "three", 5)));
  TEST_ASSERT(ZiSucceeded(zi_history_add(&history, "four", 4)));
  ZiStringView entry = {0};
  TEST_ASSERT(ZiSucceeded(zi_history_previous(&history, &entry)));
  TEST_ASSERT(string_view_equal(entry, "four", 4));
  TEST_ASSERT(ZiSucceeded(zi_history_previous(&history, &entry)));
  TEST_ASSERT(string_view_equal(entry, "three", 5));
  TEST_ASSERT(ZiSucceeded(zi_history_next(&history, &entry)));
  TEST_ASSERT(string_view_equal(entry, "four", 4));
  return true;
}

static bool test_display_scale(void) {
  ZiScaleFactor scale = zi_display_default_scale(1080);
  TEST_ASSERT(scale.numerator == 1 && scale.denominator == 1);
  scale = zi_display_default_scale(1081);
  TEST_ASSERT(scale.numerator == 5 && scale.denominator == 4);
  TEST_ASSERT(zi_scale_u32(16, scale) == 20);
  scale = zi_display_default_scale(1441);
  TEST_ASSERT(scale.numerator == 2 && scale.denominator == 1);
  scale = zi_display_default_scale(2161);
  TEST_ASSERT(scale.numerator == 5 && scale.denominator == 2);
  TEST_ASSERT(zi_scale_u32(10, (ZiScaleFactor){1, 0}) == 0);
  const uint8_t* upper_i = zi_font_glyph('I');
  const uint8_t* lower_l = zi_font_glyph('l');
  const uint8_t* digit_one = zi_font_glyph('1');
  const uint8_t* upper_o = zi_font_glyph('O');
  const uint8_t* digit_zero = zi_font_glyph('0');
  TEST_ASSERT(zi_memory_compare(upper_i, lower_l, ZI_EARLY_FONT_HEIGHT) != 0);
  TEST_ASSERT(zi_memory_compare(upper_i, digit_one, ZI_EARLY_FONT_HEIGHT) != 0);
  TEST_ASSERT(zi_memory_compare(upper_o, digit_zero, ZI_EARLY_FONT_HEIGHT) != 0);
  return true;
}

static bool test_luma(void) {
  char command[] = "Get-File \"C:\\Program Files\"";
  ZiStringView arguments[4] = {0};
  size_t argument_count = 0;
  TEST_ASSERT(ZiSucceeded(zi_luma_tokenise(command,
                                           sizeof command - 1,
                                           arguments,
                                           ARRAY_COUNT(arguments),
                                           &argument_count)));
  TEST_ASSERT(argument_count == 2);
  TEST_ASSERT(string_view_equal(arguments[0], "Get-File", 8));
  TEST_ASSERT(string_view_equal(arguments[1], "C:\\Program Files", 16));

  char unicode_command[] = {'S', 'h', 'o', 'w', ' ', 'C', ':', '\\', (char)0xc3, (char)0x91};
  TEST_ASSERT(ZiSucceeded(zi_luma_tokenise(unicode_command,
                                           sizeof unicode_command,
                                           arguments,
                                           ARRAY_COUNT(arguments),
                                           &argument_count)));
  TEST_ASSERT(argument_count == 2 && arguments[1].size == 5);
  char incomplete[] = "Get-File \"C:\\Temp";
  TEST_ASSERT(zi_luma_tokenise(incomplete,
                               sizeof incomplete - 1,
                               arguments,
                               ARRAY_COUNT(arguments),
                               &argument_count) == ZI_STATUS_INVALID_ARGUMENT);
  char too_many[] = "a b c d e";
  TEST_ASSERT(zi_luma_tokenise(too_many,
                               sizeof too_many - 1,
                               arguments,
                               ARRAY_COUNT(arguments),
                               &argument_count) == ZI_STATUS_BUFFER_TOO_SMALL);
  return true;
}

static bool test_phase3_process_parameters(void) {
  size_t assertions = 0;
  bool result = phase3_process_parameters_test(&assertions);
  g_assertion_count += assertions;
  return result;
}

static bool test_phase3_process_lifecycle(void) {
  size_t assertions = 0;
  bool result = phase3_process_lifecycle_test(&assertions);
  g_assertion_count += assertions;
  return result;
}

static bool test_phase3_pe_linking(void) {
  size_t assertions = 0;
  bool result = phase3_pe_linking_test(&assertions);
  g_assertion_count += assertions;
  return result;
}

static bool test_phase4_object_namespace(void) {
  size_t assertion_count = 0;
  bool result = phase4_object_namespace_test(&assertion_count);
  g_assertion_count += assertion_count;
  return result;
}

static bool test_phase4_handle_table(void) {
  size_t assertion_count = 0;
  bool result = phase4_handle_table_test(&assertion_count);
  g_assertion_count += assertion_count;
  return result;
}

static bool test_phase4_dispatcher(void) {
  size_t assertion_count = 0;
  bool result = phase4_dispatcher_test(&assertion_count);
  g_assertion_count += assertion_count;
  return result;
}

static bool test_phase4_ipc(void) {
  size_t assertion_count = 0;
  bool result = phase4_ipc_test(&assertion_count);
  g_assertion_count += assertion_count;
  return result;
}

static bool test_phase5_acpi(void) {
  size_t assertion_count = 0;
  bool result = phase5_acpi_test(&assertion_count);
  g_assertion_count += assertion_count;
  return result;
}

static bool test_phase5_pci(void) {
  size_t assertion_count = 0;
  bool result = phase5_pci_test(&assertion_count);
  g_assertion_count += assertion_count;
  return result;
}

static bool test_phase5_dma(void) {
  size_t assertion_count = 0;
  bool result = phase5_dma_test(&assertion_count);
  g_assertion_count += assertion_count;
  return result;
}

static bool test_phase5_gpt(void) {
  size_t assertion_count = 0;
  bool result = phase5_gpt_test(&assertion_count);
  g_assertion_count += assertion_count;
  return result;
}

static bool test_phase5_io(void) {
  size_t assertion_count = 0;
  bool result = phase5_io_test(&assertion_count);
  g_assertion_count += assertion_count;
  return result;
}

static bool test_phase6_zifs_files(void) {
  size_t assertion_count = 0;
  bool result = phase6_zifs_file_test(&assertion_count);
  g_assertion_count += assertion_count;
  return result;
}

static bool test_phase6_service_manifests(void) {
  size_t assertion_count = 0;
  bool result = phase6_service_manifest_test(&assertion_count);
  g_assertion_count += assertion_count;
  return result;
}

static bool test_phase7_zifs_wire(void) {
  size_t assertion_count = 0;
  bool result = phase7_zifs_wire_test(&assertion_count);
  g_assertion_count += assertion_count;
  return result;
}

static bool test_phase7_zifs_security(void) {
  size_t assertion_count = 0;
  bool result = phase7_zifs_security_test(&assertion_count);
  g_assertion_count += assertion_count;
  return result;
}
// NOLINTEND(readability-function-cognitive-complexity)

static ZiStatus memory_read_blocks(void* context,
                                   uint64_t first_block,
                                   uint32_t block_count,
                                   void* output,
                                   size_t output_size) {
  if (context == NULL || output == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  MemoryBlockDevice* memory = context;
  if (first_block > SIZE_MAX / ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  size_t offset = (size_t)first_block * ZI_FS_BLOCK_SIZE;
  size_t byte_count = (size_t)block_count * ZI_FS_BLOCK_SIZE;
  if (offset > memory->size || byte_count > memory->size - offset || output_size < byte_count) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  zi_memory_copy(output, memory->data + offset, byte_count);
  return ZI_STATUS_SUCCESS;
}

static bool initialise_test_volume(unsigned char* volume, size_t volume_size) {
  if (volume == NULL || volume_size != (size_t)16 * ZI_FS_BLOCK_SIZE) {
    return false;
  }
  zi_memory_zero(volume, volume_size);
  ZiFsSuperblock superblock = {0};
  superblock.format_major = ZI_FS_FORMAT_MAJOR;
  superblock.format_minor = ZI_FS_FORMAT_MINOR;
  superblock.block_shift = ZI_FS_BLOCK_SHIFT;
  superblock.checksum_type = 1;
  superblock.incompatible_features = ZI_FS_FEATURE_INCOMPAT_SECURITY_V1;
  superblock.generation = 1;
  superblock.total_blocks = 16;
  superblock.root_record_index = 0;
  superblock.record_table_start = 1;
  superblock.record_table_blocks = 1;
  superblock.allocation_bitmap_start = 2;
  superblock.allocation_bitmap_blocks = 1;
  superblock.journal_start = 3;
  superblock.journal_blocks = 1;
  superblock.security_table_start = 4;
  superblock.security_table_blocks = 1;
  superblock.directory_table_start = 5;
  superblock.directory_table_blocks = 2;
  superblock.backup_superblock = 15;
  superblock.volume_name_size = 6;
  zi_memory_copy(superblock.volume_name, "Zizium", 6);
  if (ZiFailed(ZiFsEncodeSuperblock(&superblock, volume, ZI_FS_BLOCK_SIZE))) {
    return false;
  }
  zi_memory_copy(volume + ((size_t)15 * ZI_FS_BLOCK_SIZE), volume, ZI_FS_BLOCK_SIZE);

  ZiFsFileRecord root = {0};
  root.file_id = 1;
  root.parent_file_id = 1;
  root.security_id = 1;
  root.file_type = ZI_FS_FILE_TYPE_DIRECTORY;
  root.directory_block = 5;
  ZiFsFileRecord temp = {0};
  temp.file_id = 2;
  temp.parent_file_id = 1;
  temp.security_id = 1;
  temp.file_type = ZI_FS_FILE_TYPE_DIRECTORY;
  temp.directory_block = 6;
  if (!initialise_test_security_table(volume + ((size_t)4 * ZI_FS_BLOCK_SIZE), ZI_FS_BLOCK_SIZE)) {
    return false;
  }

  unsigned char* record_block = volume + ZI_FS_BLOCK_SIZE;
  if (ZiFailed(ZiFsEncodeFileRecord(&root, record_block, ZI_FS_FILE_RECORD_SIZE)) ||
      ZiFailed(ZiFsEncodeFileRecord(&temp,
                                    record_block + ZI_FS_FILE_RECORD_SIZE,
                                    ZI_FS_FILE_RECORD_SIZE))) {
    return false;
  }

  unsigned char* root_directory = volume + ((size_t)5 * ZI_FS_BLOCK_SIZE);
  unsigned char* temp_directory = volume + ((size_t)6 * ZI_FS_BLOCK_SIZE);
  ZiFsDirectoryEntry temp_entry = {
      2,
      1,
      ZI_FS_FILE_TYPE_DIRECTORY,
      0,
      {"Temp", 4},
  };
  return (
      bool)(ZiSucceeded(
                ZiFsInitialiseDirectoryBlock(root_directory, ZI_FS_BLOCK_SIZE, root.file_id, 1)) &&
            ZiSucceeded(ZiFsAddDirectoryEntry(root_directory, ZI_FS_BLOCK_SIZE, &temp_entry)) &&
            ZiSucceeded(
                ZiFsInitialiseDirectoryBlock(temp_directory, ZI_FS_BLOCK_SIZE, temp.file_id, 1)));
}

static bool initialise_test_security_table(void* block, size_t block_size) {
  const ZiSecurityId owner = {ZI_SECURITY_AUTHORITY_USER, 21};
  const ZiSecurityId group = {ZI_SECURITY_AUTHORITY_GROUP, 7};
  const ZiAce entries[] = {
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_FULL_CONTROL, owner},
  };
  const ZiAcl dacl = {sizeof(ZiAcl), ZI_ACL_VERSION, entries, ARRAY_COUNT(entries)};
  const ZiSecurityDescriptor descriptor = {
      sizeof(ZiSecurityDescriptor),
      ZI_SECURITY_DESCRIPTOR_VERSION,
      owner,
      group,
      &dacl,
      ZI_SECURITY_DESCRIPTOR_CONTROL_NONE,
  };
  return (
      bool)(ZiSucceeded(ZiFsInitialiseSecurityTable(block, block_size, 1)) &&
            ZiSucceeded(ZiFsAppendSecurityDescriptor(block,
                                                     block_size,
                                                     1,
                                                     ZI_FS_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT,
                                                     &descriptor)));
}

static ZiStatus test_page_allocate(void* context, uint64_t* out_physical_base) {
  if (context == NULL || out_physical_base == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  TestPagePool* pool = context;
  size_t call = pool->allocation_calls++;
  if (call == pool->fail_on_call) {
    return ZI_STATUS_NO_MEMORY;
  }
  for (size_t index = 0; index < TEST_PAGE_POOL_CAPACITY; ++index) {
    if (!pool->used[index]) {
      pool->used[index] = true;
      *out_physical_base = ((uint64_t)index + 1) * ZI_X64_PAGE_SIZE;
      return ZI_STATUS_SUCCESS;
    }
  }
  return ZI_STATUS_NO_MEMORY;
}

static void test_page_release(void* context, uint64_t physical_base) {
  if (context == NULL || physical_base == 0 || (physical_base & (ZI_X64_PAGE_SIZE - 1)) != 0) {
    return;
  }
  uint64_t page_number = physical_base / ZI_X64_PAGE_SIZE;
  if (page_number == 0 || page_number > TEST_PAGE_POOL_CAPACITY) {
    return;
  }
  TestPagePool* pool = context;
  size_t index = (size_t)(page_number - 1);
  pool->used[index] = false;
  zi_memory_zero(pool->pages[index], sizeof pool->pages[index]);
}

static ZiStatus
test_page_pointer(void* context, uint64_t physical_base, size_t size, void** out_pointer) {
  if (context == NULL || out_pointer == NULL || size == 0 || size > ZI_X64_PAGE_SIZE ||
      physical_base == 0 || (physical_base & (ZI_X64_PAGE_SIZE - 1)) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t page_number = physical_base / ZI_X64_PAGE_SIZE;
  if (page_number == 0 || page_number > TEST_PAGE_POOL_CAPACITY) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  TestPagePool* pool = context;
  size_t index = (size_t)(page_number - 1);
  if (!pool->used[index]) {
    return ZI_STATUS_INVALID_STATE;
  }
  *out_pointer = pool->pages[index];
  return ZI_STATUS_SUCCESS;
}

static ZiStatus test_page_run_allocate(void* context,
                                       uint64_t page_count,
                                       uint32_t owner,
                                       uint64_t* out_physical_base) {
  if (context == NULL || out_physical_base == NULL || page_count == 0 || owner == 0 ||
      page_count > TEST_PAGE_POOL_CAPACITY) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  TestPagePool* pool = context;
  size_t count = (size_t)page_count;
  for (size_t start = 0; start + count <= TEST_PAGE_POOL_CAPACITY; ++start) {
    bool available = true;
    for (size_t index = 0; index < count; ++index) {
      if (pool->used[start + index]) {
        available = false;
        break;
      }
    }
    if (!available) {
      continue;
    }
    for (size_t index = 0; index < count; ++index) {
      pool->used[start + index] = true;
    }
    *out_physical_base = ((uint64_t)start + 1u) * ZI_X64_PAGE_SIZE;
    return ZI_STATUS_SUCCESS;
  }
  return ZI_STATUS_NO_MEMORY;
}

static ZiStatus test_page_run_release(void* context,
                                      uint64_t physical_base,
                                      uint64_t page_count,
                                      uint32_t expected_owner) {
  if (context == NULL || physical_base == 0 || page_count == 0 || expected_owner == 0 ||
      (physical_base & (ZI_X64_PAGE_SIZE - 1)) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t first_page = physical_base / ZI_X64_PAGE_SIZE;
  if (first_page == 0 || first_page - 1u > TEST_PAGE_POOL_CAPACITY ||
      page_count > TEST_PAGE_POOL_CAPACITY - (first_page - 1u)) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  TestPagePool* pool = context;
  size_t start = (size_t)(first_page - 1u);
  for (size_t index = 0; index < (size_t)page_count; ++index) {
    if (!pool->used[start + index]) {
      return ZI_STATUS_INVALID_STATE;
    }
  }
  for (size_t index = 0; index < (size_t)page_count; ++index) {
    pool->used[start + index] = false;
    zi_memory_zero(pool->pages[start + index], sizeof pool->pages[start + index]);
  }
  return ZI_STATUS_SUCCESS;
}

static size_t test_page_used_count(const TestPagePool* pool) {
  size_t count = 0;
  for (size_t index = 0; index < TEST_PAGE_POOL_CAPACITY; ++index) {
    if (pool->used[index]) {
      ++count;
    }
  }
  return count;
}

static void configure_dependency_fixture(unsigned char* image_data,
                                         size_t image_size,
                                         uint64_t image_base,
                                         bool is_library,
                                         const char* dependency_name,
                                         const char* symbol_name) {
  if (image_data == NULL || image_size < 1024 || dependency_name == NULL || symbol_name == NULL) {
    return;
  }
  unsigned char* coff = image_data + 0x84;
  unsigned char* optional = coff + 20;
  uint16_t characteristics = UINT16_C(0x0022);
  uint32_t export_address = 0;
  uint32_t export_size = 0;
  if (is_library) {
    characteristics = UINT16_C(0x2022);
    export_address = UINT32_C(0x1140);
    export_size = 40;
  }
  zi_write_u16_le(coff + 18, characteristics);
  zi_write_u64_le(optional + 24, image_base);
  zi_write_u32_le(optional + 112, export_address);
  zi_write_u32_le(optional + 116, export_size);
  zi_write_u32_le(optional + 120, UINT32_C(0x1080));
  zi_write_u32_le(optional + 124, 40);
  zi_write_u32_le(optional + 152, 0);
  zi_write_u32_le(optional + 156, 0);
  zi_memory_zero(image_data + 0x280, 0x180);
  zi_write_u32_le(image_data + 0x280, UINT32_C(0x10c0));
  zi_write_u32_le(image_data + 0x28c, UINT32_C(0x10e0));
  zi_write_u32_le(image_data + 0x290, UINT32_C(0x10d0));
  zi_write_u64_le(image_data + 0x2c0, UINT64_C(0x10f0));
  zi_write_u64_le(image_data + 0x2d0, UINT64_C(0x10f0));
  size_t dependency_size = 0;
  while (dependency_name[dependency_size] != '\0') {
    ++dependency_size;
  }
  zi_memory_copy(image_data + 0x2e0, dependency_name, dependency_size + 1u);
  size_t symbol_size = 0;
  while (symbol_name[symbol_size] != '\0') {
    ++symbol_size;
  }
  zi_memory_copy(image_data + 0x2f2, symbol_name, symbol_size + 1u);
}

static void test_object_destroy(ZiObjectHeader* object) {
  if (object != NULL) {
    ++g_destructor_calls;
  }
}

static bool string_view_equal(ZiStringView view, const char* text, size_t text_size) {
  return (bool)(view.size == text_size && zi_memory_compare(view.data, text, text_size) == 0);
}

static bool assert_true(bool condition, const char* expression, const char* file, int line) {
  ++g_assertion_count;
  if (!condition) {
    if (fprintf_s(stderr, "%s:%d: assertion failed: %s\n", file, line, expression) < 0) {
      return false;
    }
  }
  return condition;
}
