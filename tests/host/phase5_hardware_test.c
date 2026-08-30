// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "phase5_tests.h"
#include "zi/acpi.h"
#include "zi/block.h"
#include "zi/byte_order.h"
#include "zi/crc32.h"
#include "zi/dma.h"
#include "zi/gpt.h"
#include "zi/memory.h"
#include "zi/pci.h"
#include "zizium/status.h"

#define PHASE5_ASSERT(expression)                                                                  \
  do {                                                                                             \
    ++assertions;                                                                                  \
    if (!(expression)) {                                                                           \
      (void)fprintf_s(stderr, "%s:%d: assertion failed: %s\n", __FILE__, __LINE__, #expression);   \
      *out_assertion_count = assertions;                                                           \
      return false;                                                                                \
    }                                                                                              \
  } while (false)

#define ACPI_FIXTURE_SIZE (64u * 1024u)
#define PCI_CONFIG_SIZE 4096u
#define GPT_BLOCK_SIZE 512u
#define GPT_BLOCK_COUNT 128u
#define GPT_ENTRY_COUNT 128u
#define GPT_ENTRY_SIZE 128u
#define GPT_ENTRY_BLOCKS 32u

typedef struct MemoryFixture {
  unsigned char* bytes;
  size_t size;
} MemoryFixture;

typedef struct PciFixture {
  unsigned char configuration[32][PCI_CONFIG_SIZE];
  uint32_t probe_masks[ZI_PCI_BAR_COUNT];
} PciFixture;

typedef struct DmaFixture {
  _Alignas(ZI_MEMORY_PAGE_SIZE) unsigned char pages[4][ZI_MEMORY_PAGE_SIZE];
  bool allocated;
  uint32_t owner;
  uint32_t synchronise_count;
  uint32_t last_direction;
} DmaFixture;

static unsigned char s_acpi_fixture[ACPI_FIXTURE_SIZE];
static PciFixture s_pci_fixture;
static unsigned char s_gpt_fixture[GPT_BLOCK_COUNT][GPT_BLOCK_SIZE];
static uint32_t s_gpt_flush_count;
static uint32_t s_gpt_write_count;
static uint64_t s_gpt_last_write_block;
static uint32_t s_gpt_last_write_count;

static ZiStatus memory_read(void* context, uint64_t physical_address, void* output, size_t size);
static void build_acpi_fixture(bool overlapping_mcfg);
static void initialise_sdt(unsigned char* table, const char signature[4], uint32_t length);
static void set_checksum(unsigned char* bytes, size_t size, size_t checksum_offset);
static ZiStatus
pci_read32(void* context, ZiPciAddress address, uint16_t offset, uint32_t* out_value);
static ZiStatus pci_write32(void* context, ZiPciAddress address, uint16_t offset, uint32_t value);
static void build_pci_fixture(void);
static ZiStatus dma_allocate_pages(void* context,
                                   uint64_t page_count,
                                   uint64_t alignment_pages,
                                   uint64_t maximum_physical_address,
                                   uint32_t owner,
                                   uint64_t* out_physical_address);
static ZiStatus dma_release_pages(void* context,
                                  uint64_t physical_address,
                                  uint64_t page_count,
                                  uint32_t expected_owner);
static ZiStatus
dma_physical_pointer(void* context, uint64_t physical_address, size_t size, void** out_pointer);
static void dma_synchronise(void* context, uint32_t direction);
static ZiStatus gpt_read_blocks(void* context,
                                uint64_t first_block,
                                uint32_t block_count,
                                void* output,
                                size_t output_size);
static ZiStatus gpt_write_blocks(void* context,
                                 uint64_t first_block,
                                 uint32_t block_count,
                                 const void* input,
                                 size_t input_size);
static ZiStatus gpt_flush(void* context);
static bool test_partition_write_contract(const ZiBlockDevice* device,
                                          const ZiGptPartition* zifs,
                                          ZiPartitionBlockContext* partition_context,
                                          ZiBlockDevice* partition_device,
                                          size_t* out_assertion_count);
static void build_gpt_fixture(bool overlapping);
static void encode_gpt_header(unsigned char* block,
                              uint64_t current_lba,
                              uint64_t backup_lba,
                              uint64_t entries_lba,
                              uint32_t entries_crc);
static void encode_partition(unsigned char* entry,
                             const ZiGuid* type,
                             uint8_t unique_value,
                             uint64_t first_lba,
                             uint64_t last_lba);
static bool bytes_are_zero(const unsigned char* bytes, size_t size);

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
bool phase5_acpi_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  size_t assertions = 0;
  *out_assertion_count = 0;
  build_acpi_fixture(false);
  MemoryFixture memory = {s_acpi_fixture, sizeof s_acpi_fixture};
  ZiAcpiPhysicalReader reader = {
      sizeof(ZiAcpiPhysicalReader),
      ZI_ACPI_PHYSICAL_READER_VERSION,
      &memory,
      memory_read,
  };
  ZiAcpiContext context = {0};
  PHASE5_ASSERT(ZiSucceeded(zi_acpi_initialise(0x100, &reader, &context)));
  PHASE5_ASSERT(context.acpi_revision == 2 && context.root_entry_size == 8 &&
                context.root_entry_count == 1);
  ZiAcpiMcfgAllocation allocations[2] = {0};
  size_t count = 0;
  PHASE5_ASSERT(ZiSucceeded(zi_acpi_parse_mcfg(&context, allocations, 2, &count)));
  PHASE5_ASSERT(count == 1 && allocations[0].base_address == UINT64_C(0xe0000000));
  PHASE5_ASSERT(allocations[0].segment_group == 0 && allocations[0].start_bus == 0 &&
                allocations[0].end_bus == UINT8_MAX);
  PHASE5_ASSERT(zi_acpi_parse_mcfg(&context, allocations, 0, &count) == ZI_STATUS_BUFFER_TOO_SMALL);

  s_acpi_fixture[0x100 + 8] ^= 1;
  PHASE5_ASSERT(zi_acpi_initialise(0x100, &reader, &context) == ZI_STATUS_CHECKSUM_MISMATCH);
  s_acpi_fixture[0x100 + 8] ^= 1;
  build_acpi_fixture(false);
  s_acpi_fixture[0x2000 + 9] ^= 1;
  PHASE5_ASSERT(ZiSucceeded(zi_acpi_initialise(0x100, &reader, &context)));
  PHASE5_ASSERT(zi_acpi_parse_mcfg(&context, allocations, 2, &count) ==
                ZI_STATUS_CHECKSUM_MISMATCH);

  build_acpi_fixture(true);
  PHASE5_ASSERT(ZiSucceeded(zi_acpi_initialise(0x100, &reader, &context)));
  PHASE5_ASSERT(zi_acpi_parse_mcfg(&context, allocations, 2, &count) == ZI_STATUS_ADDRESS_CONFLICT);
  *out_assertion_count = assertions;
  return true;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
bool phase5_pci_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  size_t assertions = 0;
  *out_assertion_count = 0;
  build_pci_fixture();
  ZiPciConfigAccess access = {
      sizeof(ZiPciConfigAccess),
      ZI_PCI_CONFIG_ACCESS_VERSION,
      &s_pci_fixture,
      pci_read32,
      pci_write32,
  };
  ZiAcpiMcfgAllocation allocation = {UINT64_C(0xe0000000), 0, 0, 0};
  ZiPciAddress address = {0, 0, 4, 0};
  uint64_t ecam_address = 0;
  PHASE5_ASSERT(ZiSucceeded(zi_pci_ecam_address(&allocation, address, 0x10, &ecam_address)));
  PHASE5_ASSERT(ecam_address == UINT64_C(0xe0020010));
  PHASE5_ASSERT(zi_pci_ecam_address(&allocation, address, 3, &ecam_address) ==
                ZI_STATUS_INVALID_ARGUMENT);

  ZiPciDevice devices[4] = {0};
  size_t count = 0;
  PHASE5_ASSERT(ZiSucceeded(zi_pci_enumerate(&allocation, 1, &access, devices, 4, &count)) &&
                count == 1);
  PHASE5_ASSERT(devices[0].vendor_id == UINT16_C(0x1b36) &&
                devices[0].device_id == UINT16_C(0x0010));
  PHASE5_ASSERT(devices[0].class_code == 1 && devices[0].subclass == 8 &&
                devices[0].programming_interface == 2);
  PHASE5_ASSERT(devices[0].bars[0].kind == ZI_PCI_BAR_MEMORY && devices[0].bars[0].is_64_bit == 1 &&
                devices[0].bars[0].base_address == UINT64_C(0x80000000));
  PHASE5_ASSERT(ZiSucceeded(zi_pci_probe_bars(&access, &devices[0])));
  PHASE5_ASSERT(devices[0].bars[0].size == UINT64_C(0x4000));
  uint32_t command = 0;
  PHASE5_ASSERT(ZiSucceeded(pci_read32(&s_pci_fixture, address, 4, &command)) &&
                (uint16_t)command == UINT16_C(0x0003));
  PHASE5_ASSERT(ZiSucceeded(zi_pci_set_command_bits(&access, address, 4, 1)));
  PHASE5_ASSERT(ZiSucceeded(pci_read32(&s_pci_fixture, address, 4, &command)) &&
                (uint16_t)command == UINT16_C(0x0006));

  const ZiPciDriverMatch matches[] = {
      {ZI_PCI_MATCH_ANY_U16, ZI_PCI_MATCH_ANY_U16, 1, 8, 2, 10, 1},
      {UINT16_C(0x1b36),
       UINT16_C(0x0010),
       ZI_PCI_MATCH_ANY_U8,
       ZI_PCI_MATCH_ANY_U8,
       ZI_PCI_MATCH_ANY_U8,
       1,
       2},
      {ZI_PCI_MATCH_ANY_U16,
       ZI_PCI_MATCH_ANY_U16,
       ZI_PCI_MATCH_ANY_U8,
       ZI_PCI_MATCH_ANY_U8,
       ZI_PCI_MATCH_ANY_U8,
       255,
       3},
  };
  const ZiPciDriverMatch* selected = NULL;
  PHASE5_ASSERT(ZiSucceeded(
      zi_pci_select_driver(&devices[0], matches, sizeof matches / sizeof matches[0], &selected)));
  PHASE5_ASSERT(selected != NULL && selected->driver_id == 2);
  *out_assertion_count = assertions;
  return true;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
bool phase5_dma_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  size_t assertions = 0;
  *out_assertion_count = 0;
  DmaFixture fixture = {0};
  // The cast intentionally treats the complete two-dimensional array as bytes.
  // NOLINTNEXTLINE(bugprone-sizeof-expression, cert-arr39-c)
  for (size_t index = 0; index < sizeof fixture.pages; ++index) {
    ((unsigned char*)fixture.pages)[index] = UINT8_C(0xa5);
  }
  ZiDmaAllocator allocator = {
      sizeof(ZiDmaAllocator),
      ZI_DMA_ALLOCATOR_VERSION,
      &fixture,
      dma_allocate_pages,
      dma_release_pages,
      dma_physical_pointer,
      dma_synchronise,
  };
  ZiDmaBuffer buffer = {0};
  PHASE5_ASSERT(ZiSucceeded(zi_dma_allocate(&allocator,
                                            ZI_MEMORY_PAGE_SIZE + 21,
                                            ZI_MEMORY_PAGE_SIZE,
                                            UINT64_MAX,
                                            ZI_MEMORY_OWNER_DMA,
                                            &buffer)));
  PHASE5_ASSERT(buffer.allocated == 1 && buffer.page_count == 2 &&
                buffer.owner == ZI_MEMORY_OWNER_DMA);
  PHASE5_ASSERT(bytes_are_zero(buffer.virtual_address, 2 * ZI_MEMORY_PAGE_SIZE));
  PHASE5_ASSERT(ZiSucceeded(zi_dma_synchronise(&allocator, ZI_DMA_TO_DEVICE)) &&
                fixture.synchronise_count == 1 && fixture.last_direction == ZI_DMA_TO_DEVICE);
  PHASE5_ASSERT(ZiSucceeded(zi_dma_release(&allocator, &buffer)) && !fixture.allocated);
  PHASE5_ASSERT(zi_dma_release(&allocator, &buffer) == ZI_STATUS_INVALID_ARGUMENT);
  PHASE5_ASSERT(zi_dma_allocate(&allocator,
                                ZI_MEMORY_PAGE_SIZE,
                                ZI_MEMORY_PAGE_SIZE,
                                ZI_MEMORY_PAGE_SIZE - 1,
                                ZI_MEMORY_OWNER_DMA,
                                &buffer) == ZI_STATUS_NO_MEMORY);
  *out_assertion_count = assertions;
  return true;
}

// The assertion macro deliberately contributes one branch per checked contract.
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static bool test_partition_write_contract(const ZiBlockDevice* device,
                                          const ZiGptPartition* zifs,
                                          ZiPartitionBlockContext* partition_context,
                                          ZiBlockDevice* partition_device,
                                          size_t* out_assertion_count) {
  size_t assertions = 0;
  *out_assertion_count = 0;
  PHASE5_ASSERT(ZiSucceeded(zi_block_barrier(partition_device)) && s_gpt_flush_count == 1);
  unsigned char write_data[4096] = {0};
  for (size_t index = 0; index < sizeof write_data; ++index) {
    write_data[index] = (unsigned char)(index ^ UINT8_C(0x5a));
  }
  PHASE5_ASSERT(
      ZiSucceeded(zi_block_write(partition_device, 1, 1, write_data, sizeof write_data)) &&
      s_gpt_write_count == 1 && s_gpt_last_write_block == 58 && s_gpt_last_write_count == 8);
  bool write_matches = true;
  for (size_t index = 0; index < sizeof write_data; ++index) {
    if (s_gpt_fixture[58u + (index / GPT_BLOCK_SIZE)][index % GPT_BLOCK_SIZE] !=
        write_data[index]) {
      write_matches = false;
      break;
    }
  }
  PHASE5_ASSERT(write_matches);
  PHASE5_ASSERT(zi_block_write(partition_device, 5, 1, write_data, sizeof write_data) ==
                ZI_STATUS_OUT_OF_BOUNDS);
  PHASE5_ASSERT(zi_block_write(partition_device, 0, 1, write_data, sizeof write_data - 1u) ==
                ZI_STATUS_OUT_OF_BOUNDS);

  ZiBlockDevice read_only_parent = *device;
  read_only_parent.flags = ZI_BLOCK_DEVICE_READ_ONLY | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED;
  read_only_parent.write_blocks = NULL;
  PHASE5_ASSERT(ZiSucceeded(zi_partition_block_initialise(&read_only_parent,
                                                          zifs->first_lba,
                                                          zifs->last_lba - zifs->first_lba + 1,
                                                          4096,
                                                          partition_context,
                                                          partition_device)));
  PHASE5_ASSERT(zi_block_write(partition_device, 0, 1, write_data, sizeof write_data) ==
                ZI_STATUS_READ_ONLY_FILESYSTEM);
  ZiBlockDevice inconsistent_parent = *device;
  inconsistent_parent.write_blocks = NULL;
  PHASE5_ASSERT(zi_partition_block_initialise(&inconsistent_parent,
                                              zifs->first_lba,
                                              zifs->last_lba - zifs->first_lba + 1,
                                              4096,
                                              partition_context,
                                              partition_device) == ZI_STATUS_INVALID_ARGUMENT);
  *out_assertion_count = assertions;
  return true;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
bool phase5_gpt_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  size_t assertions = 0;
  *out_assertion_count = 0;
  build_gpt_fixture(false);
  s_gpt_flush_count = 0;
  s_gpt_write_count = 0;
  s_gpt_last_write_block = 0;
  s_gpt_last_write_count = 0;
  MemoryFixture memory = {&s_gpt_fixture[0][0], sizeof s_gpt_fixture};
  ZiBlockDevice device = {
      sizeof(ZiBlockDevice),
      ZI_BLOCK_DEVICE_VERSION,
      &memory,
      GPT_BLOCK_SIZE,
      GPT_BLOCK_COUNT,
      gpt_read_blocks,
      gpt_flush,
      ZI_BLOCK_DEVICE_FLUSH_SUPPORTED | ZI_BLOCK_DEVICE_WRITE_SUPPORTED,
      gpt_write_blocks,
  };
  unsigned char scratch[GPT_BLOCK_SIZE] = {0};
  ZiGptPartition partitions[4] = {0};
  ZiGptTable table = {0};
  PHASE5_ASSERT(ZiSucceeded(zi_gpt_read(&device, scratch, sizeof scratch, partitions, 4, &table)));
  PHASE5_ASSERT(table.mounted_from_backup == 0 && table.partition_count == 2);
  const ZiGptPartition* zifs = NULL;
  PHASE5_ASSERT(ZiSucceeded(zi_gpt_find_partition_by_type(&table, &ZiGptZiFsTypeGuid, &zifs)) &&
                zifs != NULL);
  PHASE5_ASSERT(zifs->first_lba == 50 && zifs->last_lba == 89);
  ZiPartitionBlockContext partition_context = {0};
  ZiBlockDevice partition_device = {0};
  PHASE5_ASSERT(ZiSucceeded(zi_partition_block_initialise(&device,
                                                          zifs->first_lba,
                                                          zifs->last_lba - zifs->first_lba + 1,
                                                          4096,
                                                          &partition_context,
                                                          &partition_device)));
  PHASE5_ASSERT(partition_device.block_size == 4096 && partition_device.block_count == 5);
  size_t write_assertions = 0;
  if (!test_partition_write_contract(&device,
                                     zifs,
                                     &partition_context,
                                     &partition_device,
                                     &write_assertions)) {
    assertions += write_assertions;
    *out_assertion_count = assertions;
    return false;
  }
  assertions += write_assertions;
  ZiBlockDevice invalid_device = device;
  ++invalid_device.version;
  PHASE5_ASSERT(zi_gpt_read(&invalid_device, scratch, sizeof scratch, partitions, 4, &table) ==
                ZI_STATUS_INVALID_ARGUMENT);
  PHASE5_ASSERT(zi_partition_block_initialise(&invalid_device,
                                              zifs->first_lba,
                                              zifs->last_lba - zifs->first_lba + 1,
                                              4096,
                                              &partition_context,
                                              &partition_device) == ZI_STATUS_INVALID_ARGUMENT);
  unsigned char partition_data[4096] = {0};
  PHASE5_ASSERT(ZiSucceeded(
      partition_device
          .read_blocks(partition_device.context, 0, 1, partition_data, sizeof partition_data)));
  PHASE5_ASSERT(partition_device.read_blocks(partition_device.context,
                                             5,
                                             1,
                                             partition_data,
                                             sizeof partition_data) == ZI_STATUS_OUT_OF_BOUNDS);

  s_gpt_fixture[1][16] ^= 1;
  PHASE5_ASSERT(ZiSucceeded(zi_gpt_read(&device, scratch, sizeof scratch, partitions, 4, &table)));
  PHASE5_ASSERT(table.mounted_from_backup == 1);
  s_gpt_fixture[GPT_BLOCK_COUNT - 1][16] ^= 1;
  PHASE5_ASSERT(ZiFailed(zi_gpt_read(&device, scratch, sizeof scratch, partitions, 4, &table)));

  build_gpt_fixture(true);
  PHASE5_ASSERT(zi_gpt_read(&device, scratch, sizeof scratch, partitions, 4, &table) ==
                ZI_STATUS_ADDRESS_CONFLICT);
  build_gpt_fixture(false);
  s_gpt_fixture[0][510] = 0;
  PHASE5_ASSERT(zi_gpt_read(&device, scratch, sizeof scratch, partitions, 4, &table) ==
                ZI_STATUS_INVALID_STATE);
  *out_assertion_count = assertions;
  return true;
}

static ZiStatus memory_read(void* context, uint64_t physical_address, void* output, size_t size) {
  if (context == NULL || output == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const MemoryFixture* memory = context;
  if (physical_address > memory->size || size > memory->size - (size_t)physical_address) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  unsigned char* destination = output;
  for (size_t index = 0; index < size; ++index) {
    destination[index] = memory->bytes[(size_t)physical_address + index];
  }
  return ZI_STATUS_SUCCESS;
}

static void build_acpi_fixture(bool overlapping_mcfg) {
  for (size_t index = 0; index < sizeof s_acpi_fixture; ++index) {
    s_acpi_fixture[index] = 0;
  }
  unsigned char* rsdp = s_acpi_fixture + 0x100;
  const unsigned char signature[8] = {'R', 'S', 'D', ' ', 'P', 'T', 'R', ' '};
  for (size_t index = 0; index < sizeof signature; ++index) {
    rsdp[index] = signature[index];
  }
  rsdp[15] = 2;
  zi_write_u32_le(rsdp + 16, 0);
  zi_write_u32_le(rsdp + 20, 36);
  zi_write_u64_le(rsdp + 24, 0x1000);
  set_checksum(rsdp, 20, 8);
  set_checksum(rsdp, 36, 32);

  unsigned char* xsdt = s_acpi_fixture + 0x1000;
  initialise_sdt(xsdt, "XSDT", 44);
  zi_write_u64_le(xsdt + 36, 0x2000);
  set_checksum(xsdt, 44, 9);

  uint32_t mcfg_length = 60;
  if (overlapping_mcfg) {
    mcfg_length = 76;
  }
  unsigned char* mcfg = s_acpi_fixture + 0x2000;
  initialise_sdt(mcfg, "MCFG", mcfg_length);
  zi_write_u64_le(mcfg + 44, UINT64_C(0xe0000000));
  zi_write_u16_le(mcfg + 52, 0);
  mcfg[54] = 0;
  mcfg[55] = UINT8_MAX;
  if (overlapping_mcfg) {
    zi_write_u64_le(mcfg + 60, UINT64_C(0xf0000000));
    zi_write_u16_le(mcfg + 68, 0);
    mcfg[70] = 128;
    mcfg[71] = UINT8_MAX;
  }
  set_checksum(mcfg, mcfg_length, 9);
}

static void initialise_sdt(unsigned char* table, const char signature[4], uint32_t length) {
  for (size_t index = 0; index < 4; ++index) {
    table[index] = (unsigned char)signature[index];
  }
  zi_write_u32_le(table + 4, length);
  table[8] = 1;
}

static void set_checksum(unsigned char* bytes, size_t size, size_t checksum_offset) {
  bytes[checksum_offset] = 0;
  uint8_t sum = 0;
  for (size_t index = 0; index < size; ++index) {
    sum = (uint8_t)(sum + bytes[index]);
  }
  bytes[checksum_offset] = (uint8_t)(0u - sum);
}

static ZiStatus
pci_read32(void* context, ZiPciAddress address, uint16_t offset, uint32_t* out_value) {
  if (context == NULL || out_value == NULL || address.segment != 0 || address.bus != 0 ||
      address.device >= 32 || address.function != 0 || offset >= PCI_CONFIG_SIZE ||
      (offset & 3u) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  PciFixture* fixture = context;
  uint32_t value = zi_read_u32_le(fixture->configuration[address.device] + offset);
  if (offset >= 0x10 && offset < 0x10 + (ZI_PCI_BAR_COUNT * 4) && value == UINT32_MAX) {
    value = fixture->probe_masks[(offset - 0x10) / 4];
  }
  *out_value = value;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus pci_write32(void* context, ZiPciAddress address, uint16_t offset, uint32_t value) {
  if (context == NULL || address.segment != 0 || address.bus != 0 || address.device >= 32 ||
      address.function != 0 || offset >= PCI_CONFIG_SIZE || (offset & 3u) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  PciFixture* fixture = context;
  zi_write_u32_le(fixture->configuration[address.device] + offset, value);
  return ZI_STATUS_SUCCESS;
}

static void build_pci_fixture(void) {
  unsigned char* bytes = &s_pci_fixture.configuration[0][0];
  // The cast intentionally treats the complete configuration array as bytes.
  // NOLINTNEXTLINE(bugprone-sizeof-expression, cert-arr39-c)
  for (size_t index = 0; index < sizeof s_pci_fixture.configuration; ++index) {
    bytes[index] = UINT8_MAX;
  }
  for (size_t index = 0; index < ZI_PCI_BAR_COUNT; ++index) {
    s_pci_fixture.probe_masks[index] = 0;
  }
  unsigned char* device = s_pci_fixture.configuration[4];
  zi_write_u32_le(device, UINT32_C(0x00101b36));
  zi_write_u32_le(device + 4, UINT32_C(0x00000003));
  zi_write_u32_le(device + 8, UINT32_C(0x01080201));
  zi_write_u32_le(device + 0x0c, 0);
  zi_write_u32_le(device + 0x10, UINT32_C(0x80000004));
  zi_write_u32_le(device + 0x14, 0);
  zi_write_u32_le(device + 0x2c, UINT32_C(0x11001b36));
  zi_write_u32_le(device + 0x3c, UINT32_C(0x0000010b));
  s_pci_fixture.probe_masks[0] = UINT32_C(0xffffc004);
  s_pci_fixture.probe_masks[1] = UINT32_MAX;
}

static ZiStatus dma_allocate_pages(void* context,
                                   uint64_t page_count,
                                   uint64_t alignment_pages,
                                   uint64_t maximum_physical_address,
                                   uint32_t owner,
                                   uint64_t* out_physical_address) {
  if (context == NULL || out_physical_address == NULL || page_count == 0 || page_count > 4 ||
      alignment_pages != 1) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  DmaFixture* fixture = context;
  uint64_t address = (uint64_t)(uintptr_t)&fixture->pages[0][0];
  if (fixture->allocated) {
    return ZI_STATUS_RESOURCE_IN_USE;
  }
  if (address > maximum_physical_address ||
      (page_count * ZI_MEMORY_PAGE_SIZE) - 1 > maximum_physical_address - address) {
    return ZI_STATUS_NO_MEMORY;
  }
  fixture->allocated = true;
  fixture->owner = owner;
  *out_physical_address = address;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus dma_release_pages(void* context,
                                  uint64_t physical_address,
                                  uint64_t page_count,
                                  uint32_t expected_owner) {
  if (context == NULL || page_count == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  DmaFixture* fixture = context;
  if (!fixture->allocated || physical_address != (uint64_t)(uintptr_t)&fixture->pages[0][0] ||
      fixture->owner != expected_owner) {
    return ZI_STATUS_INVALID_STATE;
  }
  fixture->allocated = false;
  fixture->owner = ZI_MEMORY_OWNER_NONE;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus
dma_physical_pointer(void* context, uint64_t physical_address, size_t size, void** out_pointer) {
  if (context == NULL || out_pointer == NULL || size == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  DmaFixture* fixture = context;
  uint64_t base = (uint64_t)(uintptr_t)&fixture->pages[0][0];
  if (physical_address != base || size > sizeof fixture->pages) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  *out_pointer = &fixture->pages[0][0];
  return ZI_STATUS_SUCCESS;
}

static void dma_synchronise(void* context, uint32_t direction) {
  DmaFixture* fixture = context;
  ++fixture->synchronise_count;
  fixture->last_direction = direction;
}

static ZiStatus gpt_read_blocks(void* context,
                                uint64_t first_block,
                                uint32_t block_count,
                                void* output,
                                size_t output_size) {
  if (context == NULL || output == NULL || block_count == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  MemoryFixture* memory = context;
  size_t byte_count = (size_t)block_count * GPT_BLOCK_SIZE;
  if (first_block > SIZE_MAX / GPT_BLOCK_SIZE || output_size < byte_count) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  size_t offset = (size_t)first_block * GPT_BLOCK_SIZE;
  if (offset > memory->size || byte_count > memory->size - offset) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  unsigned char* destination = output;
  for (size_t index = 0; index < byte_count; ++index) {
    destination[index] = memory->bytes[offset + index];
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus gpt_flush(void* context) {
  if (context == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ++s_gpt_flush_count;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus gpt_write_blocks(void* context,
                                 uint64_t first_block,
                                 uint32_t block_count,
                                 const void* input,
                                 size_t input_size) {
  if (context == NULL || input == NULL || block_count == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  MemoryFixture* memory = context;
  size_t byte_count = (size_t)block_count * GPT_BLOCK_SIZE;
  if (first_block > SIZE_MAX / GPT_BLOCK_SIZE || input_size != byte_count) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  size_t offset = (size_t)first_block * GPT_BLOCK_SIZE;
  if (offset > memory->size || byte_count > memory->size - offset) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  zi_memory_copy(memory->bytes + offset, input, byte_count);
  ++s_gpt_write_count;
  s_gpt_last_write_block = first_block;
  s_gpt_last_write_count = block_count;
  return ZI_STATUS_SUCCESS;
}

static void build_gpt_fixture(bool overlapping) {
  unsigned char* disk = &s_gpt_fixture[0][0];
  // The cast intentionally treats the complete block array as bytes.
  // NOLINTNEXTLINE(bugprone-sizeof-expression, cert-arr39-c)
  for (size_t index = 0; index < sizeof s_gpt_fixture; ++index) {
    disk[index] = 0;
  }
  unsigned char* mbr = s_gpt_fixture[0];
  mbr[446 + 4] = UINT8_C(0xee);
  zi_write_u32_le(mbr + 446 + 8, 1);
  zi_write_u32_le(mbr + 446 + 12, GPT_BLOCK_COUNT - 1);
  mbr[510] = UINT8_C(0x55);
  mbr[511] = UINT8_C(0xaa);

  unsigned char entries[GPT_ENTRY_COUNT * GPT_ENTRY_SIZE] = {0};
  ZiGuid esp_type = {{0x28,
                      0x73,
                      0x2a,
                      0xc1,
                      0x1f,
                      0xf8,
                      0xd2,
                      0x11,
                      0xba,
                      0x4b,
                      0x00,
                      0xa0,
                      0xc9,
                      0x3e,
                      0xc9,
                      0x3b}};
  uint64_t esp_last_lba = 49;
  if (overlapping) {
    esp_last_lba = 60;
  }
  encode_partition(entries, &esp_type, 1, 34, esp_last_lba);
  encode_partition(entries + GPT_ENTRY_SIZE, &ZiGptZiFsTypeGuid, 2, 50, 89);
  uint32_t entries_crc = zi_crc32(0, entries, sizeof entries);
  for (size_t index = 0; index < sizeof entries; ++index) {
    disk[((size_t)2u * GPT_BLOCK_SIZE) + index] = entries[index];
    disk[((size_t)(GPT_BLOCK_COUNT - GPT_ENTRY_BLOCKS - 1u) * GPT_BLOCK_SIZE) + index] =
        entries[index];
  }
  encode_gpt_header(s_gpt_fixture[1], 1, GPT_BLOCK_COUNT - 1, 2, entries_crc);
  encode_gpt_header(s_gpt_fixture[GPT_BLOCK_COUNT - 1],
                    GPT_BLOCK_COUNT - 1,
                    1,
                    GPT_BLOCK_COUNT - GPT_ENTRY_BLOCKS - 1,
                    entries_crc);
}

static void encode_gpt_header(unsigned char* block,
                              uint64_t current_lba,
                              uint64_t backup_lba,
                              uint64_t entries_lba,
                              uint32_t entries_crc) {
  const unsigned char signature[8] = {'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T'};
  for (size_t index = 0; index < sizeof signature; ++index) {
    block[index] = signature[index];
  }
  zi_write_u32_le(block + 8, UINT32_C(0x00010000));
  zi_write_u32_le(block + 12, 92);
  zi_write_u64_le(block + 24, current_lba);
  zi_write_u64_le(block + 32, backup_lba);
  zi_write_u64_le(block + 40, 34);
  zi_write_u64_le(block + 48, 94);
  for (size_t index = 0; index < 16; ++index) {
    block[56 + index] = (unsigned char)(0x20 + index);
  }
  zi_write_u64_le(block + 72, entries_lba);
  zi_write_u32_le(block + 80, GPT_ENTRY_COUNT);
  zi_write_u32_le(block + 84, GPT_ENTRY_SIZE);
  zi_write_u32_le(block + 88, entries_crc);
  zi_write_u32_le(block + 16, 0);
  zi_write_u32_le(block + 16, zi_crc32(0, block, 92));
}

static void encode_partition(unsigned char* entry,
                             const ZiGuid* type,
                             uint8_t unique_value,
                             uint64_t first_lba,
                             uint64_t last_lba) {
  for (size_t index = 0; index < 16; ++index) {
    entry[index] = type->bytes[index];
    entry[16 + index] = (unsigned char)(unique_value + index);
  }
  zi_write_u64_le(entry + 32, first_lba);
  zi_write_u64_le(entry + 40, last_lba);
}

static bool bytes_are_zero(const unsigned char* bytes, size_t size) {
  for (size_t index = 0; index < size; ++index) {
    if (bytes[index] != 0) {
      return false;
    }
  }
  return true;
}
