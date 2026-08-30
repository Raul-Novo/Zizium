// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/acpi.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/byte_order.h"
#include "zizium/status.h"

#define ACPI_SDT_HEADER_SIZE 36u
#define ACPI_MCFG_HEADER_SIZE 44u
#define ACPI_MCFG_ALLOCATION_SIZE 16u

static const unsigned char k_rsdp_signature[8] = {'R', 'S', 'D', ' ', 'P', 'T', 'R', ' '};
static const char k_xsdt_signature[4] = {'X', 'S', 'D', 'T'};
static const char k_rsdt_signature[4] = {'R', 'S', 'D', 'T'};
static const char k_mcfg_signature[4] = {'M', 'C', 'F', 'G'};

static ZiStatus read_physical(const ZiAcpiPhysicalReader* reader,
                              uint64_t physical_address,
                              void* output,
                              size_t size);
static ZiStatus
checksum_physical(const ZiAcpiPhysicalReader* reader, uint64_t physical_address, uint32_t size);
static ZiStatus read_table(const ZiAcpiPhysicalReader* reader,
                           uint64_t physical_address,
                           const char* required_signature,
                           ZiAcpiTable* out_table);
static bool bytes_equal(const void* left, const void* right, size_t size);
static bool
ranges_overlap(uint8_t first_start, uint8_t first_end, uint8_t second_start, uint8_t second_end);

ZiStatus zi_acpi_initialise(uint64_t rsdp_physical_address,
                            const ZiAcpiPhysicalReader* reader,
                            ZiAcpiContext* out_context) {
  if (rsdp_physical_address == 0 || reader == NULL || out_context == NULL ||
      reader->struct_size < sizeof *reader || reader->version != ZI_ACPI_PHYSICAL_READER_VERSION ||
      reader->read == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  unsigned char rsdp[36] = {0};
  ZiStatus status = read_physical(reader, rsdp_physical_address, rsdp, 20);
  if (ZiFailed(status)) {
    return status;
  }
  if (!bytes_equal(rsdp, k_rsdp_signature, sizeof k_rsdp_signature)) {
    return ZI_STATUS_INVALID_STATE;
  }
  uint8_t checksum = 0;
  for (size_t index = 0; index < 20; ++index) {
    checksum = (uint8_t)(checksum + rsdp[index]);
  }
  if (checksum != 0) {
    return ZI_STATUS_CHECKSUM_MISMATCH;
  }

  uint8_t revision = rsdp[15];
  uint64_t root_address = zi_read_u32_le(rsdp + 16);
  const char* root_signature = k_rsdt_signature;
  uint8_t root_entry_size = 4;
  if (revision >= 2) {
    status = read_physical(reader, rsdp_physical_address + 20, rsdp + 20, sizeof rsdp - 20);
    if (ZiFailed(status)) {
      return status;
    }
    uint32_t rsdp_length = zi_read_u32_le(rsdp + 20);
    if (rsdp_length < sizeof rsdp || rsdp_length > ZI_ACPI_MAXIMUM_RSDP_SIZE) {
      return ZI_STATUS_INVALID_STATE;
    }
    status = checksum_physical(reader, rsdp_physical_address, rsdp_length);
    if (ZiFailed(status)) {
      return status;
    }
    uint64_t xsdt_address = zi_read_u64_le(rsdp + 24);
    if (xsdt_address != 0) {
      root_address = xsdt_address;
      root_signature = k_xsdt_signature;
      root_entry_size = 8;
    }
  }
  if (root_address == 0) {
    return ZI_STATUS_NOT_FOUND;
  }

  ZiAcpiTable root = {0};
  status = read_table(reader, root_address, root_signature, &root);
  if (ZiFailed(status)) {
    return status;
  }
  uint32_t payload_size = root.length - ACPI_SDT_HEADER_SIZE;
  if (payload_size % root_entry_size != 0 ||
      payload_size / root_entry_size > ZI_ACPI_MAXIMUM_ROOT_ENTRIES) {
    return ZI_STATUS_INVALID_STATE;
  }

  ZiAcpiContext result = {
      sizeof(ZiAcpiContext),
      ZI_ACPI_CONTEXT_VERSION,
      *reader,
      rsdp_physical_address,
      root_address,
      root.length,
      payload_size / root_entry_size,
      revision,
      root_entry_size,
  };
  *out_context = result;
  return ZI_STATUS_SUCCESS;
}

ZiStatus
zi_acpi_find_table(const ZiAcpiContext* context, const char signature[4], ZiAcpiTable* out_table) {
  if (context == NULL || signature == NULL || out_table == NULL ||
      context->struct_size < sizeof *context || context->version != ZI_ACPI_CONTEXT_VERSION ||
      (context->root_entry_size != 4 && context->root_entry_size != 8) ||
      context->root_entry_count > ZI_ACPI_MAXIMUM_ROOT_ENTRIES) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  unsigned char encoded_address[8] = {0};
  for (uint32_t index = 0; index < context->root_entry_count; ++index) {
    uint64_t offset = ACPI_SDT_HEADER_SIZE + ((uint64_t)index * context->root_entry_size);
    if (context->root_physical_address > UINT64_MAX - offset) {
      return ZI_STATUS_OUT_OF_BOUNDS;
    }
    ZiStatus status = read_physical(&context->reader,
                                    context->root_physical_address + offset,
                                    encoded_address,
                                    context->root_entry_size);
    if (ZiFailed(status)) {
      return status;
    }
    uint64_t table_address = context->root_entry_size == 8 ? zi_read_u64_le(encoded_address)
                                                           : zi_read_u32_le(encoded_address);
    if (table_address == 0) {
      continue;
    }
    unsigned char table_signature[4] = {0};
    status =
        read_physical(&context->reader, table_address, table_signature, sizeof table_signature);
    if (ZiFailed(status)) {
      return status;
    }
    if (!bytes_equal(table_signature, signature, sizeof table_signature)) {
      continue;
    }
    return read_table(&context->reader, table_address, signature, out_table);
  }
  return ZI_STATUS_NOT_FOUND;
}

ZiStatus zi_acpi_parse_mcfg(const ZiAcpiContext* context,
                            ZiAcpiMcfgAllocation* allocations,
                            size_t allocation_capacity,
                            size_t* out_allocation_count) {
  if (context == NULL || out_allocation_count == NULL ||
      (allocations == NULL && allocation_capacity != 0)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_allocation_count = 0;

  ZiAcpiTable table = {0};
  ZiStatus status = zi_acpi_find_table(context, k_mcfg_signature, &table);
  if (ZiFailed(status)) {
    return status;
  }
  if (table.length < ACPI_MCFG_HEADER_SIZE ||
      (table.length - ACPI_MCFG_HEADER_SIZE) % ACPI_MCFG_ALLOCATION_SIZE != 0) {
    return ZI_STATUS_INVALID_STATE;
  }

  unsigned char reserved[8] = {0};
  status = read_physical(&context->reader,
                         table.physical_address + ACPI_SDT_HEADER_SIZE,
                         reserved,
                         sizeof reserved);
  if (ZiFailed(status)) {
    return status;
  }
  const unsigned char zeros[8] = {0};
  if (!bytes_equal(reserved, zeros, sizeof reserved)) {
    return ZI_STATUS_INVALID_STATE;
  }

  size_t count = (table.length - ACPI_MCFG_HEADER_SIZE) / ACPI_MCFG_ALLOCATION_SIZE;
  if (count > allocation_capacity) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  for (size_t index = 0; index < count; ++index) {
    unsigned char encoded[ACPI_MCFG_ALLOCATION_SIZE] = {0};
    uint64_t offset = ACPI_MCFG_HEADER_SIZE + (index * ACPI_MCFG_ALLOCATION_SIZE);
    status =
        read_physical(&context->reader, table.physical_address + offset, encoded, sizeof encoded);
    if (ZiFailed(status)) {
      return status;
    }
    ZiAcpiMcfgAllocation allocation = {
        zi_read_u64_le(encoded),
        zi_read_u16_le(encoded + 8),
        encoded[10],
        encoded[11],
    };
    if (allocation.base_address == 0 || (allocation.base_address & UINT64_C(0xfffff)) != 0 ||
        allocation.start_bus > allocation.end_bus) {
      return ZI_STATUS_INVALID_STATE;
    }
    uint64_t bus_count = (uint64_t)allocation.end_bus - allocation.start_bus + 1;
    if (bus_count > (UINT64_MAX - allocation.base_address) >> 20) {
      return ZI_STATUS_OUT_OF_BOUNDS;
    }
    for (size_t prior = 0; prior < index; ++prior) {
      if (allocations[prior].segment_group == allocation.segment_group &&
          ranges_overlap(allocations[prior].start_bus,
                         allocations[prior].end_bus,
                         allocation.start_bus,
                         allocation.end_bus)) {
        return ZI_STATUS_ADDRESS_CONFLICT;
      }
    }
    allocations[index] = allocation;
  }
  *out_allocation_count = count;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus read_physical(const ZiAcpiPhysicalReader* reader,
                              uint64_t physical_address,
                              void* output,
                              size_t size) {
  if (reader == NULL || reader->read == NULL || output == NULL || size == 0 ||
      physical_address > UINT64_MAX - size) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return reader->read(reader->context, physical_address, output, size);
}

static ZiStatus
checksum_physical(const ZiAcpiPhysicalReader* reader, uint64_t physical_address, uint32_t size) {
  if (size == 0 || size > ZI_ACPI_MAXIMUM_TABLE_SIZE) {
    return ZI_STATUS_INVALID_STATE;
  }
  unsigned char buffer[256] = {0};
  uint8_t checksum = 0;
  uint32_t consumed = 0;
  while (consumed < size) {
    size_t chunk = size - consumed;
    if (chunk > sizeof buffer) {
      chunk = sizeof buffer;
    }
    ZiStatus status = read_physical(reader, physical_address + consumed, buffer, chunk);
    if (ZiFailed(status)) {
      return status;
    }
    for (size_t index = 0; index < chunk; ++index) {
      checksum = (uint8_t)(checksum + buffer[index]);
    }
    consumed += (uint32_t)chunk;
  }
  return checksum == 0 ? ZI_STATUS_SUCCESS : ZI_STATUS_CHECKSUM_MISMATCH;
}

static ZiStatus read_table(const ZiAcpiPhysicalReader* reader,
                           uint64_t physical_address,
                           const char* required_signature,
                           ZiAcpiTable* out_table) {
  if (required_signature == NULL || out_table == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char header[ACPI_SDT_HEADER_SIZE] = {0};
  ZiStatus status = read_physical(reader, physical_address, header, sizeof header);
  if (ZiFailed(status)) {
    return status;
  }
  uint32_t length = zi_read_u32_le(header + 4);
  if (!bytes_equal(header, required_signature, 4) || length < ACPI_SDT_HEADER_SIZE ||
      length > ZI_ACPI_MAXIMUM_TABLE_SIZE) {
    return ZI_STATUS_INVALID_STATE;
  }
  status = checksum_physical(reader, physical_address, length);
  if (ZiFailed(status)) {
    return status;
  }
  ZiAcpiTable result = {{(char)header[0], (char)header[1], (char)header[2], (char)header[3]},
                        physical_address,
                        length,
                        header[8]};
  *out_table = result;
  return ZI_STATUS_SUCCESS;
}

static bool bytes_equal(const void* left, const void* right, size_t size) {
  const unsigned char* left_bytes = left;
  const unsigned char* right_bytes = right;
  for (size_t index = 0; index < size; ++index) {
    if (left_bytes[index] != right_bytes[index]) {
      return false;
    }
  }
  return true;
}

static bool
ranges_overlap(uint8_t first_start, uint8_t first_end, uint8_t second_start, uint8_t second_end) {
  return (bool)((first_start <= second_end && second_start <= first_end) != 0);
}
