// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"

#define ZI_ACPI_PHYSICAL_READER_VERSION 1u
#define ZI_ACPI_CONTEXT_VERSION 1u
#define ZI_ACPI_MAXIMUM_RSDP_SIZE 4096u
#define ZI_ACPI_MAXIMUM_TABLE_SIZE (1024u * 1024u)
#define ZI_ACPI_MAXIMUM_ROOT_ENTRIES 256u

typedef ZiStatus (*ZiAcpiReadPhysicalRoutine)(void* context,
                                              uint64_t physical_address,
                                              void* output,
                                              size_t size);

typedef struct ZiAcpiPhysicalReader {
  uint32_t struct_size;
  uint32_t version;
  void* context;
  ZiAcpiReadPhysicalRoutine read;
} ZiAcpiPhysicalReader;

typedef struct ZiAcpiTable {
  char signature[4];
  uint64_t physical_address;
  uint32_t length;
  uint8_t revision;
} ZiAcpiTable;

typedef struct ZiAcpiContext {
  uint32_t struct_size;
  uint32_t version;
  ZiAcpiPhysicalReader reader;
  uint64_t rsdp_physical_address;
  uint64_t root_physical_address;
  uint32_t root_length;
  uint32_t root_entry_count;
  uint8_t acpi_revision;
  uint8_t root_entry_size;
} ZiAcpiContext;

typedef struct ZiAcpiMcfgAllocation {
  uint64_t base_address;
  uint16_t segment_group;
  uint8_t start_bus;
  uint8_t end_bus;
} ZiAcpiMcfgAllocation;

ZiStatus zi_acpi_initialise(uint64_t rsdp_physical_address,
                            const ZiAcpiPhysicalReader* reader,
                            ZiAcpiContext* out_context);
ZiStatus
zi_acpi_find_table(const ZiAcpiContext* context, const char signature[4], ZiAcpiTable* out_table);
ZiStatus zi_acpi_parse_mcfg(const ZiAcpiContext* context,
                            ZiAcpiMcfgAllocation* allocations,
                            size_t allocation_capacity,
                            size_t* out_allocation_count);
