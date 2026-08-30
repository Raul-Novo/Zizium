// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/gpt.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/block.h"
#include "zi/byte_order.h"
#include "zi/crc32.h"
#include "zizium/status.h"

#define GPT_HEADER_MINIMUM_SIZE 92u
#define GPT_HEADER_MAXIMUM_SIZE 4096u
#define GPT_SIGNATURE_SIZE 8u
#define GPT_PROTECTIVE_MBR_SIZE 512u

typedef struct ZiGptHeaderData {
  ZiGuid disk_guid;
  uint64_t current_lba;
  uint64_t backup_lba;
  uint64_t first_usable_lba;
  uint64_t last_usable_lba;
  uint64_t entry_lba;
  uint32_t entry_count;
  uint32_t entry_size;
  uint32_t entries_crc;
} ZiGptHeaderData;

const ZiGuid ZiGptZiFsTypeGuid = {{0x2a,
                                   0xe2,
                                   0xf9,
                                   0x9e,
                                   0x19,
                                   0x37,
                                   0xd4,
                                   0x44,
                                   0x89,
                                   0xaf,
                                   0xde,
                                   0x9c,
                                   0xc7,
                                   0xb6,
                                   0xb2,
                                   0x55}};

static const unsigned char k_gpt_signature[GPT_SIGNATURE_SIZE] =
    {'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T'};
static const ZiGuid k_zero_guid = {{0}};

static ZiStatus
validate_protective_mbr(const ZiBlockDevice* device, void* block_buffer, size_t block_buffer_size);
static ZiStatus read_table_at(const ZiBlockDevice* device,
                              uint64_t header_lba,
                              void* block_buffer,
                              size_t block_buffer_size,
                              ZiGptPartition* partitions,
                              size_t partition_capacity,
                              ZiGptTable* out_table);
static ZiStatus decode_header(const ZiBlockDevice* device,
                              uint64_t expected_lba,
                              unsigned char* bytes,
                              ZiGptHeaderData* out_header);
static ZiStatus validate_entries_crc(const ZiBlockDevice* device,
                                     const ZiGptHeaderData* header,
                                     void* block_buffer,
                                     size_t block_buffer_size);
static ZiStatus decode_partitions(const ZiBlockDevice* device,
                                  const ZiGptHeaderData* header,
                                  void* block_buffer,
                                  size_t block_buffer_size,
                                  ZiGptPartition* partitions,
                                  size_t partition_capacity,
                                  size_t* out_partition_count);
static ZiStatus read_bytes(const ZiBlockDevice* device,
                           uint64_t byte_offset,
                           void* output,
                           size_t size,
                           void* block_buffer,
                           size_t block_buffer_size);
static bool bytes_equal(const void* left, const void* right, size_t size);
static bool partition_overlaps(const ZiGptPartition* left, const ZiGptPartition* right);

ZiStatus zi_gpt_read(const ZiBlockDevice* device,
                     void* block_buffer,
                     size_t block_buffer_size,
                     ZiGptPartition* partitions,
                     size_t partition_capacity,
                     ZiGptTable* out_table) {
  if (device == NULL || device->struct_size < sizeof *device ||
      device->version != ZI_BLOCK_DEVICE_VERSION || device->read_blocks == NULL ||
      device->block_size < 512 || device->block_size > GPT_HEADER_MAXIMUM_SIZE ||
      (device->block_size & (device->block_size - 1)) != 0 || device->block_count < 3 ||
      block_buffer == NULL || block_buffer_size < device->block_size || partitions == NULL ||
      partition_capacity == 0 || out_table == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_protective_mbr(device, block_buffer, block_buffer_size);
  if (ZiFailed(status)) {
    return status;
  }
  status = read_table_at(device,
                         1,
                         block_buffer,
                         block_buffer_size,
                         partitions,
                         partition_capacity,
                         out_table);
  if (ZiSucceeded(status)) {
    out_table->mounted_from_backup = 0;
    return status;
  }
  status = read_table_at(device,
                         device->block_count - 1,
                         block_buffer,
                         block_buffer_size,
                         partitions,
                         partition_capacity,
                         out_table);
  if (ZiSucceeded(status)) {
    out_table->mounted_from_backup = 1;
  }
  return status;
}

ZiStatus zi_gpt_find_partition_by_type(const ZiGptTable* table,
                                       const ZiGuid* type_guid,
                                       const ZiGptPartition** out_partition) {
  if (table == NULL || type_guid == NULL || out_partition == NULL ||
      (table->partitions == NULL && table->partition_count != 0)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_partition = NULL;
  for (size_t index = 0; index < table->partition_count; ++index) {
    if (zi_guid_equal(&table->partitions[index].type_guid, type_guid)) {
      if (*out_partition != NULL) {
        return ZI_STATUS_ALREADY_EXISTS;
      }
      *out_partition = &table->partitions[index];
    }
  }
  return *out_partition == NULL ? ZI_STATUS_NOT_FOUND : ZI_STATUS_SUCCESS;
}

bool zi_guid_equal(const ZiGuid* left, const ZiGuid* right) {
  return (bool)((left != NULL && right != NULL && bytes_equal(left->bytes, right->bytes, 16)) != 0);
}

static ZiStatus
validate_protective_mbr(const ZiBlockDevice* device, void* block_buffer, size_t block_buffer_size) {
  ZiStatus status = device->read_blocks(device->context, 0, 1, block_buffer, block_buffer_size);
  if (ZiFailed(status)) {
    return status;
  }
  const unsigned char* bytes = block_buffer;
  if (bytes[510] != UINT8_C(0x55) || bytes[511] != UINT8_C(0xaa)) {
    return ZI_STATUS_INVALID_STATE;
  }
  bool found = false;
  for (size_t index = 0; index < 4; ++index) {
    const unsigned char* entry = bytes + 446 + (index * 16);
    if (entry[4] == UINT8_C(0xee) && zi_read_u32_le(entry + 8) == 1) {
      found = true;
      break;
    }
  }
  if (found) {
    return ZI_STATUS_SUCCESS;
  }
  return ZI_STATUS_INVALID_STATE;
}

static ZiStatus read_table_at(const ZiBlockDevice* device,
                              uint64_t header_lba,
                              void* block_buffer,
                              size_t block_buffer_size,
                              ZiGptPartition* partitions,
                              size_t partition_capacity,
                              ZiGptTable* out_table) {
  ZiStatus status =
      device->read_blocks(device->context, header_lba, 1, block_buffer, block_buffer_size);
  if (ZiFailed(status)) {
    return status;
  }
  ZiGptHeaderData header = {0};
  status = decode_header(device, header_lba, block_buffer, &header);
  if (ZiFailed(status)) {
    return status;
  }
  status = validate_entries_crc(device, &header, block_buffer, block_buffer_size);
  if (ZiFailed(status)) {
    return status;
  }
  size_t partition_count = 0;
  status = decode_partitions(device,
                             &header,
                             block_buffer,
                             block_buffer_size,
                             partitions,
                             partition_capacity,
                             &partition_count);
  if (ZiFailed(status)) {
    return status;
  }
  ZiGptTable table = {
      header.disk_guid,
      header.current_lba,
      header.backup_lba,
      header.first_usable_lba,
      header.last_usable_lba,
      partitions,
      partition_count,
      0,
  };
  *out_table = table;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus decode_header(const ZiBlockDevice* device,
                              uint64_t expected_lba,
                              unsigned char* bytes,
                              ZiGptHeaderData* out_header) {
  if (!bytes_equal(bytes, k_gpt_signature, sizeof k_gpt_signature)) {
    return ZI_STATUS_INVALID_STATE;
  }
  uint32_t revision = zi_read_u32_le(bytes + 8);
  uint32_t header_size = zi_read_u32_le(bytes + 12);
  uint32_t stored_crc = zi_read_u32_le(bytes + 16);
  if (revision < UINT32_C(0x00010000) || header_size < GPT_HEADER_MINIMUM_SIZE ||
      header_size > device->block_size || zi_read_u32_le(bytes + 20) != 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  zi_write_u32_le(bytes + 16, 0);
  uint32_t calculated_crc = zi_crc32(0, bytes, header_size);
  zi_write_u32_le(bytes + 16, stored_crc);
  if (stored_crc != calculated_crc) {
    return ZI_STATUS_CHECKSUM_MISMATCH;
  }

  ZiGptHeaderData header = {0};
  header.current_lba = zi_read_u64_le(bytes + 24);
  header.backup_lba = zi_read_u64_le(bytes + 32);
  header.first_usable_lba = zi_read_u64_le(bytes + 40);
  header.last_usable_lba = zi_read_u64_le(bytes + 48);
  for (size_t index = 0; index < sizeof header.disk_guid.bytes; ++index) {
    header.disk_guid.bytes[index] = bytes[56 + index];
  }
  header.entry_lba = zi_read_u64_le(bytes + 72);
  header.entry_count = zi_read_u32_le(bytes + 80);
  header.entry_size = zi_read_u32_le(bytes + 84);
  header.entries_crc = zi_read_u32_le(bytes + 88);
  if (header.current_lba != expected_lba || header.backup_lba >= device->block_count ||
      header.backup_lba == header.current_lba || header.first_usable_lba > header.last_usable_lba ||
      header.last_usable_lba >= device->block_count || header.entry_count == 0 ||
      header.entry_count > ZI_GPT_MAXIMUM_ENTRY_COUNT ||
      header.entry_size < ZI_GPT_MINIMUM_ENTRY_SIZE ||
      header.entry_size > ZI_GPT_MAXIMUM_ENTRY_SIZE ||
      (header.entry_size & (header.entry_size - 1)) != 0 ||
      zi_guid_equal(&header.disk_guid, &k_zero_guid)) {
    return ZI_STATUS_INVALID_STATE;
  }
  uint64_t entry_bytes = (uint64_t)header.entry_count * header.entry_size;
  uint64_t entry_blocks = (entry_bytes + device->block_size - 1) / device->block_size;
  if (header.entry_lba >= device->block_count || entry_blocks == 0 ||
      entry_blocks > device->block_count - header.entry_lba ||
      !(header.entry_lba + entry_blocks - 1 < header.first_usable_lba ||
        header.entry_lba > header.last_usable_lba)) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  *out_header = header;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_entries_crc(const ZiBlockDevice* device,
                                     const ZiGptHeaderData* header,
                                     void* block_buffer,
                                     size_t block_buffer_size) {
  uint64_t total_bytes = (uint64_t)header->entry_count * header->entry_size;
  uint64_t consumed = 0;
  uint32_t crc = 0;
  while (consumed < total_bytes) {
    uint64_t lba = header->entry_lba + (consumed / device->block_size);
    ZiStatus status = device->read_blocks(device->context, lba, 1, block_buffer, block_buffer_size);
    if (ZiFailed(status)) {
      return status;
    }
    size_t chunk = (size_t)(total_bytes - consumed);
    if (chunk > device->block_size) {
      chunk = device->block_size;
    }
    crc = zi_crc32(crc, block_buffer, chunk);
    consumed += chunk;
  }
  return crc == header->entries_crc ? ZI_STATUS_SUCCESS : ZI_STATUS_CHECKSUM_MISMATCH;
}

static ZiStatus decode_partitions(const ZiBlockDevice* device,
                                  const ZiGptHeaderData* header,
                                  void* block_buffer,
                                  size_t block_buffer_size,
                                  ZiGptPartition* partitions,
                                  size_t partition_capacity,
                                  size_t* out_partition_count) {
  unsigned char encoded[ZI_GPT_MINIMUM_ENTRY_SIZE] = {0};
  size_t count = 0;
  for (uint32_t index = 0; index < header->entry_count; ++index) {
    uint64_t entry_offset =
        (header->entry_lba * device->block_size) + ((uint64_t)index * header->entry_size);
    ZiStatus status =
        read_bytes(device, entry_offset, encoded, sizeof encoded, block_buffer, block_buffer_size);
    if (ZiFailed(status)) {
      return status;
    }
    if (bytes_equal(encoded, k_zero_guid.bytes, sizeof k_zero_guid.bytes)) {
      continue;
    }
    if (count >= partition_capacity) {
      return ZI_STATUS_BUFFER_TOO_SMALL;
    }
    ZiGptPartition partition = {0};
    for (size_t byte = 0; byte < 16; ++byte) {
      partition.type_guid.bytes[byte] = encoded[byte];
      partition.unique_guid.bytes[byte] = encoded[16 + byte];
    }
    partition.first_lba = zi_read_u64_le(encoded + 32);
    partition.last_lba = zi_read_u64_le(encoded + 40);
    partition.attributes = zi_read_u64_le(encoded + 48);
    for (size_t unit = 0; unit < ZI_GPT_PARTITION_NAME_UNITS; ++unit) {
      partition.name[unit] = zi_read_u16_le(encoded + 56 + (unit * 2));
    }
    if (zi_guid_equal(&partition.unique_guid, &k_zero_guid) ||
        partition.first_lba < header->first_usable_lba ||
        partition.first_lba > partition.last_lba || partition.last_lba > header->last_usable_lba) {
      return ZI_STATUS_INVALID_STATE;
    }
    for (size_t prior = 0; prior < count; ++prior) {
      if (partition_overlaps(&partition, &partitions[prior])) {
        return ZI_STATUS_ADDRESS_CONFLICT;
      }
      if (zi_guid_equal(&partition.unique_guid, &partitions[prior].unique_guid)) {
        return ZI_STATUS_ALREADY_EXISTS;
      }
    }
    partitions[count] = partition;
    ++count;
  }
  *out_partition_count = count;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus read_bytes(const ZiBlockDevice* device,
                           uint64_t byte_offset,
                           void* output,
                           size_t size,
                           void* block_buffer,
                           size_t block_buffer_size) {
  if (output == NULL || size == 0 || byte_offset > UINT64_MAX - size) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char* destination = output;
  size_t copied = 0;
  while (copied < size) {
    uint64_t current = byte_offset + copied;
    uint64_t lba = current / device->block_size;
    size_t in_block = (size_t)(current % device->block_size);
    if (lba >= device->block_count) {
      return ZI_STATUS_OUT_OF_BOUNDS;
    }
    ZiStatus status = device->read_blocks(device->context, lba, 1, block_buffer, block_buffer_size);
    if (ZiFailed(status)) {
      return status;
    }
    size_t chunk = device->block_size - in_block;
    if (chunk > size - copied) {
      chunk = size - copied;
    }
    const unsigned char* source = block_buffer;
    for (size_t index = 0; index < chunk; ++index) {
      destination[copied + index] = source[in_block + index];
    }
    copied += chunk;
  }
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

static bool partition_overlaps(const ZiGptPartition* left, const ZiGptPartition* right) {
  return (bool)((left->first_lba <= right->last_lba && right->first_lba <= left->last_lba) != 0);
}
