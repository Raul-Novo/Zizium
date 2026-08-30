// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/security.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/block.h"
#include "zi/byte_order.h"
#include "zi/crc32c.h"
#include "zi/zifs.h"
#include "zi/zifs_security.h"
#include "zizium/status.h"
#include "zizium/types.h"

enum {
  ZIFS_SECURITY_TABLE_MAGIC_OFFSET = 0,
  ZIFS_SECURITY_TABLE_VERSION_OFFSET = 4,
  ZIFS_SECURITY_TABLE_HEADER_SIZE_OFFSET = 6,
  ZIFS_SECURITY_TABLE_RECORD_SIZE_OFFSET = 8,
  ZIFS_SECURITY_TABLE_ACE_SIZE_OFFSET = 10,
  ZIFS_SECURITY_TABLE_BLOCK_COUNT_OFFSET = 12,
  ZIFS_SECURITY_TABLE_RECORD_COUNT_OFFSET = 16,
  ZIFS_SECURITY_TABLE_RECORD_CAPACITY_OFFSET = 20,
  ZIFS_SECURITY_TABLE_GENERATION_OFFSET = 24,
  ZIFS_SECURITY_TABLE_USED_BYTES_OFFSET = 32,
  ZIFS_SECURITY_TABLE_FLAGS_OFFSET = 40,
  ZIFS_SECURITY_TABLE_RESERVED_OFFSET = 48,
  ZIFS_SECURITY_TABLE_CHECKSUM_OFFSET = 252,
  ZIFS_SECURITY_RECORD_MAGIC_OFFSET = 0,
  ZIFS_SECURITY_RECORD_VERSION_OFFSET = 4,
  ZIFS_SECURITY_RECORD_SIZE_OFFSET = 6,
  ZIFS_SECURITY_RECORD_ID_OFFSET = 8,
  ZIFS_SECURITY_RECORD_FLAGS_OFFSET = 16,
  ZIFS_SECURITY_RECORD_CONTROL_OFFSET = 20,
  ZIFS_SECURITY_RECORD_OWNER_OFFSET = 24,
  ZIFS_SECURITY_RECORD_GROUP_OFFSET = 32,
  ZIFS_SECURITY_RECORD_ACE_COUNT_OFFSET = 40,
  ZIFS_SECURITY_RECORD_ACE_SIZE_OFFSET = 42,
  ZIFS_SECURITY_RECORD_RESERVED_OFFSET = 44,
  ZIFS_SECURITY_RECORD_ACES_OFFSET = 48,
  ZIFS_SECURITY_RECORD_TRAILING_RESERVED_OFFSET = 240,
  ZIFS_SECURITY_RECORD_CHECKSUM_OFFSET = 252,
};

static const unsigned char k_security_table_magic[4] = {'Z', 'I', 'S', 'D'};
static const unsigned char k_security_record_magic[4] = {'Z', 'I', 'S', 'E'};

static bool security_table_size_is_valid(size_t table_size);
static uint32_t security_table_capacity(size_t table_size);
static uint32_t calculate_security_table_checksum(const unsigned char* bytes, size_t table_size);
static void update_security_table_checksum(unsigned char* bytes, size_t table_size);
static ZiStatus decode_security_table_header(const void* table,
                                             size_t table_size,
                                             ZiFsSecurityTableHeader* out_header);
static ZiStatus encode_security_descriptor_record(uint64_t security_id,
                                                  uint32_t flags,
                                                  const ZiSecurityDescriptor* descriptor,
                                                  void* output,
                                                  size_t output_size);
static ZiStatus validate_security_ace(const ZiAce* entry);
static bool bytes_are_zero(const unsigned char* bytes, size_t size);
static ZiStatus validate_security_table_records(const unsigned char* bytes,
                                                const ZiFsSecurityTableHeader* header,
                                                size_t table_size);
static ZiStatus calculate_device_table_checksum(const ZiFsVolume* volume,
                                                void* block_buffer,
                                                size_t block_buffer_size,
                                                uint32_t* out_checksum);
static ZiStatus validate_device_security_records(const ZiFsVolume* volume,
                                                 const ZiFsSecurityTableHeader* header,
                                                 void* block_buffer,
                                                 size_t block_buffer_size,
                                                 uint64_t* out_security_ids);
static ZiStatus validate_file_security_references(const ZiFsVolume* volume,
                                                  const uint64_t* security_ids,
                                                  size_t security_id_count,
                                                  void* block_buffer,
                                                  size_t block_buffer_size);
static bool security_id_is_present(const uint64_t* security_ids,
                                   size_t security_id_count,
                                   uint64_t security_id);
static ZiStatus read_security_record(const ZiFsVolume* volume,
                                     uint32_t record_index,
                                     void* block_buffer,
                                     size_t block_buffer_size,
                                     ZiFsSecurityDescriptorStorage* out_storage);

ZiStatus ZiFsInitialiseSecurityTable(void* table, size_t table_size, uint64_t generation) {
  if (table == NULL || generation == 0 || !security_table_size_is_valid(table_size)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  unsigned char* bytes = table;
  zi_memory_zero(bytes, table_size);
  zi_memory_copy(bytes + ZIFS_SECURITY_TABLE_MAGIC_OFFSET,
                 k_security_table_magic,
                 sizeof k_security_table_magic);
  zi_write_u16_le(bytes + ZIFS_SECURITY_TABLE_VERSION_OFFSET, ZI_FS_SECURITY_TABLE_VERSION);
  zi_write_u16_le(bytes + ZIFS_SECURITY_TABLE_HEADER_SIZE_OFFSET, ZI_FS_SECURITY_TABLE_HEADER_SIZE);
  zi_write_u16_le(bytes + ZIFS_SECURITY_TABLE_RECORD_SIZE_OFFSET,
                  ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE);
  zi_write_u16_le(bytes + ZIFS_SECURITY_TABLE_ACE_SIZE_OFFSET, ZI_FS_SECURITY_ACE_SIZE);
  zi_write_u32_le(bytes + ZIFS_SECURITY_TABLE_BLOCK_COUNT_OFFSET,
                  (uint32_t)(table_size / ZI_FS_BLOCK_SIZE));
  zi_write_u32_le(bytes + ZIFS_SECURITY_TABLE_RECORD_COUNT_OFFSET, 0);
  zi_write_u32_le(bytes + ZIFS_SECURITY_TABLE_RECORD_CAPACITY_OFFSET,
                  security_table_capacity(table_size));
  zi_write_u64_le(bytes + ZIFS_SECURITY_TABLE_GENERATION_OFFSET, generation);
  zi_write_u64_le(bytes + ZIFS_SECURITY_TABLE_USED_BYTES_OFFSET, ZI_FS_SECURITY_TABLE_HEADER_SIZE);
  zi_write_u64_le(bytes + ZIFS_SECURITY_TABLE_FLAGS_OFFSET, ZI_FS_SECURITY_TABLE_FLAGS_NONE);
  update_security_table_checksum(bytes, table_size);
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsAppendSecurityDescriptor(void* table,
                                      size_t table_size,
                                      uint64_t security_id,
                                      uint32_t flags,
                                      const ZiSecurityDescriptor* descriptor) {
  if (table == NULL || security_id == 0 || descriptor == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiFsSecurityTableHeader header = {0};
  ZiStatus status = ZiFsValidateSecurityTable(table, table_size, &header);
  if (ZiFailed(status)) {
    return status;
  }
  if (header.record_count >= header.record_capacity) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  unsigned char* bytes = table;
  if (header.record_count != 0) {
    size_t previous_offset =
        ZI_FS_SECURITY_TABLE_HEADER_SIZE +
        (((size_t)header.record_count - 1u) * ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE);
    uint64_t previous_id = zi_read_u64_le(bytes + previous_offset + ZIFS_SECURITY_RECORD_ID_OFFSET);
    if (security_id <= previous_id) {
      return security_id == previous_id ? ZI_STATUS_ALREADY_EXISTS : ZI_STATUS_INVALID_ARGUMENT;
    }
  }
  size_t record_offset = ZI_FS_SECURITY_TABLE_HEADER_SIZE +
                         ((size_t)header.record_count * ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE);
  status = encode_security_descriptor_record(security_id,
                                             flags,
                                             descriptor,
                                             bytes + record_offset,
                                             table_size - record_offset);
  if (ZiFailed(status)) {
    return status;
  }
  ++header.record_count;
  header.used_bytes = ZI_FS_SECURITY_TABLE_HEADER_SIZE +
                      ((uint64_t)header.record_count * ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE);
  zi_write_u32_le(bytes + ZIFS_SECURITY_TABLE_RECORD_COUNT_OFFSET, header.record_count);
  zi_write_u64_le(bytes + ZIFS_SECURITY_TABLE_USED_BYTES_OFFSET, header.used_bytes);
  update_security_table_checksum(bytes, table_size);
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsValidateSecurityTable(const void* table,
                                   size_t table_size,
                                   ZiFsSecurityTableHeader* out_header) {
  ZiFsSecurityTableHeader header = {0};
  ZiStatus status = decode_security_table_header(table, table_size, &header);
  if (ZiFailed(status)) {
    return status;
  }
  const unsigned char* bytes = table;
  if (zi_read_u32_le(bytes + ZIFS_SECURITY_TABLE_CHECKSUM_OFFSET) !=
      calculate_security_table_checksum(bytes, table_size)) {
    return ZI_STATUS_CHECKSUM_MISMATCH;
  }
  status = validate_security_table_records(bytes, &header, table_size);
  if (ZiFailed(status)) {
    return status;
  }
  if (out_header != NULL) {
    *out_header = header;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsDecodeSecurityDescriptor(const void* record,
                                      size_t record_size,
                                      ZiFsSecurityDescriptorStorage* out_storage) {
  if (record == NULL || out_storage == NULL ||
      record_size < ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const unsigned char* bytes = record;
  if (zi_memory_compare(bytes + ZIFS_SECURITY_RECORD_MAGIC_OFFSET,
                        k_security_record_magic,
                        sizeof k_security_record_magic) != 0 ||
      zi_read_u16_le(bytes + ZIFS_SECURITY_RECORD_VERSION_OFFSET) !=
          ZI_FS_SECURITY_DESCRIPTOR_VERSION ||
      zi_read_u16_le(bytes + ZIFS_SECURITY_RECORD_SIZE_OFFSET) !=
          ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  if (zi_read_u32_le(bytes + ZIFS_SECURITY_RECORD_CHECKSUM_OFFSET) !=
      zi_crc32c(0, bytes, ZIFS_SECURITY_RECORD_CHECKSUM_OFFSET)) {
    return ZI_STATUS_CHECKSUM_MISMATCH;
  }

  uint64_t security_id = zi_read_u64_le(bytes + ZIFS_SECURITY_RECORD_ID_OFFSET);
  uint32_t flags = zi_read_u32_le(bytes + ZIFS_SECURITY_RECORD_FLAGS_OFFSET);
  uint16_t ace_count = zi_read_u16_le(bytes + ZIFS_SECURITY_RECORD_ACE_COUNT_OFFSET);
  if (security_id == 0 || (flags & ~ZI_FS_SECURITY_DESCRIPTOR_FLAGS_SUPPORTED) != 0 ||
      zi_read_u16_le(bytes + ZIFS_SECURITY_RECORD_ACE_SIZE_OFFSET) != ZI_FS_SECURITY_ACE_SIZE ||
      ace_count > ZI_FS_SECURITY_MAXIMUM_ACES ||
      !bytes_are_zero(bytes + ZIFS_SECURITY_RECORD_RESERVED_OFFSET, 4) ||
      !bytes_are_zero(bytes + ZIFS_SECURITY_RECORD_TRAILING_RESERVED_OFFSET,
                      ZIFS_SECURITY_RECORD_CHECKSUM_OFFSET -
                          ZIFS_SECURITY_RECORD_TRAILING_RESERVED_OFFSET)) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  bool dacl_present = (flags & ZI_FS_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT) != 0;
  if (!dacl_present && ace_count != 0) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }

  ZiAce entries[ZI_FS_SECURITY_MAXIMUM_ACES] = {0};
  for (size_t index = 0; index < ZI_FS_SECURITY_MAXIMUM_ACES; ++index) {
    const unsigned char* source =
        bytes + ZIFS_SECURITY_RECORD_ACES_OFFSET + (index * ZI_FS_SECURITY_ACE_SIZE);
    if (index >= ace_count) {
      if (!bytes_are_zero(source, ZI_FS_SECURITY_ACE_SIZE)) {
        return ZI_STATUS_CORRUPT_FILESYSTEM;
      }
      continue;
    }
    entries[index].type = source[0];
    entries[index].inheritance_flags = source[1];
    entries[index].reserved = zi_read_u16_le(source + 2);
    entries[index].access_mask = zi_read_u32_le(source + 4);
    entries[index].trustee.authority = zi_read_u32_le(source + 8);
    entries[index].trustee.value = zi_read_u32_le(source + 12);
    if (ZiFailed(validate_security_ace(&entries[index]))) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
  }

  ZiSecurityDescriptor descriptor = {
      sizeof(ZiSecurityDescriptor),
      ZI_SECURITY_DESCRIPTOR_VERSION,
      {zi_read_u32_le(bytes + ZIFS_SECURITY_RECORD_OWNER_OFFSET),
       zi_read_u32_le(bytes + ZIFS_SECURITY_RECORD_OWNER_OFFSET + 4)},
      {zi_read_u32_le(bytes + ZIFS_SECURITY_RECORD_GROUP_OFFSET),
       zi_read_u32_le(bytes + ZIFS_SECURITY_RECORD_GROUP_OFFSET + 4)},
      NULL,
      zi_read_u32_le(bytes + ZIFS_SECURITY_RECORD_CONTROL_OFFSET),
  };
  ZiAcl dacl = {sizeof(ZiAcl), ZI_ACL_VERSION, entries, ace_count};
  if (dacl_present) {
    descriptor.dacl = &dacl;
  }
  if (ZiFailed(zi_security_descriptor_validate(&descriptor))) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }

  zi_memory_zero(out_storage, sizeof *out_storage);
  out_storage->security_id = security_id;
  out_storage->flags = flags;
  zi_memory_copy(out_storage->entries, entries, sizeof entries);
  out_storage->dacl = (ZiAcl){
      sizeof(ZiAcl),
      ZI_ACL_VERSION,
      out_storage->entries,
      ace_count,
  };
  out_storage->descriptor = descriptor;
  out_storage->descriptor.dacl = NULL;
  if (dacl_present) {
    out_storage->descriptor.dacl = &out_storage->dacl;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus
ZiFsValidateSecurityState(ZiFsVolume* volume, void* block_buffer, size_t block_buffer_size) {
  if (volume == NULL || block_buffer == NULL || block_buffer_size < ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if ((volume->superblock.incompatible_features & ZI_FS_FEATURE_INCOMPAT_SECURITY_V1) == 0 ||
      volume->superblock.security_table_blocks == 0 ||
      volume->superblock.security_table_blocks > ZI_FS_SECURITY_MAXIMUM_TABLE_BLOCKS) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  ZiStatus status = volume->device.read_blocks(volume->device.context,
                                               volume->superblock.security_table_start,
                                               1,
                                               block_buffer,
                                               block_buffer_size);
  if (ZiFailed(status)) {
    return status;
  }
  size_t table_size = (size_t)volume->superblock.security_table_blocks * (size_t)ZI_FS_BLOCK_SIZE;
  ZiFsSecurityTableHeader header = {0};
  status = decode_security_table_header(block_buffer, table_size, &header);
  if (ZiFailed(status)) {
    return status;
  }
  if (header.record_count == 0) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  uint32_t stored_checksum =
      zi_read_u32_le((const unsigned char*)block_buffer + ZIFS_SECURITY_TABLE_CHECKSUM_OFFSET);
  uint32_t calculated_checksum = 0;
  status = calculate_device_table_checksum(volume,
                                           block_buffer,
                                           block_buffer_size,
                                           &calculated_checksum);
  if (ZiFailed(status)) {
    return status;
  }
  if (stored_checksum != calculated_checksum) {
    return ZI_STATUS_CHECKSUM_MISMATCH;
  }

  uint64_t security_ids[ZI_FS_SECURITY_MAXIMUM_RECORDS] = {0};
  status = validate_device_security_records(volume,
                                            &header,
                                            block_buffer,
                                            block_buffer_size,
                                            security_ids);
  if (ZiFailed(status)) {
    return status;
  }
  status = validate_file_security_references(volume,
                                             security_ids,
                                             header.record_count,
                                             block_buffer,
                                             block_buffer_size);
  if (ZiFailed(status)) {
    return status;
  }
  volume->security_generation = header.generation;
  volume->security_record_count = header.record_count;
  return ZI_STATUS_SUCCESS;
}

ZiStatus ZiFsLoadSecurityDescriptor(const ZiFsVolume* volume,
                                    uint64_t security_id,
                                    void* block_buffer,
                                    size_t block_buffer_size,
                                    ZiFsSecurityDescriptorStorage* out_storage) {
  if (volume == NULL || security_id == 0 || block_buffer == NULL ||
      block_buffer_size < ZI_FS_BLOCK_SIZE || out_storage == NULL ||
      volume->security_record_count == 0 ||
      volume->security_record_count > ZI_FS_SECURITY_MAXIMUM_RECORDS) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  for (uint32_t index = 0; index < volume->security_record_count; ++index) {
    ZiFsSecurityDescriptorStorage storage = {0};
    ZiStatus status =
        read_security_record(volume, index, block_buffer, block_buffer_size, &storage);
    if (ZiFailed(status)) {
      return status;
    }
    if (storage.security_id == security_id) {
      *out_storage = storage;
      out_storage->dacl.entries = out_storage->entries;
      if ((out_storage->flags & ZI_FS_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT) != 0) {
        out_storage->descriptor.dacl = &out_storage->dacl;
      }
      return ZI_STATUS_SUCCESS;
    }
    if (storage.security_id > security_id) {
      break;
    }
  }
  return ZI_STATUS_NOT_FOUND;
}

ZiStatus ZiFsCheckSecurityAccess(const ZiFsVolume* volume,
                                 uint64_t security_id,
                                 const ZiAccessToken* token,
                                 ZiAccessMask requested_access,
                                 ZiAccessMask* out_granted_access,
                                 void* block_buffer,
                                 size_t block_buffer_size) {
  if (out_granted_access == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_granted_access = 0;
  ZiFsSecurityDescriptorStorage storage = {0};
  ZiStatus status =
      ZiFsLoadSecurityDescriptor(volume, security_id, block_buffer, block_buffer_size, &storage);
  if (ZiFailed(status)) {
    return status;
  }
  return zi_security_access_check(&storage.descriptor, token, requested_access, out_granted_access);
}

static bool security_table_size_is_valid(size_t table_size) {
  return (bool)(table_size >= ZI_FS_BLOCK_SIZE &&
                table_size <=
                    (size_t)ZI_FS_SECURITY_MAXIMUM_TABLE_BLOCKS * (size_t)ZI_FS_BLOCK_SIZE &&
                table_size % ZI_FS_BLOCK_SIZE == 0);
}

static uint32_t security_table_capacity(size_t table_size) {
  return (uint32_t)((table_size - ZI_FS_SECURITY_TABLE_HEADER_SIZE) /
                    ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE);
}

static uint32_t calculate_security_table_checksum(const unsigned char* bytes, size_t table_size) {
  static const unsigned char k_zero_checksum[4] = {0};
  uint32_t checksum = zi_crc32c(0, bytes, ZIFS_SECURITY_TABLE_CHECKSUM_OFFSET);
  checksum = zi_crc32c(checksum, k_zero_checksum, sizeof k_zero_checksum);
  return zi_crc32c(checksum,
                   bytes + ZIFS_SECURITY_TABLE_CHECKSUM_OFFSET + sizeof k_zero_checksum,
                   table_size - ZIFS_SECURITY_TABLE_CHECKSUM_OFFSET - sizeof k_zero_checksum);
}

static void update_security_table_checksum(unsigned char* bytes, size_t table_size) {
  zi_write_u32_le(bytes + ZIFS_SECURITY_TABLE_CHECKSUM_OFFSET, 0);
  zi_write_u32_le(bytes + ZIFS_SECURITY_TABLE_CHECKSUM_OFFSET,
                  calculate_security_table_checksum(bytes, table_size));
}

static ZiStatus decode_security_table_header(const void* table,
                                             size_t table_size,
                                             ZiFsSecurityTableHeader* out_header) {
  if (table == NULL || out_header == NULL || !security_table_size_is_valid(table_size)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const unsigned char* bytes = table;
  uint32_t expected_blocks = (uint32_t)(table_size / ZI_FS_BLOCK_SIZE);
  uint32_t expected_capacity = security_table_capacity(table_size);
  if (zi_memory_compare(bytes + ZIFS_SECURITY_TABLE_MAGIC_OFFSET,
                        k_security_table_magic,
                        sizeof k_security_table_magic) != 0 ||
      zi_read_u16_le(bytes + ZIFS_SECURITY_TABLE_VERSION_OFFSET) != ZI_FS_SECURITY_TABLE_VERSION ||
      zi_read_u16_le(bytes + ZIFS_SECURITY_TABLE_HEADER_SIZE_OFFSET) !=
          ZI_FS_SECURITY_TABLE_HEADER_SIZE ||
      zi_read_u16_le(bytes + ZIFS_SECURITY_TABLE_RECORD_SIZE_OFFSET) !=
          ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE ||
      zi_read_u16_le(bytes + ZIFS_SECURITY_TABLE_ACE_SIZE_OFFSET) != ZI_FS_SECURITY_ACE_SIZE ||
      zi_read_u32_le(bytes + ZIFS_SECURITY_TABLE_BLOCK_COUNT_OFFSET) != expected_blocks ||
      zi_read_u32_le(bytes + ZIFS_SECURITY_TABLE_RECORD_CAPACITY_OFFSET) != expected_capacity ||
      !bytes_are_zero(bytes + ZIFS_SECURITY_TABLE_RESERVED_OFFSET,
                      ZIFS_SECURITY_TABLE_CHECKSUM_OFFSET - ZIFS_SECURITY_TABLE_RESERVED_OFFSET)) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  ZiFsSecurityTableHeader header = {
      zi_read_u64_le(bytes + ZIFS_SECURITY_TABLE_GENERATION_OFFSET),
      expected_blocks,
      zi_read_u32_le(bytes + ZIFS_SECURITY_TABLE_RECORD_COUNT_OFFSET),
      expected_capacity,
      zi_read_u64_le(bytes + ZIFS_SECURITY_TABLE_USED_BYTES_OFFSET),
      zi_read_u64_le(bytes + ZIFS_SECURITY_TABLE_FLAGS_OFFSET),
  };
  uint64_t expected_used = ZI_FS_SECURITY_TABLE_HEADER_SIZE +
                           ((uint64_t)header.record_count * ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE);
  if (header.generation == 0 || header.record_count > header.record_capacity ||
      header.used_bytes != expected_used || header.flags != ZI_FS_SECURITY_TABLE_FLAGS_NONE) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  *out_header = header;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus encode_security_descriptor_record(uint64_t security_id,
                                                  uint32_t flags,
                                                  const ZiSecurityDescriptor* descriptor,
                                                  void* output,
                                                  size_t output_size) {
  if (security_id == 0 || descriptor == NULL || output == NULL ||
      output_size < ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE ||
      (flags & ~ZI_FS_SECURITY_DESCRIPTOR_FLAGS_SUPPORTED) != 0 ||
      ZiFailed(zi_security_descriptor_validate(descriptor))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  bool dacl_present = descriptor->dacl != NULL;
  bool flags_have_dacl = (flags & ZI_FS_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT) != 0;
  if ((dacl_present && !flags_have_dacl) || (!dacl_present && flags_have_dacl) ||
      (dacl_present && descriptor->dacl->entry_count > ZI_FS_SECURITY_MAXIMUM_ACES)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  unsigned char* bytes = output;
  zi_memory_zero(bytes, ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE);
  zi_memory_copy(bytes + ZIFS_SECURITY_RECORD_MAGIC_OFFSET,
                 k_security_record_magic,
                 sizeof k_security_record_magic);
  zi_write_u16_le(bytes + ZIFS_SECURITY_RECORD_VERSION_OFFSET, ZI_FS_SECURITY_DESCRIPTOR_VERSION);
  zi_write_u16_le(bytes + ZIFS_SECURITY_RECORD_SIZE_OFFSET, ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE);
  zi_write_u64_le(bytes + ZIFS_SECURITY_RECORD_ID_OFFSET, security_id);
  zi_write_u32_le(bytes + ZIFS_SECURITY_RECORD_FLAGS_OFFSET, flags);
  zi_write_u32_le(bytes + ZIFS_SECURITY_RECORD_CONTROL_OFFSET, descriptor->control_flags);
  zi_write_u32_le(bytes + ZIFS_SECURITY_RECORD_OWNER_OFFSET, descriptor->owner.authority);
  zi_write_u32_le(bytes + ZIFS_SECURITY_RECORD_OWNER_OFFSET + 4, descriptor->owner.value);
  zi_write_u32_le(bytes + ZIFS_SECURITY_RECORD_GROUP_OFFSET, descriptor->primary_group.authority);
  zi_write_u32_le(bytes + ZIFS_SECURITY_RECORD_GROUP_OFFSET + 4, descriptor->primary_group.value);
  size_t ace_count = 0;
  if (dacl_present) {
    ace_count = descriptor->dacl->entry_count;
  }
  zi_write_u16_le(bytes + ZIFS_SECURITY_RECORD_ACE_COUNT_OFFSET, (uint16_t)ace_count);
  zi_write_u16_le(bytes + ZIFS_SECURITY_RECORD_ACE_SIZE_OFFSET, ZI_FS_SECURITY_ACE_SIZE);
  for (size_t index = 0; index < ace_count; ++index) {
    const ZiAce* entry = &descriptor->dacl->entries[index];
    unsigned char* destination =
        bytes + ZIFS_SECURITY_RECORD_ACES_OFFSET + (index * ZI_FS_SECURITY_ACE_SIZE);
    destination[0] = entry->type;
    destination[1] = entry->inheritance_flags;
    zi_write_u16_le(destination + 2, entry->reserved);
    zi_write_u32_le(destination + 4, entry->access_mask);
    zi_write_u32_le(destination + 8, entry->trustee.authority);
    zi_write_u32_le(destination + 12, entry->trustee.value);
  }
  zi_write_u32_le(bytes + ZIFS_SECURITY_RECORD_CHECKSUM_OFFSET,
                  zi_crc32c(0, bytes, ZIFS_SECURITY_RECORD_CHECKSUM_OFFSET));
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_security_ace(const ZiAce* entry) {
  if (entry == NULL || (entry->type != ZI_ACE_DENY && entry->type != ZI_ACE_ALLOW) ||
      entry->reserved != 0 || (entry->inheritance_flags & ~ZI_ACE_INHERIT_SUPPORTED) != 0 ||
      entry->access_mask == 0 || (entry->access_mask & ~ZI_ACCESS_FULL_CONTROL) != 0 ||
      ZiFailed(zi_security_id_validate(entry->trustee))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return ZI_STATUS_SUCCESS;
}

static bool bytes_are_zero(const unsigned char* bytes, size_t size) {
  for (size_t index = 0; index < size; ++index) {
    if (bytes[index] != 0) {
      return false;
    }
  }
  return true;
}

static ZiStatus validate_security_table_records(const unsigned char* bytes,
                                                const ZiFsSecurityTableHeader* header,
                                                size_t table_size) {
  uint64_t previous_id = 0;
  for (uint32_t index = 0; index < header->record_count; ++index) {
    size_t offset =
        ZI_FS_SECURITY_TABLE_HEADER_SIZE + ((size_t)index * ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE);
    ZiFsSecurityDescriptorStorage storage = {0};
    ZiStatus status = ZiFsDecodeSecurityDescriptor(bytes + offset, table_size - offset, &storage);
    if (ZiFailed(status)) {
      return status;
    }
    if (storage.security_id <= previous_id) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    previous_id = storage.security_id;
  }
  if (!bytes_are_zero(bytes + (size_t)header->used_bytes,
                      table_size - (size_t)header->used_bytes)) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus calculate_device_table_checksum(const ZiFsVolume* volume,
                                                void* block_buffer,
                                                size_t block_buffer_size,
                                                uint32_t* out_checksum) {
  static const unsigned char k_zero_checksum[4] = {0};
  uint32_t checksum = 0;
  for (uint64_t block = 0; block < volume->superblock.security_table_blocks; ++block) {
    ZiStatus status = volume->device.read_blocks(volume->device.context,
                                                 volume->superblock.security_table_start + block,
                                                 1,
                                                 block_buffer,
                                                 block_buffer_size);
    if (ZiFailed(status)) {
      return status;
    }
    const unsigned char* bytes = block_buffer;
    if (block == 0) {
      checksum = zi_crc32c(checksum, bytes, ZIFS_SECURITY_TABLE_CHECKSUM_OFFSET);
      checksum = zi_crc32c(checksum, k_zero_checksum, sizeof k_zero_checksum);
      checksum = zi_crc32c(checksum,
                           bytes + ZIFS_SECURITY_TABLE_CHECKSUM_OFFSET + sizeof k_zero_checksum,
                           ZI_FS_BLOCK_SIZE - ZIFS_SECURITY_TABLE_CHECKSUM_OFFSET -
                               sizeof k_zero_checksum);
    } else {
      checksum = zi_crc32c(checksum, bytes, ZI_FS_BLOCK_SIZE);
    }
  }
  *out_checksum = checksum;
  return ZI_STATUS_SUCCESS;
}

// The bounded two-level walk keeps descriptor order and unused-slot checks in one pass.
// NOLINTNEXTLINE(readability-function-size)
static ZiStatus validate_device_security_records(const ZiFsVolume* volume,
                                                 const ZiFsSecurityTableHeader* header,
                                                 void* block_buffer,
                                                 size_t block_buffer_size,
                                                 uint64_t* out_security_ids) {
  uint32_t record_index = 0;
  uint64_t previous_id = 0;
  for (uint64_t table_block = 0; table_block < volume->superblock.security_table_blocks;
       ++table_block) {
    ZiStatus status =
        volume->device.read_blocks(volume->device.context,
                                   volume->superblock.security_table_start + table_block,
                                   1,
                                   block_buffer,
                                   block_buffer_size);
    if (ZiFailed(status)) {
      return status;
    }
    const unsigned char* bytes = block_buffer;
    size_t offset = table_block == 0 ? ZI_FS_SECURITY_TABLE_HEADER_SIZE : 0;
    while (offset < ZI_FS_BLOCK_SIZE) {
      const unsigned char* record = bytes + offset;
      if (record_index < header->record_count) {
        ZiFsSecurityDescriptorStorage storage = {0};
        status =
            ZiFsDecodeSecurityDescriptor(record, ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE, &storage);
        if (ZiFailed(status)) {
          return status;
        }
        if (storage.security_id <= previous_id) {
          return ZI_STATUS_CORRUPT_FILESYSTEM;
        }
        previous_id = storage.security_id;
        out_security_ids[record_index] = storage.security_id;
      } else if (!bytes_are_zero(record, ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE)) {
        return ZI_STATUS_CORRUPT_FILESYSTEM;
      }
      ++record_index;
      offset += ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE;
    }
  }
  return record_index == header->record_capacity ? ZI_STATUS_SUCCESS : ZI_STATUS_CORRUPT_FILESYSTEM;
}

static ZiStatus validate_file_security_references(const ZiFsVolume* volume,
                                                  const uint64_t* security_ids,
                                                  size_t security_id_count,
                                                  void* block_buffer,
                                                  size_t block_buffer_size) {
  const size_t records_per_block = ZI_FS_BLOCK_SIZE / ZI_FS_FILE_RECORD_SIZE;
  for (uint64_t block = 0; block < volume->superblock.record_table_blocks; ++block) {
    ZiStatus status = volume->device.read_blocks(volume->device.context,
                                                 volume->superblock.record_table_start + block,
                                                 1,
                                                 block_buffer,
                                                 block_buffer_size);
    if (ZiFailed(status)) {
      return status;
    }
    const unsigned char* bytes = block_buffer;
    for (size_t slot = 0; slot < records_per_block; ++slot) {
      const unsigned char* record_bytes = bytes + (slot * ZI_FS_FILE_RECORD_SIZE);
      if (bytes_are_zero(record_bytes, ZI_FS_FILE_RECORD_SIZE)) {
        continue;
      }
      ZiFsFileRecord record = {0};
      status = ZiFsDecodeFileRecord(record_bytes, ZI_FS_FILE_RECORD_SIZE, &record);
      if (ZiFailed(status)) {
        return status;
      }
      status = ZiFsValidateFileRecord(volume, &record);
      if (ZiFailed(status) ||
          !security_id_is_present(security_ids, security_id_count, record.security_id)) {
        return ZI_STATUS_CORRUPT_FILESYSTEM;
      }
    }
  }
  return ZI_STATUS_SUCCESS;
}

static bool security_id_is_present(const uint64_t* security_ids,
                                   size_t security_id_count,
                                   uint64_t security_id) {
  size_t first = 0;
  size_t end = security_id_count;
  while (first < end) {
    size_t middle = first + ((end - first) / 2u);
    if (security_ids[middle] == security_id) {
      return true;
    }
    if (security_ids[middle] < security_id) {
      first = middle + 1u;
    } else {
      end = middle;
    }
  }
  return false;
}

static ZiStatus read_security_record(const ZiFsVolume* volume,
                                     uint32_t record_index,
                                     void* block_buffer,
                                     size_t block_buffer_size,
                                     ZiFsSecurityDescriptorStorage* out_storage) {
  uint64_t byte_offset = ZI_FS_SECURITY_TABLE_HEADER_SIZE +
                         ((uint64_t)record_index * ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE);
  uint64_t table_block = byte_offset / ZI_FS_BLOCK_SIZE;
  size_t block_offset = (size_t)(byte_offset % ZI_FS_BLOCK_SIZE);
  if (table_block >= volume->superblock.security_table_blocks ||
      block_offset > ZI_FS_BLOCK_SIZE - ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  ZiStatus status =
      volume->device.read_blocks(volume->device.context,
                                 volume->superblock.security_table_start + table_block,
                                 1,
                                 block_buffer,
                                 block_buffer_size);
  if (ZiFailed(status)) {
    return status;
  }
  return ZiFsDecodeSecurityDescriptor((unsigned char*)block_buffer + block_offset,
                                      ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE,
                                      out_storage);
}
