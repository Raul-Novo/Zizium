// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/security.h"
#include "zi/zifs.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_FS_SECURITY_TABLE_VERSION UINT16_C(1)
#define ZI_FS_SECURITY_DESCRIPTOR_VERSION UINT16_C(1)
#define ZI_FS_SECURITY_TABLE_HEADER_SIZE 256u
#define ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE 256u
#define ZI_FS_SECURITY_ACE_SIZE 16u
#define ZI_FS_SECURITY_MAXIMUM_ACES 12u
#define ZI_FS_SECURITY_MAXIMUM_TABLE_BLOCKS 16u
#define ZI_FS_SECURITY_MAXIMUM_RECORDS                                                             \
  ((ZI_FS_SECURITY_MAXIMUM_TABLE_BLOCKS *                                                          \
    (ZI_FS_BLOCK_SIZE / ZI_FS_SECURITY_DESCRIPTOR_RECORD_SIZE)) -                                  \
   1u)

#define ZI_FS_SECURITY_TABLE_FLAGS_NONE UINT64_C(0)
#define ZI_FS_SECURITY_DESCRIPTOR_FLAGS_NONE UINT32_C(0)
#define ZI_FS_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT (UINT32_C(1) << 0)
#define ZI_FS_SECURITY_DESCRIPTOR_FLAGS_SUPPORTED ZI_FS_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT

typedef struct ZiFsSecurityTableHeader {
  uint64_t generation;
  uint32_t table_block_count;
  uint32_t record_count;
  uint32_t record_capacity;
  uint64_t used_bytes;
  uint64_t flags;
} ZiFsSecurityTableHeader;

typedef struct ZiFsSecurityDescriptorStorage {
  uint64_t security_id;
  uint32_t flags;
  ZiSecurityDescriptor descriptor;
  ZiAcl dacl;
  ZiAce entries[ZI_FS_SECURITY_MAXIMUM_ACES];
} ZiFsSecurityDescriptorStorage;

ZiStatus ZiFsInitialiseSecurityTable(void* table, size_t table_size, uint64_t generation);
ZiStatus ZiFsAppendSecurityDescriptor(void* table,
                                      size_t table_size,
                                      uint64_t security_id,
                                      uint32_t flags,
                                      const ZiSecurityDescriptor* descriptor);
ZiStatus ZiFsValidateSecurityTable(const void* table,
                                   size_t table_size,
                                   ZiFsSecurityTableHeader* out_header);
ZiStatus ZiFsDecodeSecurityDescriptor(const void* record,
                                      size_t record_size,
                                      ZiFsSecurityDescriptorStorage* out_storage);
ZiStatus
ZiFsValidateSecurityState(ZiFsVolume* volume, void* block_buffer, size_t block_buffer_size);
ZiStatus ZiFsLoadSecurityDescriptor(const ZiFsVolume* volume,
                                    uint64_t security_id,
                                    void* block_buffer,
                                    size_t block_buffer_size,
                                    ZiFsSecurityDescriptorStorage* out_storage);
ZiStatus ZiFsCheckSecurityAccess(const ZiFsVolume* volume,
                                 uint64_t security_id,
                                 const ZiAccessToken* token,
                                 ZiAccessMask requested_access,
                                 ZiAccessMask* out_granted_access,
                                 void* block_buffer,
                                 size_t block_buffer_size);
