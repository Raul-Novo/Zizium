// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>

#include "zi/executive_lock.h"
#include "zi/object.h"
#include "zi/security.h"
#include "zizium/status.h"
#include "zizium/types.h"

enum ZiHandleEntryFlags {
  ZI_HANDLE_ENTRY_IN_USE = 0x00000001,
};

enum ZiHandleDuplicateFlags {
  ZI_HANDLE_DUPLICATE_SAME_ACCESS = 0x00000001,
};

typedef struct ZiHandleTableEntry {
  ZiObjectHeader* object;
  ZiAccessMask granted_access;
  uint32_t generation;
  uint32_t flags;
} ZiHandleTableEntry;

typedef struct ZiHandleTable {
  ZiHandleTableEntry* entries;
  size_t capacity;
  size_t active_count;
  uint32_t is_closing;
  ZiExecutiveLock lock;
} ZiHandleTable;

ZiStatus
zi_handle_table_initialise(ZiHandleTable* table, ZiHandleTableEntry* entries, size_t capacity);
ZiStatus zi_handle_open(ZiHandleTable* table,
                        ZiObjectHeader* object,
                        const ZiAccessToken* token,
                        ZiAccessMask requested_access,
                        ZiHandle* out_handle);
ZiStatus zi_handle_lookup(ZiHandleTable* table,
                          ZiHandle handle,
                          ZiAccessMask desired_access,
                          const ZiObjectType* expected_type,
                          ZiObjectHeader** out_object);
ZiStatus zi_handle_duplicate(ZiHandleTable* source_table,
                             ZiHandle source_handle,
                             ZiHandleTable* target_table,
                             const ZiAccessToken* target_token,
                             ZiAccessMask requested_access,
                             uint32_t flags,
                             ZiHandle* out_handle);
ZiStatus zi_handle_close(ZiHandleTable* table, ZiHandle handle);
ZiStatus zi_handle_table_close_all(ZiHandleTable* table);
