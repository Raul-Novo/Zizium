// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/handle.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/executive_lock.h"
#include "zi/object.h"
#include "zi/security.h"
#include "zizium/status.h"
#include "zizium/types.h"

static ZiHandle encode_handle(size_t index, uint32_t generation);
static ZiStatus decode_handle(const ZiHandleTable* table,
                              ZiHandle handle,
                              size_t* out_index,
                              uint32_t* out_generation);
static uint32_t next_generation(uint32_t generation);
static ZiStatus reference_handle_entry(ZiHandleTable* table,
                                       ZiHandle handle,
                                       ZiObjectHeader** out_object,
                                       ZiAccessMask* out_granted_access);

ZiStatus
zi_handle_table_initialise(ZiHandleTable* table, ZiHandleTableEntry* entries, size_t capacity) {
  if (table == NULL || entries == NULL || capacity == 0 || capacity > UINT32_MAX - 1u) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  table->entries = entries;
  table->capacity = capacity;
  table->active_count = 0;
  table->is_closing = 0;
  zi_executive_lock_initialise(&table->lock);
  for (size_t index = 0; index < capacity; ++index) {
    entries[index].object = NULL;
    entries[index].granted_access = 0;
    entries[index].generation = 1;
    entries[index].flags = 0;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_handle_open(ZiHandleTable* table,
                        ZiObjectHeader* object,
                        const ZiAccessToken* token,
                        ZiAccessMask requested_access,
                        ZiHandle* out_handle) {
  if (table == NULL || object == NULL || token == NULL || requested_access == 0 ||
      out_handle == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_handle = ZI_INVALID_HANDLE;
  if (object->security_descriptor == NULL) {
    return ZI_STATUS_ACCESS_DENIED;
  }

  ZiAccessMask granted_access = 0;
  ZiStatus status = zi_security_access_check(object->security_descriptor,
                                             token,
                                             requested_access,
                                             &granted_access);
  if (ZiFailed(status)) {
    return status;
  }

  zi_executive_lock_acquire(&table->lock);
  if (table->is_closing != 0) {
    zi_executive_lock_release(&table->lock);
    return ZI_STATUS_PROCESS_TERMINATED;
  }
  for (size_t index = 0; index < table->capacity; ++index) {
    ZiHandleTableEntry* entry = &table->entries[index];
    if ((entry->flags & ZI_HANDLE_ENTRY_IN_USE) != 0 || entry->generation == 0) {
      continue;
    }
    status = zi_object_add_handle(object);
    if (ZiFailed(status)) {
      zi_executive_lock_release(&table->lock);
      return status;
    }
    entry->object = object;
    entry->granted_access = granted_access;
    entry->flags = ZI_HANDLE_ENTRY_IN_USE;
    ++table->active_count;
    *out_handle = encode_handle(index, entry->generation);
    zi_executive_lock_release(&table->lock);
    return ZI_STATUS_SUCCESS;
  }
  zi_executive_lock_release(&table->lock);
  return ZI_STATUS_HANDLE_TABLE_FULL;
}

ZiStatus zi_handle_lookup(ZiHandleTable* table,
                          ZiHandle handle,
                          ZiAccessMask desired_access,
                          const ZiObjectType* expected_type,
                          ZiObjectHeader** out_object) {
  if (out_object == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_object = NULL;

  ZiObjectHeader* object = NULL;
  ZiAccessMask granted_access = 0;
  ZiStatus status = reference_handle_entry(table, handle, &object, &granted_access);
  if (ZiFailed(status)) {
    return status;
  }
  if ((desired_access & ~granted_access) != 0) {
    (void)zi_object_dereference(object);
    return ZI_STATUS_ACCESS_DENIED;
  }
  if (expected_type != NULL && object->type != expected_type) {
    (void)zi_object_dereference(object);
    return ZI_STATUS_INVALID_HANDLE;
  }
  *out_object = object;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_handle_duplicate(ZiHandleTable* source_table,
                             ZiHandle source_handle,
                             ZiHandleTable* target_table,
                             const ZiAccessToken* target_token,
                             ZiAccessMask requested_access,
                             uint32_t flags,
                             ZiHandle* out_handle) {
  if (source_table == NULL || target_table == NULL || target_token == NULL || out_handle == NULL ||
      (flags & ~ZI_HANDLE_DUPLICATE_SAME_ACCESS) != 0 ||
      ((flags & ZI_HANDLE_DUPLICATE_SAME_ACCESS) == 0 && requested_access == 0)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_handle = ZI_INVALID_HANDLE;

  ZiObjectHeader* object = NULL;
  ZiAccessMask source_access = 0;
  ZiStatus status = reference_handle_entry(source_table, source_handle, &object, &source_access);
  if (ZiFailed(status)) {
    return status;
  }
  ZiAccessMask target_access =
      (flags & ZI_HANDLE_DUPLICATE_SAME_ACCESS) != 0 ? source_access : requested_access;
  if ((target_access & ~source_access) != 0) {
    (void)zi_object_dereference(object);
    return ZI_STATUS_ACCESS_DENIED;
  }

  status = zi_handle_open(target_table, object, target_token, target_access, out_handle);
  (void)zi_object_dereference(object);
  return status;
}

ZiStatus zi_handle_close(ZiHandleTable* table, ZiHandle handle) {
  size_t index = 0;
  uint32_t generation = 0;
  ZiStatus status = decode_handle(table, handle, &index, &generation);
  if (ZiFailed(status)) {
    return status;
  }

  zi_executive_lock_acquire(&table->lock);
  ZiHandleTableEntry* entry = &table->entries[index];
  if ((entry->flags & ZI_HANDLE_ENTRY_IN_USE) == 0 || entry->generation != generation ||
      entry->object == NULL) {
    zi_executive_lock_release(&table->lock);
    return ZI_STATUS_INVALID_HANDLE;
  }
  ZiObjectHeader* object = entry->object;
  entry->object = NULL;
  entry->granted_access = 0;
  entry->flags = 0;
  entry->generation = next_generation(entry->generation);
  --table->active_count;
  zi_executive_lock_release(&table->lock);
  return zi_object_remove_handle(object);
}

ZiStatus zi_handle_table_close_all(ZiHandleTable* table) {
  if (table == NULL || table->entries == NULL || table->capacity == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  ZiStatus first_failure = ZI_STATUS_SUCCESS;
  zi_executive_lock_acquire(&table->lock);
  table->is_closing = 1;
  for (size_t index = 0; index < table->capacity; ++index) {
    ZiHandleTableEntry* entry = &table->entries[index];
    if ((entry->flags & ZI_HANDLE_ENTRY_IN_USE) == 0) {
      continue;
    }
    ZiObjectHeader* object = entry->object;
    entry->object = NULL;
    entry->granted_access = 0;
    entry->flags = 0;
    entry->generation = next_generation(entry->generation);
    --table->active_count;
    zi_executive_lock_release(&table->lock);
    ZiStatus status = zi_object_remove_handle(object);
    if (ZiFailed(status) && ZiSucceeded(first_failure)) {
      first_failure = status;
    }
    zi_executive_lock_acquire(&table->lock);
  }
  zi_executive_lock_release(&table->lock);
  return first_failure;
}

static ZiHandle encode_handle(size_t index, uint32_t generation) {
  uint64_t slot = (uint64_t)index + 1u;
  return ((uint64_t)generation << 32u) | slot;
}

static ZiStatus decode_handle(const ZiHandleTable* table,
                              ZiHandle handle,
                              size_t* out_index,
                              uint32_t* out_generation) {
  if (table == NULL || table->entries == NULL || table->capacity == 0 ||
      handle == ZI_INVALID_HANDLE || out_index == NULL || out_generation == NULL) {
    return ZI_STATUS_INVALID_HANDLE;
  }
  uint32_t slot = (uint32_t)(handle & UINT32_MAX);
  uint32_t generation = (uint32_t)(handle >> 32u);
  if (slot == 0 || generation == 0 || (size_t)(slot - 1u) >= table->capacity) {
    return ZI_STATUS_INVALID_HANDLE;
  }
  *out_index = (size_t)(slot - 1u);
  *out_generation = generation;
  return ZI_STATUS_SUCCESS;
}

static uint32_t next_generation(uint32_t generation) {
  return generation == UINT32_MAX ? 0 : generation + 1u;
}

static ZiStatus reference_handle_entry(ZiHandleTable* table,
                                       ZiHandle handle,
                                       ZiObjectHeader** out_object,
                                       ZiAccessMask* out_granted_access) {
  if (out_object == NULL || out_granted_access == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_object = NULL;
  *out_granted_access = 0;
  size_t index = 0;
  uint32_t generation = 0;
  ZiStatus status = decode_handle(table, handle, &index, &generation);
  if (ZiFailed(status)) {
    return status;
  }

  zi_executive_lock_acquire(&table->lock);
  if (table->is_closing != 0) {
    zi_executive_lock_release(&table->lock);
    return ZI_STATUS_PROCESS_TERMINATED;
  }
  ZiHandleTableEntry* entry = &table->entries[index];
  if ((entry->flags & ZI_HANDLE_ENTRY_IN_USE) == 0 || entry->generation != generation ||
      entry->object == NULL) {
    zi_executive_lock_release(&table->lock);
    return ZI_STATUS_INVALID_HANDLE;
  }
  status = zi_object_reference(entry->object);
  if (ZiSucceeded(status)) {
    *out_object = entry->object;
    *out_granted_access = entry->granted_access;
  }
  zi_executive_lock_release(&table->lock);
  return status;
}
