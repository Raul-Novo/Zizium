// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/executive_lock.h"
#include "zi/security.h"
#include "zizium/status.h"
#include "zizium/types.h"

struct ZiObjectHeader;

#define ZI_OBJECT_OPERATIONS_VERSION 2u
#define ZI_OBJECT_TYPE_DIRECTORY UINT32_C(0x00000001)

typedef void (*ZiObjectDestroyRoutine)(struct ZiObjectHeader* object);
typedef void (*ZiObjectLastHandleClosedRoutine)(struct ZiObjectHeader* object);

#define ZI_OBJECT_FLAG_NEW_HANDLES_DISABLED UINT32_C(0x00000001)

typedef struct ZiObjectOperations {
  uint32_t struct_size;
  uint32_t version;
  ZiObjectDestroyRoutine destroy;
  ZiObjectLastHandleClosedRoutine last_handle_closed;
} ZiObjectOperations;

typedef struct ZiObjectType {
  uint32_t type_id;
  ZiStringView name;
  const ZiObjectOperations* operations;
  uint32_t flags;
} ZiObjectType;

typedef struct ZiObjectHeader {
  const ZiObjectType* type;
  ZiStringView name;
  struct ZiObjectHeader* parent;
  const ZiSecurityDescriptor* security_descriptor;
  const ZiObjectOperations* operations;
  const char* debug_name;
  uint32_t reference_count;
  uint32_t handle_count;
  uint32_t flags;
  uint32_t is_destroyed;
  ZiExecutiveLock lock;
} ZiObjectHeader;

typedef struct ZiObjectTypeRegistry {
  const ZiObjectType** types;
  size_t capacity;
  size_t count;
  ZiExecutiveLock lock;
} ZiObjectTypeRegistry;

typedef struct ZiObjectDirectoryEntry {
  ZiObjectHeader* object;
} ZiObjectDirectoryEntry;

typedef struct ZiObjectDirectory {
  ZiObjectHeader header;
  ZiObjectDirectoryEntry* entries;
  size_t capacity;
  size_t count;
  ZiExecutiveLock lock;
} ZiObjectDirectory;

ZiStatus zi_object_initialise(ZiObjectHeader* object,
                              const ZiObjectType* type,
                              ZiStringView name,
                              ZiObjectHeader* parent,
                              const ZiSecurityDescriptor* security_descriptor,
                              const char* debug_name);
ZiStatus zi_object_reference(ZiObjectHeader* object);
ZiStatus zi_object_dereference(ZiObjectHeader* object);
ZiStatus zi_object_add_handle(ZiObjectHeader* object);
ZiStatus zi_object_remove_handle(ZiObjectHeader* object);
ZiStatus zi_object_type_registry_initialise(ZiObjectTypeRegistry* registry,
                                            const ZiObjectType** type_storage,
                                            size_t capacity);
ZiStatus zi_object_type_register(ZiObjectTypeRegistry* registry, const ZiObjectType* type);
ZiStatus zi_object_type_find_by_id(ZiObjectTypeRegistry* registry,
                                   uint32_t type_id,
                                   const ZiObjectType** out_type);
ZiStatus zi_object_type_find_by_name(ZiObjectTypeRegistry* registry,
                                     ZiStringView name,
                                     const ZiObjectType** out_type);
ZiStatus zi_object_directory_initialise(ZiObjectDirectory* directory,
                                        const ZiObjectType* directory_type,
                                        ZiStringView name,
                                        ZiObjectDirectoryEntry* entry_storage,
                                        size_t capacity,
                                        const ZiSecurityDescriptor* security_descriptor,
                                        const char* debug_name);
ZiStatus zi_object_directory_insert(ZiObjectDirectory* directory, ZiObjectHeader* object);
ZiStatus zi_object_directory_lookup(ZiObjectDirectory* directory,
                                    ZiStringView name,
                                    ZiObjectHeader** out_object);
ZiStatus zi_object_directory_remove(ZiObjectDirectory* directory,
                                    ZiStringView name,
                                    ZiObjectHeader** out_object);
ZiStatus zi_object_namespace_lookup(ZiObjectDirectory* root,
                                    ZiStringView absolute_path,
                                    ZiObjectHeader** out_object);
