// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/object.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/executive_lock.h"
#include "zi/security.h"
#include "zi/unicode.h"
#include "zizium/status.h"
#include "zizium/types.h"

static bool object_type_is_valid(const ZiObjectType* type);
static ZiStatus object_release_locked(ZiObjectHeader* object, ZiObjectDestroyRoutine* out_destroy);
static bool string_views_equal(ZiStringView left, ZiStringView right);
static bool is_dot_component(ZiStringView name);

ZiStatus zi_object_initialise(ZiObjectHeader* object,
                              const ZiObjectType* type,
                              ZiStringView name,
                              ZiObjectHeader* parent,
                              const ZiSecurityDescriptor* security_descriptor,
                              const char* debug_name) {
  if (object == NULL || !object_type_is_valid(type) || (name.data == NULL && name.size != 0) ||
      ZiFailed(zi_utf8_validate(name.data, name.size))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  object->type = type;
  object->name = name;
  object->parent = parent;
  object->security_descriptor = security_descriptor;
  object->operations = type->operations;
  object->debug_name = debug_name;
  object->reference_count = 1;
  object->handle_count = 0;
  object->flags = 0;
  object->is_destroyed = 0;
  zi_executive_lock_initialise(&object->lock);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_object_reference(ZiObjectHeader* object) {
  if (object == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  zi_executive_lock_acquire(&object->lock);
  if (object->is_destroyed != 0 || object->reference_count == UINT32_MAX) {
    zi_executive_lock_release(&object->lock);
    return ZI_STATUS_INVALID_STATE;
  }
  ++object->reference_count;
  zi_executive_lock_release(&object->lock);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_object_dereference(ZiObjectHeader* object) {
  if (object == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  ZiObjectDestroyRoutine destroy = NULL;
  zi_executive_lock_acquire(&object->lock);
  if (object->is_destroyed != 0 || object->reference_count == 0) {
    zi_executive_lock_release(&object->lock);
    return ZI_STATUS_INVALID_STATE;
  }
  ZiStatus status = object_release_locked(object, &destroy);
  zi_executive_lock_release(&object->lock);
  if (ZiSucceeded(status) && destroy != NULL) {
    destroy(object);
  }
  return status;
}

ZiStatus zi_object_add_handle(ZiObjectHeader* object) {
  if (object == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  zi_executive_lock_acquire(&object->lock);
  if (object->is_destroyed != 0 || object->handle_count == UINT32_MAX ||
      object->reference_count == UINT32_MAX ||
      (object->flags & ZI_OBJECT_FLAG_NEW_HANDLES_DISABLED) != 0) {
    zi_executive_lock_release(&object->lock);
    return ZI_STATUS_INVALID_STATE;
  }
  ++object->reference_count;
  ++object->handle_count;
  zi_executive_lock_release(&object->lock);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_object_remove_handle(ZiObjectHeader* object) {
  if (object == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  ZiObjectDestroyRoutine destroy = NULL;
  ZiObjectLastHandleClosedRoutine last_handle_closed = NULL;
  zi_executive_lock_acquire(&object->lock);
  if (object->is_destroyed != 0 || object->handle_count == 0 || object->reference_count == 0) {
    zi_executive_lock_release(&object->lock);
    return ZI_STATUS_INVALID_STATE;
  }
  --object->handle_count;
  if (object->handle_count == 0 && object->operations != NULL &&
      object->operations->last_handle_closed != NULL) {
    object->flags |= ZI_OBJECT_FLAG_NEW_HANDLES_DISABLED;
    last_handle_closed = object->operations->last_handle_closed;
  }
  zi_executive_lock_release(&object->lock);
  if (last_handle_closed != NULL) {
    last_handle_closed(object);
  }

  zi_executive_lock_acquire(&object->lock);
  if (object->is_destroyed != 0 || object->reference_count == 0) {
    zi_executive_lock_release(&object->lock);
    return ZI_STATUS_INVALID_STATE;
  }
  ZiStatus status = object_release_locked(object, &destroy);
  zi_executive_lock_release(&object->lock);
  if (ZiSucceeded(status) && destroy != NULL) {
    destroy(object);
  }
  return status;
}

ZiStatus zi_object_type_registry_initialise(ZiObjectTypeRegistry* registry,
                                            const ZiObjectType** type_storage,
                                            size_t capacity) {
  if (registry == NULL || type_storage == NULL || capacity == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  registry->types = type_storage;
  registry->capacity = capacity;
  registry->count = 0;
  zi_executive_lock_initialise(&registry->lock);
  for (size_t index = 0; index < capacity; ++index) {
    type_storage[index] = NULL;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_object_type_register(ZiObjectTypeRegistry* registry, const ZiObjectType* type) {
  if (registry == NULL || !object_type_is_valid(type)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  zi_executive_lock_acquire(&registry->lock);
  for (size_t index = 0; index < registry->count; ++index) {
    const ZiObjectType* existing = registry->types[index];
    if (existing->type_id == type->type_id || string_views_equal(existing->name, type->name)) {
      zi_executive_lock_release(&registry->lock);
      return ZI_STATUS_ALREADY_EXISTS;
    }
  }
  if (registry->count == registry->capacity) {
    zi_executive_lock_release(&registry->lock);
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  registry->types[registry->count] = type;
  ++registry->count;
  zi_executive_lock_release(&registry->lock);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_object_type_find_by_id(ZiObjectTypeRegistry* registry,
                                   uint32_t type_id,
                                   const ZiObjectType** out_type) {
  if (registry == NULL || out_type == NULL || type_id == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_type = NULL;
  zi_executive_lock_acquire(&registry->lock);
  for (size_t index = 0; index < registry->count; ++index) {
    if (registry->types[index]->type_id == type_id) {
      *out_type = registry->types[index];
      zi_executive_lock_release(&registry->lock);
      return ZI_STATUS_SUCCESS;
    }
  }
  zi_executive_lock_release(&registry->lock);
  return ZI_STATUS_NOT_FOUND;
}

ZiStatus zi_object_type_find_by_name(ZiObjectTypeRegistry* registry,
                                     ZiStringView name,
                                     const ZiObjectType** out_type) {
  if (registry == NULL || out_type == NULL || name.data == NULL || name.size == 0 ||
      ZiFailed(zi_utf8_validate(name.data, name.size))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_type = NULL;
  zi_executive_lock_acquire(&registry->lock);
  for (size_t index = 0; index < registry->count; ++index) {
    if (string_views_equal(registry->types[index]->name, name)) {
      *out_type = registry->types[index];
      zi_executive_lock_release(&registry->lock);
      return ZI_STATUS_SUCCESS;
    }
  }
  zi_executive_lock_release(&registry->lock);
  return ZI_STATUS_NOT_FOUND;
}

ZiStatus zi_object_directory_initialise(ZiObjectDirectory* directory,
                                        const ZiObjectType* directory_type,
                                        ZiStringView name,
                                        ZiObjectDirectoryEntry* entry_storage,
                                        size_t capacity,
                                        const ZiSecurityDescriptor* security_descriptor,
                                        const char* debug_name) {
  if (directory == NULL || directory_type == NULL ||
      (directory_type->flags & ZI_OBJECT_TYPE_DIRECTORY) == 0 || entry_storage == NULL ||
      capacity == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_object_initialise(&directory->header,
                                         directory_type,
                                         name,
                                         NULL,
                                         security_descriptor,
                                         debug_name);
  if (ZiFailed(status)) {
    return status;
  }
  directory->entries = entry_storage;
  directory->capacity = capacity;
  directory->count = 0;
  zi_executive_lock_initialise(&directory->lock);
  for (size_t index = 0; index < capacity; ++index) {
    entry_storage[index].object = NULL;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_object_directory_insert(ZiObjectDirectory* directory, ZiObjectHeader* object) {
  if (directory == NULL || object == NULL || object->name.data == NULL || object->name.size == 0 ||
      is_dot_component(object->name)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  zi_executive_lock_acquire(&directory->lock);
  if (directory->header.is_destroyed != 0 || directory->count == directory->capacity) {
    zi_executive_lock_release(&directory->lock);
    return directory->count == directory->capacity ? ZI_STATUS_BUFFER_TOO_SMALL
                                                   : ZI_STATUS_INVALID_STATE;
  }
  for (size_t index = 0; index < directory->count; ++index) {
    if (string_views_equal(directory->entries[index].object->name, object->name)) {
      zi_executive_lock_release(&directory->lock);
      return ZI_STATUS_ALREADY_EXISTS;
    }
  }

  zi_executive_lock_acquire(&object->lock);
  if (object->is_destroyed != 0 || object->parent != NULL ||
      object->reference_count == UINT32_MAX) {
    zi_executive_lock_release(&object->lock);
    zi_executive_lock_release(&directory->lock);
    return ZI_STATUS_INVALID_STATE;
  }
  ++object->reference_count;
  object->parent = &directory->header;
  zi_executive_lock_release(&object->lock);
  directory->entries[directory->count].object = object;
  ++directory->count;
  zi_executive_lock_release(&directory->lock);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_object_directory_lookup(ZiObjectDirectory* directory,
                                    ZiStringView name,
                                    ZiObjectHeader** out_object) {
  if (directory == NULL || out_object == NULL || name.data == NULL || name.size == 0 ||
      is_dot_component(name) || ZiFailed(zi_utf8_validate(name.data, name.size))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_object = NULL;

  zi_executive_lock_acquire(&directory->lock);
  for (size_t index = 0; index < directory->count; ++index) {
    ZiObjectHeader* object = directory->entries[index].object;
    if (string_views_equal(object->name, name)) {
      ZiStatus status = zi_object_reference(object);
      if (ZiSucceeded(status)) {
        *out_object = object;
      }
      zi_executive_lock_release(&directory->lock);
      return status;
    }
  }
  zi_executive_lock_release(&directory->lock);
  return ZI_STATUS_NOT_FOUND;
}

ZiStatus zi_object_directory_remove(ZiObjectDirectory* directory,
                                    ZiStringView name,
                                    ZiObjectHeader** out_object) {
  if (directory == NULL || name.data == NULL || name.size == 0 || is_dot_component(name) ||
      ZiFailed(zi_utf8_validate(name.data, name.size))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (out_object != NULL) {
    *out_object = NULL;
  }

  zi_executive_lock_acquire(&directory->lock);
  for (size_t index = 0; index < directory->count; ++index) {
    ZiObjectHeader* object = directory->entries[index].object;
    if (!string_views_equal(object->name, name)) {
      continue;
    }
    directory->entries[index] = directory->entries[directory->count - 1];
    directory->entries[directory->count - 1].object = NULL;
    --directory->count;
    zi_executive_lock_acquire(&object->lock);
    object->parent = NULL;
    zi_executive_lock_release(&object->lock);
    zi_executive_lock_release(&directory->lock);
    if (out_object != NULL) {
      *out_object = object;
      return ZI_STATUS_SUCCESS;
    }
    return zi_object_dereference(object);
  }
  zi_executive_lock_release(&directory->lock);
  return ZI_STATUS_NOT_FOUND;
}

// The component walk deliberately keeps reference transfers and namespace locking together.
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
ZiStatus zi_object_namespace_lookup(ZiObjectDirectory* root,
                                    ZiStringView absolute_path,
                                    ZiObjectHeader** out_object) {
  if (root == NULL || out_object == NULL || absolute_path.data == NULL || absolute_path.size == 0 ||
      absolute_path.data[0] != '\\' ||
      ZiFailed(zi_utf8_validate(absolute_path.data, absolute_path.size))) {
    return ZI_STATUS_INVALID_PATH;
  }
  *out_object = NULL;
  for (size_t index = 0; index < absolute_path.size; ++index) {
    if (absolute_path.data[index] == '\0' || absolute_path.data[index] == '/') {
      return ZI_STATUS_INVALID_PATH;
    }
  }
  if (absolute_path.size == 1) {
    ZiStatus status = zi_object_reference(&root->header);
    if (ZiSucceeded(status)) {
      *out_object = &root->header;
    }
    return status;
  }

  ZiObjectDirectory* directory = root;
  ZiObjectHeader* held_object = NULL;
  size_t component_start = 1;
  for (size_t index = 1; index <= absolute_path.size; ++index) {
    bool at_end = index == absolute_path.size;
    if (!at_end && absolute_path.data[index] != '\\') {
      continue;
    }
    ZiStringView component = {absolute_path.data + component_start, index - component_start};
    if (component.size == 0 || is_dot_component(component)) {
      if (held_object != NULL) {
        (void)zi_object_dereference(held_object);
      }
      return ZI_STATUS_INVALID_PATH;
    }
    ZiObjectHeader* found = NULL;
    ZiStatus status = zi_object_directory_lookup(directory, component, &found);
    if (held_object != NULL) {
      (void)zi_object_dereference(held_object);
      held_object = NULL;
    }
    if (ZiFailed(status)) {
      return status;
    }
    if (at_end) {
      *out_object = found;
      return ZI_STATUS_SUCCESS;
    }
    if ((found->type->flags & ZI_OBJECT_TYPE_DIRECTORY) == 0) {
      (void)zi_object_dereference(found);
      return ZI_STATUS_INVALID_PATH;
    }
    held_object = found;
    directory = (ZiObjectDirectory*)found;
    component_start = index + 1;
  }
  return ZI_STATUS_NOT_FOUND;
}

static bool object_type_is_valid(const ZiObjectType* type) {
  return (bool)(type != NULL && type->type_id != 0 && type->name.data != NULL &&
                type->name.size != 0 &&
                ZiSucceeded(zi_utf8_validate(type->name.data, type->name.size)) &&
                type->operations != NULL &&
                type->operations->struct_size == sizeof(ZiObjectOperations) &&
                type->operations->version == ZI_OBJECT_OPERATIONS_VERSION);
}

static ZiStatus object_release_locked(ZiObjectHeader* object, ZiObjectDestroyRoutine* out_destroy) {
  --object->reference_count;
  if (object->reference_count != 0) {
    return ZI_STATUS_SUCCESS;
  }
  if (object->handle_count != 0) {
    ++object->reference_count;
    return ZI_STATUS_INVALID_STATE;
  }

  object->is_destroyed = 1;
  if (object->operations != NULL) {
    *out_destroy = object->operations->destroy;
  }
  return ZI_STATUS_SUCCESS;
}

static bool string_views_equal(ZiStringView left, ZiStringView right) {
  if (left.size != right.size) {
    return false;
  }
  for (size_t index = 0; index < left.size; ++index) {
    if (left.data[index] != right.data[index]) {
      return false;
    }
  }
  return true;
}

static bool is_dot_component(ZiStringView name) {
  return (bool)((name.size == 1 && name.data[0] == '.') ||
                (name.size == 2 && name.data[0] == '.' && name.data[1] == '.'));
}
