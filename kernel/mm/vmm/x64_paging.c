// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/x64_paging.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/byte_order.h"
#include "zizium/status.h"

#define ZI_X64_TABLE_ENTRY_COUNT 512u
#define ZI_X64_ENTRY_PRESENT (UINT64_C(1) << 0)
#define ZI_X64_ENTRY_WRITE (UINT64_C(1) << 1)
#define ZI_X64_ENTRY_USER (UINT64_C(1) << 2)
#define ZI_X64_ENTRY_WRITE_THROUGH (UINT64_C(1) << 3)
#define ZI_X64_ENTRY_CACHE_DISABLE (UINT64_C(1) << 4)
#define ZI_X64_ENTRY_ACCESSED (UINT64_C(1) << 5)
#define ZI_X64_ENTRY_DIRTY (UINT64_C(1) << 6)
#define ZI_X64_ENTRY_LARGE (UINT64_C(1) << 7)
#define ZI_X64_ENTRY_GLOBAL (UINT64_C(1) << 8)
#define ZI_X64_ENTRY_NO_EXECUTE (UINT64_C(1) << 63)
#define ZI_X64_ENTRY_PHYSICAL_MASK UINT64_C(0x000ffffffffff000)
#define ZI_X64_MAX_PHYSICAL_ADDRESS (UINT64_C(1) << 52)
#define ZI_X64_KERNEL_PML4_START 256u

typedef struct ZiX64WalkResult {
  uint64_t* tables[4];
  uint64_t* entries[4];
  uint64_t table_physical[4];
} ZiX64WalkResult;

typedef struct ZiX64CreatedTable {
  uint64_t* parent_entry;
  uint64_t physical_base;
} ZiX64CreatedTable;

static ZiStatus
validate_page_arguments(uint64_t virtual_address, uint64_t physical_address, uint32_t protection);
static ZiStatus validate_virtual_range(uint64_t virtual_address, uint64_t size);
static ZiStatus validate_protection(const ZiX64PagingContext* context, uint32_t protection);
static ZiStatus
physical_table(const ZiX64PagingContext* context, uint64_t physical_base, uint64_t** out_table);
static ZiStatus
allocate_table(ZiX64PagingContext* context, uint64_t* out_physical_base, uint64_t** out_table);
static ZiStatus walk_to_leaf(ZiX64PagingContext* context,
                             uint64_t virtual_address,
                             bool create,
                             uint32_t protection,
                             ZiX64WalkResult* out_walk);
static void
rollback_tables(ZiX64PagingContext* context, ZiX64CreatedTable* created, size_t created_count);
static uint64_t leaf_flags(const ZiX64PagingContext* context, uint32_t protection);
static uint32_t protection_from_leaf(uint64_t entry);
static void promote_user_path(const ZiX64WalkResult* walk, uint32_t protection);
static bool table_is_empty(const uint64_t* table);

ZiStatus zi_x64_paging_create(void* callback_context,
                              ZiX64PageAllocateRoutine allocate_page,
                              ZiX64PageReleaseRoutine release_page,
                              ZiX64PhysicalPointerRoutine physical_pointer,
                              bool nx_enabled,
                              ZiX64PagingContext* out_context) {
  if (allocate_page == NULL || release_page == NULL || physical_pointer == NULL ||
      out_context == NULL || !nx_enabled) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiX64PagingContext context = {0};
  context.callback_context = callback_context;
  context.allocate_page = allocate_page;
  context.release_page = release_page;
  context.physical_pointer = physical_pointer;
  context.nx_enabled = nx_enabled;
  uint64_t* root = NULL;
  ZiStatus status = allocate_table(&context, &context.root_physical_base, &root);
  if (ZiFailed(status)) {
    return status;
  }
  *out_context = context;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_x64_paging_clone_kernel_half(const ZiX64PagingContext* kernel_context,
                                         ZiX64PagingContext* out_context) {
  if (kernel_context == NULL || out_context == NULL || kernel_context->root_physical_base == 0 ||
      kernel_context->allocate_page == NULL || kernel_context->release_page == NULL ||
      kernel_context->physical_pointer == NULL || !kernel_context->nx_enabled) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  ZiX64PagingContext context = *kernel_context;
  context.root_physical_base = 0;
  uint64_t* destination_root = NULL;
  ZiStatus status = allocate_table(&context, &context.root_physical_base, &destination_root);
  if (ZiFailed(status)) {
    return status;
  }
  uint64_t* kernel_root = NULL;
  status = physical_table(kernel_context, kernel_context->root_physical_base, &kernel_root);
  if (ZiFailed(status)) {
    context.release_page(context.callback_context, context.root_physical_base);
    return status;
  }
  for (size_t index = ZI_X64_KERNEL_PML4_START; index < ZI_X64_TABLE_ENTRY_COUNT; ++index) {
    if ((kernel_root[index] & ZI_X64_ENTRY_USER) != 0) {
      context.release_page(context.callback_context, context.root_physical_base);
      return ZI_STATUS_INVALID_STATE;
    }
    destination_root[index] = kernel_root[index];
  }
  *out_context = context;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_x64_paging_release_empty_address_space(ZiX64PagingContext* context,
                                                   const ZiX64PagingContext* kernel_context) {
  if (context == NULL || kernel_context == NULL || context == kernel_context ||
      context->root_physical_base == 0 || kernel_context->root_physical_base == 0 ||
      context->release_page == NULL || context->physical_pointer == NULL ||
      context->callback_context != kernel_context->callback_context ||
      context->allocate_page != kernel_context->allocate_page ||
      context->release_page != kernel_context->release_page ||
      context->physical_pointer != kernel_context->physical_pointer) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t* root = NULL;
  uint64_t* kernel_root = NULL;
  ZiStatus status = physical_table(context, context->root_physical_base, &root);
  if (ZiSucceeded(status)) {
    status = physical_table(kernel_context, kernel_context->root_physical_base, &kernel_root);
  }
  if (ZiFailed(status)) {
    return status;
  }
  for (size_t index = 0; index < ZI_X64_KERNEL_PML4_START; ++index) {
    if ((root[index] & ZI_X64_ENTRY_PRESENT) != 0) {
      return ZI_STATUS_RESOURCE_IN_USE;
    }
  }
  for (size_t index = ZI_X64_KERNEL_PML4_START; index < ZI_X64_TABLE_ENTRY_COUNT; ++index) {
    if (root[index] != kernel_root[index] || (root[index] & ZI_X64_ENTRY_USER) != 0) {
      return ZI_STATUS_INVALID_STATE;
    }
  }
  context->release_page(context->callback_context, context->root_physical_base);
  zi_memory_zero(context, sizeof *context);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_x64_paging_map_page(ZiX64PagingContext* context,
                                uint64_t virtual_address,
                                uint64_t physical_address,
                                uint32_t protection) {
  if (context == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_page_arguments(virtual_address, physical_address, protection);
  if (ZiFailed(status)) {
    return status;
  }
  status = validate_protection(context, protection);
  if (ZiFailed(status)) {
    return status;
  }
  ZiX64WalkResult walk = {0};
  status = walk_to_leaf(context, virtual_address, true, protection, &walk);
  if (ZiFailed(status)) {
    return status;
  }
  if ((*walk.entries[3] & ZI_X64_ENTRY_PRESENT) != 0) {
    return ZI_STATUS_ALREADY_EXISTS;
  }
  promote_user_path(&walk, protection);
  *walk.entries[3] = physical_address | leaf_flags(context, protection);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_x64_paging_map_range(ZiX64PagingContext* context,
                                 uint64_t virtual_address,
                                 uint64_t physical_address,
                                 uint64_t size,
                                 uint32_t protection) {
  if (context == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_virtual_range(virtual_address, size);
  if (ZiFailed(status)) {
    return status;
  }
  if ((physical_address & (ZI_X64_PAGE_SIZE - 1)) != 0) {
    return ZI_STATUS_ALIGNMENT_ERROR;
  }
  if (physical_address >= ZI_X64_MAX_PHYSICAL_ADDRESS ||
      size > ZI_X64_MAX_PHYSICAL_ADDRESS - physical_address) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  uint64_t mapped_size = 0;
  while (mapped_size < size) {
    status = zi_x64_paging_map_page(context,
                                    virtual_address + mapped_size,
                                    physical_address + mapped_size,
                                    protection);
    if (ZiFailed(status)) {
      while (mapped_size != 0) {
        mapped_size -= ZI_X64_PAGE_SIZE;
        (void)zi_x64_paging_unmap_page(context, virtual_address + mapped_size);
      }
      return status;
    }
    mapped_size += ZI_X64_PAGE_SIZE;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_x64_paging_unmap_page(ZiX64PagingContext* context, uint64_t virtual_address) {
  if (context == NULL || !zi_x64_address_is_canonical(virtual_address) ||
      (virtual_address & (ZI_X64_PAGE_SIZE - 1)) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiX64WalkResult walk = {0};
  ZiStatus status = walk_to_leaf(context, virtual_address, false, ZI_X64_PAGE_READ, &walk);
  if (ZiFailed(status)) {
    return status;
  }
  if ((*walk.entries[3] & ZI_X64_ENTRY_PRESENT) == 0) {
    return ZI_STATUS_PAGE_NOT_MAPPED;
  }
  *walk.entries[3] = 0;
  for (size_t level = 3; level > 0; --level) {
    if (!table_is_empty(walk.tables[level])) {
      break;
    }
    *walk.entries[level - 1] = 0;
    context->release_page(context->callback_context, walk.table_physical[level]);
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus
zi_x64_paging_unmap_range(ZiX64PagingContext* context, uint64_t virtual_address, uint64_t size) {
  ZiStatus status = validate_virtual_range(virtual_address, size);
  if (ZiFailed(status)) {
    return status;
  }
  for (uint64_t offset = 0; offset < size; offset += ZI_X64_PAGE_SIZE) {
    ZiX64PageMapping mapping = {0};
    status = zi_x64_paging_query(context, virtual_address + offset, &mapping);
    if (ZiFailed(status)) {
      return status;
    }
  }
  for (uint64_t offset = 0; offset < size; offset += ZI_X64_PAGE_SIZE) {
    status = zi_x64_paging_unmap_page(context, virtual_address + offset);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_x64_paging_protect_page(ZiX64PagingContext* context,
                                    uint64_t virtual_address,
                                    uint32_t protection) {
  if (context == NULL || !zi_x64_address_is_canonical(virtual_address) ||
      (virtual_address & (ZI_X64_PAGE_SIZE - 1)) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_protection(context, protection);
  if (ZiFailed(status)) {
    return status;
  }
  ZiX64WalkResult walk = {0};
  status = walk_to_leaf(context, virtual_address, false, protection, &walk);
  if (ZiFailed(status)) {
    return status;
  }
  uint64_t entry = *walk.entries[3];
  if ((entry & ZI_X64_ENTRY_PRESENT) == 0) {
    return ZI_STATUS_PAGE_NOT_MAPPED;
  }
  uint64_t retained =
      entry & (ZI_X64_ENTRY_PHYSICAL_MASK | ZI_X64_ENTRY_ACCESSED | ZI_X64_ENTRY_DIRTY);
  promote_user_path(&walk, protection);
  *walk.entries[3] = retained | leaf_flags(context, protection);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_x64_paging_protect_range(ZiX64PagingContext* context,
                                     uint64_t virtual_address,
                                     uint64_t size,
                                     uint32_t protection) {
  ZiStatus status = validate_virtual_range(virtual_address, size);
  if (ZiFailed(status)) {
    return status;
  }
  status = validate_protection(context, protection);
  if (ZiFailed(status)) {
    return status;
  }
  for (uint64_t offset = 0; offset < size; offset += ZI_X64_PAGE_SIZE) {
    ZiX64PageMapping mapping = {0};
    status = zi_x64_paging_query(context, virtual_address + offset, &mapping);
    if (ZiFailed(status)) {
      return status;
    }
  }
  for (uint64_t offset = 0; offset < size; offset += ZI_X64_PAGE_SIZE) {
    status = zi_x64_paging_protect_page(context, virtual_address + offset, protection);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_x64_paging_query(const ZiX64PagingContext* context,
                             uint64_t virtual_address,
                             ZiX64PageMapping* out_mapping) {
  if (context == NULL || out_mapping == NULL || !zi_x64_address_is_canonical(virtual_address)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiX64PagingContext mutable_context = *context;
  ZiX64WalkResult walk = {0};
  uint64_t page_address = virtual_address & ~(ZI_X64_PAGE_SIZE - 1);
  ZiStatus status = walk_to_leaf(&mutable_context, page_address, false, ZI_X64_PAGE_READ, &walk);
  if (ZiFailed(status)) {
    return status;
  }
  uint64_t entry = *walk.entries[3];
  if ((entry & ZI_X64_ENTRY_PRESENT) == 0) {
    return ZI_STATUS_PAGE_NOT_MAPPED;
  }
  out_mapping->physical_base =
      (entry & ZI_X64_ENTRY_PHYSICAL_MASK) | (virtual_address & (ZI_X64_PAGE_SIZE - 1));
  out_mapping->protection = protection_from_leaf(entry);
  return ZI_STATUS_SUCCESS;
}

bool zi_x64_address_is_canonical(uint64_t virtual_address) {
  uint64_t upper = virtual_address >> 48;
  uint64_t sign = (virtual_address >> 47) & 1u;
  if (sign == 0) {
    return (bool)(upper == 0);
  }
  return (bool)(upper == UINT64_C(0xffff));
}

static ZiStatus
validate_page_arguments(uint64_t virtual_address, uint64_t physical_address, uint32_t protection) {
  if (!zi_x64_address_is_canonical(virtual_address) || (protection & ZI_X64_PAGE_READ) == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if ((virtual_address & (ZI_X64_PAGE_SIZE - 1)) != 0 ||
      (physical_address & (ZI_X64_PAGE_SIZE - 1)) != 0) {
    return ZI_STATUS_ALIGNMENT_ERROR;
  }
  if (physical_address >= ZI_X64_MAX_PHYSICAL_ADDRESS) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_virtual_range(uint64_t virtual_address, uint64_t size) {
  if (size == 0 || !zi_x64_address_is_canonical(virtual_address)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if ((size & (ZI_X64_PAGE_SIZE - 1)) != 0 || (virtual_address & (ZI_X64_PAGE_SIZE - 1)) != 0) {
    return ZI_STATUS_ALIGNMENT_ERROR;
  }
  if (virtual_address > UINT64_MAX - (size - 1) ||
      !zi_x64_address_is_canonical(virtual_address + size - 1)) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_protection(const ZiX64PagingContext* context, uint32_t protection) {
  const uint32_t valid = ZI_X64_PAGE_READ | ZI_X64_PAGE_WRITE | ZI_X64_PAGE_EXECUTE |
                         ZI_X64_PAGE_USER | ZI_X64_PAGE_GLOBAL | ZI_X64_PAGE_DEVICE;
  if (context == NULL || !context->nx_enabled || (protection & ZI_X64_PAGE_READ) == 0 ||
      (protection & ~valid) != 0 ||
      ((protection & ZI_X64_PAGE_WRITE) != 0 && (protection & ZI_X64_PAGE_EXECUTE) != 0) ||
      ((protection & ZI_X64_PAGE_DEVICE) != 0 && (protection & ZI_X64_PAGE_EXECUTE) != 0)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus
physical_table(const ZiX64PagingContext* context, uint64_t physical_base, uint64_t** out_table) {
  if (context == NULL || context->physical_pointer == NULL || out_table == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if ((physical_base & (ZI_X64_PAGE_SIZE - 1)) != 0) {
    return ZI_STATUS_ALIGNMENT_ERROR;
  }
  if (physical_base >= ZI_X64_MAX_PHYSICAL_ADDRESS) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  void* pointer = NULL;
  ZiStatus status = context->physical_pointer(context->callback_context,
                                              physical_base,
                                              (size_t)ZI_X64_PAGE_SIZE,
                                              &pointer);
  if (ZiFailed(status)) {
    return status;
  }
  if (pointer == NULL) {
    return ZI_STATUS_INVALID_STATE;
  }
  *out_table = pointer;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus
allocate_table(ZiX64PagingContext* context, uint64_t* out_physical_base, uint64_t** out_table) {
  uint64_t physical_base = 0;
  ZiStatus status = context->allocate_page(context->callback_context, &physical_base);
  if (ZiFailed(status)) {
    return status;
  }
  if ((physical_base & (ZI_X64_PAGE_SIZE - 1)) != 0 ||
      physical_base >= ZI_X64_MAX_PHYSICAL_ADDRESS) {
    context->release_page(context->callback_context, physical_base);
    return ZI_STATUS_INVALID_STATE;
  }
  uint64_t* table = NULL;
  status = physical_table(context, physical_base, &table);
  if (ZiFailed(status)) {
    context->release_page(context->callback_context, physical_base);
    return status;
  }
  zi_memory_zero(table, (size_t)ZI_X64_PAGE_SIZE);
  *out_physical_base = physical_base;
  *out_table = table;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus walk_to_leaf(ZiX64PagingContext* context,
                             uint64_t virtual_address,
                             bool create,
                             uint32_t protection,
                             ZiX64WalkResult* out_walk) {
  if (context == NULL || out_walk == NULL || !zi_x64_address_is_canonical(virtual_address)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (context->root_physical_base == 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  const uint16_t indices[4] = {
      (uint16_t)((virtual_address >> 39) & UINT64_C(0x1ff)),
      (uint16_t)((virtual_address >> 30) & UINT64_C(0x1ff)),
      (uint16_t)((virtual_address >> 21) & UINT64_C(0x1ff)),
      (uint16_t)((virtual_address >> 12) & UINT64_C(0x1ff)),
  };
  ZiX64CreatedTable created[3] = {0};
  size_t created_count = 0;
  out_walk->table_physical[0] = context->root_physical_base;
  ZiStatus status = physical_table(context, context->root_physical_base, &out_walk->tables[0]);
  if (ZiFailed(status)) {
    return status;
  }

  for (size_t level = 0; level < 3; ++level) {
    uint64_t* entry = &out_walk->tables[level][indices[level]];
    out_walk->entries[level] = entry;
    if ((*entry & ZI_X64_ENTRY_PRESENT) == 0) {
      if (!create) {
        rollback_tables(context, created, created_count);
        return ZI_STATUS_PAGE_NOT_MAPPED;
      }
      uint64_t physical_base = 0;
      uint64_t* table = NULL;
      status = allocate_table(context, &physical_base, &table);
      if (ZiFailed(status)) {
        rollback_tables(context, created, created_count);
        return status;
      }
      uint64_t flags = ZI_X64_ENTRY_PRESENT | ZI_X64_ENTRY_WRITE;
      if ((protection & ZI_X64_PAGE_USER) != 0) {
        flags |= ZI_X64_ENTRY_USER;
      }
      *entry = physical_base | flags;
      created[created_count].parent_entry = entry;
      created[created_count].physical_base = physical_base;
      ++created_count;
      out_walk->tables[level + 1] = table;
      out_walk->table_physical[level + 1] = physical_base;
    } else {
      if ((*entry & ZI_X64_ENTRY_LARGE) != 0) {
        rollback_tables(context, created, created_count);
        return ZI_STATUS_INVALID_STATE;
      }
      uint64_t physical_base = *entry & ZI_X64_ENTRY_PHYSICAL_MASK;
      out_walk->table_physical[level + 1] = physical_base;
      status = physical_table(context, physical_base, &out_walk->tables[level + 1]);
      if (ZiFailed(status)) {
        rollback_tables(context, created, created_count);
        return status;
      }
    }
  }
  out_walk->entries[3] = &out_walk->tables[3][indices[3]];
  return ZI_STATUS_SUCCESS;
}

static void
rollback_tables(ZiX64PagingContext* context, ZiX64CreatedTable* created, size_t created_count) {
  while (created_count != 0) {
    --created_count;
    *created[created_count].parent_entry = 0;
    context->release_page(context->callback_context, created[created_count].physical_base);
  }
}

static uint64_t leaf_flags(const ZiX64PagingContext* context, uint32_t protection) {
  uint64_t flags = ZI_X64_ENTRY_PRESENT;
  if ((protection & ZI_X64_PAGE_WRITE) != 0) {
    flags |= ZI_X64_ENTRY_WRITE;
  }
  if ((protection & ZI_X64_PAGE_USER) != 0) {
    flags |= ZI_X64_ENTRY_USER;
  }
  if ((protection & ZI_X64_PAGE_GLOBAL) != 0) {
    flags |= ZI_X64_ENTRY_GLOBAL;
  }
  if ((protection & ZI_X64_PAGE_DEVICE) != 0) {
    flags |= ZI_X64_ENTRY_WRITE_THROUGH | ZI_X64_ENTRY_CACHE_DISABLE;
  }
  if (context->nx_enabled && (protection & ZI_X64_PAGE_EXECUTE) == 0) {
    flags |= ZI_X64_ENTRY_NO_EXECUTE;
  }
  return flags;
}

static uint32_t protection_from_leaf(uint64_t entry) {
  uint32_t protection = ZI_X64_PAGE_READ;
  if ((entry & ZI_X64_ENTRY_WRITE) != 0) {
    protection |= ZI_X64_PAGE_WRITE;
  }
  if ((entry & ZI_X64_ENTRY_NO_EXECUTE) == 0) {
    protection |= ZI_X64_PAGE_EXECUTE;
  }
  if ((entry & ZI_X64_ENTRY_USER) != 0) {
    protection |= ZI_X64_PAGE_USER;
  }
  if ((entry & ZI_X64_ENTRY_GLOBAL) != 0) {
    protection |= ZI_X64_PAGE_GLOBAL;
  }
  if ((entry & (ZI_X64_ENTRY_WRITE_THROUGH | ZI_X64_ENTRY_CACHE_DISABLE)) != 0) {
    protection |= ZI_X64_PAGE_DEVICE;
  }
  return protection;
}

static void promote_user_path(const ZiX64WalkResult* walk, uint32_t protection) {
  if ((protection & ZI_X64_PAGE_USER) == 0) {
    return;
  }
  for (size_t level = 0; level < 3; ++level) {
    *walk->entries[level] |= ZI_X64_ENTRY_USER;
  }
}

static bool table_is_empty(const uint64_t* table) {
  for (size_t index = 0; index < ZI_X64_TABLE_ENTRY_COUNT; ++index) {
    if ((table[index] & ZI_X64_ENTRY_PRESENT) != 0) {
      return false;
    }
  }
  return true;
}
