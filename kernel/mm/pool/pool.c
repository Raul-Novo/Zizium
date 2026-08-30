// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/pool.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/byte_order.h"
#include "zizium/status.h"

#define ZI_POOL_BLOCK_MAGIC UINT64_C(0x5a69506f6f6c426c)
#define ZI_POOL_TAIL_SIZE sizeof(uint64_t)
#define ZI_POOL_BLOCK_FREE 1u
#define ZI_POOL_BLOCK_ALLOCATED 2u
#define ZI_OBJECT_SLOT_MAGIC UINT64_C(0x5a694f626a536c74)
#define ZI_OBJECT_SLOT_FREE 1u
#define ZI_OBJECT_SLOT_ALLOCATED 2u

typedef struct ZiPoolBlockHeader {
  uint64_t magic;
  size_t span;
  size_t previous_span;
  size_t requested_size;
  uint64_t generation;
  uint64_t checksum;
  uint32_t state;
  uint32_t reserved32;
  uint64_t reserved64;
} ZiPoolBlockHeader;

typedef struct ZiObjectSlotHeader {
  uint64_t magic;
  uint64_t generation;
  uint64_t checksum;
  uint32_t state;
  uint32_t index;
} ZiObjectSlotHeader;

_Static_assert(sizeof(ZiPoolBlockHeader) % ZI_POOL_ALIGNMENT == 0,
               "Pool headers must preserve allocation alignment.");
_Static_assert(sizeof(ZiObjectSlotHeader) % ZI_POOL_ALIGNMENT == 0,
               "Object-cache headers must preserve allocation alignment.");

static ZiStatus allocation_span(size_t requested_size, size_t* out_span);
static bool bytes_are_zero(const unsigned char* bytes, size_t size);
static uint64_t calculate_pool_cookie(const ZiPool* pool);
static uint64_t
calculate_block_checksum(const ZiPool* pool, const ZiPoolBlockHeader* block, size_t offset);
static uint64_t
calculate_block_tail(const ZiPool* pool, const ZiPoolBlockHeader* block, size_t offset);
static uint64_t calculate_cache_cookie(const ZiObjectCache* cache);
static uint64_t calculate_slot_checksum(const ZiObjectCache* cache, const ZiObjectSlotHeader* slot);
static uint64_t calculate_slot_tail(const ZiObjectCache* cache, const ZiObjectSlotHeader* slot);
static ZiStatus cache_slot_stride(size_t object_size, size_t* out_stride);
static ZiPoolBlockHeader* first_block(const ZiPool* pool);
static ZiPoolBlockHeader* next_block(const ZiPool* pool, ZiPoolBlockHeader* block, size_t offset);
static ZiPoolBlockHeader*
previous_block(const ZiPool* pool, ZiPoolBlockHeader* block, size_t offset);
static void initialise_free_block(const ZiPool* pool,
                                  ZiPoolBlockHeader* block,
                                  size_t offset,
                                  size_t span,
                                  size_t previous_span,
                                  uint64_t generation);
static ZiStatus next_generation(uint64_t* inout_generation);
static ZiStatus pool_descriptor_validate(const ZiPool* pool);
static ZiStatus pool_scan(const ZiPool* pool, ZiPoolStatistics* out_statistics);
static void refresh_block_checksum(const ZiPool* pool, ZiPoolBlockHeader* block, size_t offset);
static ZiObjectSlotHeader* slot_at(const ZiObjectCache* cache, size_t index);
static unsigned char* slot_object(ZiObjectSlotHeader* slot);
static ZiStatus object_cache_descriptor_validate(const ZiObjectCache* cache);
static uint64_t mix_value(uint64_t hash, uint64_t value);

ZiStatus zi_pool_initialise(void* arena, size_t arena_size, ZiPool* out_pool) {
  if (arena == NULL || out_pool == NULL ||
      ((uintptr_t)arena & (uintptr_t)(ZI_POOL_ALIGNMENT - 1u)) != 0 ||
      (arena_size & (ZI_POOL_ALIGNMENT - 1u)) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  size_t minimum_span = 0;
  ZiStatus status = allocation_span(ZI_POOL_ALIGNMENT, &minimum_span);
  if (ZiFailed(status) || arena_size < minimum_span) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }

  ZiPool pool = {
      sizeof(ZiPool),
      ZI_POOL_VERSION,
      arena,
      arena_size,
      0,
      0,
      0,
      1,
      0,
  };
  pool.cookie = calculate_pool_cookie(&pool);
  zi_memory_zero(arena, arena_size);
  initialise_free_block(&pool, first_block(&pool), 0, arena_size, 0, pool.generation);
  *out_pool = pool;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_pool_allocate(ZiPool* pool, size_t size, void** out_allocation) {
  if (out_allocation == NULL || size == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_pool_validate(pool);
  if (ZiFailed(status)) {
    return status;
  }
  size_t required_span = 0;
  status = allocation_span(size, &required_span);
  if (ZiFailed(status)) {
    return status;
  }
  size_t minimum_span = 0;
  status = allocation_span(ZI_POOL_ALIGNMENT, &minimum_span);
  if (ZiFailed(status)) {
    return status;
  }

  size_t offset = 0;
  ZiPoolBlockHeader* block = first_block(pool);
  while (offset < pool->arena_size) {
    if (block->state == ZI_POOL_BLOCK_FREE && block->span >= required_span) {
      break;
    }
    offset += block->span;
    block = next_block(pool, block, offset - block->span);
  }
  if (offset >= pool->arena_size || block == NULL) {
    return ZI_STATUS_NO_MEMORY;
  }
  if (pool->allocated_bytes > SIZE_MAX - size || pool->active_allocations == SIZE_MAX) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  status = next_generation(&pool->generation);
  if (ZiFailed(status)) {
    return status;
  }

  size_t original_span = block->span;
  zi_memory_zero((unsigned char*)block + sizeof *block, original_span - sizeof *block);
  size_t remainder_span = original_span - required_span;
  if (remainder_span >= minimum_span) {
    block->span = required_span;
    ZiPoolBlockHeader* remainder_block =
        (ZiPoolBlockHeader*)((unsigned char*)block + required_span);
    size_t previous_span = required_span;
    initialise_free_block(pool,
                          remainder_block,
                          offset + required_span,
                          remainder_span,
                          previous_span,
                          pool->generation);
    ZiPoolBlockHeader* following = next_block(pool, remainder_block, offset + required_span);
    if (following != NULL) {
      following->previous_span = remainder_span;
      refresh_block_checksum(pool, following, offset + original_span);
    }
  }

  block->magic = ZI_POOL_BLOCK_MAGIC;
  block->requested_size = size;
  block->generation = pool->generation;
  block->state = ZI_POOL_BLOCK_ALLOCATED;
  block->reserved32 = 0;
  block->reserved64 = 0;
  refresh_block_checksum(pool, block, offset);
  unsigned char* allocation = (unsigned char*)block + sizeof *block;
  zi_write_u64_le(allocation + size, calculate_block_tail(pool, block, offset));
  ++pool->active_allocations;
  pool->allocated_bytes += size;
  if (pool->allocated_bytes > pool->peak_allocated_bytes) {
    pool->peak_allocated_bytes = pool->allocated_bytes;
  }
  *out_allocation = allocation;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_pool_free(ZiPool* pool, void* allocation) {
  if (allocation == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_pool_validate(pool);
  if (ZiFailed(status)) {
    return status;
  }
  uintptr_t allocation_address = (uintptr_t)allocation;
  uintptr_t arena_address = (uintptr_t)pool->arena;
  if (allocation_address < arena_address + sizeof(ZiPoolBlockHeader) ||
      allocation_address >= arena_address + pool->arena_size ||
      (allocation_address & (uintptr_t)(ZI_POOL_ALIGNMENT - 1u)) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  size_t offset = 0;
  ZiPoolBlockHeader* block = first_block(pool);
  while (offset < pool->arena_size && (unsigned char*)block + sizeof *block != allocation) {
    offset += block->span;
    block = next_block(pool, block, offset - block->span);
  }
  if (offset >= pool->arena_size || block == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (block->state == ZI_POOL_BLOCK_FREE) {
    return ZI_STATUS_INVALID_STATE;
  }
  if (block->state != ZI_POOL_BLOCK_ALLOCATED || pool->active_allocations == 0 ||
      pool->allocated_bytes < block->requested_size) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  status = next_generation(&pool->generation);
  if (ZiFailed(status)) {
    return status;
  }
  pool->allocated_bytes -= block->requested_size;
  --pool->active_allocations;
  block->requested_size = 0;
  block->generation = pool->generation;
  block->state = ZI_POOL_BLOCK_FREE;
  refresh_block_checksum(pool, block, offset);

  ZiPoolBlockHeader* following = next_block(pool, block, offset);
  if (following != NULL && following->state == ZI_POOL_BLOCK_FREE) {
    block->span += following->span;
    following = next_block(pool, block, offset);
    if (following != NULL) {
      following->previous_span = block->span;
      refresh_block_checksum(pool, following, offset + block->span);
    }
  }
  ZiPoolBlockHeader* preceding = previous_block(pool, block, offset);
  if (preceding != NULL && preceding->state == ZI_POOL_BLOCK_FREE) {
    size_t preceding_offset = offset - block->previous_span;
    preceding->span += block->span;
    preceding->generation = pool->generation;
    block = preceding;
    offset = preceding_offset;
    following = next_block(pool, block, offset);
    if (following != NULL) {
      following->previous_span = block->span;
      refresh_block_checksum(pool, following, offset + block->span);
    }
  }
  zi_memory_zero((unsigned char*)block + sizeof *block, block->span - sizeof *block);
  refresh_block_checksum(pool, block, offset);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_pool_validate(const ZiPool* pool) {
  ZiStatus status = pool_descriptor_validate(pool);
  if (ZiFailed(status)) {
    return status;
  }
  return pool_scan(pool, NULL);
}

ZiStatus zi_pool_statistics(const ZiPool* pool, ZiPoolStatistics* out_statistics) {
  if (out_statistics == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = pool_descriptor_validate(pool);
  if (ZiFailed(status)) {
    return status;
  }
  ZiPoolStatistics statistics = {0};
  status = pool_scan(pool, &statistics);
  if (ZiSucceeded(status)) {
    *out_statistics = statistics;
  }
  return status;
}

ZiStatus zi_object_cache_initialise(ZiPool* pool,
                                    size_t object_size,
                                    size_t capacity,
                                    ZiObjectCache* out_cache) {
  if (out_cache == NULL || capacity == 0 || capacity > UINT32_MAX) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_pool_validate(pool);
  if (ZiFailed(status)) {
    return status;
  }
  size_t slot_stride = 0;
  status = cache_slot_stride(object_size, &slot_stride);
  if (ZiFailed(status)) {
    return status;
  }
  if (capacity > SIZE_MAX / slot_stride) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  size_t storage_size = capacity * slot_stride;
  void* storage = NULL;
  status = zi_pool_allocate(pool, storage_size, &storage);
  if (ZiFailed(status)) {
    return status;
  }

  ZiObjectCache cache = {sizeof(ZiObjectCache),
                         ZI_OBJECT_CACHE_VERSION,
                         pool,
                         storage,
                         storage_size,
                         object_size,
                         slot_stride,
                         capacity,
                         0,
                         1,
                         0};
  cache.cookie = calculate_cache_cookie(&cache);
  zi_memory_zero(storage, storage_size);
  for (size_t index = 0; index < capacity; ++index) {
    ZiObjectSlotHeader* slot = slot_at(&cache, index);
    slot->magic = ZI_OBJECT_SLOT_MAGIC;
    slot->generation = 0;
    slot->state = ZI_OBJECT_SLOT_FREE;
    slot->index = (uint32_t)index;
    slot->checksum = calculate_slot_checksum(&cache, slot);
  }
  *out_cache = cache;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_object_cache_allocate(ZiObjectCache* cache, void** out_object) {
  if (out_object == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_object_cache_validate(cache);
  if (ZiFailed(status)) {
    return status;
  }
  if (cache->active_objects == cache->capacity) {
    return ZI_STATUS_NO_MEMORY;
  }
  status = next_generation(&cache->generation);
  if (ZiFailed(status)) {
    return status;
  }
  for (size_t index = 0; index < cache->capacity; ++index) {
    ZiObjectSlotHeader* slot = slot_at(cache, index);
    if (slot->state != ZI_OBJECT_SLOT_FREE) {
      continue;
    }
    unsigned char* object = slot_object(slot);
    zi_memory_zero(object, cache->slot_stride - sizeof *slot);
    slot->generation = cache->generation;
    slot->state = ZI_OBJECT_SLOT_ALLOCATED;
    slot->checksum = calculate_slot_checksum(cache, slot);
    zi_write_u64_le(object + cache->object_size, calculate_slot_tail(cache, slot));
    ++cache->active_objects;
    *out_object = object;
    return ZI_STATUS_SUCCESS;
  }
  return ZI_STATUS_MEMORY_CORRUPTION;
}

ZiStatus zi_object_cache_free(ZiObjectCache* cache, void* object) {
  if (object == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_object_cache_validate(cache);
  if (ZiFailed(status)) {
    return status;
  }
  size_t index = cache->capacity;
  ZiObjectSlotHeader* slot = NULL;
  for (size_t candidate = 0; candidate < cache->capacity; ++candidate) {
    ZiObjectSlotHeader* candidate_slot = slot_at(cache, candidate);
    if (slot_object(candidate_slot) == object) {
      index = candidate;
      slot = candidate_slot;
      break;
    }
  }
  if (index == cache->capacity || slot == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (slot->state == ZI_OBJECT_SLOT_FREE) {
    return ZI_STATUS_INVALID_STATE;
  }
  if (slot->state != ZI_OBJECT_SLOT_ALLOCATED || cache->active_objects == 0) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  status = next_generation(&cache->generation);
  if (ZiFailed(status)) {
    return status;
  }
  zi_memory_zero(slot_object(slot), cache->slot_stride - sizeof *slot);
  slot->generation = cache->generation;
  slot->state = ZI_OBJECT_SLOT_FREE;
  slot->checksum = calculate_slot_checksum(cache, slot);
  --cache->active_objects;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_object_cache_validate(const ZiObjectCache* cache) {
  ZiStatus status = object_cache_descriptor_validate(cache);
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_pool_validate(cache->pool);
  if (ZiFailed(status)) {
    return status;
  }
  size_t active_objects = 0;
  for (size_t index = 0; index < cache->capacity; ++index) {
    const ZiObjectSlotHeader* slot = slot_at(cache, index);
    if (slot->magic != ZI_OBJECT_SLOT_MAGIC || slot->index != index ||
        slot->checksum != calculate_slot_checksum(cache, slot)) {
      return ZI_STATUS_MEMORY_CORRUPTION;
    }
    const unsigned char* object = (const unsigned char*)slot + sizeof *slot;
    if (slot->state == ZI_OBJECT_SLOT_ALLOCATED) {
      uint64_t tail = zi_read_u64_le(object + cache->object_size);
      if (tail != calculate_slot_tail(cache, slot) ||
          !bytes_are_zero(object + cache->object_size + ZI_POOL_TAIL_SIZE,
                          cache->slot_stride - sizeof *slot - cache->object_size -
                              ZI_POOL_TAIL_SIZE)) {
        return ZI_STATUS_MEMORY_CORRUPTION;
      }
      ++active_objects;
    } else if (slot->state != ZI_OBJECT_SLOT_FREE ||
               !bytes_are_zero(object, cache->slot_stride - sizeof *slot)) {
      return ZI_STATUS_MEMORY_CORRUPTION;
    }
  }
  return active_objects == cache->active_objects ? ZI_STATUS_SUCCESS : ZI_STATUS_MEMORY_CORRUPTION;
}

ZiStatus zi_object_cache_destroy(ZiObjectCache* cache) {
  ZiStatus status = zi_object_cache_validate(cache);
  if (ZiFailed(status)) {
    return status;
  }
  if (cache->active_objects != 0) {
    return ZI_STATUS_RESOURCE_IN_USE;
  }
  ZiPool* pool = cache->pool;
  void* storage = cache->storage;
  status = zi_pool_free(pool, storage);
  if (ZiSucceeded(status)) {
    zi_memory_zero(cache, sizeof *cache);
  }
  return status;
}

static ZiStatus allocation_span(size_t requested_size, size_t* out_span) {
  if (requested_size == 0 || out_span == NULL ||
      requested_size > SIZE_MAX - sizeof(ZiPoolBlockHeader) - ZI_POOL_TAIL_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  size_t unaligned = sizeof(ZiPoolBlockHeader) + requested_size + ZI_POOL_TAIL_SIZE;
  if (unaligned > SIZE_MAX - (ZI_POOL_ALIGNMENT - 1u)) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  *out_span = (unaligned + ZI_POOL_ALIGNMENT - 1u) & ~(size_t)(ZI_POOL_ALIGNMENT - 1u);
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

static uint64_t calculate_pool_cookie(const ZiPool* pool) {
  uint64_t hash = UINT64_C(0x6496e6d1ecfc1720);
  hash = mix_value(hash, (uint64_t)(uintptr_t)pool->arena);
  hash = mix_value(hash, (uint64_t)pool->arena_size);
  return hash;
}

static uint64_t
calculate_block_checksum(const ZiPool* pool, const ZiPoolBlockHeader* block, size_t offset) {
  uint64_t hash = mix_value(pool->cookie, (uint64_t)offset);
  hash = mix_value(hash, block->magic);
  hash = mix_value(hash, (uint64_t)block->span);
  hash = mix_value(hash, (uint64_t)block->previous_span);
  hash = mix_value(hash, (uint64_t)block->requested_size);
  hash = mix_value(hash, block->generation);
  hash = mix_value(hash, block->state);
  hash = mix_value(hash, block->reserved32);
  return mix_value(hash, block->reserved64);
}

static uint64_t
calculate_block_tail(const ZiPool* pool, const ZiPoolBlockHeader* block, size_t offset) {
  uint64_t tail = mix_value(pool->cookie ^ UINT64_C(0xa55aa55aa55aa55a), block->generation);
  tail = mix_value(tail, (uint64_t)offset);
  return mix_value(tail, (uint64_t)block->requested_size);
}

static uint64_t calculate_cache_cookie(const ZiObjectCache* cache) {
  uint64_t hash = UINT64_C(0xd1ecfc6496e61720);
  hash = mix_value(hash, (uint64_t)(uintptr_t)cache->storage);
  hash = mix_value(hash, (uint64_t)cache->storage_size);
  hash = mix_value(hash, (uint64_t)cache->object_size);
  return mix_value(hash, (uint64_t)cache->capacity);
}

static uint64_t calculate_slot_checksum(const ZiObjectCache* cache,
                                        const ZiObjectSlotHeader* slot) {
  uint64_t hash = mix_value(cache->cookie, slot->magic);
  hash = mix_value(hash, slot->generation);
  hash = mix_value(hash, slot->state);
  return mix_value(hash, slot->index);
}

static uint64_t calculate_slot_tail(const ZiObjectCache* cache, const ZiObjectSlotHeader* slot) {
  uint64_t tail = mix_value(cache->cookie ^ UINT64_C(0x5aa55aa55aa55aa5), slot->generation);
  tail = mix_value(tail, slot->index);
  return mix_value(tail, (uint64_t)cache->object_size);
}

static ZiStatus cache_slot_stride(size_t object_size, size_t* out_stride) {
  if (object_size == 0 || out_stride == NULL ||
      object_size > SIZE_MAX - sizeof(ZiObjectSlotHeader) - ZI_POOL_TAIL_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  size_t unaligned = sizeof(ZiObjectSlotHeader) + object_size + ZI_POOL_TAIL_SIZE;
  if (unaligned > SIZE_MAX - (ZI_POOL_ALIGNMENT - 1u)) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  *out_stride = (unaligned + ZI_POOL_ALIGNMENT - 1u) & ~(size_t)(ZI_POOL_ALIGNMENT - 1u);
  return ZI_STATUS_SUCCESS;
}

static ZiPoolBlockHeader* first_block(const ZiPool* pool) {
  return (ZiPoolBlockHeader*)pool->arena;
}

static ZiPoolBlockHeader* next_block(const ZiPool* pool, ZiPoolBlockHeader* block, size_t offset) {
  if (block->span > pool->arena_size - offset || offset + block->span == pool->arena_size) {
    return NULL;
  }
  return (ZiPoolBlockHeader*)(pool->arena + offset + block->span);
}

static ZiPoolBlockHeader*
previous_block(const ZiPool* pool, ZiPoolBlockHeader* block, size_t offset) {
  if (block->previous_span == 0) {
    return NULL;
  }
  if (block->previous_span > offset) {
    return NULL;
  }
  return (ZiPoolBlockHeader*)(pool->arena + offset - block->previous_span);
}

static void initialise_free_block(const ZiPool* pool,
                                  ZiPoolBlockHeader* block,
                                  size_t offset,
                                  size_t span,
                                  size_t previous_span,
                                  uint64_t generation) {
  block->magic = ZI_POOL_BLOCK_MAGIC;
  block->span = span;
  block->previous_span = previous_span;
  block->requested_size = 0;
  block->generation = generation;
  block->state = ZI_POOL_BLOCK_FREE;
  block->reserved32 = 0;
  block->reserved64 = 0;
  refresh_block_checksum(pool, block, offset);
}

static ZiStatus next_generation(uint64_t* inout_generation) {
  if (inout_generation == NULL || *inout_generation == UINT64_MAX) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  ++*inout_generation;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus pool_descriptor_validate(const ZiPool* pool) {
  if (pool == NULL || pool->struct_size != sizeof(ZiPool) || pool->version != ZI_POOL_VERSION ||
      pool->arena == NULL || ((uintptr_t)pool->arena & (uintptr_t)(ZI_POOL_ALIGNMENT - 1u)) != 0 ||
      (pool->arena_size & (ZI_POOL_ALIGNMENT - 1u)) != 0 ||
      pool->arena_size < sizeof(ZiPoolBlockHeader) + ZI_POOL_TAIL_SIZE + ZI_POOL_ALIGNMENT) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (pool->cookie != calculate_pool_cookie(pool) || pool->generation == 0 ||
      pool->allocated_bytes > pool->peak_allocated_bytes) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus pool_scan(const ZiPool* pool, ZiPoolStatistics* out_statistics) {
  ZiPoolStatistics statistics =
      {pool->arena_size, 0, 0, 0, 0, 0, pool->peak_allocated_bytes, pool->generation};
  size_t offset = 0;
  size_t previous_span = 0;
  while (offset < pool->arena_size) {
    if (pool->arena_size - offset < sizeof(ZiPoolBlockHeader)) {
      return ZI_STATUS_MEMORY_CORRUPTION;
    }
    const ZiPoolBlockHeader* block = (const ZiPoolBlockHeader*)(pool->arena + offset);
    if (block->magic != ZI_POOL_BLOCK_MAGIC || block->previous_span != previous_span ||
        block->span < sizeof *block + ZI_POOL_TAIL_SIZE + 1u ||
        (block->span & (ZI_POOL_ALIGNMENT - 1u)) != 0 || block->span > pool->arena_size - offset ||
        block->checksum != calculate_block_checksum(pool, block, offset)) {
      return ZI_STATUS_MEMORY_CORRUPTION;
    }
    const unsigned char* payload = (const unsigned char*)block + sizeof *block;
    if (block->state == ZI_POOL_BLOCK_ALLOCATED) {
      size_t required_span = 0;
      if (ZiFailed(allocation_span(block->requested_size, &required_span)) ||
          required_span > block->span ||
          zi_read_u64_le(payload + block->requested_size) !=
              calculate_block_tail(pool, block, offset) ||
          !bytes_are_zero(payload + block->requested_size + ZI_POOL_TAIL_SIZE,
                          block->span - sizeof *block - block->requested_size -
                              ZI_POOL_TAIL_SIZE) ||
          statistics.allocated_bytes > SIZE_MAX - block->requested_size) {
        return ZI_STATUS_MEMORY_CORRUPTION;
      }
      statistics.allocated_bytes += block->requested_size;
      ++statistics.allocation_count;
    } else if (block->state == ZI_POOL_BLOCK_FREE) {
      size_t minimum_free_span = 0;
      if (ZiFailed(allocation_span(ZI_POOL_ALIGNMENT, &minimum_free_span)) ||
          block->span < minimum_free_span || block->requested_size != 0 ||
          !bytes_are_zero(payload, block->span - sizeof *block)) {
        return ZI_STATUS_MEMORY_CORRUPTION;
      }
      statistics.free_span_bytes += block->span;
      size_t free_payload = block->span - sizeof *block - ZI_POOL_TAIL_SIZE;
      if (free_payload > statistics.largest_free_payload) {
        statistics.largest_free_payload = free_payload;
      }
    } else {
      return ZI_STATUS_MEMORY_CORRUPTION;
    }
    ++statistics.block_count;
    previous_span = block->span;
    offset += block->span;
  }
  if (offset != pool->arena_size || statistics.allocation_count != pool->active_allocations ||
      statistics.allocated_bytes != pool->allocated_bytes) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  if (out_statistics != NULL) {
    *out_statistics = statistics;
  }
  return ZI_STATUS_SUCCESS;
}

static void refresh_block_checksum(const ZiPool* pool, ZiPoolBlockHeader* block, size_t offset) {
  block->checksum = calculate_block_checksum(pool, block, offset);
}

static ZiObjectSlotHeader* slot_at(const ZiObjectCache* cache, size_t index) {
  return (ZiObjectSlotHeader*)(cache->storage + (index * cache->slot_stride));
}

static unsigned char* slot_object(ZiObjectSlotHeader* slot) {
  return (unsigned char*)slot + sizeof *slot;
}

static ZiStatus object_cache_descriptor_validate(const ZiObjectCache* cache) {
  if (cache == NULL || cache->struct_size != sizeof(ZiObjectCache) ||
      cache->version != ZI_OBJECT_CACHE_VERSION || cache->pool == NULL || cache->storage == NULL ||
      cache->object_size == 0 || cache->capacity == 0 || cache->capacity > UINT32_MAX) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  size_t expected_stride = 0;
  ZiStatus status = cache_slot_stride(cache->object_size, &expected_stride);
  if (ZiFailed(status) || cache->slot_stride != expected_stride ||
      cache->capacity > SIZE_MAX / cache->slot_stride ||
      cache->storage_size != cache->capacity * cache->slot_stride) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  if (cache->cookie != calculate_cache_cookie(cache) || cache->generation == 0 ||
      cache->active_objects > cache->capacity) {
    return ZI_STATUS_MEMORY_CORRUPTION;
  }
  return ZI_STATUS_SUCCESS;
}

static uint64_t mix_value(uint64_t hash, uint64_t value) {
  hash ^= value + UINT64_C(0x9e3779b97f4a7c15) + (hash << 6u) + (hash >> 2u);
  return hash;
}
