// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"

#define ZI_POOL_VERSION 1u
#define ZI_OBJECT_CACHE_VERSION 1u
#define ZI_POOL_ALIGNMENT 16u

typedef struct ZiPool {
  uint32_t struct_size;
  uint32_t version;
  unsigned char* arena;
  size_t arena_size;
  size_t active_allocations;
  size_t allocated_bytes;
  size_t peak_allocated_bytes;
  uint64_t generation;
  uint64_t cookie;
} ZiPool;

typedef struct ZiPoolStatistics {
  size_t capacity_bytes;
  size_t allocated_bytes;
  size_t free_span_bytes;
  size_t largest_free_payload;
  size_t allocation_count;
  size_t block_count;
  size_t peak_allocated_bytes;
  uint64_t generation;
} ZiPoolStatistics;

typedef struct ZiObjectCache {
  uint32_t struct_size;
  uint32_t version;
  ZiPool* pool;
  unsigned char* storage;
  size_t storage_size;
  size_t object_size;
  size_t slot_stride;
  size_t capacity;
  size_t active_objects;
  uint64_t generation;
  uint64_t cookie;
} ZiObjectCache;

ZiStatus zi_pool_initialise(void* arena, size_t arena_size, ZiPool* out_pool);
ZiStatus zi_pool_allocate(ZiPool* pool, size_t size, void** out_allocation);
ZiStatus zi_pool_free(ZiPool* pool, void* allocation);
ZiStatus zi_pool_validate(const ZiPool* pool);
ZiStatus zi_pool_statistics(const ZiPool* pool, ZiPoolStatistics* out_statistics);

ZiStatus zi_object_cache_initialise(ZiPool* pool,
                                    size_t object_size,
                                    size_t capacity,
                                    ZiObjectCache* out_cache);
ZiStatus zi_object_cache_allocate(ZiObjectCache* cache, void** out_object);
ZiStatus zi_object_cache_free(ZiObjectCache* cache, void* object);
ZiStatus zi_object_cache_validate(const ZiObjectCache* cache);
ZiStatus zi_object_cache_destroy(ZiObjectCache* cache);
