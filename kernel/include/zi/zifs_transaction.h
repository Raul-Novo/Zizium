// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/zifs.h"
#include "zi/zifs_journal.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_FS_TRANSACTION_VERSION 3u
#define ZI_FS_CREATE_REQUEST_VERSION 1u
#define ZI_FS_CREATE_RESULT_VERSION 1u
#define ZI_FS_MOVE_REQUEST_VERSION 1u
#define ZI_FS_MOVE_RESULT_VERSION 1u
#define ZI_FS_TRUNCATE_REQUEST_VERSION 1u
#define ZI_FS_TRUNCATE_RESULT_VERSION 1u
#define ZI_FS_DELETE_REQUEST_VERSION 1u
#define ZI_FS_DELETE_RESULT_VERSION 1u
#define ZI_FS_MOVE_FLAG_NONE UINT32_C(0)
#define ZI_FS_TRUNCATE_FLAG_NONE UINT32_C(0)
#define ZI_FS_DELETE_FLAG_NONE UINT32_C(0)
#define ZI_FS_TRANSACTION_MINIMUM_BLOCK_IMAGES 1u
#define ZI_FS_TRANSACTION_MAXIMUM_BLOCK_IMAGES ZI_FS_JOURNAL_MAXIMUM_BLOCK_IMAGES
#define ZI_FS_TRANSACTION_MAXIMUM_DATA_BLOCKS 24u
#define ZI_FS_TRANSACTION_MAXIMUM_DEFERRED_EXTENTS ZI_FS_INLINE_EXTENT_COUNT
#define ZI_FS_TRANSACTION_SCRATCH_BLOCKS 2u
#define ZI_FS_TRANSACTION_MINIMUM_WORKSPACE_BLOCKS                                                 \
  (ZI_FS_TRANSACTION_MINIMUM_BLOCK_IMAGES + ZI_FS_TRANSACTION_SCRATCH_BLOCKS)
#define ZI_FS_TRANSACTION_MINIMUM_WORKSPACE_SIZE                                                   \
  ((size_t)ZI_FS_TRANSACTION_MINIMUM_WORKSPACE_BLOCKS * (size_t)ZI_FS_BLOCK_SIZE)
#define ZI_FS_TRANSACTION_WORKSPACE_BLOCKS                                                         \
  (ZI_FS_TRANSACTION_MAXIMUM_BLOCK_IMAGES + ZI_FS_TRANSACTION_SCRATCH_BLOCKS)
#define ZI_FS_TRANSACTION_WORKSPACE_SIZE                                                           \
  ((size_t)ZI_FS_TRANSACTION_WORKSPACE_BLOCKS * (size_t)ZI_FS_BLOCK_SIZE)

enum ZiFsTransactionState {
  ZI_FS_TRANSACTION_STATE_UNINITIALISED = 0,
  ZI_FS_TRANSACTION_STATE_READY = 1,
  ZI_FS_TRANSACTION_STATE_PREPARED = 2,
  ZI_FS_TRANSACTION_STATE_FAILED = 3,
};

typedef struct ZiFsTransactionBlockImage {
  uint64_t target_block;
} ZiFsTransactionBlockImage;

typedef struct ZiFsDeferredExtent {
  uint64_t first_block;
  uint64_t block_count;
} ZiFsDeferredExtent;

typedef struct ZiFsTransaction {
  uint32_t struct_size;
  uint32_t version;
  ZiFsVolume* volume;
  void* workspace;
  size_t workspace_size;
  uint64_t source_generation;
  uint64_t target_generation;
  uint64_t transaction_id;
  uint32_t state;
  uint32_t block_image_count;
  uint32_t block_image_capacity;
  uint32_t deferred_extent_count;
  ZiFsTransactionBlockImage block_images[ZI_FS_TRANSACTION_MAXIMUM_BLOCK_IMAGES];
  ZiFsDeferredExtent deferred_extents[ZI_FS_TRANSACTION_MAXIMUM_DEFERRED_EXTENTS];
} ZiFsTransaction;

typedef struct ZiFsCreateRequest {
  uint32_t struct_size;
  uint32_t version;
  uint64_t parent_record_index;
  uint64_t security_id;
  uint64_t timestamp;
  ZiStringView name;
  ZiConstBuffer data;
} ZiFsCreateRequest;

typedef struct ZiFsCreateResult {
  uint32_t struct_size;
  uint32_t version;
  uint64_t file_id;
  uint64_t record_index;
  uint64_t first_data_block;
  uint64_t data_block_count;
} ZiFsCreateResult;

typedef struct ZiFsMoveRequest {
  uint32_t struct_size;
  uint32_t version;
  uint64_t source_parent_record_index;
  uint64_t target_parent_record_index;
  uint64_t timestamp;
  uint32_t flags;
  uint32_t reserved;
  ZiStringView source_name;
  ZiStringView target_name;
} ZiFsMoveRequest;

typedef struct ZiFsMoveResult {
  uint32_t struct_size;
  uint32_t version;
  uint64_t file_id;
  uint64_t record_index;
  uint64_t source_parent_file_id;
  uint64_t target_parent_file_id;
  uint16_t file_type;
  uint16_t reserved16;
  uint32_t reserved32;
} ZiFsMoveResult;

typedef struct ZiFsTruncateRequest {
  uint32_t struct_size;
  uint32_t version;
  uint64_t record_index;
  uint64_t new_size;
  uint64_t timestamp;
  uint32_t flags;
  uint32_t reserved;
} ZiFsTruncateRequest;

typedef struct ZiFsTruncateResult {
  uint32_t struct_size;
  uint32_t version;
  uint64_t file_id;
  uint64_t record_index;
  uint64_t previous_size;
  uint64_t new_size;
  uint64_t retained_block_count;
  uint64_t released_block_count;
} ZiFsTruncateResult;

typedef struct ZiFsDeleteRequest {
  uint32_t struct_size;
  uint32_t version;
  uint64_t parent_record_index;
  uint64_t timestamp;
  uint32_t flags;
  uint32_t reserved;
  ZiStringView name;
} ZiFsDeleteRequest;

typedef struct ZiFsDeleteResult {
  uint32_t struct_size;
  uint32_t version;
  uint64_t file_id;
  uint64_t record_index;
  uint64_t parent_file_id;
  uint64_t released_block_count;
} ZiFsDeleteResult;

ZiStatus ZiFsTransactionInitialise(ZiFsTransaction* transaction,
                                   ZiFsVolume* volume,
                                   void* workspace,
                                   size_t workspace_size);
ZiStatus ZiFsTransactionReset(ZiFsTransaction* transaction);
ZiStatus ZiFsTransactionPrepareCreateFile(ZiFsTransaction* transaction,
                                          const ZiFsCreateRequest* request,
                                          ZiFsCreateResult* out_result);
ZiStatus ZiFsTransactionPrepareMove(ZiFsTransaction* transaction,
                                    const ZiFsMoveRequest* request,
                                    ZiFsMoveResult* out_result);
ZiStatus ZiFsTransactionPrepareTruncate(ZiFsTransaction* transaction,
                                        const ZiFsTruncateRequest* request,
                                        ZiFsTruncateResult* out_result);
ZiStatus ZiFsTransactionPrepareDelete(ZiFsTransaction* transaction,
                                      const ZiFsDeleteRequest* request,
                                      ZiFsDeleteResult* out_result);
ZiStatus ZiFsTransactionCommit(ZiFsTransaction* transaction);
ZiStatus ZiFsTransactionGetBlockImage(const ZiFsTransaction* transaction,
                                      size_t image_index,
                                      uint64_t* out_target_block,
                                      ZiConstBuffer* out_image);
ZiStatus ZiFsTransactionGetDeferredExtent(const ZiFsTransaction* transaction,
                                          size_t extent_index,
                                          ZiFsDeferredExtent* out_extent);
