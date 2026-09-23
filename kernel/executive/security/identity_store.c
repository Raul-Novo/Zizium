// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/identity_store.h"

#include <stddef.h>
#include <stdint.h>

#include "zi/byte_order.h"
#include "zi/identity.h"
#include "zi/identity_database.h"
#include "zi/security.h"
#include "zi/zifs.h"
#include "zi/zifs_security.h"
#include "zi/zifs_transaction.h"
#include "zizium/status.h"
#include "zizium/types.h"

_Static_assert(ZI_IDENTITY_DATABASE_SIZE % ZI_FS_BLOCK_SIZE == 0,
               "Database must use whole blocks.");
_Static_assert(ZI_IDENTITY_DATABASE_SIZE / ZI_FS_BLOCK_SIZE <=
                   ZI_FS_TRANSACTION_MAXIMUM_DATA_BLOCKS,
               "Database must fit one transaction.");

static ZiStatus validate_store(const ZiIdentityStore* store, const void* workspace, size_t size);
static ZiStatus read_bound_record(const ZiIdentityStore* store,
                                  const ZiAccessToken* token,
                                  void* scratch,
                                  ZiFsFileRecord* out_record);
static ZiStatus commit_snapshot(ZiIdentityStore* store, void* workspace, uint64_t generation);

ZiStatus zi_identity_store_load(ZiIdentityStore* store,
                                const ZiAccessToken* token,
                                void* workspace,
                                size_t workspace_size,
                                ZiIdentityDatabaseState* out_state) {
  if (out_state == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_store(store, workspace, workspace_size);
  if (ZiFailed(status)) {
    return status;
  }
  unsigned char* bytes = workspace;
  void* scratch = bytes + ZI_IDENTITY_DATABASE_SIZE;
  ZiFsFileRecord record = {0};
  status = read_bound_record(store, token, scratch, &record);
  if (ZiFailed(status)) {
    return status;
  }
  size_t read_size = 0;
  status = ZiFsReadFile(store->volume,
                        &record,
                        0,
                        bytes,
                        ZI_IDENTITY_DATABASE_SIZE,
                        &read_size,
                        scratch,
                        ZI_FS_BLOCK_SIZE);
  if (ZiFailed(status)) {
    return status;
  }
  if (read_size != ZI_IDENTITY_DATABASE_SIZE) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiIdentityDatabaseState state = {0};
  status = zi_identity_database_validate(bytes,
                                         ZI_IDENTITY_DATABASE_SIZE,
                                         &store->authority,
                                         store->minimum_generation,
                                         &state);
  if (ZiFailed(status)) {
    return status;
  }
  store->minimum_generation = state.generation;
  *out_state = state;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_identity_store_issue(ZiIdentityStore* store,
                                 const ZiAccessToken* token,
                                 const ZiIdentityCreateRequest* request,
                                 void* workspace,
                                 size_t workspace_size,
                                 ZiNativeIdentity* out_identity) {
  if (out_identity == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiIdentityDatabaseState state = {0};
  ZiStatus status = zi_identity_store_load(store, token, workspace, workspace_size, &state);
  if (ZiFailed(status)) {
    return status;
  }
  ZiNativeIdentity identity = {0};
  status = zi_identity_database_append(workspace,
                                       ZI_IDENTITY_DATABASE_SIZE,
                                       &store->authority,
                                       request,
                                       &identity);
  if (ZiFailed(status)) {
    return status;
  }
  status = commit_snapshot(store, workspace, state.generation + 1u);
  if (ZiFailed(status)) {
    return status;
  }
  *out_identity = identity;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_identity_store_remove(ZiIdentityStore* store,
                                  const ZiAccessToken* token,
                                  const ZiNativeIdentity* identity,
                                  void* workspace,
                                  size_t workspace_size) {
  ZiIdentityDatabaseState state = {0};
  ZiStatus status = zi_identity_store_load(store, token, workspace, workspace_size, &state);
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_identity_database_remove(workspace,
                                       ZI_IDENTITY_DATABASE_SIZE,
                                       &store->authority,
                                       identity);
  if (ZiFailed(status)) {
    return status;
  }
  return commit_snapshot(store, workspace, state.generation + 1u);
}

static ZiStatus validate_store(const ZiIdentityStore* store, const void* workspace, size_t size) {
  if (store == NULL || store->struct_size != sizeof *store ||
      store->version != ZI_IDENTITY_STORE_VERSION || store->volume == NULL || store->file_id == 0 ||
      store->minimum_generation == 0 || workspace == NULL ||
      ZiFailed(zi_identity_database_authority_validate(&store->authority))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (size < ZI_IDENTITY_STORE_WORKSPACE_SIZE) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  if (store->needs_recovery != 0 || store->volume->needs_recovery != 0 ||
      store->volume->is_mounted == 0) {
    return ZI_STATUS_RECOVERY_REQUIRED;
  }
  if (zi_memory_compare(store->authority.volume, store->volume->superblock.volume_uuid, 16) != 0) {
    return ZI_STATUS_ACCESS_DENIED;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus read_bound_record(const ZiIdentityStore* store,
                                  const ZiAccessToken* token,
                                  void* scratch,
                                  ZiFsFileRecord* out_record) {
  ZiStatus status = zi_security_token_validate(token);
  if (ZiFailed(status)) {
    return status;
  }
  ZiFsFileRecord record = {0};
  status =
      ZiFsReadFileRecord(store->volume, store->record_index, scratch, ZI_FS_BLOCK_SIZE, &record);
  if (ZiFailed(status)) {
    return status;
  }
  if (record.file_id != store->file_id || record.file_type != ZI_FS_FILE_TYPE_REGULAR ||
      record.file_size != ZI_IDENTITY_DATABASE_SIZE || record.flags != 0) {
    return ZI_STATUS_ACCESS_DENIED;
  }
  ZiFsSecurityDescriptorStorage security = {0};
  status = ZiFsLoadSecurityDescriptor(store->volume,
                                      record.security_id,
                                      scratch,
                                      ZI_FS_BLOCK_SIZE,
                                      &security);
  if (ZiFailed(status)) {
    return status;
  }
  const ZiSecurityId system = {ZI_SECURITY_AUTHORITY_SYSTEM, 1};
  if (security.flags != ZI_FS_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT ||
      security.descriptor.control_flags != 0 ||
      !zi_security_id_equal(security.descriptor.owner, system) || security.dacl.entry_count != 1 ||
      security.entries[0].type != ZI_ACE_ALLOW || security.entries[0].inheritance_flags != 0 ||
      security.entries[0].access_mask != ZI_ACCESS_FULL_CONTROL ||
      !zi_security_id_equal(security.entries[0].trustee, system)) {
    return ZI_STATUS_ACCESS_DENIED;
  }
  ZiAccessMask granted = 0;
  status = zi_security_access_check(&security.descriptor, token, ZI_ACCESS_FULL_CONTROL, &granted);
  if (ZiFailed(status)) {
    return status;
  }
  *out_record = record;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus commit_snapshot(ZiIdentityStore* store, void* workspace, uint64_t generation) {
  unsigned char* bytes = workspace;
  ZiFsTransaction transaction = {0};
  ZiStatus status = ZiFsTransactionInitialise(&transaction,
                                              store->volume,
                                              bytes + ZI_IDENTITY_DATABASE_SIZE + ZI_FS_BLOCK_SIZE,
                                              ZI_FS_TRANSACTION_WORKSPACE_SIZE);
  if (ZiFailed(status)) {
    return status;
  }
  const ZiFsWriteRequest request = {sizeof(ZiFsWriteRequest),
                                    ZI_FS_WRITE_REQUEST_VERSION,
                                    store->record_index,
                                    0,
                                    0,
                                    ZI_FS_WRITE_FLAG_NONE,
                                    0,
                                    {workspace, ZI_IDENTITY_DATABASE_SIZE}};
  ZiFsWriteResult result = {0};
  status = ZiFsTransactionPrepareWrite(&transaction, &request, &result);
  if (ZiFailed(status)) {
    return status;
  }
  status = ZiFsTransactionCommit(&transaction);
  if (ZiFailed(status)) {
    store->needs_recovery = 1;
    return status;
  }
  store->minimum_generation = generation;
  return ZI_STATUS_SUCCESS;
}
