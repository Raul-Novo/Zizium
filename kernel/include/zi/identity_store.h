// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/identity.h"
#include "zi/identity_database.h"
#include "zi/security.h"
#include "zi/zifs.h"
#include "zi/zifs_transaction.h"
#include "zizium/status.h"

#define ZI_IDENTITY_STORE_VERSION 1u
#define ZI_IDENTITY_STORE_WORKSPACE_SIZE                                                           \
  (ZI_IDENTITY_DATABASE_SIZE + ZI_FS_BLOCK_SIZE + ZI_FS_TRANSACTION_WORKSPACE_SIZE)

// Kernel-owned binding supplied by trusted provisioning, never inferred from file contents.
// Caller serialises the store AND volume across complete operations. No public token API.
// One live store owns the accepted generation; copying/resetting it defeats the rollback floor.
typedef struct ZiIdentityStore {
  uint32_t struct_size;
  uint32_t version;
  ZiFsVolume* volume;
  ZiIdentityDatabaseAuthority authority;
  uint64_t record_index;
  uint64_t file_id;
  uint64_t minimum_generation;
  uint32_t needs_recovery;
} ZiIdentityStore;

// Workspaces are borrowed, stable, non-overlapping with all other arguments and overwritten.
// Load validates binding and explicit SYSTEM:1-only policy BEFORE reading payload bytes.
// On success the first ZI_IDENTITY_DATABASE_SIZE bytes contain the validated snapshot.
// This is a single-running-instance freshness floor, not protection from offline rollback.
ZiStatus zi_identity_store_load(ZiIdentityStore* store,
                                const ZiAccessToken* token,
                                void* workspace,
                                size_t workspace_size,
                                ZiIdentityDatabaseState* out_state);
// Issue publishes out_identity only AFTER successful commit. Any uncertain commit poisons
// the store; callers must recover/reopen under trusted policy, never silently retry old state.
ZiStatus zi_identity_store_issue(ZiIdentityStore* store,
                                 const ZiAccessToken* token,
                                 const ZiIdentityCreateRequest* request,
                                 void* workspace,
                                 size_t workspace_size,
                                 ZiNativeIdentity* out_identity);
ZiStatus zi_identity_store_remove(ZiIdentityStore* store,
                                  const ZiAccessToken* token,
                                  const ZiNativeIdentity* identity,
                                  void* workspace,
                                  size_t workspace_size);
