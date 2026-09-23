// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "phase8_tests.h"
#include "zi/block.h"
#include "zi/byte_order.h"
#include "zi/identity.h"
#include "zi/identity_database.h"
#include "zi/identity_store.h"
#include "zi/security.h"
#include "zi/zifs.h"
#include "zi/zifs_journal.h"
#include "zi/zifs_recovery.h"
#include "zi/zifs_security.h"
#include "zi/zifs_transaction.h"
#include "zizium/status.h"

#define STORE_TEST_BLOCKS 128u
#define STORE_TEST_PRIVATE_ID UINT64_C(7)

static unsigned char s_disk[STORE_TEST_BLOCKS][ZI_FS_BLOCK_SIZE];
static unsigned char s_snapshot[sizeof s_disk];
static unsigned char s_checkpoint_snapshot[sizeof s_disk];
static unsigned char s_old_database[ZI_IDENTITY_DATABASE_SIZE];
static unsigned char s_new_database[ZI_IDENTITY_DATABASE_SIZE];
static size_t s_checkpoint_block;
static size_t s_commit_block;
static unsigned char s_workspace[ZI_IDENTITY_STORE_WORKSPACE_SIZE];
static unsigned char s_recovery[ZI_FS_RECOVERY_WORKSPACE_SIZE];
static size_t s_operations;
static size_t s_fail_operation;
static size_t s_payload_reads;
static const ZiIdentityDatabaseAuthority k_authority = {sizeof(ZiIdentityDatabaseAuthority),
                                                        ZI_IDENTITY_DATABASE_VERSION,
                                                        {1},
                                                        {2},
                                                        {3}};
static const ZiAccessToken k_system =
    {sizeof(ZiAccessToken), ZI_ACCESS_TOKEN_VERSION, {ZI_SECURITY_AUTHORITY_SYSTEM, 1}, NULL, 0, 0};
static const ZiIdentityCreateRequest k_request = {sizeof(ZiIdentityCreateRequest),
                                                  ZI_IDENTITY_DATABASE_VERSION,
                                                  ZI_SECURITY_AUTHORITY_USER,
                                                  {"First User", 10},
                                                  NULL,
                                                  0};

static bool expect(size_t* count, bool condition, int line);
static ZiStatus
disk_read(void* context, uint64_t first, uint32_t blocks, void* output, size_t size);
static ZiStatus
disk_write(void* context, uint64_t first, uint32_t blocks, const void* input, size_t size);
static ZiStatus disk_flush(void* context);
static ZiBlockDevice device(void);
static ZiStatus mount(ZiFsVolume* volume);
static ZiStatus initialise_volume(ZiFsVolume* volume);
static ZiStatus initialise_security(void);
static ZiStatus provision(ZiFsVolume* volume, ZiIdentityStore* store);
static bool test_store_lifecycle(size_t* count);
static bool test_store_reuse(size_t* count, ZiIdentityStore* store, const ZiNativeIdentity* first);
static bool test_store_denials(size_t* count);
static bool test_public_policy_denial(size_t* count, ZiIdentityStore* store);
static bool test_binding_denials(size_t* count, ZiIdentityStore* store);
static bool test_store_crashes(size_t* count, bool remove);
static bool capture_old_database(size_t* count, ZiIdentityStore* store);
static ZiStatus mutate_store(ZiIdentityStore* store, bool remove, ZiNativeIdentity* out_identity);
static bool test_crash_prefix(size_t* count,
                              const ZiIdentityStore* original,
                              bool remove,
                              size_t failure,
                              bool* out_new);
static bool check_recovered(size_t* count, ZiIdentityStore* store, bool remove, bool* out_new);
static bool
check_removed_record(size_t* count, const ZiIdentityDatabaseState* state, bool* out_new);
static void capture_checkpoint(void);
static bool test_checkpoint_rejection(size_t* count);
static bool mutate_checkpoint(size_t* count, size_t mutation);

#define EXPECT(condition)                                                                          \
  do {                                                                                             \
    if (!expect(count, (condition), __LINE__)) {                                                   \
      return false;                                                                                \
    }                                                                                              \
  } while (false)

bool phase8_store_test(size_t* out_assertion_count) {
  size_t count = 0;
  bool result = (bool)(test_store_lifecycle(&count) && test_store_denials(&count) &&
                       test_store_crashes(&count, false) && test_store_crashes(&count, true) &&
                       test_checkpoint_rejection(&count));
  *out_assertion_count = count;
  return result;
}

static bool test_store_lifecycle(size_t* count) {
  ZiFsVolume volume = {0};
  ZiIdentityStore store = {0};
  EXPECT(provision(&volume, &store) == ZI_STATUS_SUCCESS);
  ZiNativeIdentity first = {0};
  EXPECT(zi_identity_store_issue(&store,
                                 &k_system,
                                 &k_request,
                                 s_workspace,
                                 sizeof s_workspace,
                                 &first) == ZI_STATUS_SUCCESS);
  EXPECT(first.local_id.value == 256 && store.minimum_generation == 2);
  EXPECT(mount(&volume) == ZI_STATUS_SUCCESS);
  ZiIdentityDatabaseState state = {0};
  EXPECT(zi_identity_store_load(&store, &k_system, s_workspace, sizeof s_workspace, &state) ==
         ZI_STATUS_SUCCESS);
  EXPECT(state.record_count == 1 && state.issuer.user_high_water == 256);
  return test_store_reuse(count, &store, &first);
}

static bool test_store_reuse(size_t* count, ZiIdentityStore* store, const ZiNativeIdentity* first) {
  EXPECT(zi_identity_store_remove(store, &k_system, first, s_workspace, sizeof s_workspace) ==
         ZI_STATUS_SUCCESS);
  EXPECT(mount(store->volume) == ZI_STATUS_SUCCESS);
  ZiNativeIdentity next = {0};
  EXPECT(zi_identity_store_issue(store,
                                 &k_system,
                                 &k_request,
                                 s_workspace,
                                 sizeof s_workspace,
                                 &next) == ZI_STATUS_SUCCESS);
  EXPECT(next.local_id.value == 257 && store->minimum_generation == 4);
  ZiIdentityDatabaseState state = {0};
  ZiIdentityDatabaseRecord record = {0};
  EXPECT(zi_identity_store_load(store, &k_system, s_workspace, sizeof s_workspace, &state) ==
         ZI_STATUS_SUCCESS);
  EXPECT(zi_identity_database_record(s_workspace,
                                     ZI_IDENTITY_DATABASE_SIZE,
                                     &k_authority,
                                     0,
                                     &record) == ZI_STATUS_SUCCESS);
  EXPECT(record.state == ZI_IDENTITY_RECORD_TOMBSTONE);
  return true;
}

static bool test_store_denials(size_t* count) {
  ZiFsVolume volume = {0};
  ZiIdentityStore store = {0};
  EXPECT(provision(&volume, &store) == ZI_STATUS_SUCCESS);
  const ZiSecurityId groups[] = {{ZI_SECURITY_AUTHORITY_GROUP, 1},
                                 {ZI_SECURITY_AUTHORITY_GROUP, 2}};
  const ZiAccessToken user = {sizeof(ZiAccessToken),
                              ZI_ACCESS_TOKEN_VERSION,
                              {ZI_SECURITY_AUTHORITY_USER, 21},
                              groups,
                              2,
                              0};
  ZiIdentityDatabaseState state = {.generation = UINT64_MAX};
  s_payload_reads = 0;
  EXPECT(zi_identity_store_load(&store, &user, s_workspace, sizeof s_workspace, &state) ==
         ZI_STATUS_ACCESS_DENIED);
  EXPECT(s_payload_reads == 0 && state.generation == UINT64_MAX);
  EXPECT(zi_identity_store_load(&store, NULL, s_workspace, sizeof s_workspace, &state) ==
         ZI_STATUS_INVALID_ARGUMENT);
  EXPECT(zi_identity_store_load(&store, &k_system, s_workspace, sizeof s_workspace - 1u, &state) ==
         ZI_STATUS_BUFFER_TOO_SMALL);
  EXPECT(test_binding_denials(count, &store));
  return test_public_policy_denial(count, &store);
}

static bool test_public_policy_denial(size_t* count, ZiIdentityStore* store) {
  ZiIdentityDatabaseState state = {0};
  // A syntactically valid but public descriptor must fail BEFORE payload reads.
  const ZiAce entries[] = {
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_FULL_CONTROL, {ZI_SECURITY_AUTHORITY_SYSTEM, 1}},
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_READ, {ZI_SECURITY_AUTHORITY_GROUP, 2}},
  };
  const ZiAcl dacl = {sizeof(ZiAcl), ZI_ACL_VERSION, entries, 2};
  const ZiSecurityDescriptor descriptor = {sizeof(ZiSecurityDescriptor),
                                           ZI_SECURITY_DESCRIPTOR_VERSION,
                                           {ZI_SECURITY_AUTHORITY_SYSTEM, 1},
                                           {ZI_SECURITY_AUTHORITY_GROUP, 1},
                                           &dacl,
                                           0};
  EXPECT(ZiFsInitialiseSecurityTable(s_disk[70], ZI_FS_BLOCK_SIZE, 1) == ZI_STATUS_SUCCESS);
  EXPECT(ZiFsAppendSecurityDescriptor(s_disk[70],
                                      ZI_FS_BLOCK_SIZE,
                                      STORE_TEST_PRIVATE_ID,
                                      ZI_FS_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT,
                                      &descriptor) == ZI_STATUS_SUCCESS);
  s_payload_reads = 0;
  EXPECT(zi_identity_store_load(store, &k_system, s_workspace, sizeof s_workspace, &state) ==
         ZI_STATUS_ACCESS_DENIED);
  EXPECT(s_payload_reads == 0);
  return true;
}

static bool test_binding_denials(size_t* count, ZiIdentityStore* store) {
  ZiIdentityDatabaseState state = {0};
  ZiIdentityStore original = *store;
  store->file_id += 1;
  s_payload_reads = 0;
  EXPECT(zi_identity_store_load(store, &k_system, s_workspace, sizeof s_workspace, &state) ==
         ZI_STATUS_ACCESS_DENIED);
  EXPECT(s_payload_reads == 0);
  *store = original;
  store->authority.volume[15] = 1;
  EXPECT(zi_identity_store_load(store, &k_system, s_workspace, sizeof s_workspace, &state) ==
         ZI_STATUS_ACCESS_DENIED);
  *store = original;
  store->authority.issuer[15] = 1;
  EXPECT(zi_identity_store_load(store, &k_system, s_workspace, sizeof s_workspace, &state) ==
         ZI_STATUS_ACCESS_DENIED);
  *store = original;
  store->authority.database[15] = 1;
  EXPECT(zi_identity_store_load(store, &k_system, s_workspace, sizeof s_workspace, &state) ==
         ZI_STATUS_ACCESS_DENIED);
  *store = original;
  store->minimum_generation = 2;
  EXPECT(zi_identity_store_load(store, &k_system, s_workspace, sizeof s_workspace, &state) ==
         ZI_STATUS_INVALID_STATE);
  *store = original;
  return true;
}

static ZiStatus mutate_store(ZiIdentityStore* store, bool remove, ZiNativeIdentity* out_identity) {
  if (remove) {
    const ZiNativeIdentity first = {{1}, {ZI_SECURITY_AUTHORITY_USER, 256}};
    return zi_identity_store_remove(store, &k_system, &first, s_workspace, sizeof s_workspace);
  }
  return zi_identity_store_issue(store,
                                 &k_system,
                                 &k_request,
                                 s_workspace,
                                 sizeof s_workspace,
                                 out_identity);
}

static bool test_store_crashes(size_t* count, bool remove) {
  ZiFsVolume volume = {0};
  ZiIdentityStore store = {0};
  EXPECT(provision(&volume, &store) == ZI_STATUS_SUCCESS);
  ZiNativeIdentity first = {0};
  if (remove && ZiFailed(mutate_store(&store, false, &first))) {
    return false;
  }
  if (!capture_old_database(count, &store)) {
    return false;
  }
  ZiIdentityStore original = store;
  zi_memory_copy(s_snapshot, s_disk, sizeof s_disk);
  s_operations = 0;
  EXPECT(mutate_store(&store, remove, &first) == ZI_STATUS_SUCCESS);
  zi_memory_copy(s_new_database, s_workspace, sizeof s_new_database);
  size_t operations = s_operations;
  EXPECT(operations > 0 && operations < 100);
  size_t new_states = 0;
  for (size_t failure = 1; failure <= operations; ++failure) {
    bool is_new = false;
    if (!test_crash_prefix(count, &original, remove, failure, &is_new)) {
      return false;
    }
    if (is_new) {
      ++new_states;
    }
  }
  EXPECT(new_states > 0 && new_states < operations);
  const char* operation = "issuance";
  if (remove) {
    operation = "tombstone";
  }
  (void)printf("Identity %s crash campaign: %zu write/flush boundaries checked.\n",
               operation,
               operations);
  return true;
}

static bool capture_old_database(size_t* count, ZiIdentityStore* store) {
  ZiIdentityDatabaseState state = {0};
  EXPECT(zi_identity_store_load(store, &k_system, s_workspace, sizeof s_workspace, &state) ==
         ZI_STATUS_SUCCESS);
  zi_memory_copy(s_old_database, s_workspace, sizeof s_old_database);
  return true;
}

static bool test_crash_prefix(size_t* count,
                              const ZiIdentityStore* original,
                              bool remove,
                              size_t failure,
                              bool* out_new) {
  zi_memory_copy(s_disk, s_snapshot, sizeof s_disk);
  ZiIdentityStore store = *original;
  s_fail_operation = 0;
  EXPECT(mount(store.volume) == ZI_STATUS_SUCCESS);
  s_operations = 0;
  s_fail_operation = failure;
  ZiNativeIdentity output = {{9}, {ZI_SECURITY_AUTHORITY_USER, 999}};
  ZiStatus status = mutate_store(&store, remove, &output);
  EXPECT(status == ZI_STATUS_DEVICE_ERROR && store.needs_recovery != 0);
  EXPECT(output.local_id.value == 999 && output.issuer[0] == 9);
  ZiIdentityDatabaseState state = {0};
  EXPECT(zi_identity_store_load(&store, &k_system, s_workspace, sizeof s_workspace, &state) ==
         ZI_STATUS_RECOVERY_REQUIRED);
  s_fail_operation = 0;
  capture_checkpoint();
  status = mount(store.volume);
  if (ZiFailed(status)) {
    (void)fprintf_s(stderr, "Database remount failed at operation %zu: %d.\n", failure, status);
    return false;
  }
  // Explicit trusted fixture reopen after recovery, never an automatic retry.
  store = *original;
  return check_recovered(count, &store, remove, out_new);
}

static void capture_checkpoint(void) {
  ZiFsJournalHeader header = {0};
  uint32_t copy = 0;
  ZiBlockDevice disk = device();
  if (ZiFailed(ZiFsLoadJournalHeader(&disk, 4, s_recovery, ZI_FS_BLOCK_SIZE, &header, &copy)) ||
      header.last_checkpoint_transaction == header.last_committed_transaction) {
    return;
  }
  size_t checkpoint = 0;
  size_t commit = 0;
  for (size_t block = 6; block < 70; block += 2) {
    ZiFsJournalRecord record = {0};
    if (ZiSucceeded(ZiFsDecodeJournalRecord(s_disk[block], ZI_FS_JOURNAL_RECORD_SIZE, &record)) &&
        record.transaction_id == header.last_committed_transaction) {
      if (record.record_type == ZI_FS_JOURNAL_RECORD_CHECKPOINT) {
        checkpoint = block;
      } else if (record.record_type == ZI_FS_JOURNAL_RECORD_COMMIT) {
        commit = block;
      }
    }
  }
  if (checkpoint != 0 && commit != 0) {
    zi_memory_copy(s_checkpoint_snapshot, s_disk, sizeof s_disk);
    s_checkpoint_block = checkpoint;
    s_commit_block = commit;
  }
}

static bool test_checkpoint_rejection(size_t* count) {
  EXPECT(s_checkpoint_block != 0 && s_commit_block != 0);
  for (size_t mutation = 0; mutation < 6; ++mutation) {
    zi_memory_copy(s_disk, s_checkpoint_snapshot, sizeof s_disk);
    if (!mutate_checkpoint(count, mutation)) {
      return false;
    }
    zi_memory_copy(s_snapshot, s_disk, sizeof s_disk);
    s_fail_operation = 0;
    s_operations = 0;
    ZiFsVolume volume = {0};
    EXPECT(mount(&volume) == ZI_STATUS_CORRUPT_FILESYSTEM);
    EXPECT(s_operations == 0 && zi_memory_compare(s_snapshot, s_disk, sizeof s_disk) == 0);
  }
  return true;
}

static bool mutate_checkpoint(size_t* count, size_t mutation) {
  size_t block = s_checkpoint_block;
  if (mutation == 5) {
    block = s_commit_block;
  }
  ZiFsJournalRecord record = {0};
  EXPECT(ZiFsDecodeJournalRecord(s_disk[block], ZI_FS_JOURNAL_RECORD_SIZE, &record) ==
         ZI_STATUS_SUCCESS);
  if (mutation == 0) {
    ++record.sequence;
  } else if (mutation == 1 || mutation == 5) {
    ++record.image_count;
  } else if (mutation == 2) {
    record.transaction_checksum ^= UINT32_C(0x80000000);
    if (record.transaction_checksum == 0) {
      record.transaction_checksum = 1;
    }
  }
  EXPECT(ZiFsEncodeJournalRecord(&record, s_disk[block], ZI_FS_JOURNAL_RECORD_SIZE) ==
         ZI_STATUS_SUCCESS);
  if (mutation == 3) {
    size_t duplicate = 6u + ((s_checkpoint_block - 6u + 2u) % 64u);
    zi_memory_copy(s_disk[duplicate], s_disk[s_checkpoint_block], ZI_FS_JOURNAL_RECORD_SIZE);
  } else if (mutation == 4) {
    zi_memory_zero(s_disk[s_commit_block], ZI_FS_JOURNAL_RECORD_SIZE);
  }
  return true;
}

static bool check_recovered(size_t* count, ZiIdentityStore* store, bool remove, bool* out_new) {
  ZiIdentityDatabaseState state = {0};
  EXPECT(zi_identity_store_load(store, &k_system, s_workspace, sizeof s_workspace, &state) ==
         ZI_STATUS_SUCCESS);
  EXPECT(zi_memory_compare(s_workspace, s_old_database, sizeof s_old_database) == 0 ||
         zi_memory_compare(s_workspace, s_new_database, sizeof s_new_database) == 0);
  if (!remove) {
    EXPECT(
        (state.record_count == 0 && state.generation == 1 && state.issuer.user_high_water == 255) ||
        (state.record_count == 1 && state.generation == 2 && state.issuer.user_high_water == 256));
    *out_new = (bool)(state.record_count == 1);
  } else {
    return check_removed_record(count, &state, out_new);
  }
  return true;
}

static bool
check_removed_record(size_t* count, const ZiIdentityDatabaseState* state, bool* out_new) {
  ZiIdentityDatabaseRecord record = {0};
  EXPECT(zi_identity_database_record(s_workspace,
                                     ZI_IDENTITY_DATABASE_SIZE,
                                     &k_authority,
                                     0,
                                     &record) == ZI_STATUS_SUCCESS);
  EXPECT(state->record_count == 1 && state->issuer.user_high_water == 256);
  EXPECT((state->generation == 2 && record.state == ZI_IDENTITY_RECORD_DISABLED) ||
         (state->generation == 3 && record.state == ZI_IDENTITY_RECORD_TOMBSTONE));
  *out_new = (bool)(record.state == ZI_IDENTITY_RECORD_TOMBSTONE);
  return true;
}

static ZiStatus provision(ZiFsVolume* volume, ZiIdentityStore* store) {
  ZiStatus status = initialise_volume(volume);
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_identity_database_initialise(&k_authority, s_workspace, ZI_IDENTITY_DATABASE_SIZE);
  if (ZiFailed(status)) {
    return status;
  }
  ZiFsTransaction transaction = {0};
  status = ZiFsTransactionInitialise(&transaction,
                                     volume,
                                     s_workspace + ZI_IDENTITY_DATABASE_SIZE + ZI_FS_BLOCK_SIZE,
                                     ZI_FS_TRANSACTION_WORKSPACE_SIZE);
  if (ZiFailed(status)) {
    return status;
  }
  const ZiFsCreateRequest request = {sizeof(ZiFsCreateRequest),
                                     ZI_FS_CREATE_REQUEST_VERSION,
                                     0,
                                     STORE_TEST_PRIVATE_ID,
                                     0,
                                     {"Identity.db", 11},
                                     {s_workspace, ZI_IDENTITY_DATABASE_SIZE}};
  ZiFsCreateResult result = {0};
  status = ZiFsTransactionPrepareCreateFile(&transaction, &request, &result);
  if (ZiFailed(status)) {
    return status;
  }
  status = ZiFsTransactionCommit(&transaction);
  if (ZiFailed(status)) {
    return status;
  }
  *store = (ZiIdentityStore){sizeof(ZiIdentityStore),
                             ZI_IDENTITY_STORE_VERSION,
                             volume,
                             k_authority,
                             result.record_index,
                             result.file_id,
                             1,
                             0};
  return ZI_STATUS_SUCCESS;
}

static ZiStatus initialise_security(void) {
  const ZiSecurityId system = {ZI_SECURITY_AUTHORITY_SYSTEM, 1};
  const ZiAce entry = {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_FULL_CONTROL, system};
  const ZiAcl dacl = {sizeof(ZiAcl), ZI_ACL_VERSION, &entry, 1};
  const ZiSecurityDescriptor descriptor = {sizeof(ZiSecurityDescriptor),
                                           ZI_SECURITY_DESCRIPTOR_VERSION,
                                           system,
                                           {ZI_SECURITY_AUTHORITY_GROUP, 1},
                                           &dacl,
                                           0};
  ZiStatus status = ZiFsInitialiseSecurityTable(s_disk[70], ZI_FS_BLOCK_SIZE, 1);
  if (ZiFailed(status)) {
    return status;
  }
  return ZiFsAppendSecurityDescriptor(s_disk[70],
                                      ZI_FS_BLOCK_SIZE,
                                      STORE_TEST_PRIVATE_ID,
                                      ZI_FS_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT,
                                      &descriptor);
}

static ZiStatus initialise_volume(ZiFsVolume* volume) {
  zi_memory_zero(s_disk, sizeof s_disk);
  s_fail_operation = 0;
  s_operations = 0;
  ZiFsSuperblock superblock = {0};
  superblock.format_major = ZI_FS_FORMAT_MAJOR;
  superblock.format_minor = ZI_FS_FORMAT_MINOR;
  superblock.block_shift = ZI_FS_BLOCK_SHIFT;
  superblock.checksum_type = 1;
  superblock.incompatible_features = ZI_FS_FEATURE_INCOMPAT_JOURNAL_V1 |
                                     ZI_FS_FEATURE_INCOMPAT_SECURITY_V1 |
                                     ZI_FS_FEATURE_INCOMPAT_CLEAN_UNMOUNT_V1;
  zi_memory_copy(superblock.volume_uuid, k_authority.volume, 16);
  superblock.generation = 1;
  superblock.total_blocks = STORE_TEST_BLOCKS;
  superblock.record_table_start = 1;
  superblock.record_table_blocks = 2;
  superblock.allocation_bitmap_start = 3;
  superblock.allocation_bitmap_blocks = 1;
  superblock.journal_start = 4;
  superblock.journal_blocks = 66;
  superblock.security_table_start = 70;
  superblock.security_table_blocks = 1;
  superblock.directory_table_start = 71;
  superblock.directory_table_blocks = 1;
  superblock.backup_superblock = STORE_TEST_BLOCKS - 1u;
  superblock.volume_name_size = 4;
  zi_memory_copy(superblock.volume_name, "Test", 4);
  ZiStatus status = ZiFsEncodeSuperblock(&superblock, s_disk[0], ZI_FS_BLOCK_SIZE);
  if (ZiFailed(status)) {
    return status;
  }
  zi_memory_copy(s_disk[STORE_TEST_BLOCKS - 1u], s_disk[0], ZI_FS_BLOCK_SIZE);
  status = initialise_security();
  if (ZiFailed(status)) {
    return status;
  }
  const ZiFsFileRecord root = {.file_id = 1,
                               .parent_file_id = 1,
                               .security_id = STORE_TEST_PRIVATE_ID,
                               .directory_block = 71,
                               .file_type = ZI_FS_FILE_TYPE_DIRECTORY};
  status = ZiFsEncodeFileRecord(&root, s_disk[1], ZI_FS_FILE_RECORD_SIZE);
  if (ZiFailed(status)) {
    return status;
  }
  status = ZiFsInitialiseDirectoryBlock(s_disk[71], ZI_FS_BLOCK_SIZE, 1, 1);
  if (ZiFailed(status)) {
    return status;
  }
  for (uint64_t block = 0; block < STORE_TEST_BLOCKS; ++block) {
    if (block <= 71 || block == STORE_TEST_BLOCKS - 1u) {
      status = ZiFsAllocationBitSet(s_disk[3], ZI_FS_BLOCK_SIZE, block, true);
      if (ZiFailed(status)) {
        return status;
      }
    }
  }
  ZiFsJournalHeader journal = {.volume_generation = 1,
                               .record_capacity = 32,
                               .next_sequence = 1,
                               .next_transaction_id = 1};
  for (size_t index = 0; index < 2; ++index) {
    journal.header_sequence = index + 1u;
    status = ZiFsEncodeJournalHeader(&journal, s_disk[4 + index], ZI_FS_BLOCK_SIZE);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return mount(volume);
}

static ZiStatus mount(ZiFsVolume* volume) {
  ZiBlockDevice disk = device();
  ZiStatus status = ZiFsMountVolume(&disk, s_recovery, ZI_FS_BLOCK_SIZE, volume);
  if (status == ZI_STATUS_RECOVERY_REQUIRED) {
    ZiFsRecoveryReport report = {0};
    status = ZiFsRecoverVolume(volume, s_recovery, sizeof s_recovery, &report);
    if (ZiFailed(status)) {
      return status;
    }
    status = ZiFsMountVolume(&disk, s_recovery, ZI_FS_BLOCK_SIZE, volume);
  }
  return status;
}

static ZiBlockDevice device(void) {
  return (ZiBlockDevice){sizeof(ZiBlockDevice),
                         ZI_BLOCK_DEVICE_VERSION,
                         NULL,
                         ZI_FS_BLOCK_SIZE,
                         STORE_TEST_BLOCKS,
                         disk_read,
                         disk_flush,
                         ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED,
                         disk_write};
}

static ZiStatus
disk_read(void* context, uint64_t first, uint32_t blocks, void* output, size_t size) {
  (void)context;
  if (first >= STORE_TEST_BLOCKS || blocks > STORE_TEST_BLOCKS - first ||
      size != (size_t)blocks * ZI_FS_BLOCK_SIZE || output == NULL) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  if (first >= 72 && first < 81) {
    ++s_payload_reads;
  }
  zi_memory_copy(output, s_disk[first], size);
  return ZI_STATUS_SUCCESS;
}

static ZiStatus
disk_write(void* context, uint64_t first, uint32_t blocks, const void* input, size_t size) {
  (void)context;
  ++s_operations;
  if (s_operations == s_fail_operation) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  if (first >= STORE_TEST_BLOCKS || blocks > STORE_TEST_BLOCKS - first ||
      size != (size_t)blocks * ZI_FS_BLOCK_SIZE || input == NULL) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  zi_memory_copy(s_disk[first], input, size);
  return ZI_STATUS_SUCCESS;
}

static ZiStatus disk_flush(void* context) {
  (void)context;
  ++s_operations;
  return s_operations == s_fail_operation ? ZI_STATUS_DEVICE_ERROR : ZI_STATUS_SUCCESS;
}

static bool expect(size_t* count, bool condition, int line) {
  ++*count;
  if (!condition) {
    (void)fprintf_s(stderr, "Identity store test failed at line %d.\n", line);
  }
  return condition;
}
