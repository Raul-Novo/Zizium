// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "phase7_tests.h"
#include "zi/block.h"
#include "zi/byte_order.h"
#include "zi/path.h"
#include "zi/security.h"
#include "zi/zifs.h"
#include "zi/zifs_journal.h"
#include "zi/zifs_recovery.h"
#include "zi/zifs_security.h"
#include "zi/zifs_transaction.h"
#include "zizium/status.h"
#include "zizium/types.h"

static size_t s_assertions;

#define PHASE7_VOLUME_BLOCKS 128u
#define PHASE7_RECORD_TABLE_START 1u
#define PHASE7_BITMAP_BLOCK 3u
#define PHASE7_JOURNAL_START 4u
#define PHASE7_JOURNAL_BLOCKS 66u
#define PHASE7_SECURITY_BLOCK 70u
#define PHASE7_ROOT_DIRECTORY_BLOCK 71u
#define PHASE7_SOURCE_DIRECTORY_BLOCK 72u
#define PHASE7_TARGET_DIRECTORY_BLOCK 73u
#define PHASE7_CHILD_DIRECTORY_BLOCK 74u
#define PHASE7_FIRST_DATA_BLOCK 75u
#define PHASE7_ROOT_FILE_ID 1u
#define PHASE7_SOURCE_FILE_ID 2u
#define PHASE7_TARGET_FILE_ID 3u
#define PHASE7_CHILD_FILE_ID 4u
#define PHASE7_MOVED_FILE_ID 5u
#define PHASE7_OCCUPIED_FILE_ID 6u

typedef struct Phase7MemoryVolume {
  unsigned char* bytes;
  size_t size;
  size_t operation_count;
  size_t fail_operation;
  size_t write_count;
  size_t flush_count;
} Phase7MemoryVolume;

static unsigned char s_phase7_volume[PHASE7_VOLUME_BLOCKS][ZI_FS_BLOCK_SIZE];
static unsigned char s_phase7_snapshot[PHASE7_VOLUME_BLOCKS][ZI_FS_BLOCK_SIZE];
static unsigned char s_phase7_workspace[ZI_FS_TRANSACTION_WORKSPACE_SIZE];
static unsigned char s_phase7_second_workspace[ZI_FS_TRANSACTION_WORKSPACE_SIZE];
static unsigned char s_phase7_recovery_workspace[ZI_FS_RECOVERY_WORKSPACE_SIZE];
static unsigned char s_phase7_payload[5000];
static unsigned char
    s_phase7_large_payload[ZI_FS_TRANSACTION_MAXIMUM_DATA_BLOCKS * ZI_FS_BLOCK_SIZE];
static unsigned char s_phase7_large_readback[sizeof s_phase7_large_payload];
static unsigned char s_phase7_growth_expected[10000];
static Phase7MemoryVolume s_phase7_memory;

static bool phase7_assert(bool condition, const char* expression, int line) {
  ++s_assertions;
  if (!condition) {
    (void)fprintf_s(stderr, "Phase 7 assertion failed at line %d: %s\n", line, expression);
    return false;
  }
  return true;
}

#define PHASE7_ASSERT(expression)                                                                  \
  do {                                                                                             \
    if (!phase7_assert((expression), #expression, __LINE__)) {                                     \
      return false;                                                                                \
    }                                                                                              \
  } while (false)

static bool test_allocation_contract(void);
static bool test_journal_header_contract(void);
static bool test_journal_record_contract(void);
static bool test_in_memory_create_transaction(void);
static bool test_durable_commit_and_recovery(void);
static bool test_large_transaction_and_journal_wrap(void);
static bool test_move_transaction_contract(void);
static bool test_move_fault_boundaries(void);
static bool test_truncate_delete_contract(void);
static bool test_reclamation_fault_boundaries(void);
static bool test_write_growth_contract(void);
static bool test_directory_expansion_contract(void);
static ZiStatus phase7_memory_read(void* context,
                                   uint64_t first_block,
                                   uint32_t block_count,
                                   void* output,
                                   size_t output_size);
static ZiStatus phase7_memory_write(void* context,
                                    uint64_t first_block,
                                    uint32_t block_count,
                                    const void* input,
                                    size_t input_size);
static ZiStatus phase7_memory_flush(void* context);
static bool initialise_transaction_volume(ZiFsVolume* out_volume, bool writable);
static bool initialise_security_table(void);
static bool mount_transaction_volume(ZiFsVolume* out_volume, bool writable);
static bool enable_directory_extents(ZiFsVolume* out_volume, bool writable);
static bool initialise_move_fixture(ZiFsVolume* out_volume, bool writable);
static bool add_move_fixture(void);
static bool add_move_fixture_records(void);
static bool add_move_fixture_entries(void);
static bool find_transaction_image(const ZiFsTransaction* transaction,
                                   uint64_t target_block,
                                   ZiConstBuffer* out_image);
static bool fill_root_directory(void);
static bool
prepare_test_create(ZiFsVolume* volume, ZiFsTransaction* transaction, ZiFsCreateResult* out_result);
static bool verify_test_file(ZiFsVolume* volume, bool expected_present);
static bool prepare_named_create(ZiFsVolume* volume,
                                 ZiFsTransaction* transaction,
                                 ZiStringView name,
                                 ZiConstBuffer data,
                                 ZiFsCreateResult* out_result);
static bool prepare_named_create_in_workspace(ZiFsVolume* volume,
                                              ZiFsTransaction* transaction,
                                              void* workspace,
                                              size_t workspace_size,
                                              ZiStringView name,
                                              ZiConstBuffer data,
                                              ZiFsCreateResult* out_result);
static bool verify_named_file(ZiFsVolume* volume,
                              const char* path_text,
                              size_t path_size,
                              ZiConstBuffer expected_data,
                              bool expected_present);
static bool prepare_move(ZiFsVolume* volume,
                         ZiFsTransaction* transaction,
                         uint64_t source_parent_record_index,
                         ZiStringView source_name,
                         uint64_t target_parent_record_index,
                         ZiStringView target_name,
                         ZiFsMoveResult* out_result);
static bool recover_failed_transaction(const ZiBlockDevice* device, ZiFsVolume* out_volume);
static bool prepare_truncate(ZiFsVolume* volume,
                             ZiFsTransaction* transaction,
                             uint64_t new_size,
                             ZiFsTruncateResult* out_result);
static bool prepare_delete(ZiFsVolume* volume,
                           ZiFsTransaction* transaction,
                           ZiStringView name,
                           ZiFsDeleteResult* out_result);
static bool
query_allocation_bit(const ZiFsVolume* volume, uint64_t block_number, bool* out_allocated);

bool phase7_zifs_wire_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  s_assertions = 0;
  bool result = test_allocation_contract();
  if (result) {
    result = test_journal_header_contract();
  }
  if (result) {
    result = test_journal_record_contract();
  }
  if (result) {
    result = test_in_memory_create_transaction();
  }
  if (result) {
    result = test_durable_commit_and_recovery();
  }
  if (result) {
    result = test_large_transaction_and_journal_wrap();
  }
  if (result) {
    result = test_move_transaction_contract();
  }
  if (result) {
    result = test_move_fault_boundaries();
  }
  if (result) {
    result = test_truncate_delete_contract();
  }
  if (result) {
    result = test_reclamation_fault_boundaries();
  }
  if (result) {
    result = test_write_growth_contract();
  }
  if (result) {
    result = test_directory_expansion_contract();
  }
  *out_assertion_count = s_assertions;
  return result;
}

// The assertion helper deliberately contributes one branch per checked contract.
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static bool test_allocation_contract(void) {
  uint64_t bitmap_blocks = 0;
  PHASE7_ASSERT(ZiFsAllocationBitmapBlockCount(1, &bitmap_blocks) == ZI_STATUS_SUCCESS &&
                bitmap_blocks == 1);
  PHASE7_ASSERT(ZiFsAllocationBitmapBlockCount(UINT64_C(32768), &bitmap_blocks) ==
                    ZI_STATUS_SUCCESS &&
                bitmap_blocks == 1);
  PHASE7_ASSERT(ZiFsAllocationBitmapBlockCount(UINT64_C(32769), &bitmap_blocks) ==
                    ZI_STATUS_SUCCESS &&
                bitmap_blocks == 2);
  PHASE7_ASSERT(ZiFsAllocationBitmapBlockCount(UINT64_MAX, &bitmap_blocks) == ZI_STATUS_SUCCESS &&
                bitmap_blocks == UINT64_C(562949953421312));
  PHASE7_ASSERT(ZiFsAllocationBitmapBlockCount(0, &bitmap_blocks) == ZI_STATUS_INVALID_ARGUMENT);

  unsigned char bitmap[ZI_FS_BLOCK_SIZE * 2u] = {0};
  bool is_allocated = true;
  PHASE7_ASSERT(
      ZiSucceeded(ZiFsAllocationBitQuery(bitmap, sizeof bitmap, UINT64_C(32768), &is_allocated)) &&
      !is_allocated);
  PHASE7_ASSERT(ZiSucceeded(ZiFsAllocationBitSet(bitmap, sizeof bitmap, UINT64_C(32768), true)));
  PHASE7_ASSERT(bitmap[ZI_FS_BLOCK_SIZE] == UINT8_C(1));
  PHASE7_ASSERT(
      ZiSucceeded(ZiFsAllocationBitQuery(bitmap, sizeof bitmap, UINT64_C(32768), &is_allocated)) &&
      is_allocated);
  PHASE7_ASSERT(ZiSucceeded(ZiFsAllocationBitSet(bitmap, sizeof bitmap, UINT64_C(32768), false)));
  PHASE7_ASSERT(bitmap[ZI_FS_BLOCK_SIZE] == UINT8_C(0));
  PHASE7_ASSERT(
      ZiFsAllocationBitQuery(bitmap, sizeof bitmap, (uint64_t)sizeof bitmap * 8u, &is_allocated) ==
      ZI_STATUS_INVALID_ARGUMENT);

  uint64_t capacity = 0;
  PHASE7_ASSERT(ZiFsJournalRecordCapacity(66, &capacity) == ZI_STATUS_SUCCESS && capacity == 32);
  PHASE7_ASSERT(ZiFsJournalRecordCapacity(2, &capacity) == ZI_STATUS_INVALID_ARGUMENT);
  PHASE7_ASSERT(ZiFsJournalRecordCapacity(5, &capacity) == ZI_STATUS_INVALID_ARGUMENT);
  uint64_t block_number = 0;
  PHASE7_ASSERT(ZiFsJournalRecordBlock(10, 32, 31, &block_number) == ZI_STATUS_SUCCESS &&
                block_number == 74);
  PHASE7_ASSERT(ZiFsJournalRecordBlock(10, 32, 32, &block_number) == ZI_STATUS_INVALID_ARGUMENT);
  PHASE7_ASSERT(ZiFsJournalRecordBlock(UINT64_MAX, 1, 0, &block_number) == ZI_STATUS_OUT_OF_BOUNDS);
  uint64_t record_index = 0;
  PHASE7_ASSERT(ZiFsJournalAdvanceRecord(32, 31, 1, &record_index) == ZI_STATUS_SUCCESS &&
                record_index == 0);
  PHASE7_ASSERT(ZiFsJournalAdvanceRecord(32, 30, 35, &record_index) == ZI_STATUS_SUCCESS &&
                record_index == 1);
  PHASE7_ASSERT(ZiFsJournalAdvanceRecord(0, 0, 1, &record_index) == ZI_STATUS_INVALID_ARGUMENT);
  PHASE7_ASSERT(ZiFsJournalAdvanceRecord(32, 32, 1, &record_index) == ZI_STATUS_INVALID_ARGUMENT);
  return true;
}

// The assertion helper deliberately contributes one branch per checked wire invariant.
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static bool test_journal_header_contract(void) {
  ZiFsJournalHeader header = {0};
  header.header_sequence = 7;
  header.volume_generation = 3;
  header.record_capacity = 32;
  header.head_record = 5;
  header.tail_record = 2;
  header.next_sequence = 14;
  header.next_transaction_id = 4;
  header.last_committed_transaction = 3;
  header.last_checkpoint_transaction = 2;
  unsigned char encoded[ZI_FS_BLOCK_SIZE] = {0};
  PHASE7_ASSERT(ZiFsEncodeJournalHeader(&header, encoded, sizeof encoded) == ZI_STATUS_SUCCESS);
  PHASE7_ASSERT(zi_read_u16_le(encoded + 4) == ZI_FS_JOURNAL_VERSION &&
                zi_read_u16_le(encoded + 6) == ZI_FS_JOURNAL_HEADER_SIZE &&
                zi_read_u32_le(encoded + 24) == ZI_FS_JOURNAL_RECORD_BLOCKS);
  ZiFsJournalHeader decoded = {0};
  PHASE7_ASSERT(ZiFsDecodeJournalHeader(encoded, sizeof encoded, &decoded) == ZI_STATUS_SUCCESS &&
                decoded.header_sequence == header.header_sequence &&
                decoded.volume_generation == header.volume_generation &&
                decoded.record_capacity == header.record_capacity &&
                decoded.head_record == header.head_record &&
                decoded.tail_record == header.tail_record &&
                decoded.next_sequence == header.next_sequence &&
                decoded.next_transaction_id == header.next_transaction_id &&
                decoded.last_committed_transaction == header.last_committed_transaction &&
                decoded.last_checkpoint_transaction == header.last_checkpoint_transaction);
  uint64_t occupied_records = 0;
  uint64_t available_records = 0;
  PHASE7_ASSERT(ZiFsJournalQuerySpace(&decoded, &occupied_records, &available_records) ==
                    ZI_STATUS_SUCCESS &&
                occupied_records == 3 && available_records == 28);

  encoded[72] ^= UINT8_C(1);
  PHASE7_ASSERT(ZiFsDecodeJournalHeader(encoded, sizeof encoded, &decoded) ==
                ZI_STATUS_CHECKSUM_MISMATCH);
  encoded[72] ^= UINT8_C(1);
  header.last_checkpoint_transaction = 4;
  PHASE7_ASSERT(ZiFsEncodeJournalHeader(&header, encoded, sizeof encoded) ==
                ZI_STATUS_INVALID_ARGUMENT);
  header.last_checkpoint_transaction = 2;
  header.head_record = header.tail_record;
  PHASE7_ASSERT(ZiFsEncodeJournalHeader(&header, encoded, sizeof encoded) ==
                ZI_STATUS_INVALID_ARGUMENT);
  header.last_checkpoint_transaction = header.last_committed_transaction;
  PHASE7_ASSERT(ZiFsEncodeJournalHeader(&header, encoded, sizeof encoded) == ZI_STATUS_SUCCESS);
  PHASE7_ASSERT(ZiFsJournalQuerySpace(&header, &occupied_records, &available_records) ==
                    ZI_STATUS_SUCCESS &&
                occupied_records == 0 && available_records == 31);
  header.last_checkpoint_transaction = 2;
  header.head_record = header.record_capacity;
  PHASE7_ASSERT(ZiFsEncodeJournalHeader(&header, encoded, sizeof encoded) ==
                ZI_STATUS_INVALID_ARGUMENT);
  PHASE7_ASSERT(ZiFsDecodeJournalHeader(encoded, ZI_FS_JOURNAL_HEADER_SIZE, &decoded) ==
                ZI_STATUS_INVALID_ARGUMENT);
  return true;
}

// The assertion helper deliberately contributes one branch per checked contract.
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static bool test_journal_record_contract(void) {
  unsigned char payload[ZI_FS_BLOCK_SIZE] = {0};
  for (size_t index = 0; index < sizeof payload; ++index) {
    payload[index] = (unsigned char)(index ^ (index >> 8u));
  }
  ZiFsJournalRecord image = {0};
  image.record_type = ZI_FS_JOURNAL_RECORD_BLOCK_IMAGE;
  image.transaction_id = 9;
  image.sequence = 101;
  image.target_block = 77;
  image.source_generation = 5;
  image.target_generation = 6;
  image.payload = (ZiConstBuffer){payload, sizeof payload};
  unsigned char encoded[ZI_FS_JOURNAL_RECORD_SIZE] = {0};
  PHASE7_ASSERT(ZiFsEncodeJournalRecord(&image, encoded, sizeof encoded) == ZI_STATUS_SUCCESS);
  ZiFsJournalRecord decoded = {0};
  PHASE7_ASSERT(ZiFsDecodeJournalRecord(encoded, sizeof encoded, &decoded) == ZI_STATUS_SUCCESS &&
                decoded.record_type == image.record_type &&
                decoded.transaction_id == image.transaction_id &&
                decoded.sequence == image.sequence && decoded.target_block == image.target_block &&
                decoded.payload.size == sizeof payload &&
                zi_memory_compare(decoded.payload.data, payload, sizeof payload) == 0);

  uint32_t checksum = 0;
  PHASE7_ASSERT(ZiFsJournalExtendTransactionChecksum(0, &decoded, &checksum) == ZI_STATUS_SUCCESS &&
                checksum != 0);
  uint32_t repeated_checksum = 0;
  PHASE7_ASSERT(ZiFsJournalExtendTransactionChecksum(0, &decoded, &repeated_checksum) ==
                    ZI_STATUS_SUCCESS &&
                repeated_checksum == checksum);

  encoded[ZI_FS_JOURNAL_RECORD_HEADER_SIZE + 99u] ^= UINT8_C(1);
  PHASE7_ASSERT(ZiFsDecodeJournalRecord(encoded, sizeof encoded, &decoded) ==
                ZI_STATUS_CHECKSUM_MISMATCH);
  encoded[ZI_FS_JOURNAL_RECORD_HEADER_SIZE + 99u] ^= UINT8_C(1);

  ZiFsJournalRecord begin = {0};
  begin.record_type = ZI_FS_JOURNAL_RECORD_BEGIN;
  begin.transaction_id = image.transaction_id;
  begin.sequence = 100;
  begin.target_block = ZI_FS_JOURNAL_TARGET_NONE;
  begin.source_generation = 5;
  begin.target_generation = 6;
  begin.image_count = 1;
  PHASE7_ASSERT(ZiFsEncodeJournalRecord(&begin, encoded, sizeof encoded) == ZI_STATUS_SUCCESS);
  PHASE7_ASSERT(ZiFsDecodeJournalRecord(encoded, sizeof encoded, &decoded) == ZI_STATUS_SUCCESS &&
                decoded.record_type == ZI_FS_JOURNAL_RECORD_BEGIN && decoded.payload.size == 0);

  ZiFsJournalRecord commit = begin;
  commit.record_type = ZI_FS_JOURNAL_RECORD_COMMIT;
  commit.sequence = 102;
  commit.transaction_checksum = checksum;
  PHASE7_ASSERT(ZiFsEncodeJournalRecord(&commit, encoded, sizeof encoded) == ZI_STATUS_SUCCESS);
  PHASE7_ASSERT(ZiFsDecodeJournalRecord(encoded, sizeof encoded, &decoded) == ZI_STATUS_SUCCESS &&
                decoded.transaction_checksum == checksum);

  commit.transaction_checksum = 0;
  PHASE7_ASSERT(ZiFsEncodeJournalRecord(&commit, encoded, sizeof encoded) ==
                ZI_STATUS_INVALID_ARGUMENT);
  image.payload.size = ZI_FS_BLOCK_SIZE - 1u;
  PHASE7_ASSERT(ZiFsEncodeJournalRecord(&image, encoded, sizeof encoded) ==
                ZI_STATUS_INVALID_ARGUMENT);
  image.payload.size = ZI_FS_BLOCK_SIZE;
  image.target_generation = image.source_generation;
  PHASE7_ASSERT(ZiFsEncodeJournalRecord(&image, encoded, sizeof encoded) ==
                ZI_STATUS_INVALID_ARGUMENT);
  PHASE7_ASSERT(ZiFsDecodeJournalRecord(encoded, ZI_FS_JOURNAL_RECORD_SIZE - 1u, &decoded) ==
                ZI_STATUS_INVALID_ARGUMENT);
  return true;
}

// The test keeps staged metadata inspection and all failure paths together as one transaction.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static bool test_in_memory_create_transaction(void) {
  ZiFsVolume volume = {0};
  PHASE7_ASSERT(initialise_transaction_volume(&volume, false));
  zi_memory_copy(s_phase7_snapshot, s_phase7_volume, sizeof s_phase7_snapshot);
  for (size_t index = 0; index < sizeof s_phase7_payload; ++index) {
    s_phase7_payload[index] = (unsigned char)(index ^ (index >> 8u));
  }

  ZiFsTransaction transaction = {0};
  PHASE7_ASSERT(ZiFsTransactionInitialise(&transaction,
                                          &volume,
                                          s_phase7_workspace,
                                          ZI_FS_TRANSACTION_MINIMUM_WORKSPACE_SIZE - 1u) ==
                ZI_STATUS_INVALID_ARGUMENT);
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionInitialise(&transaction,
                                                      &volume,
                                                      s_phase7_workspace,
                                                      ZI_FS_TRANSACTION_MINIMUM_WORKSPACE_SIZE)) &&
                transaction.block_image_capacity == ZI_FS_TRANSACTION_MINIMUM_BLOCK_IMAGES);
  ZiFsCreateRequest request = {0};
  request.struct_size = sizeof request;
  request.version = ZI_FS_CREATE_REQUEST_VERSION;
  request.parent_record_index = 0;
  request.security_id = 1;
  request.timestamp = UINT64_C(21000000);
  request.name = (ZiStringView){"First Light.txt", sizeof "First Light.txt" - 1u};
  request.data = (ZiConstBuffer){s_phase7_payload, sizeof s_phase7_payload};
  ZiFsCreateResult result = {0};
  request.security_id = 99;
  PHASE7_ASSERT(
      ZiFsTransactionPrepareCreateFile(&transaction, &request, &result) == ZI_STATUS_NOT_FOUND &&
      transaction.block_image_count == 0 && transaction.state == ZI_FS_TRANSACTION_STATE_READY);
  request.security_id = 1;
  PHASE7_ASSERT(ZiFsTransactionPrepareCreateFile(&transaction, &request, &result) ==
                    ZI_STATUS_BUFFER_TOO_SMALL &&
                transaction.block_image_count == 0 &&
                transaction.state == ZI_FS_TRANSACTION_STATE_READY);
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionInitialise(&transaction,
                                                      &volume,
                                                      s_phase7_workspace,
                                                      sizeof s_phase7_workspace)) &&
                transaction.block_image_capacity == ZI_FS_TRANSACTION_MAXIMUM_BLOCK_IMAGES);
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionPrepareCreateFile(&transaction, &request, &result)));
  PHASE7_ASSERT(transaction.state == ZI_FS_TRANSACTION_STATE_PREPARED &&
                transaction.block_image_count == 5 && result.file_id == 2 &&
                result.record_index == 1 && result.first_data_block == PHASE7_FIRST_DATA_BLOCK &&
                result.data_block_count == 2);
  PHASE7_ASSERT(zi_memory_compare(s_phase7_snapshot, s_phase7_volume, sizeof s_phase7_volume) == 0);

  ZiConstBuffer image = {0};
  PHASE7_ASSERT(find_transaction_image(&transaction, PHASE7_BITMAP_BLOCK, &image));
  bool allocated = false;
  PHASE7_ASSERT(
      ZiSucceeded(
          ZiFsAllocationBitQuery(image.data, image.size, PHASE7_FIRST_DATA_BLOCK, &allocated)) &&
      allocated);
  PHASE7_ASSERT(ZiSucceeded(ZiFsAllocationBitQuery(image.data,
                                                   image.size,
                                                   PHASE7_FIRST_DATA_BLOCK + 1u,
                                                   &allocated)) &&
                allocated);

  PHASE7_ASSERT(find_transaction_image(&transaction, PHASE7_RECORD_TABLE_START, &image));
  ZiFsFileRecord record = {0};
  PHASE7_ASSERT(
      ZiSucceeded(ZiFsDecodeFileRecord((const unsigned char*)image.data + ZI_FS_FILE_RECORD_SIZE,
                                       ZI_FS_FILE_RECORD_SIZE,
                                       &record)));
  PHASE7_ASSERT(record.file_id == result.file_id && record.parent_file_id == 1 &&
                record.file_size == sizeof s_phase7_payload && record.extent_count == 1 &&
                record.extents[0].physical_block == PHASE7_FIRST_DATA_BLOCK &&
                record.extents[0].block_count == 2 && record.security_id == 1);

  PHASE7_ASSERT(find_transaction_image(&transaction, PHASE7_ROOT_DIRECTORY_BLOCK, &image));
  ZiFsDirectoryEntry entry = {0};
  PHASE7_ASSERT(ZiSucceeded(ZiFsFindDirectoryEntry(image.data, image.size, request.name, &entry)) &&
                entry.file_id == result.file_id && entry.record_index == result.record_index);
  PHASE7_ASSERT(find_transaction_image(&transaction, PHASE7_FIRST_DATA_BLOCK, &image) &&
                zi_memory_compare(image.data, s_phase7_payload, ZI_FS_BLOCK_SIZE) == 0);
  PHASE7_ASSERT(find_transaction_image(&transaction, PHASE7_FIRST_DATA_BLOCK + 1u, &image) &&
                zi_memory_compare(image.data,
                                  s_phase7_payload + ZI_FS_BLOCK_SIZE,
                                  sizeof s_phase7_payload - ZI_FS_BLOCK_SIZE) == 0);
  const unsigned char* second_data = image.data;
  PHASE7_ASSERT(second_data[sizeof s_phase7_payload - ZI_FS_BLOCK_SIZE] == 0);
  PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_READ_ONLY_FILESYSTEM &&
                transaction.state == ZI_FS_TRANSACTION_STATE_PREPARED);
  PHASE7_ASSERT(ZiFsTransactionPrepareCreateFile(&transaction, &request, &result) ==
                ZI_STATUS_INVALID_STATE);
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionReset(&transaction)) &&
                transaction.block_image_count == 0 &&
                transaction.state == ZI_FS_TRANSACTION_STATE_READY);

  request.name = (ZiStringView){"Existing", sizeof "Existing" - 1u};
  PHASE7_ASSERT(ZiFsTransactionPrepareCreateFile(&transaction, &request, &result) ==
                    ZI_STATUS_ALREADY_EXISTS &&
                transaction.block_image_count == 0);
  const char invalid_utf8[] = {(char)0xc0, (char)0x80};
  request.name = (ZiStringView){invalid_utf8, sizeof invalid_utf8};
  PHASE7_ASSERT(ZiFsTransactionPrepareCreateFile(&transaction, &request, &result) ==
                ZI_STATUS_INVALID_ENCODING);
  request.name = (ZiStringView){"Bad/Name", sizeof "Bad/Name" - 1u};
  PHASE7_ASSERT(ZiFsTransactionPrepareCreateFile(&transaction, &request, &result) ==
                ZI_STATUS_INVALID_PATH);
  request.name = (ZiStringView){"Too Large", sizeof "Too Large" - 1u};
  request.data.size = ((size_t)ZI_FS_TRANSACTION_MAXIMUM_DATA_BLOCKS * ZI_FS_BLOCK_SIZE) + 1u;
  PHASE7_ASSERT(ZiFsTransactionPrepareCreateFile(&transaction, &request, &result) ==
                ZI_STATUS_INVALID_ARGUMENT);

  PHASE7_ASSERT(initialise_transaction_volume(&volume, false));
  for (uint64_t block = 0; block < PHASE7_VOLUME_BLOCKS; ++block) {
    PHASE7_ASSERT(ZiSucceeded(
        ZiFsAllocationBitSet(s_phase7_volume[PHASE7_BITMAP_BLOCK], ZI_FS_BLOCK_SIZE, block, true)));
  }
  zi_memory_copy(s_phase7_snapshot, s_phase7_volume, sizeof s_phase7_snapshot);
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionInitialise(&transaction,
                                                      &volume,
                                                      s_phase7_workspace,
                                                      sizeof s_phase7_workspace)));
  request.name = (ZiStringView){"No Space", sizeof "No Space" - 1u};
  request.data = (ZiConstBuffer){s_phase7_payload, 1};
  PHASE7_ASSERT(ZiFsTransactionPrepareCreateFile(&transaction, &request, &result) ==
                    ZI_STATUS_VOLUME_FULL &&
                transaction.block_image_count == 0 &&
                zi_memory_compare(s_phase7_snapshot, s_phase7_volume, sizeof s_phase7_volume) == 0);

  PHASE7_ASSERT(initialise_transaction_volume(&volume, false));
  PHASE7_ASSERT(fill_root_directory());
  zi_memory_copy(s_phase7_snapshot, s_phase7_volume, sizeof s_phase7_snapshot);
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionInitialise(&transaction,
                                                      &volume,
                                                      s_phase7_workspace,
                                                      sizeof s_phase7_workspace)));
  char long_name[ZI_FS_MAX_DIRECTORY_NAME_BYTES];
  for (size_t index = 0; index < sizeof long_name; ++index) {
    long_name[index] = 'A';
  }
  request.name = (ZiStringView){long_name, sizeof long_name};
  request.data = (ZiConstBuffer){s_phase7_payload, 1};
  PHASE7_ASSERT(ZiFsTransactionPrepareCreateFile(&transaction, &request, &result) ==
                    ZI_STATUS_BUFFER_TOO_SMALL &&
                transaction.block_image_count == 0 &&
                transaction.state == ZI_FS_TRANSACTION_STATE_READY &&
                zi_memory_compare(s_phase7_snapshot, s_phase7_volume, sizeof s_phase7_volume) == 0);
  return true;
}

static ZiStatus phase7_memory_read(void* context,
                                   uint64_t first_block,
                                   uint32_t block_count,
                                   void* output,
                                   size_t output_size) {
  if (context == NULL || output == NULL || block_count == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  Phase7MemoryVolume* memory = context;
  if (first_block > SIZE_MAX / ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  size_t offset = (size_t)first_block * ZI_FS_BLOCK_SIZE;
  size_t byte_count = (size_t)block_count * ZI_FS_BLOCK_SIZE;
  if (offset > memory->size || byte_count > memory->size - offset || output_size < byte_count) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  zi_memory_copy(output, memory->bytes + offset, byte_count);
  return ZI_STATUS_SUCCESS;
}

static ZiStatus phase7_memory_write(void* context,
                                    uint64_t first_block,
                                    uint32_t block_count,
                                    const void* input,
                                    size_t input_size) {
  if (context == NULL || input == NULL || block_count == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  Phase7MemoryVolume* memory = context;
  if (first_block > SIZE_MAX / ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  size_t offset = (size_t)first_block * ZI_FS_BLOCK_SIZE;
  size_t byte_count = (size_t)block_count * ZI_FS_BLOCK_SIZE;
  if (offset > memory->size || byte_count > memory->size - offset || input_size != byte_count) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  ++memory->operation_count;
  if (memory->fail_operation != 0 && memory->operation_count == memory->fail_operation) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  zi_memory_copy(memory->bytes + offset, input, byte_count);
  ++memory->write_count;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus phase7_memory_flush(void* context) {
  if (context == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  Phase7MemoryVolume* memory = context;
  ++memory->operation_count;
  if (memory->fail_operation != 0 && memory->operation_count == memory->fail_operation) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  ++memory->flush_count;
  return ZI_STATUS_SUCCESS;
}

static bool initialise_transaction_volume(ZiFsVolume* out_volume, bool writable) {
  zi_memory_zero(s_phase7_volume, sizeof s_phase7_volume);
  ZiFsSuperblock superblock = {0};
  superblock.format_major = ZI_FS_FORMAT_MAJOR;
  superblock.format_minor = ZI_FS_FORMAT_MINOR;
  superblock.block_shift = ZI_FS_BLOCK_SHIFT;
  superblock.checksum_type = 1;
  superblock.incompatible_features =
      ZI_FS_FEATURE_INCOMPAT_JOURNAL_V1 | ZI_FS_FEATURE_INCOMPAT_SECURITY_V1;
  superblock.generation = 1;
  superblock.total_blocks = PHASE7_VOLUME_BLOCKS;
  superblock.root_record_index = 0;
  superblock.record_table_start = PHASE7_RECORD_TABLE_START;
  superblock.record_table_blocks = 2;
  superblock.allocation_bitmap_start = PHASE7_BITMAP_BLOCK;
  superblock.allocation_bitmap_blocks = 1;
  superblock.journal_start = PHASE7_JOURNAL_START;
  superblock.journal_blocks = PHASE7_JOURNAL_BLOCKS;
  superblock.security_table_start = PHASE7_SECURITY_BLOCK;
  superblock.security_table_blocks = 1;
  superblock.directory_table_start = PHASE7_ROOT_DIRECTORY_BLOCK;
  superblock.directory_table_blocks = 4;
  superblock.backup_superblock = PHASE7_VOLUME_BLOCKS - 1u;
  superblock.volume_name_size = 6;
  zi_memory_copy(superblock.volume_name, "Zizium", superblock.volume_name_size);
  if (ZiFailed(ZiFsEncodeSuperblock(&superblock, s_phase7_volume[0], ZI_FS_BLOCK_SIZE))) {
    return false;
  }
  zi_memory_copy(s_phase7_volume[PHASE7_VOLUME_BLOCKS - 1u], s_phase7_volume[0], ZI_FS_BLOCK_SIZE);
  if (!initialise_security_table()) {
    return false;
  }

  ZiFsFileRecord root = {0};
  root.file_id = 1;
  root.parent_file_id = 1;
  root.file_type = ZI_FS_FILE_TYPE_DIRECTORY;
  root.security_id = 1;
  root.directory_block = PHASE7_ROOT_DIRECTORY_BLOCK;
  if (ZiFailed(ZiFsEncodeFileRecord(&root,
                                    s_phase7_volume[PHASE7_RECORD_TABLE_START],
                                    ZI_FS_FILE_RECORD_SIZE)) ||
      ZiFailed(ZiFsInitialiseDirectoryBlock(s_phase7_volume[PHASE7_ROOT_DIRECTORY_BLOCK],
                                            ZI_FS_BLOCK_SIZE,
                                            root.file_id,
                                            superblock.generation))) {
    return false;
  }
  ZiFsDirectoryEntry existing = {
      root.file_id,
      0,
      ZI_FS_FILE_TYPE_DIRECTORY,
      0,
      {"Existing", sizeof "Existing" - 1u},
  };
  if (ZiFailed(ZiFsAddDirectoryEntry(s_phase7_volume[PHASE7_ROOT_DIRECTORY_BLOCK],
                                     ZI_FS_BLOCK_SIZE,
                                     &existing))) {
    return false;
  }

  for (uint64_t block = 0; block <= PHASE7_CHILD_DIRECTORY_BLOCK; ++block) {
    if (ZiFailed(ZiFsAllocationBitSet(s_phase7_volume[PHASE7_BITMAP_BLOCK],
                                      ZI_FS_BLOCK_SIZE,
                                      block,
                                      true))) {
      return false;
    }
  }
  if (ZiFailed(ZiFsAllocationBitSet(s_phase7_volume[PHASE7_BITMAP_BLOCK],
                                    ZI_FS_BLOCK_SIZE,
                                    PHASE7_VOLUME_BLOCKS - 1u,
                                    true))) {
    return false;
  }

  ZiFsJournalHeader journal = {0};
  journal.volume_generation = 1;
  journal.record_capacity = 32;
  journal.next_sequence = 1;
  journal.next_transaction_id = 1;
  for (uint64_t index = 0; index < ZI_FS_JOURNAL_HEADER_COPIES; ++index) {
    journal.header_sequence = index + 1u;
    if (ZiFailed(ZiFsEncodeJournalHeader(&journal,
                                         s_phase7_volume[PHASE7_JOURNAL_START + index],
                                         ZI_FS_BLOCK_SIZE))) {
      return false;
    }
  }

  return mount_transaction_volume(out_volume, writable);
}

static bool initialise_security_table(void) {
  const ZiSecurityId owner = {ZI_SECURITY_AUTHORITY_USER, 21};
  const ZiSecurityId group = {ZI_SECURITY_AUTHORITY_GROUP, 7};
  const ZiAce entries[] = {{ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_FULL_CONTROL, owner}};
  const ZiAcl dacl = {sizeof(ZiAcl), ZI_ACL_VERSION, entries, 1};
  const ZiSecurityDescriptor descriptor = {
      sizeof(ZiSecurityDescriptor),
      ZI_SECURITY_DESCRIPTOR_VERSION,
      owner,
      group,
      &dacl,
      ZI_SECURITY_DESCRIPTOR_CONTROL_NONE,
  };
  return (
      bool)(ZiSucceeded(ZiFsInitialiseSecurityTable(s_phase7_volume[PHASE7_SECURITY_BLOCK],
                                                    ZI_FS_BLOCK_SIZE,
                                                    1)) &&
            ZiSucceeded(ZiFsAppendSecurityDescriptor(s_phase7_volume[PHASE7_SECURITY_BLOCK],
                                                     ZI_FS_BLOCK_SIZE,
                                                     1,
                                                     ZI_FS_SECURITY_DESCRIPTOR_FLAG_DACL_PRESENT,
                                                     &descriptor)));
}

static bool mount_transaction_volume(ZiFsVolume* out_volume, bool writable) {
  s_phase7_memory.bytes = &s_phase7_volume[0][0];
  s_phase7_memory.size = sizeof s_phase7_volume;
  s_phase7_memory.operation_count = 0;
  s_phase7_memory.fail_operation = 0;
  s_phase7_memory.write_count = 0;
  s_phase7_memory.flush_count = 0;
  ZiBlockDevice device = {
      sizeof(ZiBlockDevice),
      ZI_BLOCK_DEVICE_VERSION,
      &s_phase7_memory,
      ZI_FS_BLOCK_SIZE,
      PHASE7_VOLUME_BLOCKS,
      phase7_memory_read,
      NULL,
      ZI_BLOCK_DEVICE_READ_ONLY,
      NULL,
  };
  if (writable) {
    device.flush = phase7_memory_flush;
    device.flags = ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED;
    device.write_blocks = phase7_memory_write;
  }
  unsigned char scratch[ZI_FS_BLOCK_SIZE] = {0};
  return ZiSucceeded(ZiFsMountVolume(&device, scratch, sizeof scratch, out_volume));
}

static bool enable_directory_extents(ZiFsVolume* out_volume, bool writable) {
  if (out_volume == NULL) {
    return false;
  }
  ZiFsSuperblock superblock = out_volume->superblock;
  superblock.incompatible_features |= ZI_FS_FEATURE_INCOMPAT_DIRECTORY_EXTENTS_V1;
  if (ZiFailed(ZiFsEncodeSuperblock(&superblock, s_phase7_volume[0], ZI_FS_BLOCK_SIZE))) {
    return false;
  }
  zi_memory_copy(s_phase7_volume[PHASE7_VOLUME_BLOCKS - 1u], s_phase7_volume[0], ZI_FS_BLOCK_SIZE);
  return mount_transaction_volume(out_volume, writable);
}

static bool initialise_move_fixture(ZiFsVolume* out_volume, bool writable) {
  for (size_t index = 0; index < sizeof s_phase7_payload; ++index) {
    s_phase7_payload[index] = (unsigned char)(index ^ (index >> 8u) ^ UINT8_C(0xa5));
  }
  return (bool)(initialise_transaction_volume(out_volume, writable) && add_move_fixture() &&
                mount_transaction_volume(out_volume, writable));
}

static bool add_move_fixture(void) {
  if (!add_move_fixture_records() || !add_move_fixture_entries()) {
    return false;
  }
  zi_memory_copy(s_phase7_volume[PHASE7_FIRST_DATA_BLOCK], s_phase7_payload, ZI_FS_BLOCK_SIZE);
  zi_memory_copy(s_phase7_volume[PHASE7_FIRST_DATA_BLOCK + 1u],
                 s_phase7_payload + ZI_FS_BLOCK_SIZE,
                 sizeof s_phase7_payload - ZI_FS_BLOCK_SIZE);
  return true;
}

static bool add_move_fixture_records(void) {
  ZiFsFileRecord source = {0};
  source.file_id = PHASE7_SOURCE_FILE_ID;
  source.parent_file_id = PHASE7_ROOT_FILE_ID;
  source.file_type = ZI_FS_FILE_TYPE_DIRECTORY;
  source.security_id = 1;
  source.directory_block = PHASE7_SOURCE_DIRECTORY_BLOCK;
  ZiFsFileRecord target = source;
  target.file_id = PHASE7_TARGET_FILE_ID;
  target.directory_block = PHASE7_TARGET_DIRECTORY_BLOCK;
  ZiFsFileRecord child = source;
  child.file_id = PHASE7_CHILD_FILE_ID;
  child.parent_file_id = source.file_id;
  child.directory_block = PHASE7_CHILD_DIRECTORY_BLOCK;
  ZiFsFileRecord moved_file = {0};
  moved_file.file_id = PHASE7_MOVED_FILE_ID;
  moved_file.parent_file_id = source.file_id;
  moved_file.file_type = ZI_FS_FILE_TYPE_REGULAR;
  moved_file.file_size = sizeof s_phase7_payload;
  moved_file.allocated_size = UINT64_C(2) * ZI_FS_BLOCK_SIZE;
  moved_file.security_id = 1;
  moved_file.created_time = UINT64_C(20000000);
  moved_file.modified_time = UINT64_C(20000000);
  moved_file.changed_time = UINT64_C(20000000);
  moved_file.accessed_time = UINT64_C(20000000);
  moved_file.extent_count = 1;
  moved_file.extents[0].physical_block = PHASE7_FIRST_DATA_BLOCK;
  moved_file.extents[0].block_count = 2;
  ZiFsFileRecord occupied = {0};
  occupied.file_id = PHASE7_OCCUPIED_FILE_ID;
  occupied.parent_file_id = target.file_id;
  occupied.file_type = ZI_FS_FILE_TYPE_REGULAR;
  occupied.security_id = 1;

  unsigned char* records = s_phase7_volume[PHASE7_RECORD_TABLE_START];
  if (ZiFailed(ZiFsEncodeFileRecord(&source,
                                    records + ZI_FS_FILE_RECORD_SIZE,
                                    ZI_FS_FILE_RECORD_SIZE)) ||
      ZiFailed(ZiFsEncodeFileRecord(&target,
                                    records + ((size_t)2u * ZI_FS_FILE_RECORD_SIZE),
                                    ZI_FS_FILE_RECORD_SIZE)) ||
      ZiFailed(ZiFsEncodeFileRecord(&child,
                                    records + ((size_t)3u * ZI_FS_FILE_RECORD_SIZE),
                                    ZI_FS_FILE_RECORD_SIZE)) ||
      ZiFailed(ZiFsEncodeFileRecord(&moved_file,
                                    records + ((size_t)4u * ZI_FS_FILE_RECORD_SIZE),
                                    ZI_FS_FILE_RECORD_SIZE)) ||
      ZiFailed(ZiFsEncodeFileRecord(&occupied,
                                    records + ((size_t)5u * ZI_FS_FILE_RECORD_SIZE),
                                    ZI_FS_FILE_RECORD_SIZE)) ||
      ZiFailed(ZiFsInitialiseDirectoryBlock(s_phase7_volume[PHASE7_SOURCE_DIRECTORY_BLOCK],
                                            ZI_FS_BLOCK_SIZE,
                                            source.file_id,
                                            1)) ||
      ZiFailed(ZiFsInitialiseDirectoryBlock(s_phase7_volume[PHASE7_TARGET_DIRECTORY_BLOCK],
                                            ZI_FS_BLOCK_SIZE,
                                            target.file_id,
                                            1)) ||
      ZiFailed(ZiFsInitialiseDirectoryBlock(s_phase7_volume[PHASE7_CHILD_DIRECTORY_BLOCK],
                                            ZI_FS_BLOCK_SIZE,
                                            child.file_id,
                                            1))) {
    return false;
  }

  return true;
}

static bool add_move_fixture_entries(void) {
  ZiFsDirectoryEntry source_entry = {
      PHASE7_SOURCE_FILE_ID,
      1,
      ZI_FS_FILE_TYPE_DIRECTORY,
      0,
      {"Source Space", sizeof "Source Space" - 1u},
  };
  ZiFsDirectoryEntry target_entry = {
      PHASE7_TARGET_FILE_ID,
      2,
      ZI_FS_FILE_TYPE_DIRECTORY,
      0,
      {"Target Space", sizeof "Target Space" - 1u},
  };
  ZiFsDirectoryEntry child_entry = {
      PHASE7_CHILD_FILE_ID,
      3,
      ZI_FS_FILE_TYPE_DIRECTORY,
      0,
      {"Child", sizeof "Child" - 1u},
  };
  ZiFsDirectoryEntry file_entry = {
      PHASE7_MOVED_FILE_ID,
      4,
      ZI_FS_FILE_TYPE_REGULAR,
      0,
      {"Temp", sizeof "Temp" - 1u},
  };
  static const char k_decomposed_name[] = "Cafe\xcc\x81 moved.txt";
  ZiFsDirectoryEntry occupied_entry = {
      PHASE7_OCCUPIED_FILE_ID,
      5,
      ZI_FS_FILE_TYPE_REGULAR,
      0,
      {k_decomposed_name, sizeof k_decomposed_name - 1u},
  };
  if (ZiFailed(ZiFsAddDirectoryEntry(s_phase7_volume[PHASE7_ROOT_DIRECTORY_BLOCK],
                                     ZI_FS_BLOCK_SIZE,
                                     &source_entry)) ||
      ZiFailed(ZiFsAddDirectoryEntry(s_phase7_volume[PHASE7_ROOT_DIRECTORY_BLOCK],
                                     ZI_FS_BLOCK_SIZE,
                                     &target_entry)) ||
      ZiFailed(ZiFsAddDirectoryEntry(s_phase7_volume[PHASE7_SOURCE_DIRECTORY_BLOCK],
                                     ZI_FS_BLOCK_SIZE,
                                     &child_entry)) ||
      ZiFailed(ZiFsAddDirectoryEntry(s_phase7_volume[PHASE7_SOURCE_DIRECTORY_BLOCK],
                                     ZI_FS_BLOCK_SIZE,
                                     &file_entry)) ||
      ZiFailed(ZiFsAddDirectoryEntry(s_phase7_volume[PHASE7_TARGET_DIRECTORY_BLOCK],
                                     ZI_FS_BLOCK_SIZE,
                                     &occupied_entry)) ||
      ZiFailed(ZiFsAllocationBitSet(s_phase7_volume[PHASE7_BITMAP_BLOCK],
                                    ZI_FS_BLOCK_SIZE,
                                    PHASE7_FIRST_DATA_BLOCK,
                                    true)) ||
      ZiFailed(ZiFsAllocationBitSet(s_phase7_volume[PHASE7_BITMAP_BLOCK],
                                    ZI_FS_BLOCK_SIZE,
                                    PHASE7_FIRST_DATA_BLOCK + 1u,
                                    true))) {
    return false;
  }
  return true;
}

static bool find_transaction_image(const ZiFsTransaction* transaction,
                                   uint64_t target_block,
                                   ZiConstBuffer* out_image) {
  for (size_t index = 0; index < transaction->block_image_count; ++index) {
    uint64_t candidate = 0;
    ZiConstBuffer image = {0};
    if (ZiFailed(ZiFsTransactionGetBlockImage(transaction, index, &candidate, &image))) {
      return false;
    }
    if (candidate == target_block) {
      *out_image = image;
      return true;
    }
  }
  return false;
}

static bool fill_root_directory(void) {
  char name[220];
  for (size_t index = 0; index < sizeof name; ++index) {
    name[index] = 'D';
  }
  ZiFsDirectoryEntry entry = {
      1,
      0,
      ZI_FS_FILE_TYPE_DIRECTORY,
      0,
      {name, sizeof name},
  };
  for (size_t index = 0; index < 32; ++index) {
    name[sizeof name - 2u] = (char)('A' + (index / 26u));
    name[sizeof name - 1u] = (char)('A' + (index % 26u));
    ZiStatus status = ZiFsAddDirectoryEntry(s_phase7_volume[PHASE7_ROOT_DIRECTORY_BLOCK],
                                            ZI_FS_BLOCK_SIZE,
                                            &entry);
    if (status == ZI_STATUS_BUFFER_TOO_SMALL) {
      return true;
    }
    if (ZiFailed(status)) {
      return false;
    }
  }
  return false;
}

static bool prepare_test_create(ZiFsVolume* volume,
                                ZiFsTransaction* transaction,
                                ZiFsCreateResult* out_result) {
  bool prepared =
      prepare_named_create(volume,
                           transaction,
                           (ZiStringView){"First Light.txt", sizeof "First Light.txt" - 1u},
                           (ZiConstBuffer){s_phase7_payload, sizeof s_phase7_payload},
                           out_result);
  return (bool)(prepared && transaction->state == ZI_FS_TRANSACTION_STATE_PREPARED &&
                transaction->block_image_count == 5 && out_result->file_id == 2 &&
                out_result->record_index == 1 &&
                out_result->first_data_block == PHASE7_FIRST_DATA_BLOCK &&
                out_result->data_block_count == 2);
}

static bool prepare_named_create(ZiFsVolume* volume,
                                 ZiFsTransaction* transaction,
                                 ZiStringView name,
                                 ZiConstBuffer data,
                                 ZiFsCreateResult* out_result) {
  return prepare_named_create_in_workspace(volume,
                                           transaction,
                                           s_phase7_workspace,
                                           sizeof s_phase7_workspace,
                                           name,
                                           data,
                                           out_result);
}

static bool prepare_named_create_in_workspace(ZiFsVolume* volume,
                                              ZiFsTransaction* transaction,
                                              void* workspace,
                                              size_t workspace_size,
                                              ZiStringView name,
                                              ZiConstBuffer data,
                                              ZiFsCreateResult* out_result) {
  if (ZiFailed(ZiFsTransactionInitialise(transaction, volume, workspace, workspace_size))) {
    return false;
  }
  ZiFsCreateRequest request = {0};
  request.struct_size = sizeof request;
  request.version = ZI_FS_CREATE_REQUEST_VERSION;
  request.parent_record_index = 0;
  request.security_id = 1;
  request.timestamp = UINT64_C(21000000);
  request.name = name;
  request.data = data;
  return ZiSucceeded(ZiFsTransactionPrepareCreateFile(transaction, &request, out_result));
}

static bool prepare_truncate(ZiFsVolume* volume,
                             ZiFsTransaction* transaction,
                             uint64_t new_size,
                             ZiFsTruncateResult* out_result) {
  if (ZiFailed(ZiFsTransactionInitialise(transaction,
                                         volume,
                                         s_phase7_workspace,
                                         sizeof s_phase7_workspace))) {
    return false;
  }
  ZiFsTruncateRequest request = {
      sizeof(ZiFsTruncateRequest),
      ZI_FS_TRUNCATE_REQUEST_VERSION,
      4,
      new_size,
      UINT64_C(23000000),
      ZI_FS_TRUNCATE_FLAG_NONE,
      0,
  };
  return ZiSucceeded(ZiFsTransactionPrepareTruncate(transaction, &request, out_result));
}

static bool prepare_delete(ZiFsVolume* volume,
                           ZiFsTransaction* transaction,
                           ZiStringView name,
                           ZiFsDeleteResult* out_result) {
  if (ZiFailed(ZiFsTransactionInitialise(transaction,
                                         volume,
                                         s_phase7_workspace,
                                         sizeof s_phase7_workspace))) {
    return false;
  }
  ZiFsDeleteRequest request = {
      sizeof(ZiFsDeleteRequest),
      ZI_FS_DELETE_REQUEST_VERSION,
      1,
      UINT64_C(24000000),
      ZI_FS_DELETE_FLAG_NONE,
      0,
      name,
  };
  return ZiSucceeded(ZiFsTransactionPrepareDelete(transaction, &request, out_result));
}

static bool
query_allocation_bit(const ZiFsVolume* volume, uint64_t block_number, bool* out_allocated) {
  if (volume == NULL || out_allocated == NULL) {
    return false;
  }
  const uint64_t bits_per_bitmap_block = (uint64_t)ZI_FS_BLOCK_SIZE * 8u;
  uint64_t bitmap_block = block_number / bits_per_bitmap_block;
  if (bitmap_block >= volume->superblock.allocation_bitmap_blocks ||
      ZiFailed(volume->device.read_blocks(volume->device.context,
                                          volume->superblock.allocation_bitmap_start + bitmap_block,
                                          1,
                                          s_phase7_recovery_workspace,
                                          ZI_FS_BLOCK_SIZE))) {
    return false;
  }
  return ZiSucceeded(ZiFsAllocationBitQuery(s_phase7_recovery_workspace,
                                            ZI_FS_BLOCK_SIZE,
                                            block_number % bits_per_bitmap_block,
                                            out_allocated));
}

static bool prepare_move(ZiFsVolume* volume,
                         ZiFsTransaction* transaction,
                         uint64_t source_parent_record_index,
                         ZiStringView source_name,
                         uint64_t target_parent_record_index,
                         ZiStringView target_name,
                         ZiFsMoveResult* out_result) {
  if (ZiFailed(ZiFsTransactionInitialise(transaction,
                                         volume,
                                         s_phase7_workspace,
                                         sizeof s_phase7_workspace))) {
    return false;
  }
  ZiFsMoveRequest request = {0};
  request.struct_size = sizeof request;
  request.version = ZI_FS_MOVE_REQUEST_VERSION;
  request.source_parent_record_index = source_parent_record_index;
  request.target_parent_record_index = target_parent_record_index;
  request.timestamp = UINT64_C(22000000);
  request.source_name = source_name;
  request.target_name = target_name;
  return ZiSucceeded(ZiFsTransactionPrepareMove(transaction, &request, out_result));
}

static bool recover_failed_transaction(const ZiBlockDevice* device, ZiFsVolume* out_volume) {
  ZiFsVolume mounted = {0};
  ZiStatus status =
      ZiFsMountVolume(device, s_phase7_recovery_workspace, ZI_FS_BLOCK_SIZE, &mounted);
  if (status == ZI_STATUS_RECOVERY_REQUIRED) {
    ZiFsRecoveryReport report = {0};
    if (ZiFailed(ZiFsRecoverVolume(&mounted,
                                   s_phase7_recovery_workspace,
                                   sizeof s_phase7_recovery_workspace,
                                   &report))) {
      return false;
    }
    zi_memory_zero(&mounted, sizeof mounted);
    status = ZiFsMountVolume(device, s_phase7_recovery_workspace, ZI_FS_BLOCK_SIZE, &mounted);
  }
  if (ZiFailed(status)) {
    return false;
  }
  *out_volume = mounted;
  return true;
}

static bool verify_test_file(ZiFsVolume* volume, bool expected_present) {
  const char path_text[] = "C:\\First Light.txt";
  return verify_named_file(volume,
                           path_text,
                           sizeof path_text - 1u,
                           (ZiConstBuffer){s_phase7_payload, sizeof s_phase7_payload},
                           expected_present);
}

static bool verify_named_file(ZiFsVolume* volume,
                              const char* path_text,
                              size_t path_size,
                              ZiConstBuffer expected_data,
                              bool expected_present) {
  ZiStringView components[4] = {0};
  ZiParsedPath path = {0};
  if (expected_data.size > sizeof s_phase7_large_readback ||
      ZiFailed(zi_path_parse_absolute(path_text,
                                      path_size,
                                      components,
                                      sizeof components / sizeof components[0],
                                      &path))) {
    return false;
  }
  ZiFsFileRecord record = {0};
  ZiStatus status =
      ZiFsLookupPath(volume, &path, s_phase7_recovery_workspace, ZI_FS_BLOCK_SIZE, &record);
  if (!expected_present) {
    return status == ZI_STATUS_NOT_FOUND;
  }
  if (ZiFailed(status) || record.file_type != ZI_FS_FILE_TYPE_REGULAR ||
      record.file_size != expected_data.size) {
    return false;
  }
  if (expected_data.size == 0) {
    return true;
  }
  zi_memory_zero(s_phase7_large_readback, expected_data.size);
  size_t bytes_read = 0;
  status = ZiFsReadFile(volume,
                        &record,
                        0,
                        s_phase7_large_readback,
                        expected_data.size,
                        &bytes_read,
                        s_phase7_recovery_workspace,
                        ZI_FS_BLOCK_SIZE);
  return (bool)(ZiSucceeded(status) && bytes_read == expected_data.size &&
                zi_memory_compare(s_phase7_large_readback,
                                  expected_data.data,
                                  expected_data.size) == 0);
}

// Every durable device operation is failed once to prove old-or-new recovery.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static bool test_durable_commit_and_recovery(void) {
  for (size_t index = 0; index < sizeof s_phase7_payload; ++index) {
    s_phase7_payload[index] = (unsigned char)(index ^ (index >> 8u));
  }

  ZiFsVolume volume = {0};
  PHASE7_ASSERT(initialise_transaction_volume(&volume, true));
  PHASE7_ASSERT(volume.is_read_only == 0 && volume.needs_recovery == 0 &&
                volume.journal_header_valid != 0);
  ZiFsTransaction transaction = {0};
  ZiFsCreateResult result = {0};
  PHASE7_ASSERT(prepare_test_create(&volume, &transaction, &result));
  PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS &&
                transaction.state == ZI_FS_TRANSACTION_STATE_READY);
  size_t successful_operation_count = s_phase7_memory.operation_count;
  PHASE7_ASSERT(successful_operation_count > 0 && successful_operation_count < 100 &&
                s_phase7_memory.write_count > 0 && s_phase7_memory.flush_count > 0);

  ZiFsVolume restarted = {0};
  PHASE7_ASSERT(
      ZiFsMountVolume(&volume.device, s_phase7_recovery_workspace, ZI_FS_BLOCK_SIZE, &restarted) ==
      ZI_STATUS_SUCCESS);
  PHASE7_ASSERT(restarted.superblock.generation == 2 &&
                restarted.superblock.last_committed_transaction == 1 &&
                restarted.superblock.state_flags == ZI_FS_SUPERBLOCK_STATE_NONE &&
                verify_test_file(&restarted, true));
  ZiFsJournalHeader journal = {0};
  uint32_t journal_copy = 0;
  PHASE7_ASSERT(ZiFsLoadJournalHeader(&restarted.device,
                                      restarted.superblock.journal_start,
                                      s_phase7_recovery_workspace,
                                      ZI_FS_BLOCK_SIZE,
                                      &journal,
                                      &journal_copy) == ZI_STATUS_SUCCESS &&
                journal.last_committed_transaction == 1 &&
                journal.last_checkpoint_transaction == 1);

  size_t replay_count = 0;
  size_t rollback_count = 0;
  size_t repair_count = 0;
  size_t present_count = 0;
  size_t absent_count = 0;
  for (size_t fail_operation = 1; fail_operation <= successful_operation_count; ++fail_operation) {
    PHASE7_ASSERT(initialise_transaction_volume(&volume, true));
    zi_memory_zero(&transaction, sizeof transaction);
    zi_memory_zero(&result, sizeof result);
    PHASE7_ASSERT(prepare_test_create(&volume, &transaction, &result));
    s_phase7_memory.operation_count = 0;
    s_phase7_memory.fail_operation = fail_operation;
    PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_DEVICE_ERROR &&
                  transaction.state == ZI_FS_TRANSACTION_STATE_FAILED &&
                  volume.needs_recovery != 0);
    s_phase7_memory.fail_operation = 0;
    s_phase7_memory.operation_count = 0;

    zi_memory_zero(&restarted, sizeof restarted);
    ZiStatus mount_status =
        ZiFsMountVolume(&volume.device, s_phase7_recovery_workspace, ZI_FS_BLOCK_SIZE, &restarted);
    if (mount_status == ZI_STATUS_RECOVERY_REQUIRED) {
      ZiFsRecoveryReport report = {0};
      PHASE7_ASSERT(ZiFsRecoverVolume(&restarted,
                                      s_phase7_recovery_workspace,
                                      sizeof s_phase7_recovery_workspace,
                                      &report) == ZI_STATUS_SUCCESS);
      if (report.action == ZI_FS_RECOVERY_ACTION_REPLAYED) {
        ++replay_count;
      } else if (report.action == ZI_FS_RECOVERY_ACTION_ROLLED_BACK) {
        ++rollback_count;
      } else if (report.action == ZI_FS_RECOVERY_ACTION_REPAIRED_REDUNDANCY) {
        ++repair_count;
      } else {
        PHASE7_ASSERT(false);
      }
      ZiFsVolume recovered = {0};
      PHASE7_ASSERT(ZiFsMountVolume(&restarted.device,
                                    s_phase7_recovery_workspace,
                                    ZI_FS_BLOCK_SIZE,
                                    &recovered) == ZI_STATUS_SUCCESS);
      restarted = recovered;
    } else {
      PHASE7_ASSERT(mount_status == ZI_STATUS_SUCCESS);
    }

    bool file_present = verify_test_file(&restarted, true);
    if (file_present) {
      ++present_count;
      PHASE7_ASSERT(restarted.superblock.generation == 2 &&
                    restarted.superblock.last_committed_transaction == 1);
    } else {
      ++absent_count;
      PHASE7_ASSERT(verify_test_file(&restarted, false) && restarted.superblock.generation == 1 &&
                    restarted.superblock.last_committed_transaction == 0);
    }
    PHASE7_ASSERT(restarted.superblock.state_flags == ZI_FS_SUPERBLOCK_STATE_NONE &&
                  restarted.needs_recovery == 0 && restarted.is_read_only == 0);
  }
  PHASE7_ASSERT(replay_count > 0 && rollback_count > 0 && repair_count > 0 && present_count > 0 &&
                absent_count > 0);
  return true;
}

// The wrapped transaction is failed at every durable write boundary to prove recovery.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static bool test_large_transaction_and_journal_wrap(void) {
  for (size_t index = 0; index < sizeof s_phase7_large_payload; ++index) {
    s_phase7_large_payload[index] = (unsigned char)(index ^ (index >> 8u) ^ UINT8_C(0x5a));
  }

  const ZiStringView large_name = {"Wide Journal.bin", sizeof "Wide Journal.bin" - 1u};
  const ZiConstBuffer large_data = {s_phase7_large_payload, sizeof s_phase7_large_payload};
  const ZiStringView wrapped_name = {"Wrapped.txt", sizeof "Wrapped.txt" - 1u};
  const ZiConstBuffer empty_data = {NULL, 0};
  const char large_path[] = "C:\\Wide Journal.bin";
  const char wrapped_path[] = "C:\\Wrapped.txt";

  ZiFsVolume volume = {0};
  PHASE7_ASSERT(initialise_transaction_volume(&volume, true));
  ZiFsTransaction transaction = {0};
  ZiFsCreateResult result = {0};
  PHASE7_ASSERT(prepare_named_create(&volume, &transaction, large_name, large_data, &result));
  PHASE7_ASSERT(transaction.block_image_capacity == ZI_FS_TRANSACTION_MAXIMUM_BLOCK_IMAGES &&
                transaction.block_image_count == 27 && result.data_block_count == 24 &&
                result.first_data_block == PHASE7_FIRST_DATA_BLOCK);
  PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS);

  ZiFsJournalHeader journal = {0};
  uint32_t journal_copy = 0;
  PHASE7_ASSERT(ZiFsLoadJournalHeader(&volume.device,
                                      volume.superblock.journal_start,
                                      s_phase7_recovery_workspace,
                                      ZI_FS_BLOCK_SIZE,
                                      &journal,
                                      &journal_copy) == ZI_STATUS_SUCCESS &&
                journal.head_record == 30 && journal.tail_record == 30 &&
                journal.next_sequence == 31 && journal.last_committed_transaction == 1 &&
                journal.last_checkpoint_transaction == 1);
  PHASE7_ASSERT(verify_named_file(&volume, large_path, sizeof large_path - 1u, large_data, true));
  zi_memory_copy(s_phase7_snapshot, s_phase7_volume, sizeof s_phase7_snapshot);

  zi_memory_zero(&transaction, sizeof transaction);
  zi_memory_zero(&result, sizeof result);
  PHASE7_ASSERT(prepare_named_create(&volume, &transaction, wrapped_name, empty_data, &result));
  PHASE7_ASSERT(transaction.block_image_count == 2 && result.data_block_count == 0);
  s_phase7_memory.operation_count = 0;
  PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS);
  size_t successful_operation_count = s_phase7_memory.operation_count;
  PHASE7_ASSERT(successful_operation_count > 0 && successful_operation_count < 100);
  PHASE7_ASSERT(ZiFsLoadJournalHeader(&volume.device,
                                      volume.superblock.journal_start,
                                      s_phase7_recovery_workspace,
                                      ZI_FS_BLOCK_SIZE,
                                      &journal,
                                      &journal_copy) == ZI_STATUS_SUCCESS &&
                journal.head_record == 3 && journal.tail_record == 3 &&
                journal.next_sequence == 36 && journal.last_committed_transaction == 2 &&
                journal.last_checkpoint_transaction == 2);
  uint64_t occupied_records = 0;
  uint64_t available_records = 0;
  PHASE7_ASSERT(ZiFsJournalQuerySpace(&journal, &occupied_records, &available_records) ==
                    ZI_STATUS_SUCCESS &&
                occupied_records == 0 && available_records == 31);
  PHASE7_ASSERT(
      verify_named_file(&volume, large_path, sizeof large_path - 1u, large_data, true) &&
      verify_named_file(&volume, wrapped_path, sizeof wrapped_path - 1u, empty_data, true));
  ZiFsVolume restarted = {0};
  PHASE7_ASSERT(
      mount_transaction_volume(&restarted, true) &&
      verify_named_file(&restarted, large_path, sizeof large_path - 1u, large_data, true) &&
      verify_named_file(&restarted, wrapped_path, sizeof wrapped_path - 1u, empty_data, true));

  size_t replay_count = 0;
  size_t rollback_count = 0;
  size_t repair_count = 0;
  size_t present_count = 0;
  size_t absent_count = 0;
  for (size_t fail_operation = 1; fail_operation <= successful_operation_count; ++fail_operation) {
    zi_memory_copy(s_phase7_volume, s_phase7_snapshot, sizeof s_phase7_volume);
    zi_memory_zero(&volume, sizeof volume);
    PHASE7_ASSERT(mount_transaction_volume(&volume, true));
    zi_memory_zero(&transaction, sizeof transaction);
    zi_memory_zero(&result, sizeof result);
    PHASE7_ASSERT(prepare_named_create(&volume, &transaction, wrapped_name, empty_data, &result));
    s_phase7_memory.operation_count = 0;
    s_phase7_memory.fail_operation = fail_operation;
    PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_DEVICE_ERROR &&
                  transaction.state == ZI_FS_TRANSACTION_STATE_FAILED &&
                  volume.needs_recovery != 0);
    s_phase7_memory.fail_operation = 0;
    s_phase7_memory.operation_count = 0;

    zi_memory_zero(&restarted, sizeof restarted);
    ZiStatus mount_status =
        ZiFsMountVolume(&volume.device, s_phase7_recovery_workspace, ZI_FS_BLOCK_SIZE, &restarted);
    if (mount_status == ZI_STATUS_RECOVERY_REQUIRED) {
      ZiFsRecoveryReport report = {0};
      PHASE7_ASSERT(ZiFsRecoverVolume(&restarted,
                                      s_phase7_recovery_workspace,
                                      sizeof s_phase7_recovery_workspace,
                                      &report) == ZI_STATUS_SUCCESS);
      if (report.action == ZI_FS_RECOVERY_ACTION_REPLAYED) {
        ++replay_count;
      } else if (report.action == ZI_FS_RECOVERY_ACTION_ROLLED_BACK) {
        ++rollback_count;
      } else if (report.action == ZI_FS_RECOVERY_ACTION_REPAIRED_REDUNDANCY) {
        ++repair_count;
      } else {
        PHASE7_ASSERT(false);
      }
      ZiFsVolume recovered = {0};
      PHASE7_ASSERT(ZiFsMountVolume(&restarted.device,
                                    s_phase7_recovery_workspace,
                                    ZI_FS_BLOCK_SIZE,
                                    &recovered) == ZI_STATUS_SUCCESS);
      restarted = recovered;
    } else {
      PHASE7_ASSERT(mount_status == ZI_STATUS_SUCCESS);
    }

    PHASE7_ASSERT(
        verify_named_file(&restarted, large_path, sizeof large_path - 1u, large_data, true));
    bool wrapped_present =
        verify_named_file(&restarted, wrapped_path, sizeof wrapped_path - 1u, empty_data, true);
    if (wrapped_present) {
      ++present_count;
      PHASE7_ASSERT(restarted.superblock.generation == 3 &&
                    restarted.superblock.last_committed_transaction == 2);
    } else {
      ++absent_count;
      PHASE7_ASSERT(verify_named_file(&restarted,
                                      wrapped_path,
                                      sizeof wrapped_path - 1u,
                                      empty_data,
                                      false) &&
                    restarted.superblock.generation == 2 &&
                    restarted.superblock.last_committed_transaction == 1);
    }
    PHASE7_ASSERT(restarted.superblock.state_flags == ZI_FS_SUPERBLOCK_STATE_NONE &&
                  restarted.needs_recovery == 0 && restarted.is_read_only == 0);
    PHASE7_ASSERT(ZiFsLoadJournalHeader(&restarted.device,
                                        restarted.superblock.journal_start,
                                        s_phase7_recovery_workspace,
                                        ZI_FS_BLOCK_SIZE,
                                        &journal,
                                        &journal_copy) == ZI_STATUS_SUCCESS &&
                  journal.head_record == journal.tail_record);
    PHASE7_ASSERT(ZiFsJournalQuerySpace(&journal, &occupied_records, &available_records) ==
                      ZI_STATUS_SUCCESS &&
                  occupied_records == 0 && available_records == 31);
  }
  PHASE7_ASSERT(replay_count > 0 && rollback_count > 0 && repair_count > 0 && present_count > 0 &&
                absent_count > 0);
  return true;
}

// Exact-case semantics, directory ownership, and staged metadata are checked together.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static bool test_move_transaction_contract(void) {
  static const ZiStringView k_upper_name = {"Temp", sizeof "Temp" - 1u};
  static const ZiStringView k_lower_name = {"temp", sizeof "temp" - 1u};
  static const char k_decomposed_name[] = "Cafe\xcc\x81 moved.txt";
  static const char k_composed_name[] = "Caf\xc3\xa9 moved.txt";
  static const ZiConstBuffer k_payload = {s_phase7_payload, sizeof s_phase7_payload};
  const char old_path[] = "C:\\Source Space\\Temp";
  const char renamed_path[] = "C:\\Source Space\\temp";
  const char moved_path[] = "C:\\Target Space\\Caf\xc3\xa9 moved.txt";
  const char distinct_path[] = "C:\\Target Space\\Cafe\xcc\x81 moved.txt";

  ZiFsVolume volume = {0};
  PHASE7_ASSERT(initialise_move_fixture(&volume, false));
  ZiFsTransaction transaction = {0};
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionInitialise(&transaction,
                                                      &volume,
                                                      s_phase7_workspace,
                                                      sizeof s_phase7_workspace)));
  ZiFsMoveRequest request = {
      sizeof(ZiFsMoveRequest),
      ZI_FS_MOVE_REQUEST_VERSION,
      1,
      1,
      UINT64_C(22000000),
      ZI_FS_MOVE_FLAG_NONE,
      0,
      k_upper_name,
      k_upper_name,
  };
  ZiFsMoveResult result = {0};
  PHASE7_ASSERT(
      ZiFsTransactionPrepareMove(&transaction, &request, &result) == ZI_STATUS_ALREADY_EXISTS &&
      transaction.state == ZI_FS_TRANSACTION_STATE_READY && transaction.block_image_count == 0);

  request.target_parent_record_index = 2;
  request.target_name = (ZiStringView){k_decomposed_name, sizeof k_decomposed_name - 1u};
  PHASE7_ASSERT(ZiFsTransactionPrepareMove(&transaction, &request, &result) ==
                ZI_STATUS_ALREADY_EXISTS);
  const char invalid_utf8[] = {(char)0xc0, (char)0x80};
  request.target_name = (ZiStringView){invalid_utf8, sizeof invalid_utf8};
  PHASE7_ASSERT(ZiFsTransactionPrepareMove(&transaction, &request, &result) ==
                ZI_STATUS_INVALID_ENCODING);
  request.target_name = (ZiStringView){"Bad\\Name", sizeof "Bad\\Name" - 1u};
  PHASE7_ASSERT(ZiFsTransactionPrepareMove(&transaction, &request, &result) ==
                ZI_STATUS_INVALID_PATH);
  request.target_name = (ZiStringView){"Moved", sizeof "Moved" - 1u};
  request.source_name = (ZiStringView){"Missing", sizeof "Missing" - 1u};
  PHASE7_ASSERT(ZiFsTransactionPrepareMove(&transaction, &request, &result) == ZI_STATUS_NOT_FOUND);

  request.source_parent_record_index = 0;
  request.source_name = (ZiStringView){"Source Space", sizeof "Source Space" - 1u};
  request.target_parent_record_index = 3;
  request.target_name = (ZiStringView){"Nested Source", sizeof "Nested Source" - 1u};
  PHASE7_ASSERT(ZiFsTransactionPrepareMove(&transaction, &request, &result) ==
                ZI_STATUS_INVALID_PATH);

  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionInitialise(&transaction,
                                                      &volume,
                                                      s_phase7_workspace,
                                                      ZI_FS_TRANSACTION_MINIMUM_WORKSPACE_SIZE)));
  request.source_parent_record_index = 1;
  request.source_name = k_upper_name;
  request.target_parent_record_index = 1;
  request.target_name = k_lower_name;
  PHASE7_ASSERT(
      ZiFsTransactionPrepareMove(&transaction, &request, &result) == ZI_STATUS_BUFFER_TOO_SMALL &&
      transaction.state == ZI_FS_TRANSACTION_STATE_READY && transaction.block_image_count == 0);

  PHASE7_ASSERT(prepare_move(&volume, &transaction, 1, k_upper_name, 1, k_lower_name, &result));
  PHASE7_ASSERT(transaction.state == ZI_FS_TRANSACTION_STATE_PREPARED &&
                transaction.block_image_count == 2 && result.file_id == 5 &&
                result.record_index == 4 && result.source_parent_file_id == 2 &&
                result.target_parent_file_id == 2 && result.file_type == ZI_FS_FILE_TYPE_REGULAR);
  ZiConstBuffer image = {0};
  PHASE7_ASSERT(find_transaction_image(&transaction, PHASE7_SOURCE_DIRECTORY_BLOCK, &image));
  ZiFsDirectoryEntry entry = {0};
  PHASE7_ASSERT(
      ZiFsFindDirectoryEntry(image.data, image.size, k_upper_name, &entry) == ZI_STATUS_NOT_FOUND &&
      ZiFsFindDirectoryEntry(image.data, image.size, k_lower_name, &entry) == ZI_STATUS_SUCCESS &&
      entry.file_id == 5 && zi_read_u64_le((const unsigned char*)image.data + 24u) == 2);
  PHASE7_ASSERT(find_transaction_image(&transaction, PHASE7_RECORD_TABLE_START, &image));
  ZiFsFileRecord moved_record = {0};
  PHASE7_ASSERT(ZiSucceeded(ZiFsDecodeFileRecord((const unsigned char*)image.data +
                                                     ((size_t)4u * ZI_FS_FILE_RECORD_SIZE),
                                                 ZI_FS_FILE_RECORD_SIZE,
                                                 &moved_record)) &&
                moved_record.file_id == 5 && moved_record.parent_file_id == 2 &&
                moved_record.changed_time == UINT64_C(22000000));
  PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_READ_ONLY_FILESYSTEM &&
                transaction.state == ZI_FS_TRANSACTION_STATE_PREPARED);

  PHASE7_ASSERT(initialise_move_fixture(&volume, true));
  PHASE7_ASSERT(prepare_move(&volume, &transaction, 1, k_upper_name, 1, k_lower_name, &result));
  PHASE7_ASSERT(
      ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS &&
      verify_named_file(&volume, old_path, sizeof old_path - 1u, k_payload, false) &&
      verify_named_file(&volume, renamed_path, sizeof renamed_path - 1u, k_payload, true));

  PHASE7_ASSERT(prepare_move(&volume,
                             &transaction,
                             1,
                             k_lower_name,
                             2,
                             (ZiStringView){k_composed_name, sizeof k_composed_name - 1u},
                             &result));
  PHASE7_ASSERT(transaction.block_image_count == 3 && result.file_id == 5 &&
                result.source_parent_file_id == 2 && result.target_parent_file_id == 3);
  PHASE7_ASSERT(
      ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS &&
      verify_named_file(&volume, renamed_path, sizeof renamed_path - 1u, k_payload, false) &&
      verify_named_file(&volume, moved_path, sizeof moved_path - 1u, k_payload, true) &&
      verify_named_file(&volume,
                        distinct_path,
                        sizeof distinct_path - 1u,
                        (ZiConstBuffer){NULL, 0},
                        true));

  ZiStringView components[3] = {0};
  ZiParsedPath path = {0};
  uint64_t record_index = 0;
  PHASE7_ASSERT(ZiSucceeded(zi_path_parse_absolute(moved_path,
                                                   sizeof moved_path - 1u,
                                                   components,
                                                   sizeof components / sizeof components[0],
                                                   &path)) &&
                ZiFsLookupPathRecord(&volume,
                                     &path,
                                     s_phase7_recovery_workspace,
                                     ZI_FS_BLOCK_SIZE,
                                     &moved_record,
                                     &record_index) == ZI_STATUS_SUCCESS &&
                record_index == 4 && moved_record.file_id == 5 &&
                moved_record.parent_file_id == 3 &&
                moved_record.changed_time == UINT64_C(22000000));

  PHASE7_ASSERT(initialise_move_fixture(&volume, false));
  ZiFsDirectoryEntry duplicate = {
      6,
      5,
      ZI_FS_FILE_TYPE_REGULAR,
      0,
      {k_decomposed_name, sizeof k_decomposed_name - 1u},
  };
  PHASE7_ASSERT(ZiFsAddDirectoryEntry(s_phase7_volume[PHASE7_TARGET_DIRECTORY_BLOCK],
                                      ZI_FS_BLOCK_SIZE,
                                      &duplicate) == ZI_STATUS_ALREADY_EXISTS);
  s_phase7_volume[PHASE7_SOURCE_DIRECTORY_BLOCK][100] ^= UINT8_C(1);
  PHASE7_ASSERT(ZiFsRemoveDirectoryEntry(s_phase7_volume[PHASE7_SOURCE_DIRECTORY_BLOCK],
                                         ZI_FS_BLOCK_SIZE,
                                         k_upper_name,
                                         NULL) == ZI_STATUS_CHECKSUM_MISMATCH);
  PHASE7_ASSERT(initialise_move_fixture(&volume, false));
  PHASE7_ASSERT(
      ZiSucceeded(ZiFsInitialiseDirectoryBlock(s_phase7_volume[PHASE7_SOURCE_DIRECTORY_BLOCK],
                                               ZI_FS_BLOCK_SIZE,
                                               999,
                                               1)));
  PHASE7_ASSERT(!prepare_move(&volume, &transaction, 1, k_upper_name, 1, k_lower_name, &result));
  PHASE7_ASSERT(transaction.state == ZI_FS_TRANSACTION_STATE_READY &&
                transaction.block_image_count == 0);
  return true;
}

// Every write and flush is failed once for both two-image rename and three-image move.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static bool test_move_fault_boundaries(void) {
  static const ZiStringView k_upper_name = {"Temp", sizeof "Temp" - 1u};
  static const ZiStringView k_lower_name = {"temp", sizeof "temp" - 1u};
  static const ZiStringView k_moved_name = {"Moved File.txt", sizeof "Moved File.txt" - 1u};
  static const ZiConstBuffer k_payload = {s_phase7_payload, sizeof s_phase7_payload};
  const char old_path[] = "C:\\Source Space\\Temp";
  const char renamed_path[] = "C:\\Source Space\\temp";
  const char moved_path[] = "C:\\Target Space\\Moved File.txt";

  ZiFsVolume volume = {0};
  PHASE7_ASSERT(initialise_move_fixture(&volume, true));
  zi_memory_copy(s_phase7_snapshot, s_phase7_volume, sizeof s_phase7_snapshot);
  ZiFsTransaction transaction = {0};
  ZiFsMoveResult result = {0};
  PHASE7_ASSERT(prepare_move(&volume, &transaction, 1, k_upper_name, 1, k_lower_name, &result) &&
                transaction.block_image_count == 2);
  s_phase7_memory.operation_count = 0;
  PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS);
  size_t rename_operation_count = s_phase7_memory.operation_count;
  PHASE7_ASSERT(rename_operation_count == 23);

  for (size_t fail_operation = 1; fail_operation <= rename_operation_count; ++fail_operation) {
    zi_memory_copy(s_phase7_volume, s_phase7_snapshot, sizeof s_phase7_volume);
    PHASE7_ASSERT(mount_transaction_volume(&volume, true));
    zi_memory_zero(&transaction, sizeof transaction);
    zi_memory_zero(&result, sizeof result);
    PHASE7_ASSERT(prepare_move(&volume, &transaction, 1, k_upper_name, 1, k_lower_name, &result));
    s_phase7_memory.operation_count = 0;
    s_phase7_memory.fail_operation = fail_operation;
    PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_DEVICE_ERROR &&
                  transaction.state == ZI_FS_TRANSACTION_STATE_FAILED &&
                  volume.needs_recovery != 0);
    s_phase7_memory.fail_operation = 0;
    s_phase7_memory.operation_count = 0;
    ZiFsVolume restarted = {0};
    PHASE7_ASSERT(recover_failed_transaction(&volume.device, &restarted));
    bool old_present =
        verify_named_file(&restarted, old_path, sizeof old_path - 1u, k_payload, true);
    bool new_present =
        verify_named_file(&restarted, renamed_path, sizeof renamed_path - 1u, k_payload, true);
    PHASE7_ASSERT(old_present != new_present);
    if (old_present) {
      PHASE7_ASSERT(
          verify_named_file(&restarted, renamed_path, sizeof renamed_path - 1u, k_payload, false) &&
          restarted.superblock.generation == 1 &&
          restarted.superblock.last_committed_transaction == 0);
    } else {
      PHASE7_ASSERT(
          verify_named_file(&restarted, old_path, sizeof old_path - 1u, k_payload, false) &&
          restarted.superblock.generation == 2 &&
          restarted.superblock.last_committed_transaction == 1);
    }
  }

  PHASE7_ASSERT(initialise_move_fixture(&volume, true));
  zi_memory_copy(s_phase7_snapshot, s_phase7_volume, sizeof s_phase7_snapshot);
  PHASE7_ASSERT(prepare_move(&volume, &transaction, 1, k_upper_name, 2, k_moved_name, &result) &&
                transaction.block_image_count == 3);
  s_phase7_memory.operation_count = 0;
  PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS);
  size_t move_operation_count = s_phase7_memory.operation_count;
  PHASE7_ASSERT(move_operation_count == 25);

  for (size_t fail_operation = 1; fail_operation <= move_operation_count; ++fail_operation) {
    zi_memory_copy(s_phase7_volume, s_phase7_snapshot, sizeof s_phase7_volume);
    PHASE7_ASSERT(mount_transaction_volume(&volume, true));
    zi_memory_zero(&transaction, sizeof transaction);
    zi_memory_zero(&result, sizeof result);
    PHASE7_ASSERT(prepare_move(&volume, &transaction, 1, k_upper_name, 2, k_moved_name, &result));
    s_phase7_memory.operation_count = 0;
    s_phase7_memory.fail_operation = fail_operation;
    PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_DEVICE_ERROR &&
                  transaction.state == ZI_FS_TRANSACTION_STATE_FAILED &&
                  volume.needs_recovery != 0);
    s_phase7_memory.fail_operation = 0;
    s_phase7_memory.operation_count = 0;
    ZiFsVolume restarted = {0};
    PHASE7_ASSERT(recover_failed_transaction(&volume.device, &restarted));
    bool old_present =
        verify_named_file(&restarted, old_path, sizeof old_path - 1u, k_payload, true);
    bool new_present =
        verify_named_file(&restarted, moved_path, sizeof moved_path - 1u, k_payload, true);
    PHASE7_ASSERT(old_present != new_present);
    if (old_present) {
      PHASE7_ASSERT(
          verify_named_file(&restarted, moved_path, sizeof moved_path - 1u, k_payload, false) &&
          restarted.superblock.generation == 1 &&
          restarted.superblock.last_committed_transaction == 0);
    } else {
      PHASE7_ASSERT(
          verify_named_file(&restarted, old_path, sizeof old_path - 1u, k_payload, false) &&
          restarted.superblock.generation == 2 &&
          restarted.superblock.last_committed_transaction == 1);
    }
  }
  return true;
}

// Truncate and delete expose deferred extents while keeping the live bitmap unchanged.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static bool test_truncate_delete_contract(void) {
  static const ZiStringView k_file_name = {"Temp", sizeof "Temp" - 1u};
  static const ZiStringView k_lower_name = {"temp", sizeof "temp" - 1u};
  static const ZiStringView k_child_name = {"Child", sizeof "Child" - 1u};
  static const ZiStringView k_probe_name = {"After Checkpoint.bin",
                                            sizeof "After Checkpoint.bin" - 1u};
  const char file_path[] = "C:\\Source Space\\Temp";
  for (size_t index = 0; index < sizeof s_phase7_payload; ++index) {
    s_phase7_payload[index] = (unsigned char)(index ^ (index >> 8u) ^ UINT8_C(0xa5));
  }

  ZiFsVolume volume = {0};
  PHASE7_ASSERT(initialise_move_fixture(&volume, false));
  ZiFsTransaction transaction = {0};
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionInitialise(&transaction,
                                                      &volume,
                                                      s_phase7_workspace,
                                                      sizeof s_phase7_workspace)));
  ZiFsTruncateRequest truncate_request = {
      sizeof(ZiFsTruncateRequest),
      ZI_FS_TRUNCATE_REQUEST_VERSION,
      4,
      sizeof s_phase7_payload,
      UINT64_C(23000000),
      ZI_FS_TRUNCATE_FLAG_NONE,
      0,
  };
  ZiFsTruncateResult truncate_result = {0};
  truncate_request.version = 0;
  PHASE7_ASSERT(ZiFsTransactionPrepareTruncate(&transaction, &truncate_request, &truncate_result) ==
                ZI_STATUS_INVALID_ARGUMENT);
  truncate_request.version = ZI_FS_TRUNCATE_REQUEST_VERSION;
  truncate_request.flags = 1;
  PHASE7_ASSERT(ZiFsTransactionPrepareTruncate(&transaction, &truncate_request, &truncate_result) ==
                ZI_STATUS_INVALID_ARGUMENT);
  truncate_request.flags = ZI_FS_TRUNCATE_FLAG_NONE;
  truncate_request.new_size = sizeof s_phase7_payload + 1u;
  PHASE7_ASSERT(ZiFsTransactionPrepareTruncate(&transaction, &truncate_request, &truncate_result) ==
                ZI_STATUS_NOT_IMPLEMENTED);
  truncate_request.record_index = 1;
  truncate_request.new_size = 0;
  PHASE7_ASSERT(ZiFsTransactionPrepareTruncate(&transaction, &truncate_request, &truncate_result) ==
                ZI_STATUS_INVALID_ARGUMENT);
  truncate_request.record_index = 4;
  truncate_request.new_size = sizeof s_phase7_payload;
  PHASE7_ASSERT(ZiSucceeded(
      ZiFsTransactionPrepareTruncate(&transaction, &truncate_request, &truncate_result)));
  PHASE7_ASSERT(transaction.block_image_count == 2 && transaction.deferred_extent_count == 0 &&
                truncate_result.previous_size == sizeof s_phase7_payload &&
                truncate_result.new_size == sizeof s_phase7_payload &&
                truncate_result.released_block_count == 0);
  ZiFsDeferredExtent deferred = {0};
  PHASE7_ASSERT(ZiFsTransactionGetDeferredExtent(&transaction, 0, &deferred) ==
                ZI_STATUS_INVALID_ARGUMENT);
  PHASE7_ASSERT(ZiFsTransactionReset(&transaction) == ZI_STATUS_SUCCESS);

  truncate_request.new_size = 1000;
  PHASE7_ASSERT(ZiSucceeded(
      ZiFsTransactionPrepareTruncate(&transaction, &truncate_request, &truncate_result)));
  PHASE7_ASSERT(transaction.block_image_count == 3 && transaction.deferred_extent_count == 1 &&
                truncate_result.file_id == PHASE7_MOVED_FILE_ID &&
                truncate_result.record_index == 4 && truncate_result.previous_size == 5000 &&
                truncate_result.new_size == 1000 && truncate_result.retained_block_count == 1 &&
                truncate_result.released_block_count == 1);
  PHASE7_ASSERT(ZiFsTransactionGetDeferredExtent(&transaction, 0, &deferred) == ZI_STATUS_SUCCESS &&
                deferred.first_block == PHASE7_FIRST_DATA_BLOCK + 1u && deferred.block_count == 1);
  ZiConstBuffer image = {0};
  PHASE7_ASSERT(find_transaction_image(&transaction, PHASE7_RECORD_TABLE_START, &image));
  ZiFsFileRecord changed = {0};
  PHASE7_ASSERT(ZiSucceeded(ZiFsDecodeFileRecord((const unsigned char*)image.data +
                                                     ((size_t)4u * ZI_FS_FILE_RECORD_SIZE),
                                                 ZI_FS_FILE_RECORD_SIZE,
                                                 &changed)) &&
                changed.file_size == 1000 && changed.allocated_size == ZI_FS_BLOCK_SIZE &&
                changed.extent_count == 1 && changed.extents[0].block_count == 1 &&
                changed.modified_time == UINT64_C(23000000));
  PHASE7_ASSERT(find_transaction_image(&transaction, PHASE7_FIRST_DATA_BLOCK, &image) &&
                zi_memory_compare(image.data, s_phase7_payload, 1000) == 0);
  bool tail_zero = true;
  for (size_t index = 1000; index < ZI_FS_BLOCK_SIZE; ++index) {
    if (((const unsigned char*)image.data)[index] != 0) {
      tail_zero = false;
      break;
    }
  }
  PHASE7_ASSERT(tail_zero);
  PHASE7_ASSERT(find_transaction_image(&transaction, PHASE7_BITMAP_BLOCK, &image));
  bool allocated = false;
  PHASE7_ASSERT(ZiSucceeded(ZiFsAllocationBitQuery(image.data,
                                                   image.size,
                                                   PHASE7_FIRST_DATA_BLOCK + 1u,
                                                   &allocated)) &&
                !allocated);
  PHASE7_ASSERT(query_allocation_bit(&volume, PHASE7_FIRST_DATA_BLOCK + 1u, &allocated) &&
                allocated);
  PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_READ_ONLY_FILESYSTEM);

  PHASE7_ASSERT(initialise_move_fixture(&volume, false));
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionInitialise(&transaction,
                                                      &volume,
                                                      s_phase7_workspace,
                                                      ZI_FS_TRANSACTION_MINIMUM_WORKSPACE_SIZE)));
  PHASE7_ASSERT(ZiFsTransactionPrepareTruncate(&transaction, &truncate_request, &truncate_result) ==
                    ZI_STATUS_BUFFER_TOO_SMALL &&
                transaction.state == ZI_FS_TRANSACTION_STATE_READY &&
                transaction.block_image_count == 0 && transaction.deferred_extent_count == 0);

  PHASE7_ASSERT(initialise_move_fixture(&volume, false));
  PHASE7_ASSERT(ZiSucceeded(ZiFsAllocationBitSet(s_phase7_volume[PHASE7_BITMAP_BLOCK],
                                                 ZI_FS_BLOCK_SIZE,
                                                 PHASE7_FIRST_DATA_BLOCK + 1u,
                                                 false)));
  PHASE7_ASSERT(mount_transaction_volume(&volume, false));
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionInitialise(&transaction,
                                                      &volume,
                                                      s_phase7_workspace,
                                                      sizeof s_phase7_workspace)));
  PHASE7_ASSERT(ZiFsTransactionPrepareTruncate(&transaction, &truncate_request, &truncate_result) ==
                ZI_STATUS_CORRUPT_FILESYSTEM);

  PHASE7_ASSERT(initialise_move_fixture(&volume, false));
  ZiFsFileRecord cross_link = {0};
  cross_link.file_id = PHASE7_OCCUPIED_FILE_ID;
  cross_link.parent_file_id = PHASE7_TARGET_FILE_ID;
  cross_link.file_type = ZI_FS_FILE_TYPE_REGULAR;
  cross_link.file_size = 1;
  cross_link.allocated_size = ZI_FS_BLOCK_SIZE;
  cross_link.security_id = 1;
  cross_link.extent_count = 1;
  cross_link.extents[0].physical_block = PHASE7_FIRST_DATA_BLOCK + 1u;
  cross_link.extents[0].block_count = 1;
  PHASE7_ASSERT(ZiSucceeded(ZiFsEncodeFileRecord(&cross_link,
                                                 s_phase7_volume[PHASE7_RECORD_TABLE_START] +
                                                     ((size_t)5u * ZI_FS_FILE_RECORD_SIZE),
                                                 ZI_FS_FILE_RECORD_SIZE)));
  PHASE7_ASSERT(mount_transaction_volume(&volume, false));
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionInitialise(&transaction,
                                                      &volume,
                                                      s_phase7_workspace,
                                                      sizeof s_phase7_workspace)));
  PHASE7_ASSERT(ZiFsTransactionPrepareTruncate(&transaction, &truncate_request, &truncate_result) ==
                ZI_STATUS_CORRUPT_FILESYSTEM);

  PHASE7_ASSERT(initialise_move_fixture(&volume, true));
  PHASE7_ASSERT(prepare_truncate(&volume, &transaction, 1000, &truncate_result));
  ZiFsTransaction speculative = {0};
  ZiFsCreateResult create_result = {0};
  PHASE7_ASSERT(prepare_named_create_in_workspace(
                    &volume,
                    &speculative,
                    s_phase7_second_workspace,
                    sizeof s_phase7_second_workspace,
                    (ZiStringView){"Before Checkpoint.bin", sizeof "Before Checkpoint.bin" - 1u},
                    (ZiConstBuffer){s_phase7_payload, 1},
                    &create_result) &&
                create_result.first_data_block == PHASE7_FIRST_DATA_BLOCK + 2u);
  PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS);
  PHASE7_ASSERT(ZiFsTransactionCommit(&speculative) == ZI_STATUS_RECOVERY_REQUIRED);
  PHASE7_ASSERT(verify_named_file(&volume,
                                  file_path,
                                  sizeof file_path - 1u,
                                  (ZiConstBuffer){s_phase7_payload, 1000},
                                  true));
  PHASE7_ASSERT(query_allocation_bit(&volume, PHASE7_FIRST_DATA_BLOCK, &allocated) && allocated);
  PHASE7_ASSERT(query_allocation_bit(&volume, PHASE7_FIRST_DATA_BLOCK + 1u, &allocated) &&
                !allocated);
  zi_memory_zero(&transaction, sizeof transaction);
  zi_memory_zero(&create_result, sizeof create_result);
  PHASE7_ASSERT(prepare_named_create(&volume,
                                     &transaction,
                                     k_probe_name,
                                     (ZiConstBuffer){s_phase7_payload, 1},
                                     &create_result) &&
                create_result.first_data_block == PHASE7_FIRST_DATA_BLOCK + 1u);

  PHASE7_ASSERT(initialise_move_fixture(&volume, false));
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionInitialise(&transaction,
                                                      &volume,
                                                      s_phase7_workspace,
                                                      sizeof s_phase7_workspace)));
  ZiFsDeleteRequest delete_request = {
      sizeof(ZiFsDeleteRequest),
      ZI_FS_DELETE_REQUEST_VERSION,
      1,
      UINT64_C(24000000),
      ZI_FS_DELETE_FLAG_NONE,
      0,
      k_lower_name,
  };
  ZiFsDeleteResult delete_result = {0};
  PHASE7_ASSERT(ZiFsTransactionPrepareDelete(&transaction, &delete_request, &delete_result) ==
                ZI_STATUS_NOT_FOUND);
  const char invalid_utf8[] = {(char)0xc0, (char)0x80};
  delete_request.name = (ZiStringView){invalid_utf8, sizeof invalid_utf8};
  PHASE7_ASSERT(ZiFsTransactionPrepareDelete(&transaction, &delete_request, &delete_result) ==
                ZI_STATUS_INVALID_ENCODING);
  delete_request.name = (ZiStringView){"Bad\\Name", sizeof "Bad\\Name" - 1u};
  PHASE7_ASSERT(ZiFsTransactionPrepareDelete(&transaction, &delete_request, &delete_result) ==
                ZI_STATUS_INVALID_PATH);
  delete_request.name = k_child_name;
  PHASE7_ASSERT(ZiFsTransactionPrepareDelete(&transaction, &delete_request, &delete_result) ==
                ZI_STATUS_NOT_IMPLEMENTED);

  PHASE7_ASSERT(initialise_move_fixture(&volume, false));
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionInitialise(&transaction,
                                                      &volume,
                                                      s_phase7_workspace,
                                                      ZI_FS_TRANSACTION_MINIMUM_WORKSPACE_SIZE)));
  delete_request.name = k_file_name;
  PHASE7_ASSERT(ZiFsTransactionPrepareDelete(&transaction, &delete_request, &delete_result) ==
                    ZI_STATUS_BUFFER_TOO_SMALL &&
                transaction.state == ZI_FS_TRANSACTION_STATE_READY &&
                transaction.block_image_count == 0 && transaction.deferred_extent_count == 0);

  PHASE7_ASSERT(initialise_move_fixture(&volume, true));
  PHASE7_ASSERT(prepare_delete(&volume, &transaction, k_file_name, &delete_result));
  PHASE7_ASSERT(transaction.block_image_count == 3 && transaction.deferred_extent_count == 1 &&
                delete_result.file_id == PHASE7_MOVED_FILE_ID && delete_result.record_index == 4 &&
                delete_result.parent_file_id == PHASE7_SOURCE_FILE_ID &&
                delete_result.released_block_count == 2);
  PHASE7_ASSERT(ZiFsTransactionGetDeferredExtent(&transaction, 0, &deferred) == ZI_STATUS_SUCCESS &&
                deferred.first_block == PHASE7_FIRST_DATA_BLOCK && deferred.block_count == 2);
  PHASE7_ASSERT(query_allocation_bit(&volume, PHASE7_FIRST_DATA_BLOCK, &allocated) && allocated);
  PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS);
  PHASE7_ASSERT(verify_named_file(&volume,
                                  file_path,
                                  sizeof file_path - 1u,
                                  (ZiConstBuffer){s_phase7_payload, sizeof s_phase7_payload},
                                  false));
  PHASE7_ASSERT(query_allocation_bit(&volume, PHASE7_FIRST_DATA_BLOCK, &allocated) && !allocated);
  PHASE7_ASSERT(query_allocation_bit(&volume, PHASE7_FIRST_DATA_BLOCK + 1u, &allocated) &&
                !allocated);
  zi_memory_zero(&transaction, sizeof transaction);
  zi_memory_zero(&create_result, sizeof create_result);
  PHASE7_ASSERT(prepare_named_create(&volume,
                                     &transaction,
                                     k_probe_name,
                                     (ZiConstBuffer){s_phase7_payload, 1},
                                     &create_result) &&
                create_result.first_data_block == PHASE7_FIRST_DATA_BLOCK);
  return true;
}

// Every truncate/delete write and flush boundary must recover to one reusable allocation state.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static bool test_reclamation_fault_boundaries(void) {
  static const ZiStringView k_file_name = {"Temp", sizeof "Temp" - 1u};
  static const ZiStringView k_probe_name = {"Reuse Probe.bin", sizeof "Reuse Probe.bin" - 1u};
  const char file_path[] = "C:\\Source Space\\Temp";
  static const ZiConstBuffer k_full_data = {s_phase7_payload, sizeof s_phase7_payload};
  static const ZiConstBuffer k_short_data = {s_phase7_payload, 1000};
  for (size_t index = 0; index < sizeof s_phase7_payload; ++index) {
    s_phase7_payload[index] = (unsigned char)(index ^ (index >> 8u) ^ UINT8_C(0xa5));
  }

  ZiFsVolume volume = {0};
  PHASE7_ASSERT(initialise_move_fixture(&volume, true));
  zi_memory_copy(s_phase7_snapshot, s_phase7_volume, sizeof s_phase7_snapshot);
  ZiFsTransaction transaction = {0};
  ZiFsTruncateResult truncate_result = {0};
  PHASE7_ASSERT(prepare_truncate(&volume, &transaction, 1000, &truncate_result));
  s_phase7_memory.operation_count = 0;
  PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS);
  size_t truncate_operation_count = s_phase7_memory.operation_count;
  PHASE7_ASSERT(truncate_operation_count > 0 && truncate_operation_count < 100);

  size_t truncated_count = 0;
  size_t original_count = 0;
  for (size_t fail_operation = 1; fail_operation <= truncate_operation_count; ++fail_operation) {
    zi_memory_copy(s_phase7_volume, s_phase7_snapshot, sizeof s_phase7_volume);
    PHASE7_ASSERT(mount_transaction_volume(&volume, true));
    zi_memory_zero(&transaction, sizeof transaction);
    zi_memory_zero(&truncate_result, sizeof truncate_result);
    PHASE7_ASSERT(prepare_truncate(&volume, &transaction, 1000, &truncate_result));
    s_phase7_memory.operation_count = 0;
    s_phase7_memory.fail_operation = fail_operation;
    PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_DEVICE_ERROR &&
                  transaction.state == ZI_FS_TRANSACTION_STATE_FAILED &&
                  volume.needs_recovery != 0);
    s_phase7_memory.fail_operation = 0;
    s_phase7_memory.operation_count = 0;
    ZiFsTransaction blocked = {0};
    PHASE7_ASSERT(ZiFsTransactionInitialise(&blocked,
                                            &volume,
                                            s_phase7_second_workspace,
                                            sizeof s_phase7_second_workspace) ==
                  ZI_STATUS_RECOVERY_REQUIRED);
    ZiFsVolume restarted = {0};
    PHASE7_ASSERT(recover_failed_transaction(&volume.device, &restarted));
    bool truncated =
        verify_named_file(&restarted, file_path, sizeof file_path - 1u, k_short_data, true);
    bool original =
        verify_named_file(&restarted, file_path, sizeof file_path - 1u, k_full_data, true);
    PHASE7_ASSERT(truncated != original);
    bool first_allocated = false;
    bool second_allocated = false;
    PHASE7_ASSERT(
        query_allocation_bit(&restarted, PHASE7_FIRST_DATA_BLOCK, &first_allocated) &&
        query_allocation_bit(&restarted, PHASE7_FIRST_DATA_BLOCK + 1u, &second_allocated) &&
        first_allocated);
    if (truncated) {
      ++truncated_count;
      PHASE7_ASSERT(!second_allocated && restarted.superblock.generation == 2 &&
                    restarted.superblock.last_committed_transaction == 1);
    } else {
      ++original_count;
      PHASE7_ASSERT(second_allocated && restarted.superblock.generation == 1 &&
                    restarted.superblock.last_committed_transaction == 0);
    }
    ZiFsCreateResult create_result = {0};
    zi_memory_zero(&blocked, sizeof blocked);
    PHASE7_ASSERT(prepare_named_create_in_workspace(&restarted,
                                                    &blocked,
                                                    s_phase7_second_workspace,
                                                    sizeof s_phase7_second_workspace,
                                                    k_probe_name,
                                                    (ZiConstBuffer){s_phase7_payload, 1},
                                                    &create_result));
    PHASE7_ASSERT(create_result.first_data_block ==
                  (truncated ? PHASE7_FIRST_DATA_BLOCK + 1u : PHASE7_FIRST_DATA_BLOCK + 2u));
  }
  PHASE7_ASSERT(truncated_count > 0 && original_count > 0);

  PHASE7_ASSERT(initialise_move_fixture(&volume, true));
  zi_memory_copy(s_phase7_snapshot, s_phase7_volume, sizeof s_phase7_snapshot);
  ZiFsDeleteResult delete_result = {0};
  PHASE7_ASSERT(prepare_delete(&volume, &transaction, k_file_name, &delete_result));
  s_phase7_memory.operation_count = 0;
  PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS);
  size_t delete_operation_count = s_phase7_memory.operation_count;
  PHASE7_ASSERT(delete_operation_count > 0 && delete_operation_count < 100);

  size_t deleted_count = 0;
  size_t present_count = 0;
  for (size_t fail_operation = 1; fail_operation <= delete_operation_count; ++fail_operation) {
    zi_memory_copy(s_phase7_volume, s_phase7_snapshot, sizeof s_phase7_volume);
    PHASE7_ASSERT(mount_transaction_volume(&volume, true));
    zi_memory_zero(&transaction, sizeof transaction);
    zi_memory_zero(&delete_result, sizeof delete_result);
    PHASE7_ASSERT(prepare_delete(&volume, &transaction, k_file_name, &delete_result));
    s_phase7_memory.operation_count = 0;
    s_phase7_memory.fail_operation = fail_operation;
    PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_DEVICE_ERROR &&
                  transaction.state == ZI_FS_TRANSACTION_STATE_FAILED &&
                  volume.needs_recovery != 0);
    s_phase7_memory.fail_operation = 0;
    s_phase7_memory.operation_count = 0;
    ZiFsTransaction blocked = {0};
    PHASE7_ASSERT(ZiFsTransactionInitialise(&blocked,
                                            &volume,
                                            s_phase7_second_workspace,
                                            sizeof s_phase7_second_workspace) ==
                  ZI_STATUS_RECOVERY_REQUIRED);
    ZiFsVolume restarted = {0};
    PHASE7_ASSERT(recover_failed_transaction(&volume.device, &restarted));
    bool present =
        verify_named_file(&restarted, file_path, sizeof file_path - 1u, k_full_data, true);
    bool deleted =
        verify_named_file(&restarted, file_path, sizeof file_path - 1u, k_full_data, false);
    PHASE7_ASSERT(present != deleted);
    bool first_allocated = false;
    bool second_allocated = false;
    PHASE7_ASSERT(
        query_allocation_bit(&restarted, PHASE7_FIRST_DATA_BLOCK, &first_allocated) &&
        query_allocation_bit(&restarted, PHASE7_FIRST_DATA_BLOCK + 1u, &second_allocated));
    if (deleted) {
      ++deleted_count;
      PHASE7_ASSERT(!first_allocated && !second_allocated && restarted.superblock.generation == 2 &&
                    restarted.superblock.last_committed_transaction == 1);
    } else {
      ++present_count;
      PHASE7_ASSERT(first_allocated && second_allocated && restarted.superblock.generation == 1 &&
                    restarted.superblock.last_committed_transaction == 0);
    }
    ZiFsCreateResult create_result = {0};
    zi_memory_zero(&blocked, sizeof blocked);
    PHASE7_ASSERT(prepare_named_create_in_workspace(&restarted,
                                                    &blocked,
                                                    s_phase7_second_workspace,
                                                    sizeof s_phase7_second_workspace,
                                                    k_probe_name,
                                                    (ZiConstBuffer){s_phase7_payload, 1},
                                                    &create_result));
    PHASE7_ASSERT(create_result.first_data_block ==
                  (deleted ? PHASE7_FIRST_DATA_BLOCK : PHASE7_FIRST_DATA_BLOCK + 2u));
  }
  PHASE7_ASSERT(deleted_count > 0 && present_count > 0);
  return true;
}

// Growth covers an existing partial block, a new block, allocation, and the record in one redo set.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static bool test_write_growth_contract(void) {
  const char file_path[] = "C:\\Source Space\\Temp";
  for (size_t index = 0; index < sizeof s_phase7_payload; ++index) {
    s_phase7_payload[index] = (unsigned char)(index ^ (index >> 8u) ^ UINT8_C(0xa5));
    s_phase7_growth_expected[index] = s_phase7_payload[index];
    s_phase7_growth_expected[sizeof s_phase7_payload + index] =
        (unsigned char)(index ^ (index >> 7u) ^ UINT8_C(0x3c));
  }

  ZiFsVolume volume = {0};
  PHASE7_ASSERT(initialise_move_fixture(&volume, true));
  ZiFsTransaction transaction = {0};
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionInitialise(&transaction,
                                                      &volume,
                                                      s_phase7_workspace,
                                                      sizeof s_phase7_workspace)));
  ZiFsWriteRequest request = {
      sizeof(ZiFsWriteRequest),
      ZI_FS_WRITE_REQUEST_VERSION,
      4,
      sizeof s_phase7_payload + 1u,
      UINT64_C(25000000),
      ZI_FS_WRITE_FLAG_NONE,
      0,
      {s_phase7_growth_expected + sizeof s_phase7_payload, 1},
  };
  ZiFsWriteResult result = {0};
  PHASE7_ASSERT(ZiFsTransactionPrepareWrite(&transaction, &request, &result) ==
                    ZI_STATUS_NOT_IMPLEMENTED &&
                transaction.block_image_count == 0);
  request.offset = sizeof s_phase7_payload;
  request.data = (ZiConstBuffer){NULL, 0};
  PHASE7_ASSERT(ZiFsTransactionPrepareWrite(&transaction, &request, &result) ==
                ZI_STATUS_INVALID_ARGUMENT);
  request.data =
      (ZiConstBuffer){s_phase7_large_payload,
                      ((size_t)ZI_FS_TRANSACTION_MAXIMUM_DATA_BLOCKS * ZI_FS_BLOCK_SIZE) + 1u};
  PHASE7_ASSERT(ZiFsTransactionPrepareWrite(&transaction, &request, &result) ==
                ZI_STATUS_INVALID_ARGUMENT);

  request.data =
      (ZiConstBuffer){s_phase7_growth_expected + sizeof s_phase7_payload, sizeof s_phase7_payload};
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionPrepareWrite(&transaction, &request, &result)));
  PHASE7_ASSERT(result.struct_size == sizeof result &&
                result.version == ZI_FS_WRITE_RESULT_VERSION &&
                result.file_id == PHASE7_MOVED_FILE_ID && result.record_index == 4 &&
                result.previous_size == sizeof s_phase7_payload &&
                result.new_size == sizeof s_phase7_growth_expected &&
                result.bytes_written == sizeof s_phase7_payload &&
                result.allocated_block_count == 1 && transaction.block_image_count == 4);
  ZiConstBuffer image = {0};
  PHASE7_ASSERT(find_transaction_image(&transaction, PHASE7_RECORD_TABLE_START, &image));
  ZiFsFileRecord changed = {0};
  PHASE7_ASSERT(ZiSucceeded(ZiFsDecodeFileRecord((const unsigned char*)image.data +
                                                     ((size_t)4u * ZI_FS_FILE_RECORD_SIZE),
                                                 ZI_FS_FILE_RECORD_SIZE,
                                                 &changed)) &&
                changed.file_size == sizeof s_phase7_growth_expected && changed.extent_count == 1 &&
                changed.extents[0].physical_block == PHASE7_FIRST_DATA_BLOCK &&
                changed.extents[0].block_count == 3 &&
                changed.allocated_size == UINT64_C(3) * ZI_FS_BLOCK_SIZE);
  PHASE7_ASSERT(find_transaction_image(&transaction, PHASE7_FIRST_DATA_BLOCK + 1u, &image) &&
                zi_memory_compare(
                    (const unsigned char*)image.data + (sizeof s_phase7_payload - ZI_FS_BLOCK_SIZE),
                    s_phase7_growth_expected + sizeof s_phase7_payload,
                    ZI_FS_BLOCK_SIZE - (sizeof s_phase7_payload - ZI_FS_BLOCK_SIZE)) == 0);
  PHASE7_ASSERT(find_transaction_image(&transaction, PHASE7_FIRST_DATA_BLOCK + 2u, &image));
  PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS);
  PHASE7_ASSERT(
      verify_named_file(&volume,
                        file_path,
                        sizeof file_path - 1u,
                        (ZiConstBuffer){s_phase7_growth_expected, sizeof s_phase7_growth_expected},
                        true));

  PHASE7_ASSERT(initialise_move_fixture(&volume, true));
  zi_memory_copy(s_phase7_snapshot, s_phase7_volume, sizeof s_phase7_snapshot);
  zi_memory_zero(&transaction, sizeof transaction);
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionInitialise(&transaction,
                                                      &volume,
                                                      s_phase7_workspace,
                                                      sizeof s_phase7_workspace)));
  request.offset = sizeof s_phase7_payload;
  PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionPrepareWrite(&transaction, &request, &result)));
  s_phase7_memory.operation_count = 0;
  PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS);
  size_t operation_count = s_phase7_memory.operation_count;
  PHASE7_ASSERT(operation_count > 0 && operation_count < 100);
  size_t old_state_count = 0;
  size_t new_state_count = 0;
  for (size_t fail_operation = 1; fail_operation <= operation_count; ++fail_operation) {
    zi_memory_copy(s_phase7_volume, s_phase7_snapshot, sizeof s_phase7_volume);
    PHASE7_ASSERT(mount_transaction_volume(&volume, true));
    zi_memory_zero(&transaction, sizeof transaction);
    PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionInitialise(&transaction,
                                                        &volume,
                                                        s_phase7_workspace,
                                                        sizeof s_phase7_workspace)));
    PHASE7_ASSERT(ZiSucceeded(ZiFsTransactionPrepareWrite(&transaction, &request, &result)));
    s_phase7_memory.operation_count = 0;
    s_phase7_memory.fail_operation = fail_operation;
    PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_DEVICE_ERROR);
    s_phase7_memory.fail_operation = 0;
    ZiFsVolume restarted = {0};
    PHASE7_ASSERT(recover_failed_transaction(&volume.device, &restarted));
    bool old_state = verify_named_file(&restarted,
                                       file_path,
                                       sizeof file_path - 1u,
                                       (ZiConstBuffer){s_phase7_payload, sizeof s_phase7_payload},
                                       true);
    bool new_state = verify_named_file(
        &restarted,
        file_path,
        sizeof file_path - 1u,
        (ZiConstBuffer){s_phase7_growth_expected, sizeof s_phase7_growth_expected},
        true);
    PHASE7_ASSERT(old_state != new_state);
    bool third_block_allocated = false;
    PHASE7_ASSERT(
        query_allocation_bit(&restarted, PHASE7_FIRST_DATA_BLOCK + 2u, &third_block_allocated));
    if (new_state) {
      ++new_state_count;
      PHASE7_ASSERT(third_block_allocated && restarted.superblock.generation == 2);
    } else {
      ++old_state_count;
      PHASE7_ASSERT(!third_block_allocated && restarted.superblock.generation == 1);
    }
  }
  PHASE7_ASSERT(old_state_count > 0 && new_state_count > 0);
  return true;
}

// Repeated valid creates force a directory continuation block, then exercise its lookup and edits.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static bool test_directory_expansion_contract(void) {
  ZiFsVolume volume = {0};
  PHASE7_ASSERT(initialise_transaction_volume(&volume, true));
  PHASE7_ASSERT(enable_directory_extents(&volume, true));
  char long_name[220];
  for (size_t index = 0; index < sizeof long_name; ++index) {
    long_name[index] = 'D';
  }
  ZiFsTransaction transaction = {0};
  ZiFsCreateResult create_result = {0};
  bool expansion_faults_exercised = false;
  size_t expansion_old_state_count = 0;
  size_t expansion_new_state_count = 0;
  for (size_t index = 0; index < 18; ++index) {
    long_name[sizeof long_name - 2u] = (char)('A' + (index / 26u));
    long_name[sizeof long_name - 1u] = (char)('A' + (index % 26u));
    ZiFsFileRecord current_root = {0};
    PHASE7_ASSERT(ZiSucceeded(ZiFsReadFileRecord(&volume,
                                                 volume.superblock.root_record_index,
                                                 s_phase7_recovery_workspace,
                                                 ZI_FS_BLOCK_SIZE,
                                                 &current_root)));
    zi_memory_zero(&transaction, sizeof transaction);
    PHASE7_ASSERT(prepare_named_create(&volume,
                                       &transaction,
                                       (ZiStringView){long_name, sizeof long_name},
                                       (ZiConstBuffer){NULL, 0},
                                       &create_result));

    ZiConstBuffer record_image = {0};
    ZiFsFileRecord staged_root = {0};
    PHASE7_ASSERT(
        find_transaction_image(&transaction, volume.superblock.record_table_start, &record_image) &&
        ZiSucceeded(ZiFsDecodeFileRecord(record_image.data, ZI_FS_FILE_RECORD_SIZE, &staged_root)));
    bool expands_directory = staged_root.extent_count > current_root.extent_count;
    if (expands_directory) {
      PHASE7_ASSERT(
          !expansion_faults_exercised && current_root.extent_count == 0 &&
          staged_root.extent_count == 1 && staged_root.allocated_size == ZI_FS_BLOCK_SIZE &&
          staged_root.extents[0].logical_block == 1 && staged_root.extents[0].block_count == 1);
      uint64_t continuation_block = staged_root.extents[0].physical_block;
      uint64_t source_generation = volume.superblock.generation;
      char expansion_path[3u + sizeof long_name];
      expansion_path[0] = 'C';
      expansion_path[1] = ':';
      expansion_path[2] = '\\';
      zi_memory_copy(expansion_path + 3, long_name, sizeof long_name);
      zi_memory_copy(s_phase7_snapshot, s_phase7_volume, sizeof s_phase7_snapshot);

      s_phase7_memory.operation_count = 0;
      PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS);
      size_t operation_count = s_phase7_memory.operation_count;
      PHASE7_ASSERT(operation_count > 0 && operation_count < 100 &&
                    verify_named_file(&volume,
                                      expansion_path,
                                      sizeof expansion_path,
                                      (ZiConstBuffer){NULL, 0},
                                      true));

      for (size_t fail_operation = 1; fail_operation <= operation_count; ++fail_operation) {
        zi_memory_copy(s_phase7_volume, s_phase7_snapshot, sizeof s_phase7_volume);
        PHASE7_ASSERT(mount_transaction_volume(&volume, true));
        zi_memory_zero(&transaction, sizeof transaction);
        PHASE7_ASSERT(prepare_named_create(&volume,
                                           &transaction,
                                           (ZiStringView){long_name, sizeof long_name},
                                           (ZiConstBuffer){NULL, 0},
                                           &create_result));
        s_phase7_memory.operation_count = 0;
        s_phase7_memory.fail_operation = fail_operation;
        PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_DEVICE_ERROR);
        s_phase7_memory.fail_operation = 0;

        ZiFsVolume restarted = {0};
        PHASE7_ASSERT(recover_failed_transaction(&volume.device, &restarted));
        bool old_state = verify_named_file(&restarted,
                                           expansion_path,
                                           sizeof expansion_path,
                                           (ZiConstBuffer){NULL, 0},
                                           false);
        bool new_state = verify_named_file(&restarted,
                                           expansion_path,
                                           sizeof expansion_path,
                                           (ZiConstBuffer){NULL, 0},
                                           true);
        PHASE7_ASSERT(old_state != new_state);

        ZiFsFileRecord recovered_root = {0};
        uint64_t recovered_block_count = 0;
        bool continuation_allocated = false;
        PHASE7_ASSERT(
            ZiSucceeded(ZiFsReadFileRecord(&restarted,
                                           restarted.superblock.root_record_index,
                                           s_phase7_recovery_workspace,
                                           ZI_FS_BLOCK_SIZE,
                                           &recovered_root)) &&
            ZiFsDirectoryBlockCount(&restarted, &recovered_root, &recovered_block_count) ==
                ZI_STATUS_SUCCESS &&
            query_allocation_bit(&restarted, continuation_block, &continuation_allocated));
        if (new_state) {
          ++expansion_new_state_count;
          PHASE7_ASSERT(restarted.superblock.generation == source_generation + 1u &&
                        recovered_root.extent_count == 1 && recovered_block_count == 2 &&
                        recovered_root.extents[0].logical_block == 1 &&
                        recovered_root.extents[0].physical_block == continuation_block &&
                        recovered_root.extents[0].block_count == 1 && continuation_allocated);
        } else {
          ++expansion_old_state_count;
          PHASE7_ASSERT(restarted.superblock.generation == source_generation &&
                        recovered_root.extent_count == 0 && recovered_block_count == 1 &&
                        !continuation_allocated);
        }
      }
      PHASE7_ASSERT(expansion_old_state_count > 0 && expansion_new_state_count > 0);

      zi_memory_copy(s_phase7_volume, s_phase7_snapshot, sizeof s_phase7_volume);
      PHASE7_ASSERT(mount_transaction_volume(&volume, true));
      zi_memory_zero(&transaction, sizeof transaction);
      PHASE7_ASSERT(prepare_named_create(&volume,
                                         &transaction,
                                         (ZiStringView){long_name, sizeof long_name},
                                         (ZiConstBuffer){NULL, 0},
                                         &create_result));
      expansion_faults_exercised = true;
    }
    PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS);
  }
  PHASE7_ASSERT(expansion_faults_exercised && expansion_old_state_count > 0 &&
                expansion_new_state_count > 0);

  ZiFsFileRecord root = {0};
  PHASE7_ASSERT(ZiSucceeded(ZiFsReadFileRecord(&volume,
                                               volume.superblock.root_record_index,
                                               s_phase7_recovery_workspace,
                                               ZI_FS_BLOCK_SIZE,
                                               &root)) &&
                root.file_type == ZI_FS_FILE_TYPE_DIRECTORY && root.extent_count == 1 &&
                root.allocated_size == ZI_FS_BLOCK_SIZE && root.extents[0].logical_block == 1 &&
                root.extents[0].block_count == 1);
  uint64_t directory_block_count = 0;
  uint64_t continuation_block = 0;
  PHASE7_ASSERT(
      ZiFsDirectoryBlockCount(&volume, &root, &directory_block_count) == ZI_STATUS_SUCCESS &&
      directory_block_count == 2 &&
      ZiFsDirectoryBlockAt(&volume, &root, 1, &continuation_block) == ZI_STATUS_SUCCESS &&
      continuation_block == root.extents[0].physical_block &&
      ZiFsDirectoryBlockAt(&volume, &root, 2, &continuation_block) == ZI_STATUS_OUT_OF_BOUNDS);
  bool continuation_allocated = false;
  PHASE7_ASSERT(
      query_allocation_bit(&volume, root.extents[0].physical_block, &continuation_allocated) &&
      continuation_allocated);

  char long_path[3u + sizeof long_name];
  long_path[0] = 'C';
  long_path[1] = ':';
  long_path[2] = '\\';
  zi_memory_copy(long_path + 3, long_name, sizeof long_name);
  PHASE7_ASSERT(
      verify_named_file(&volume, long_path, sizeof long_path, (ZiConstBuffer){NULL, 0}, true));
  long_path[3] = 'd';
  PHASE7_ASSERT(
      verify_named_file(&volume, long_path, sizeof long_path, (ZiConstBuffer){NULL, 0}, false));
  long_path[3] = 'D';

  const ZiStringView renamed = {"Continuation Renamed.txt", sizeof "Continuation Renamed.txt" - 1u};
  ZiFsMoveResult move_result = {0};
  zi_memory_zero(&transaction, sizeof transaction);
  PHASE7_ASSERT(prepare_move(&volume,
                             &transaction,
                             0,
                             (ZiStringView){long_name, sizeof long_name},
                             0,
                             renamed,
                             &move_result));
  PHASE7_ASSERT(ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS);
  PHASE7_ASSERT(
      verify_named_file(&volume,
                        "C:\\Continuation Renamed.txt",
                        sizeof "C:\\Continuation Renamed.txt" - 1u,
                        (ZiConstBuffer){NULL, 0},
                        true) &&
      verify_named_file(&volume, long_path, sizeof long_path, (ZiConstBuffer){NULL, 0}, false));

  ZiFsDeleteRequest delete_request = {
      sizeof(ZiFsDeleteRequest),
      ZI_FS_DELETE_REQUEST_VERSION,
      0,
      UINT64_C(26000000),
      ZI_FS_DELETE_FLAG_NONE,
      0,
      renamed,
  };
  ZiFsDeleteResult delete_result = {0};
  zi_memory_zero(&transaction, sizeof transaction);
  PHASE7_ASSERT(
      ZiSucceeded(ZiFsTransactionInitialise(&transaction,
                                            &volume,
                                            s_phase7_workspace,
                                            sizeof s_phase7_workspace)) &&
      ZiSucceeded(ZiFsTransactionPrepareDelete(&transaction, &delete_request, &delete_result)) &&
      ZiFsTransactionCommit(&transaction) == ZI_STATUS_SUCCESS &&
      verify_named_file(&volume,
                        "C:\\Continuation Renamed.txt",
                        sizeof "C:\\Continuation Renamed.txt" - 1u,
                        (ZiConstBuffer){NULL, 0},
                        false));

  PHASE7_ASSERT(initialise_transaction_volume(&volume, true));
  PHASE7_ASSERT(enable_directory_extents(&volume, true));
  PHASE7_ASSERT(ZiSucceeded(
      ZiFsReadFileRecord(&volume, 0, s_phase7_recovery_workspace, ZI_FS_BLOCK_SIZE, &root)));
  root.allocated_size = ZI_FS_BLOCK_SIZE;
  root.extent_count = 1;
  root.extents[0].logical_block = 1;
  root.extents[0].physical_block = PHASE7_FIRST_DATA_BLOCK;
  root.extents[0].block_count = 1;
  PHASE7_ASSERT(ZiSucceeded(ZiFsEncodeFileRecord(&root,
                                                 s_phase7_volume[PHASE7_RECORD_TABLE_START],
                                                 ZI_FS_FILE_RECORD_SIZE)) &&
                ZiSucceeded(ZiFsInitialiseDirectoryBlock(s_phase7_volume[PHASE7_FIRST_DATA_BLOCK],
                                                         ZI_FS_BLOCK_SIZE,
                                                         root.file_id,
                                                         1)));
  ZiFsDirectoryEntry duplicate = {
      root.file_id,
      0,
      ZI_FS_FILE_TYPE_DIRECTORY,
      0,
      {"Existing", sizeof "Existing" - 1u},
  };
  PHASE7_ASSERT(ZiSucceeded(ZiFsAddDirectoryEntry(s_phase7_volume[PHASE7_FIRST_DATA_BLOCK],
                                                  ZI_FS_BLOCK_SIZE,
                                                  &duplicate)) &&
                ZiSucceeded(ZiFsAllocationBitSet(s_phase7_volume[PHASE7_BITMAP_BLOCK],
                                                 ZI_FS_BLOCK_SIZE,
                                                 PHASE7_FIRST_DATA_BLOCK,
                                                 true)) &&
                mount_transaction_volume(&volume, true));
  ZiFsDirectoryEntry found = {0};
  uint64_t found_block = 0;
  PHASE7_ASSERT(ZiFsFindDirectoryEntryInRecord(&volume,
                                               &root,
                                               duplicate.name,
                                               s_phase7_recovery_workspace,
                                               ZI_FS_BLOCK_SIZE,
                                               &found,
                                               &found_block) == ZI_STATUS_CORRUPT_FILESYSTEM);
  ZiFsSuperblock unsupported = volume.superblock;
  unsupported.incompatible_features &= ~ZI_FS_FEATURE_INCOMPAT_DIRECTORY_EXTENTS_V1;
  PHASE7_ASSERT(
      ZiSucceeded(ZiFsEncodeSuperblock(&unsupported, s_phase7_volume[0], ZI_FS_BLOCK_SIZE)));
  zi_memory_copy(s_phase7_volume[PHASE7_VOLUME_BLOCKS - 1u], s_phase7_volume[0], ZI_FS_BLOCK_SIZE);
  ZiFsVolume rejected = {0};
  PHASE7_ASSERT(!mount_transaction_volume(&rejected, true));
  return true;
}
