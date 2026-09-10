// SPDX-License-Identifier: GPL-3.0-or-later

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#include <Windows.h>
#include <bcrypt.h>

#include "repair.h"
#include "source.h"
#include "zi/byte_order.h"
#include "zi/zifs.h"
#include "zizium/status.h"

#pragma comment(lib, "bcrypt.lib")

#define REPAIR_TOKEN_BYTES ((size_t)32)
#define REPAIR_TOKEN_TEXT_SIZE ((size_t)64)

enum RepairCommand {
  REPAIR_COMMAND_NONE = 0,
  REPAIR_COMMAND_PLAN = 1,
  REPAIR_COMMAND_APPLY = 2,
};

typedef struct RepairInvocation {
  enum RepairCommand command;
  enum ZiFsRepairSourceMode mode;
  const wchar_t* path;
  const wchar_t* supplied_token;
  char* display_path;
} RepairInvocation;

typedef struct RepairHash {
  BCRYPT_ALG_HANDLE algorithm;
  BCRYPT_HASH_HANDLE hash;
  unsigned char* object;
  DWORD object_size;
} RepairHash;

static int run_invocation(const RepairInvocation* invocation);
static int run_plan(const RepairInvocation* invocation);
static int run_apply(const RepairInvocation* invocation);
static bool parse_invocation(int argc, wchar_t* argv[], RepairInvocation* out_invocation);
static bool parse_mode(const wchar_t* text, enum ZiFsRepairSourceMode* out_mode);
static void print_usage(void);
static void print_plan(const char* path,
                       const ZiFsRepairSource* source,
                       const ZiFsRepairPlan* plan,
                       const char token[REPAIR_TOKEN_TEXT_SIZE + 1u]);
static const char* action_name(const ZiFsRepairAction* action);
static ZiStatus plan_token(const ZiFsRepairPlan* plan, char output[REPAIR_TOKEN_TEXT_SIZE + 1u]);
static ZiStatus hash_begin(RepairHash* out_hash);
static ZiStatus hash_update(RepairHash* hash, const void* data, size_t size);
static ZiStatus hash_u32(RepairHash* hash, uint32_t value);
static ZiStatus hash_u64(RepairHash* hash, uint64_t value);
static ZiStatus hash_finish(RepairHash* hash, unsigned char output[REPAIR_TOKEN_BYTES]);
static void hash_destroy(RepairHash* hash);
static bool token_equal(const char* left, const wchar_t* right);
static char lowercase_hex(unsigned char value);
static const char* status_name(ZiStatus status);
static bool text_equal(const wchar_t* left, const wchar_t* right);
static ZiStatus path_to_utf8(const wchar_t* path, char** out_path);

// NOLINTNEXTLINE(misc-use-internal-linkage) -- Windows CRT entry point.
int wmain(int argc, wchar_t* argv[]) {
  RepairInvocation invocation = {0};
  if (!parse_invocation(argc, argv, &invocation)) {
    print_usage();
    return 2;
  }
  ZiStatus status = path_to_utf8(invocation.path, &invocation.display_path);
  if (ZiFailed(status)) {
    (void)fputs("The UTF-16 input path could not be represented as validated UTF-8.\n", stderr);
    return 2;
  }
  int result = run_invocation(&invocation);
  free(invocation.display_path);
  return result;
}

static int run_invocation(const RepairInvocation* invocation) {
  if (invocation->command == REPAIR_COMMAND_PLAN) {
    return run_plan(invocation);
  }
  return run_apply(invocation);
}

static int run_plan(const RepairInvocation* invocation) {
  ZiFsRepairSource source = {0};
  ZiStatus status = zifs_repair_source_open(invocation->path, invocation->mode, false, &source);
  if (ZiFailed(status)) {
    (void)fprintf_s(stderr,
                    "Unable to open '%s' for ZiFS repair planning (%s, status %d).\n",
                    invocation->display_path,
                    status_name(status),
                    (int)status);
    return 2;
  }
  ZiFsRepairPlan* plan = malloc(sizeof *plan);
  if (plan == NULL) {
    (void)zifs_repair_source_close(&source);
    (void)fputs("Unable to allocate the bounded ZiFS repair plan.\n", stderr);
    return 1;
  }
  status = zifs_repair_plan(&source.volume_device, plan);
  if (ZiFailed(status)) {
    (void)fprintf_s(stderr,
                    "ZiFS repair was refused for '%s' (%s, status %d).\n",
                    invocation->display_path,
                    status_name(status),
                    (int)status);
    free(plan);
    (void)zifs_repair_source_close(&source);
    return 1;
  }
  if (plan->action_count == 0) {
    (void)printf_s("ZiFS repair plan: %s\n", invocation->display_path);
    (void)printf_s("  Container: %s\n", source.container_name);
    (void)puts("  Result: no repair is required; the volume is already valid and clean");
    free(plan);
    status = zifs_repair_source_close(&source);
    if (ZiFailed(status)) {
      return 1;
    }
    return 0;
  }
  char token[REPAIR_TOKEN_TEXT_SIZE + 1u] = {0};
  status = plan_token(plan, token);
  if (ZiSucceeded(status)) {
    print_plan(invocation->display_path, &source, plan, token);
  }
  free(plan);
  ZiStatus close_status = zifs_repair_source_close(&source);
  if (ZiFailed(status) || ZiFailed(close_status)) {
    (void)fputs("The repair plan could not be finalised safely.\n", stderr);
    return 1;
  }
  return 0;
}

static int run_apply(const RepairInvocation* invocation) {
  ZiFsRepairSource source = {0};
  ZiStatus status = zifs_repair_source_open(invocation->path, invocation->mode, true, &source);
  if (ZiFailed(status)) {
    (void)fprintf_s(stderr,
                    "Unable to open '%s' exclusively for ZiFS repair (%s, status %d).\n",
                    invocation->display_path,
                    status_name(status),
                    (int)status);
    return 2;
  }
  ZiFsRepairPlan* plan = malloc(sizeof *plan);
  if (plan == NULL) {
    (void)zifs_repair_source_close(&source);
    (void)fputs("Unable to allocate the bounded ZiFS repair plan.\n", stderr);
    return 1;
  }
  status = zifs_repair_plan(&source.volume_device, plan);
  if (ZiFailed(status)) {
    (void)fprintf_s(stderr,
                    "ZiFS repair was refused for '%s' (%s, status %d).\n",
                    invocation->display_path,
                    status_name(status),
                    (int)status);
    free(plan);
    (void)zifs_repair_source_close(&source);
    return 1;
  }
  if (plan->action_count == 0) {
    (void)puts("No repair is required; no block was written.");
    free(plan);
    status = zifs_repair_source_close(&source);
    if (ZiFailed(status)) {
      return 1;
    }
    return 0;
  }
  char token[REPAIR_TOKEN_TEXT_SIZE + 1u] = {0};
  status = plan_token(plan, token);
  if (ZiFailed(status) || !token_equal(token, invocation->supplied_token)) {
    (void)fputs("The review token does not match the freshly derived repair plan.\n", stderr);
    free(plan);
    (void)zifs_repair_source_close(&source);
    return 2;
  }

  ZiFsRepairApplyReport report = {0};
  status = zifs_repair_apply(&source.volume_device, plan, &report);
  free(plan);
  ZiStatus close_status = zifs_repair_source_close(&source);
  if (ZiFailed(status) || ZiFailed(close_status)) {
    ZiStatus completion_status = status;
    if (ZiSucceeded(completion_status)) {
      completion_status = close_status;
    }
    (void)fprintf_s(stderr,
                    "ZiFS repair did not complete (%s, status %d). Replan before retrying.\n",
                    status_name(completion_status),
                    (int)completion_status);
    return 1;
  }
  (void)printf_s("ZiFS repair completed: %u action(s) written, %u already durable.\n",
                 report.applied_actions,
                 report.already_present_actions);
  (void)puts("A complete post-repair inspection found a valid clean volume.");
  return 0;
}

static bool parse_invocation(int argc, wchar_t* argv[], RepairInvocation* out_invocation) {
  if (argv == NULL || out_invocation == NULL || argc < 3) {
    return false;
  }
  RepairInvocation invocation = {0};
  invocation.mode = ZIFS_REPAIR_SOURCE_AUTO;
  if (text_equal(argv[1], L"plan")) {
    invocation.command = REPAIR_COMMAND_PLAN;
  } else if (text_equal(argv[1], L"apply")) {
    invocation.command = REPAIR_COMMAND_APPLY;
  } else {
    return false;
  }

  int argument = 2;
  if (argument < argc &&
      (text_equal(argv[argument], L"--raw") || text_equal(argv[argument], L"--gpt"))) {
    if (!parse_mode(argv[argument], &invocation.mode)) {
      return false;
    }
    ++argument;
  }
  if (argument >= argc) {
    return false;
  }
  invocation.path = argv[argument++];
  if (invocation.command == REPAIR_COMMAND_APPLY) {
    if (argument >= argc) {
      return false;
    }
    invocation.supplied_token = argv[argument++];
  }
  if (argument != argc) {
    return false;
  }
  *out_invocation = invocation;
  return true;
}

static bool parse_mode(const wchar_t* text, enum ZiFsRepairSourceMode* out_mode) {
  if (text_equal(text, L"--raw")) {
    *out_mode = ZIFS_REPAIR_SOURCE_RAW;
    return true;
  }
  if (text_equal(text, L"--gpt")) {
    *out_mode = ZIFS_REPAIR_SOURCE_GPT;
    return true;
  }
  return false;
}

static void print_usage(void) {
  (void)fputs("Usage:\n", stderr);
  (void)fputs("  zifsrepair.exe plan [--raw|--gpt] <ZiFS volume or GPT image>\n", stderr);
  (void)fputs("  zifsrepair.exe apply [--raw|--gpt] <ZiFS volume or GPT image> "
              "<review-token>\n",
              stderr);
  (void)fputs("Planning is read-only. Apply recomputes and verifies the complete plan.\n", stderr);
}

static void print_plan(const char* path,
                       const ZiFsRepairSource* source,
                       const ZiFsRepairPlan* plan,
                       const char token[REPAIR_TOKEN_TEXT_SIZE + 1u]) {
  (void)printf_s("ZiFS repair plan: %s\n", path);
  (void)printf_s("  Container: %s\n", source->container_name);
  (void)printf_s("  Generation: %llu\n", (unsigned long long)plan->generation);
  (void)printf_s("  Actions: %u\n", plan->action_count);
  for (uint32_t index = 0; index < plan->action_count; ++index) {
    const ZiFsRepairAction* action = &plan->actions[index];
    (void)printf_s("    %u. %s copy %u at ZiFS block %llu, then flush\n",
                   index + 1u,
                   action_name(action),
                   action->copy_index,
                   (unsigned long long)action->block_number);
  }
  if ((plan->flags & ZIFS_REPAIR_PLAN_UNCLEAN_MOUNT) != 0) {
    (void)puts("  Lifecycle: clear one transaction-free interrupted mount");
  }
  (void)puts("  Validation: the complete replacement overlay is valid and clean");
  (void)printf_s("  Review token: %s\n", token);
}

static const char* action_name(const ZiFsRepairAction* action) {
  if (action->kind == ZIFS_REPAIR_ACTION_JOURNAL_HEADER) {
    return "repair journal header";
  }
  return "repair superblock";
}

static ZiStatus plan_token(const ZiFsRepairPlan* plan, char output[REPAIR_TOKEN_TEXT_SIZE + 1u]) {
  static const unsigned char k_domain[] = "Zizium ZiFS repair plan v1";
  if (plan == NULL || output == NULL || plan->action_count > ZIFS_REPAIR_MAXIMUM_ACTIONS) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  RepairHash hash = {0};
  ZiStatus status = hash_begin(&hash);
  if (ZiSucceeded(status)) {
    status = hash_update(&hash, k_domain, sizeof k_domain - 1u);
  }
  if (ZiSucceeded(status)) {
    status = hash_u32(&hash, plan->version);
  }
  if (ZiSucceeded(status)) {
    status = hash_u32(&hash, plan->flags);
  }
  if (ZiSucceeded(status)) {
    status = hash_u32(&hash, plan->action_count);
  }
  if (ZiSucceeded(status)) {
    status = hash_update(&hash, plan->volume_uuid, sizeof plan->volume_uuid);
  }
  if (ZiSucceeded(status)) {
    status = hash_u64(&hash, plan->total_blocks);
  }
  if (ZiSucceeded(status)) {
    status = hash_u64(&hash, plan->generation);
  }
  if (ZiSucceeded(status)) {
    status = hash_u64(&hash, plan->last_committed_transaction);
  }
  if (ZiSucceeded(status)) {
    status = hash_u32(&hash, plan->selected_superblock_copy);
  }
  if (ZiSucceeded(status)) {
    status = hash_u32(&hash, plan->selected_journal_copy);
  }
  for (uint32_t index = 0; ZiSucceeded(status) && index < plan->action_count; ++index) {
    const ZiFsRepairAction* action = &plan->actions[index];
    status = hash_u32(&hash, action->kind);
    if (ZiSucceeded(status)) {
      status = hash_u32(&hash, action->copy_index);
    }
    if (ZiSucceeded(status)) {
      status = hash_u64(&hash, action->block_number);
    }
    if (ZiSucceeded(status)) {
      status = hash_update(&hash, action->expected_block, ZI_FS_BLOCK_SIZE);
    }
    if (ZiSucceeded(status)) {
      status = hash_update(&hash, action->replacement_block, ZI_FS_BLOCK_SIZE);
    }
  }
  unsigned char digest[REPAIR_TOKEN_BYTES] = {0};
  if (ZiSucceeded(status)) {
    status = hash_finish(&hash, digest);
  }
  hash_destroy(&hash);
  if (ZiFailed(status)) {
    return status;
  }
  for (size_t index = 0; index < sizeof digest; ++index) {
    output[index * 2u] = lowercase_hex((unsigned char)(digest[index] >> 4u));
    output[(index * 2u) + 1u] = lowercase_hex((unsigned char)(digest[index] & 0x0fu));
  }
  output[REPAIR_TOKEN_TEXT_SIZE] = '\0';
  return ZI_STATUS_SUCCESS;
}

static ZiStatus hash_begin(RepairHash* out_hash) {
  if (out_hash == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  RepairHash hash = {0};
  NTSTATUS result = BCryptOpenAlgorithmProvider(&hash.algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
  DWORD result_size = 0;
  if (result >= 0) {
    result = BCryptGetProperty(hash.algorithm,
                               BCRYPT_OBJECT_LENGTH,
                               (PUCHAR)&hash.object_size,
                               sizeof hash.object_size,
                               &result_size,
                               0);
  }
  if (result >= 0 && result_size == sizeof hash.object_size && hash.object_size != 0) {
    hash.object = malloc(hash.object_size);
    if (hash.object == NULL) {
      hash_destroy(&hash);
      return ZI_STATUS_NO_MEMORY;
    }
    result =
        BCryptCreateHash(hash.algorithm, &hash.hash, hash.object, hash.object_size, NULL, 0, 0);
  }
  if (result < 0) {
    hash_destroy(&hash);
    return ZI_STATUS_DEVICE_ERROR;
  }
  *out_hash = hash;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus hash_update(RepairHash* hash, const void* data, size_t size) {
  if (hash == NULL || hash->hash == NULL || data == NULL || size > ULONG_MAX) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  // BCrypt declares mutable input. Keep the reviewed plan bytes immutable even
  // across that external boundary by hashing bounded owned copies.
  const unsigned char* bytes = data;
  unsigned char chunk[256];
  size_t offset = 0;
  while (offset < size) {
    size_t count = size - offset;
    if (count > sizeof chunk) {
      count = sizeof chunk;
    }
    zi_memory_copy(chunk, bytes + offset, count);
    if (BCryptHashData(hash->hash, chunk, (ULONG)count, 0) < 0) {
      return ZI_STATUS_DEVICE_ERROR;
    }
    offset += count;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus hash_u32(RepairHash* hash, uint32_t value) {
  unsigned char encoded[4] = {0};
  zi_write_u32_le(encoded, value);
  return hash_update(hash, encoded, sizeof encoded);
}

static ZiStatus hash_u64(RepairHash* hash, uint64_t value) {
  unsigned char encoded[8] = {0};
  zi_write_u64_le(encoded, value);
  return hash_update(hash, encoded, sizeof encoded);
}

static ZiStatus hash_finish(RepairHash* hash, unsigned char output[REPAIR_TOKEN_BYTES]) {
  if (hash == NULL || hash->hash == NULL || output == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  NTSTATUS result = BCryptFinishHash(hash->hash, output, REPAIR_TOKEN_BYTES, 0);
  return result >= 0 ? ZI_STATUS_SUCCESS : ZI_STATUS_DEVICE_ERROR;
}

static void hash_destroy(RepairHash* hash) {
  if (hash == NULL) {
    return;
  }
  if (hash->hash != NULL) {
    (void)BCryptDestroyHash(hash->hash);
  }
  if (hash->algorithm != NULL) {
    (void)BCryptCloseAlgorithmProvider(hash->algorithm, 0);
  }
  free(hash->object);
  zi_memory_zero(hash, sizeof *hash);
}

static bool token_equal(const char* left, const wchar_t* right) {
  if (left == NULL || right == NULL) {
    return false;
  }
  for (size_t index = 0; index < REPAIR_TOKEN_TEXT_SIZE; ++index) {
    char left_character = left[index];
    wchar_t right_character = right[index];
    if (left_character >= 'A' && left_character <= 'F') {
      left_character = (char)(left_character - 'A' + 'a');
    }
    if (right_character >= 'A' && right_character <= 'F') {
      right_character = right_character - L'A' + L'a';
    }
    if (left_character != right_character || left_character == '\0') {
      return false;
    }
  }
  return (bool)(left[REPAIR_TOKEN_TEXT_SIZE] == '\0' && right[REPAIR_TOKEN_TEXT_SIZE] == L'\0');
}

static char lowercase_hex(unsigned char value) {
  return value < 10u ? (char)('0' + value) : (char)('a' + (value - 10u));
}

static const char* status_name(ZiStatus status) {
  switch (status) {
    case ZI_STATUS_NOT_FOUND:
      return "not found";
    case ZI_STATUS_INVALID_ARGUMENT:
      return "invalid argument";
    case ZI_STATUS_NO_MEMORY:
      return "insufficient memory";
    case ZI_STATUS_DEVICE_ERROR:
      return "device error";
    case ZI_STATUS_BUFFER_TOO_SMALL:
      return "repair bound exceeded";
    case ZI_STATUS_CHECKSUM_MISMATCH:
      return "checksum mismatch";
    case ZI_STATUS_CORRUPT_FILESYSTEM:
      return "corrupt filesystem";
    case ZI_STATUS_INVALID_STATE:
      return "stale or invalid state";
    case ZI_STATUS_OUT_OF_BOUNDS:
      return "out of bounds";
    case ZI_STATUS_ALIGNMENT_ERROR:
      return "alignment error";
    case ZI_STATUS_RECOVERY_REQUIRED:
      return "outside the bounded repair policy";
    default:
      return "failure";
  }
}

static bool text_equal(const wchar_t* left, const wchar_t* right) {
  size_t index = 0;
  while (left[index] != L'\0' && right[index] != L'\0') {
    if (left[index] != right[index]) {
      return false;
    }
    ++index;
  }
  return (bool)(left[index] == right[index]);
}

static ZiStatus path_to_utf8(const wchar_t* path, char** out_path) {
  if (path == NULL || out_path == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_path = NULL;
  int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, -1, NULL, 0, NULL, NULL);
  if (required <= 0) {
    return ZI_STATUS_INVALID_ENCODING;
  }
  char* converted = malloc((size_t)required);
  if (converted == NULL) {
    return ZI_STATUS_NO_MEMORY;
  }
  int written =
      WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, -1, converted, required, NULL, NULL);
  if (written != required) {
    free(converted);
    return ZI_STATUS_INVALID_ENCODING;
  }
  *out_path = converted;
  return ZI_STATUS_SUCCESS;
}
