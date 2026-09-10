// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#include <Windows.h>
#include <share.h>

#include "inspect.h"
#include "zi/block.h"
#include "zi/gpt.h"
#include "zi/zifs.h"
#include "zizium/status.h"

// Host-file diagnostics and cleanup after a fatal inspection error are best effort.
// NOLINTBEGIN(cert-err33-c, clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)

enum InspectMode {
  INSPECT_MODE_AUTO = 0,
  INSPECT_MODE_RAW = 1,
  INSPECT_MODE_GPT = 2,
};

typedef struct FileBlockContext {
  FILE* file;
  uint64_t file_size;
  uint32_t block_size;
} FileBlockContext;

typedef struct InspectionSource {
  FILE* file;
  FileBlockContext file_context;
  ZiBlockDevice file_device;
  ZiPartitionBlockContext partition_context;
  ZiBlockDevice volume_device;
  const char* container_name;
  uint64_t partition_first_lba;
  uint64_t partition_lba_count;
  uint32_t gpt_from_backup;
} InspectionSource;

static int inspect_path(const wchar_t* path, enum InspectMode requested_mode);
static ZiStatus
open_source(const wchar_t* path, enum InspectMode requested_mode, InspectionSource* out_source);
static ZiStatus configure_raw_source(InspectionSource* source);
static ZiStatus configure_gpt_source(InspectionSource* source);
static enum InspectMode detect_mode(FILE* file, uint64_t file_size);
static bool read_signature(FILE* file, uint64_t offset, void* output, size_t output_size);
static ZiStatus file_read_blocks(void* context,
                                 uint64_t first_block,
                                 uint32_t block_count,
                                 void* output,
                                 size_t output_size);
static void
print_report(const char* path, const InspectionSource* source, const ZiFsInspectReport* report);
static const char* superblock_state_name(uint32_t state_flags);
static const char* status_name(ZiStatus status);
static bool text_equal(const wchar_t* left, const wchar_t* right);
static ZiStatus path_to_utf8(const wchar_t* path, char** out_path);

// NOLINTNEXTLINE(misc-use-internal-linkage) -- Windows CRT entry point.
int wmain(int argc, wchar_t* argv[]) {
  enum InspectMode mode = INSPECT_MODE_AUTO;
  const wchar_t* path = NULL;
  if (argc == 2) {
    path = argv[1];
  } else if (argc == 3 && text_equal(argv[1], L"--raw")) {
    mode = INSPECT_MODE_RAW;
    path = argv[2];
  } else if (argc == 3 && text_equal(argv[1], L"--gpt")) {
    mode = INSPECT_MODE_GPT;
    path = argv[2];
  } else {
    fputs("Usage: zifsinspect.exe [--raw|--gpt] <ZiFS volume or GPT image>\n", stderr);
    fputs("The inspector opens its input read-only and never performs recovery.\n", stderr);
    return 2;
  }
  return inspect_path(path, mode);
}

static int inspect_path(const wchar_t* path, enum InspectMode requested_mode) {
  char* display_path = NULL;
  ZiStatus status = path_to_utf8(path, &display_path);
  if (ZiFailed(status)) {
    fputs("The UTF-16 input path could not be represented as validated UTF-8.\n", stderr);
    return 2;
  }
  InspectionSource source = {0};
  status = open_source(path, requested_mode, &source);
  if (ZiFailed(status)) {
    fprintf(stderr,
            "Unable to open a ZiFS volume from '%s' (%s, status %d).\n",
            display_path,
            status_name(status),
            (int)status);
    if (source.file != NULL) {
      fclose(source.file);
    }
    free(display_path);
    return 2;
  }

  ZiFsInspectReport report = {0};
  status = zifs_inspect_volume(&source.volume_device, &report);
  print_report(display_path, &source, &report);
  free(display_path);
  if (fclose(source.file) != 0) {
    fputs("Warning: the read-only input could not be closed cleanly.\n", stderr);
    return 2;
  }
  if (ZiSucceeded(status)) {
    return 0;
  }
  return 1;
}

static ZiStatus
open_source(const wchar_t* path, enum InspectMode requested_mode, InspectionSource* out_source) {
  if (path == NULL || out_source == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  FILE* file = _wfsopen(path, L"rb", _SH_DENYWR);
  if (file == NULL) {
    return ZI_STATUS_NOT_FOUND;
  }
  if (_fseeki64(file, 0, SEEK_END) != 0) {
    fclose(file);
    return ZI_STATUS_DEVICE_ERROR;
  }
  int64_t signed_size = _ftelli64(file);
  if (signed_size <= 0 || _fseeki64(file, 0, SEEK_SET) != 0) {
    fclose(file);
    return ZI_STATUS_DEVICE_ERROR;
  }

  InspectionSource source = {0};
  source.file = file;
  source.file_context.file = file;
  source.file_context.file_size = (uint64_t)signed_size;
  enum InspectMode mode = requested_mode;
  if (mode == INSPECT_MODE_AUTO) {
    mode = detect_mode(file, source.file_context.file_size);
  }
  ZiStatus status = ZI_STATUS_INVALID_ARGUMENT;
  if (mode == INSPECT_MODE_RAW) {
    status = configure_raw_source(&source);
  } else if (mode == INSPECT_MODE_GPT) {
    status = configure_gpt_source(&source);
  }
  if (ZiFailed(status)) {
    fclose(file);
    return status;
  }
  *out_source = source;
  out_source->file_device.context = &out_source->file_context;
  if (out_source->partition_lba_count == 0) {
    out_source->volume_device.context = &out_source->file_context;
  } else {
    out_source->partition_context.parent = &out_source->file_device;
    out_source->volume_device.context = &out_source->partition_context;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus configure_raw_source(InspectionSource* source) {
  if (source->file_context.file_size % ZI_FS_BLOCK_SIZE != 0 ||
      source->file_context.file_size / ZI_FS_BLOCK_SIZE < 2) {
    return ZI_STATUS_ALIGNMENT_ERROR;
  }
  source->file_context.block_size = ZI_FS_BLOCK_SIZE;
  source->file_device = (ZiBlockDevice){
      sizeof(ZiBlockDevice),
      ZI_BLOCK_DEVICE_VERSION,
      &source->file_context,
      ZI_FS_BLOCK_SIZE,
      source->file_context.file_size / ZI_FS_BLOCK_SIZE,
      file_read_blocks,
      NULL,
      ZI_BLOCK_DEVICE_READ_ONLY,
      NULL,
  };
  source->volume_device = source->file_device;
  source->container_name = "raw ZiFS volume";
  return ZI_STATUS_SUCCESS;
}

static ZiStatus configure_gpt_source(InspectionSource* source) {
  if (source->file_context.file_size % 512u != 0 || source->file_context.file_size / 512u < 3) {
    return ZI_STATUS_ALIGNMENT_ERROR;
  }
  source->file_context.block_size = 512;
  source->file_device = (ZiBlockDevice){
      sizeof(ZiBlockDevice),
      ZI_BLOCK_DEVICE_VERSION,
      &source->file_context,
      512,
      source->file_context.file_size / 512u,
      file_read_blocks,
      NULL,
      ZI_BLOCK_DEVICE_READ_ONLY,
      NULL,
  };
  ZiGptPartition* partitions = calloc(ZI_GPT_MAXIMUM_ENTRY_COUNT, sizeof *partitions);
  if (partitions == NULL) {
    return ZI_STATUS_NO_MEMORY;
  }
  unsigned char block_buffer[4096] = {0};
  ZiGptTable table = {0};
  ZiStatus status = zi_gpt_read(&source->file_device,
                                block_buffer,
                                sizeof block_buffer,
                                partitions,
                                ZI_GPT_MAXIMUM_ENTRY_COUNT,
                                &table);
  const ZiGptPartition* partition = NULL;
  if (ZiSucceeded(status)) {
    status = zi_gpt_find_partition_by_type(&table, &ZiGptZiFsTypeGuid, &partition);
  }
  if (ZiSucceeded(status) && partition != NULL) {
    uint64_t lba_count = partition->last_lba - partition->first_lba + 1u;
    status = zi_partition_block_initialise(&source->file_device,
                                           partition->first_lba,
                                           lba_count,
                                           ZI_FS_BLOCK_SIZE,
                                           &source->partition_context,
                                           &source->volume_device);
    if (ZiSucceeded(status)) {
      source->container_name = "GPT image with ZiFS partition";
      source->partition_first_lba = partition->first_lba;
      source->partition_lba_count = lba_count;
      source->gpt_from_backup = table.mounted_from_backup;
    }
  }
  free(partitions);
  return status;
}

static enum InspectMode detect_mode(FILE* file, uint64_t file_size) {
  static const unsigned char k_zifs_magic[8] = {'Z', 'i', 'F', 'S', '\r', '\n', 0x1a, '\n'};
  static const unsigned char k_gpt_magic[8] = {'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T'};
  unsigned char signature[8] = {0};
  if (read_signature(file, 0, signature, sizeof signature)) {
    bool matches = true;
    for (size_t index = 0; index < sizeof signature; ++index) {
      if (signature[index] != k_zifs_magic[index]) {
        matches = false;
      }
    }
    if (matches) {
      return INSPECT_MODE_RAW;
    }
  }
  if (file_size >= 520u && read_signature(file, 512, signature, sizeof signature)) {
    bool matches = true;
    for (size_t index = 0; index < sizeof signature; ++index) {
      if (signature[index] != k_gpt_magic[index]) {
        matches = false;
      }
    }
    if (matches) {
      return INSPECT_MODE_GPT;
    }
  }
  return file_size % ZI_FS_BLOCK_SIZE == 0 ? INSPECT_MODE_RAW : INSPECT_MODE_GPT;
}

static bool read_signature(FILE* file, uint64_t offset, void* output, size_t output_size) {
  if (offset > INT64_MAX || _fseeki64(file, (int64_t)offset, SEEK_SET) != 0) {
    return false;
  }
  return (bool)(fread(output, 1, output_size, file) == output_size);
}

static ZiStatus file_read_blocks(void* context,
                                 uint64_t first_block,
                                 uint32_t block_count,
                                 void* output,
                                 size_t output_size) {
  if (context == NULL || output == NULL || block_count == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  FileBlockContext* file = context;
  if (file->file == NULL || file->block_size == 0 || first_block > UINT64_MAX / file->block_size ||
      block_count > SIZE_MAX / file->block_size) {
    return ZI_STATUS_INVALID_STATE;
  }
  uint64_t byte_offset = first_block * file->block_size;
  size_t byte_count = (size_t)block_count * file->block_size;
  if (output_size < byte_count || byte_offset > file->file_size ||
      byte_count > file->file_size - byte_offset || byte_offset > INT64_MAX ||
      _fseeki64(file->file, (int64_t)byte_offset, SEEK_SET) != 0) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  return fread(output, 1, byte_count, file->file) == byte_count ? ZI_STATUS_SUCCESS
                                                                : ZI_STATUS_DEVICE_ERROR;
}

static void
print_report(const char* path, const InspectionSource* source, const ZiFsInspectReport* report) {
  printf("ZiFS inspection: %s\n", path);
  printf("  Container: %s\n", source->container_name);
  puts("  Access: read-only; recovery and repair are disabled");
  if (source->partition_lba_count != 0) {
    printf("  ZiFS partition: LBA %llu, %llu sectors%s\n",
           (unsigned long long)source->partition_first_lba,
           (unsigned long long)source->partition_lba_count,
           source->gpt_from_backup != 0 ? ", backup GPT selected" : "");
  }
  printf("  Primary superblock: %s\n", status_name(report->primary_superblock_status));
  printf("  Backup superblock: %s\n", status_name(report->backup_superblock_status));
  if (report->superblock.total_blocks != 0) {
    printf("  Selected superblock: %s\n",
           report->selected_superblock_copy == 0 ? "primary" : "backup");
    printf("  Volume: %s\n", report->superblock.volume_name);
    printf("  Generation: %llu, %s\n",
           (unsigned long long)report->superblock.generation,
           superblock_state_name(report->superblock.state_flags));
    printf("  Blocks: %llu total\n", (unsigned long long)report->superblock.total_blocks);
    printf("  Journal header 0: %s\n", status_name(report->journal_header_status[0]));
    printf("  Journal header 1: %s\n", status_name(report->journal_header_status[1]));
    printf("  Journal: copy %u, sequence %llu, head %llu, tail %llu, %llu occupied\n",
           report->selected_journal_copy,
           (unsigned long long)report->journal.header_sequence,
           (unsigned long long)report->journal.head_record,
           (unsigned long long)report->journal.tail_record,
           (unsigned long long)report->occupied_journal_records);
    printf("  Journal records: %llu begin, %llu images, %llu commit, %llu checkpoint\n",
           (unsigned long long)report->journal_begin_records,
           (unsigned long long)report->journal_block_images,
           (unsigned long long)report->journal_commit_records,
           (unsigned long long)report->journal_checkpoint_records);
    printf("  Metadata view: %s\n",
           report->inspected_replay_view != 0 ? "validated journal replay overlay"
                                              : "on-disk home blocks");
    if (report->unclean_mount != 0) {
      puts("  Mount state: interrupted without a clean unmount; recovery is required");
    }
    printf("  Security: %llu descriptors, %llu ACEs\n",
           (unsigned long long)report->security_descriptor_count,
           (unsigned long long)report->security_ace_count);
    printf("  Namespace: %llu live records (%llu regular, %llu directories, %llu other), "
           "%llu entries\n",
           (unsigned long long)report->live_file_records,
           (unsigned long long)report->regular_file_records,
           (unsigned long long)report->directory_records,
           (unsigned long long)report->other_file_records,
           (unsigned long long)report->directory_entries);
    printf("  Allocation: %llu allocated, %llu free, %llu allocated but unreferenced\n",
           (unsigned long long)report->allocated_blocks,
           (unsigned long long)report->free_blocks,
           (unsigned long long)report->unreferenced_allocated_blocks);
  }
  printf("  Component status: mount=%s, journal=%s, security=%s, namespace=%s, "
         "allocation=%s\n",
         status_name(report->mount_status),
         status_name(report->journal_status),
         status_name(report->security_status),
         status_name(report->namespace_status),
         status_name(report->allocation_status));
  if (ZiSucceeded(report->overall_status)) {
    puts("  Result: valid ZiFS metadata");
  } else if (report->overall_status == ZI_STATUS_RECOVERY_REQUIRED) {
    puts("  Result: metadata is readable but requires recovery or repair");
  } else {
    printf("  Result: invalid ZiFS metadata (%s, status %d)\n",
           status_name(report->overall_status),
           (int)report->overall_status);
  }
}

static const char* superblock_state_name(uint32_t state_flags) {
  switch (state_flags) {
    case ZI_FS_SUPERBLOCK_STATE_NONE:
      return "cleanly unmounted";
    case ZI_FS_SUPERBLOCK_STATE_TRANSACTION_DIRTY:
      return "transaction dirty";
    case ZI_FS_SUPERBLOCK_STATE_MOUNTED:
      return "mounted";
    case ZI_FS_SUPERBLOCK_STATE_MOUNTED | ZI_FS_SUPERBLOCK_STATE_TRANSACTION_DIRTY:
      return "mounted, transaction dirty";
    default:
      return "unknown state";
  }
}

static const char* status_name(ZiStatus status) {
  switch (status) {
    case ZI_STATUS_SUCCESS:
      return "valid";
    case ZI_STATUS_NOT_FOUND:
      return "not found";
    case ZI_STATUS_INVALID_ARGUMENT:
      return "invalid argument";
    case ZI_STATUS_NO_MEMORY:
      return "insufficient memory";
    case ZI_STATUS_DEVICE_ERROR:
      return "device error";
    case ZI_STATUS_BUFFER_TOO_SMALL:
      return "inspection bound exceeded";
    case ZI_STATUS_INVALID_ENCODING:
      return "invalid UTF-8";
    case ZI_STATUS_CHECKSUM_MISMATCH:
      return "checksum mismatch";
    case ZI_STATUS_CORRUPT_FILESYSTEM:
      return "corrupt filesystem";
    case ZI_STATUS_INVALID_STATE:
      return "invalid state";
    case ZI_STATUS_OUT_OF_BOUNDS:
      return "out of bounds";
    case ZI_STATUS_ALIGNMENT_ERROR:
      return "alignment error";
    case ZI_STATUS_RECOVERY_REQUIRED:
      return "recovery required";
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

// NOLINTEND(cert-err33-c, clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
