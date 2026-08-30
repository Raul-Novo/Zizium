// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

enum ZiLogLevel {
  ZI_LOG_TRACE = 0,
  ZI_LOG_INFORMATION = 1,
  ZI_LOG_WARNING = 2,
  ZI_LOG_ERROR = 3,
  ZI_LOG_FATAL = 4,
};

#define ZI_LOG_RECORD_CAPACITY 64u
#define ZI_LOG_STAGE_CAPACITY 24u
#define ZI_LOG_MESSAGE_CAPACITY 112u

typedef struct ZiLogRecord {
  uint64_t sequence;
  uint32_t level;
  char stage[ZI_LOG_STAGE_CAPACITY];
  char message[ZI_LOG_MESSAGE_CAPACITY];
} ZiLogRecord;

typedef void (*ZiLogSinkRoutine)(const char* text, size_t text_size);

void zi_log_initialise(void);
void zi_log_set_sink(ZiLogSinkRoutine sink);
void zi_log_write(uint32_t level, const char* stage, const char* message);
void zi_log_write_hex(uint32_t level, const char* stage, const char* name, uint64_t value);
void zi_log_boot_marker(const char* marker);
size_t zi_log_record_count(void);
const ZiLogRecord* zi_log_record_at(size_t logical_index);
_Noreturn void zi_panic(const char* message);
