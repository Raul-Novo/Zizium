// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/log.h"

#include <stddef.h>
#include <stdint.h>

#include "zi/arch_x64.h"
#include "zi/byte_order.h"
#include "zi/serial.h"

static ZiLogRecord g_records[ZI_LOG_RECORD_CAPACITY];
static size_t g_first_record;
static size_t g_record_count;
static uint64_t g_next_sequence;
static ZiLogSinkRoutine g_sink;

static size_t bounded_text_size(const char* text, size_t capacity);
static void copy_text(char* output, size_t output_capacity, const char* text);
static size_t append_text(char* output, size_t capacity, size_t offset, const char* text);
static const char* level_name(uint32_t level);
static void emit(const char* text);

void zi_log_initialise(void) {
  zi_memory_zero(g_records, sizeof g_records);
  g_first_record = 0;
  g_record_count = 0;
  g_next_sequence = 1;
  g_sink = NULL;
}

void zi_log_set_sink(ZiLogSinkRoutine sink) {
  g_sink = sink;
}

void zi_log_write(uint32_t level, const char* stage, const char* message) {
  if (stage == NULL || message == NULL) {
    return;
  }
  size_t index = 0;
  if (g_record_count < ZI_LOG_RECORD_CAPACITY) {
    index = (g_first_record + g_record_count) % ZI_LOG_RECORD_CAPACITY;
    ++g_record_count;
  } else {
    index = g_first_record;
    g_first_record = (g_first_record + 1) % ZI_LOG_RECORD_CAPACITY;
  }
  ZiLogRecord* record = &g_records[index];
  record->sequence = g_next_sequence++;
  record->level = level;
  copy_text(record->stage, sizeof record->stage, stage);
  copy_text(record->message, sizeof record->message, message);

  emit("[Zizium][");
  emit(level_name(level));
  emit("][");
  emit(record->stage);
  emit("] ");
  emit(record->message);
  emit("\r\n");
}

void zi_log_write_hex(uint32_t level, const char* stage, const char* name, uint64_t value) {
  if (name == NULL) {
    return;
  }
  static const char k_digits[] = "0123456789abcdef";
  char message[ZI_LOG_MESSAGE_CAPACITY] = {0};
  size_t offset = append_text(message, sizeof message, 0, name);
  offset = append_text(message, sizeof message, offset, "=0x");
  for (uint32_t shift = 64; shift != 0 && offset + 1 < sizeof message; shift -= 4) {
    message[offset++] = k_digits[(value >> (shift - 4u)) & UINT64_C(0x0f)];
  }
  message[offset] = '\0';
  zi_log_write(level, stage, message);
}

void zi_log_boot_marker(const char* marker) {
  if (marker == NULL) {
    return;
  }
  emit("[ZI:BOOT:");
  emit(marker);
  emit("]\r\n");
}

size_t zi_log_record_count(void) {
  return g_record_count;
}

const ZiLogRecord* zi_log_record_at(size_t logical_index) {
  if (logical_index >= g_record_count) {
    return NULL;
  }
  size_t index = (g_first_record + logical_index) % ZI_LOG_RECORD_CAPACITY;
  return &g_records[index];
}

_Noreturn void zi_panic(const char* message) {
  zi_log_write(ZI_LOG_FATAL, "Panic", message != NULL ? message : "Unspecified kernel panic.");
  zi_log_boot_marker("PANIC");
  ZkArchHalt();
}

static size_t bounded_text_size(const char* text, size_t capacity) {
  size_t size = 0;
  if (text == NULL) {
    return 0;
  }
  while (size < capacity && text[size] != '\0') {
    ++size;
  }
  return size;
}

static void copy_text(char* output, size_t output_capacity, const char* text) {
  if (output_capacity == 0) {
    return;
  }
  size_t size = bounded_text_size(text, output_capacity - 1);
  zi_memory_copy(output, text, size);
  output[size] = '\0';
}

static size_t append_text(char* output, size_t capacity, size_t offset, const char* text) {
  if (output == NULL || text == NULL || offset >= capacity) {
    return offset;
  }
  while (*text != '\0' && offset + 1 < capacity) {
    output[offset++] = *text++;
  }
  output[offset] = '\0';
  return offset;
}

static const char* level_name(uint32_t level) {
  switch (level) {
    case ZI_LOG_TRACE:
      return "Trace";
    case ZI_LOG_INFORMATION:
      return "Information";
    case ZI_LOG_WARNING:
      return "Warning";
    case ZI_LOG_ERROR:
      return "Error";
    case ZI_LOG_FATAL:
      return "Fatal";
    default:
      return "Unknown";
  }
}

static void emit(const char* text) {
  size_t size = bounded_text_size(text, SIZE_MAX);
  zi_serial_write(text, size);
  if (g_sink != NULL) {
    g_sink(text, size);
  }
}
