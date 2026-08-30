// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/early_shell.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/arch_x64.h"
#include "zi/boot.h"
#include "zi/byte_order.h"
#include "zi/framebuffer_console.h"
#include "zi/kernel_memory.h"
#include "zi/log.h"
#include "zi/luma.h"
#include "zi/memory.h"
#include "zi/path.h"
#include "zi/serial.h"
#include "zi/terminal.h"
#include "zi/unicode.h"
#include "zi/zifs.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_LUMA_LINE_CAPACITY 512u
#define ZI_LUMA_ARGUMENT_CAPACITY 16u
#define ZI_LUMA_HISTORY_CAPACITY 16u

static char g_line[ZI_LUMA_LINE_CAPACITY];
static char g_token_buffer[ZI_LUMA_LINE_CAPACITY];
static char g_history_storage[ZI_LUMA_HISTORY_CAPACITY * ZI_LUMA_LINE_CAPACITY];
static unsigned char g_shell_block[ZI_FS_BLOCK_SIZE];
static ZiCommandHistory g_history;

static void console_write(const char* text, size_t text_size);
static void console_text(const char* text);
static void console_line(const char* text);
static void console_u64(uint64_t value);
static void execute_line(const ZiEarlyShellContext* context, const char* line, size_t line_size);
static void execute_command(const ZiEarlyShellContext* context,
                            const ZiStringView* arguments,
                            size_t argument_count);
static void command_get_memory(const ZiEarlyShellContext* context);
static void command_get_volume(const ZiEarlyShellContext* context);
static void command_get_file(const ZiEarlyShellContext* context, ZiStringView path_text);
static void command_show_log(void);
static void command_history(void);
static bool view_equal(ZiStringView view, const char* text);
static size_t text_size(const char* text);
static size_t remove_last_utf8_sequence(const char* line, size_t line_size);

_Noreturn void zi_early_luma_run(const ZiEarlyShellContext* context) {
  if (context == NULL || context->boot_context == NULL || context->root_volume == NULL) {
    zi_panic("Luma received an invalid early-shell context.");
  }
  if (ZiFailed(zi_history_initialise(&g_history,
                                     g_history_storage,
                                     ZI_LUMA_HISTORY_CAPACITY,
                                     ZI_LUMA_LINE_CAPACITY))) {
    zi_panic("Luma could not initialise command history.");
  }

  console_line("");
  console_line("Zizium 0.1 \"Seed\" — early Luma");
  console_line("Type Help for commands. Paths are Unicode, quoted, and case-sensitive.");
  console_text("Luma C:\\> ");

  size_t line_size = 0;
  for (;;) {
    uint8_t input = 0;
    if (!zi_serial_try_read(&input)) {
      ZkArchPause();
      continue;
    }
    if (input == '\r' || input == '\n') {
      zi_serial_write("\r\n", 2);
      zi_framebuffer_console_write(g_line, line_size);
      zi_framebuffer_console_write("\n", 1);
      if (line_size != 0) {
        execute_line(context, g_line, line_size);
      }
      line_size = 0;
      console_text("Luma C:\\> ");
      continue;
    }
    if (input == 0x08u || input == 0x7fu) {
      if (line_size != 0) {
        line_size = remove_last_utf8_sequence(g_line, line_size);
        zi_serial_write("\b \b", 3);
      }
      continue;
    }
    if (input < 0x20u || line_size + 1u >= sizeof g_line) {
      continue;
    }
    g_line[line_size++] = (char)input;
    zi_serial_write_byte(input);
  }
}

static void console_write(const char* text, size_t text_size_value) {
  zi_serial_write(text, text_size_value);
  zi_framebuffer_console_write(text, text_size_value);
}

static void console_text(const char* text) {
  console_write(text, text_size(text));
}

static void console_line(const char* text) {
  console_text(text);
  console_write("\r\n", 2);
}

static void console_u64(uint64_t value) {
  char buffer[24] = {0};
  size_t size = 0;
  do {
    buffer[size++] = (char)('0' + (value % 10u));
    value /= 10u;
  } while (value != 0);
  for (size_t index = 0; index < size / 2u; ++index) {
    char temporary = buffer[index];
    buffer[index] = buffer[size - index - 1u];
    buffer[size - index - 1u] = temporary;
  }
  console_write(buffer, size);
}

static void execute_line(const ZiEarlyShellContext* context, const char* line, size_t line_size) {
  ZiStatus status = zi_utf8_validate(line, line_size);
  if (ZiFailed(status)) {
    console_line("Input is not valid UTF-8.");
    return;
  }
  if (line_size >= sizeof g_token_buffer) {
    console_line("The command line is too long.");
    return;
  }
  zi_memory_copy(g_token_buffer, line, line_size);
  ZiStringView arguments[ZI_LUMA_ARGUMENT_CAPACITY] = {0};
  size_t argument_count = 0;
  status = zi_luma_tokenise(g_token_buffer,
                            line_size,
                            arguments,
                            ZI_LUMA_ARGUMENT_CAPACITY,
                            &argument_count);
  if (ZiFailed(status)) {
    console_line("The command contains incomplete quoting or too many arguments.");
    return;
  }
  (void)zi_history_add(&g_history, line, line_size);
  if (argument_count != 0) {
    execute_command(context, arguments, argument_count);
  }
}

static void execute_command(const ZiEarlyShellContext* context,
                            const ZiStringView* arguments,
                            size_t argument_count) {
  if (view_equal(arguments[0], "Help")) {
    console_line("Help               Show this command list");
    console_line("Version            Show the Zizium version");
    console_line("Get-Memory         Summarise usable physical memory");
    console_line("Get-Volume         Show the mounted ZiFS root volume");
    console_line("Get-File <path>    Perform an exact-case ZiFS lookup");
    console_line("Show-Log           Show the structured kernel log ring");
    console_line("History            Show recent commands");
    console_line("Clear-Screen       Clear the framebuffer terminal");
  } else if (view_equal(arguments[0], "Version")) {
    console_line("Zizium 0.1.0 \"Seed\" (x86-64 PE32+ foundation)");
  } else if (view_equal(arguments[0], "Get-Memory")) {
    command_get_memory(context);
  } else if (view_equal(arguments[0], "Get-Volume")) {
    command_get_volume(context);
  } else if (view_equal(arguments[0], "Get-File")) {
    if (argument_count != 2) {
      console_line("Usage: Get-File \"C:\\path with spaces\"");
    } else {
      command_get_file(context, arguments[1]);
    }
  } else if (view_equal(arguments[0], "Show-Log")) {
    command_show_log();
  } else if (view_equal(arguments[0], "History")) {
    command_history();
  } else if (view_equal(arguments[0], "Clear-Screen")) {
    zi_serial_write("\x1b[2J\x1b[H", 7);
    zi_framebuffer_console_clear();
  } else {
    console_line("Command not found. Type Help for available commands.");
  }
}

static void command_get_memory(const ZiEarlyShellContext* context) {
  ZiPhysicalMemoryStatistics statistics = zi_kernel_memory_statistics();
  console_text("Managed physical memory: ");
  console_u64(statistics.managed_pages / UINT64_C(256));
  console_line(" MiB");
  console_text("Free pages: ");
  console_u64(statistics.free_pages);
  console_text("  Reserved pages: ");
  console_u64(statistics.reserved_pages);
  console_text("  Allocated pages: ");
  console_u64(statistics.allocated_pages);
  console_line("");
  console_text("Memory map entries: ");
  console_u64(context->boot_context->memory_range_count);
  console_line("");
}

static void command_get_volume(const ZiEarlyShellContext* context) {
  console_text("C:  ZiFS ");
  console_u64(context->root_volume->superblock.format_major);
  console_text(".");
  console_u64(context->root_volume->superblock.format_minor);
  console_text("  ");
  console_write(context->root_volume->superblock.volume_name,
                context->root_volume->superblock.volume_name_size);
  console_line("  Read-only boot module");
}

static void command_get_file(const ZiEarlyShellContext* context, ZiStringView path_text) {
  ZiStringView components[32] = {0};
  ZiParsedPath path = {0};
  ZiStatus status = zi_path_parse_absolute(path_text.data, path_text.size, components, 32, &path);
  if (ZiFailed(status)) {
    console_line("The path is not a valid absolute Zizium path.");
    return;
  }
  ZiFsFileRecord record = {0};
  status =
      ZiFsLookupPath(context->root_volume, &path, g_shell_block, sizeof g_shell_block, &record);
  if (status == ZI_STATUS_NOT_FOUND) {
    console_line("The exact-case path was not found.");
    return;
  }
  if (ZiFailed(status)) {
    console_line("ZiFS could not complete the lookup.");
    return;
  }
  console_text("Found file ID ");
  console_u64(record.file_id);
  console_text(" (type ");
  console_u64(record.file_type);
  console_line(").");
}

static void command_show_log(void) {
  size_t count = zi_log_record_count();
  for (size_t index = 0; index < count; ++index) {
    const ZiLogRecord* record = zi_log_record_at(index);
    if (record == NULL) {
      continue;
    }
    console_text("#");
    console_u64(record->sequence);
    console_text(" [");
    console_text(record->stage);
    console_text("] ");
    console_line(record->message);
  }
}

static void command_history(void) {
  ZiStringView entry = {0};
  for (size_t index = 0; index < g_history.count; ++index) {
    if (ZiFailed(zi_history_previous(&g_history, &entry))) {
      break;
    }
    console_write(entry.data, entry.size);
    console_line("");
  }
  g_history.navigation_offset = 0;
}

static bool view_equal(ZiStringView view, const char* text) {
  size_t comparison_size = text_size(text);
  return (bool)(view.size == comparison_size &&
                zi_memory_compare(view.data, text, comparison_size) == 0);
}

static size_t text_size(const char* text) {
  size_t size = 0;
  while (text[size] != '\0') {
    ++size;
  }
  return size;
}

static size_t remove_last_utf8_sequence(const char* line, size_t line_size) {
  if (line == NULL || line_size == 0) {
    return 0;
  }
  --line_size;
  while (line_size != 0 && ((unsigned char)line[line_size] & 0xc0u) == 0x80u) {
    --line_size;
  }
  return line_size;
}
