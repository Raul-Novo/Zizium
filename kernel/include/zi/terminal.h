// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_TERMINAL_COMBINING_CAPACITY 2u
#define ZI_TERMINAL_CELL_CONTINUATION UINT8_C(0x01)

typedef struct ZiTerminalCell {
  uint32_t scalar;
  uint32_t combining[ZI_TERMINAL_COMBINING_CAPACITY];
  ZiColour foreground;
  ZiColour background;
  uint8_t combining_count;
  uint8_t width;
  uint8_t flags;
  uint8_t reserved;
} ZiTerminalCell;

typedef struct ZiTerminalBuffer {
  ZiTerminalCell* cells;
  size_t* used_columns;
  size_t columns;
  size_t line_capacity;
  size_t line_count;
  size_t first_line;
  size_t cursor_column;
  size_t viewport_offset;
  ZiColour foreground;
  ZiColour background;
} ZiTerminalBuffer;

typedef struct ZiCommandHistory {
  char* storage;
  size_t entry_capacity;
  size_t entry_size;
  size_t count;
  size_t first_entry;
  size_t navigation_offset;
} ZiCommandHistory;

ZiStatus zi_terminal_initialise(ZiTerminalBuffer* terminal,
                                ZiTerminalCell* cell_storage,
                                size_t* used_column_storage,
                                size_t columns,
                                size_t line_capacity,
                                ZiColour foreground,
                                ZiColour background);
void zi_terminal_clear(ZiTerminalBuffer* terminal);
ZiStatus zi_terminal_write_scalar(ZiTerminalBuffer* terminal, uint32_t scalar);
ZiStatus zi_terminal_write_utf8(ZiTerminalBuffer* terminal, const char* text, size_t text_size);
const ZiTerminalCell* zi_terminal_get_line(const ZiTerminalBuffer* terminal,
                                           size_t logical_line,
                                           size_t* out_used_columns);
void zi_terminal_page_up(ZiTerminalBuffer* terminal, size_t visible_lines);
void zi_terminal_page_down(ZiTerminalBuffer* terminal, size_t visible_lines);
ZiStatus zi_history_initialise(ZiCommandHistory* history,
                               char* storage,
                               size_t entry_capacity,
                               size_t entry_size);
ZiStatus zi_history_add(ZiCommandHistory* history, const char* text, size_t text_size);
ZiStatus zi_history_previous(ZiCommandHistory* history, ZiStringView* out_entry);
ZiStatus zi_history_next(ZiCommandHistory* history, ZiStringView* out_entry);
