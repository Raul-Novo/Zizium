// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/terminal.h"

#include <stddef.h>
#include <stdint.h>

#include "zi/byte_order.h"
#include "zi/unicode.h"
#include "zizium/status.h"
#include "zizium/types.h"

static size_t physical_line(const ZiTerminalBuffer* terminal, size_t logical_line);
static ZiTerminalCell* mutable_line(ZiTerminalBuffer* terminal, size_t logical_line);
static void clear_line(ZiTerminalBuffer* terminal, size_t logical_line);
static void append_line(ZiTerminalBuffer* terminal);
static ZiTerminalCell* previous_base_cell(ZiTerminalBuffer* terminal);
static size_t bounded_string_size(const char* text, size_t capacity);

ZiStatus zi_terminal_initialise(ZiTerminalBuffer* terminal,
                                ZiTerminalCell* cell_storage,
                                size_t* used_column_storage,
                                size_t columns,
                                size_t line_capacity,
                                ZiColour foreground,
                                ZiColour background) {
  if (terminal == NULL || cell_storage == NULL || used_column_storage == NULL || columns == 0 ||
      line_capacity == 0 || columns > SIZE_MAX / line_capacity) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  terminal->cells = cell_storage;
  terminal->used_columns = used_column_storage;
  terminal->columns = columns;
  terminal->line_capacity = line_capacity;
  terminal->line_count = 1;
  terminal->first_line = 0;
  terminal->cursor_column = 0;
  terminal->viewport_offset = 0;
  terminal->foreground = foreground;
  terminal->background = background;
  zi_terminal_clear(terminal);
  return ZI_STATUS_SUCCESS;
}

void zi_terminal_clear(ZiTerminalBuffer* terminal) {
  if (terminal == NULL || terminal->cells == NULL || terminal->used_columns == NULL) {
    return;
  }

  terminal->line_count = 1;
  terminal->first_line = 0;
  terminal->cursor_column = 0;
  terminal->viewport_offset = 0;
  for (size_t line = 0; line < terminal->line_capacity; ++line) {
    clear_line(terminal, line);
  }
}

ZiStatus zi_terminal_write_scalar(ZiTerminalBuffer* terminal, uint32_t scalar) {
  if (terminal == NULL || !zi_unicode_is_scalar(scalar)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (scalar == '\r') {
    terminal->cursor_column = 0;
    return ZI_STATUS_SUCCESS;
  }
  if (scalar == '\n') {
    append_line(terminal);
    return ZI_STATUS_SUCCESS;
  }
  if (scalar == '\t') {
    size_t spaces = 4u - (terminal->cursor_column % 4u);
    for (size_t index = 0; index < spaces; ++index) {
      ZiStatus status = zi_terminal_write_scalar(terminal, ' ');
      if (ZiFailed(status)) {
        return status;
      }
    }
    return ZI_STATUS_SUCCESS;
  }

  if (zi_unicode_is_combining(scalar)) {
    ZiTerminalCell* base = previous_base_cell(terminal);
    if (base != NULL && base->combining_count < ZI_TERMINAL_COMBINING_CAPACITY) {
      base->combining[base->combining_count] = scalar;
      ++base->combining_count;
      return ZI_STATUS_SUCCESS;
    }
    scalar = ZI_UNICODE_REPLACEMENT_CHARACTER;
  }

  uint8_t width = zi_unicode_cell_width(scalar);
  if (width == 0) {
    return ZI_STATUS_SUCCESS;
  }
  if (width > terminal->columns) {
    scalar = ZI_UNICODE_REPLACEMENT_CHARACTER;
    width = 1;
  }
  if (terminal->cursor_column + width > terminal->columns) {
    append_line(terminal);
  }

  size_t active_line = terminal->line_count - 1;
  ZiTerminalCell* line = mutable_line(terminal, active_line);
  ZiTerminalCell* cell = &line[terminal->cursor_column];
  cell->scalar = scalar;
  cell->combining[0] = 0;
  cell->combining[1] = 0;
  cell->foreground = terminal->foreground;
  cell->background = terminal->background;
  cell->combining_count = 0;
  cell->width = width;
  cell->flags = 0;
  if (width == 2) {
    ZiTerminalCell* continuation = &line[terminal->cursor_column + 1];
    *continuation = *cell;
    continuation->scalar = 0;
    continuation->width = 0;
    continuation->flags = ZI_TERMINAL_CELL_CONTINUATION;
  }

  terminal->cursor_column += width;
  size_t line_index = physical_line(terminal, active_line);
  if (terminal->used_columns[line_index] < terminal->cursor_column) {
    terminal->used_columns[line_index] = terminal->cursor_column;
  }
  if (terminal->cursor_column == terminal->columns) {
    append_line(terminal);
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_terminal_write_utf8(ZiTerminalBuffer* terminal, const char* text, size_t text_size) {
  if (terminal == NULL || (text == NULL && text_size != 0)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  size_t offset = 0;
  while (offset < text_size) {
    ZiUtf8DecodeResult result = {0};
    ZiStatus status = zi_utf8_decode(text + offset, text_size - offset, &result);
    if (ZiFailed(status)) {
      return status;
    }
    status = zi_terminal_write_scalar(terminal, result.scalar);
    if (ZiFailed(status)) {
      return status;
    }
    offset += result.consumed;
  }
  return ZI_STATUS_SUCCESS;
}

const ZiTerminalCell* zi_terminal_get_line(const ZiTerminalBuffer* terminal,
                                           size_t logical_line,
                                           size_t* out_used_columns) {
  if (terminal == NULL || logical_line >= terminal->line_count) {
    return NULL;
  }
  size_t index = physical_line(terminal, logical_line);
  if (out_used_columns != NULL) {
    *out_used_columns = terminal->used_columns[index];
  }
  return terminal->cells + (index * terminal->columns);
}

void zi_terminal_page_up(ZiTerminalBuffer* terminal, size_t visible_lines) {
  if (terminal == NULL || terminal->line_count <= 1) {
    return;
  }
  size_t maximum_offset = terminal->line_count - 1;
  if (visible_lines > maximum_offset - terminal->viewport_offset) {
    terminal->viewport_offset = maximum_offset;
  } else {
    terminal->viewport_offset += visible_lines;
  }
}

void zi_terminal_page_down(ZiTerminalBuffer* terminal, size_t visible_lines) {
  if (terminal == NULL) {
    return;
  }
  if (visible_lines >= terminal->viewport_offset) {
    terminal->viewport_offset = 0;
  } else {
    terminal->viewport_offset -= visible_lines;
  }
}

ZiStatus zi_history_initialise(ZiCommandHistory* history,
                               char* storage,
                               size_t entry_capacity,
                               size_t entry_size) {
  if (history == NULL || storage == NULL || entry_capacity == 0 || entry_size < 2 ||
      entry_capacity > SIZE_MAX / entry_size) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  history->storage = storage;
  history->entry_capacity = entry_capacity;
  history->entry_size = entry_size;
  history->count = 0;
  history->first_entry = 0;
  history->navigation_offset = 0;
  zi_memory_zero(storage, entry_capacity * entry_size);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_history_add(ZiCommandHistory* history, const char* text, size_t text_size) {
  if (history == NULL || text == NULL || text_size == 0 || text_size >= history->entry_size) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_utf8_validate(text, text_size);
  if (ZiFailed(status)) {
    return status;
  }

  size_t index = 0;
  if (history->count < history->entry_capacity) {
    index = (history->first_entry + history->count) % history->entry_capacity;
    ++history->count;
  } else {
    index = history->first_entry;
    history->first_entry = (history->first_entry + 1) % history->entry_capacity;
  }
  char* destination = history->storage + (index * history->entry_size);
  zi_memory_zero(destination, history->entry_size);
  zi_memory_copy(destination, text, text_size);
  history->navigation_offset = 0;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_history_previous(ZiCommandHistory* history, ZiStringView* out_entry) {
  if (history == NULL || out_entry == NULL || history->count == 0) {
    return ZI_STATUS_NOT_FOUND;
  }
  if (history->navigation_offset < history->count) {
    ++history->navigation_offset;
  }
  size_t logical_index = history->count - history->navigation_offset;
  size_t index = (history->first_entry + logical_index) % history->entry_capacity;
  out_entry->data = history->storage + (index * history->entry_size);
  out_entry->size = bounded_string_size(out_entry->data, history->entry_size);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_history_next(ZiCommandHistory* history, ZiStringView* out_entry) {
  if (history == NULL || out_entry == NULL || history->count == 0 ||
      history->navigation_offset == 0) {
    return ZI_STATUS_NOT_FOUND;
  }
  --history->navigation_offset;
  if (history->navigation_offset == 0) {
    out_entry->data = NULL;
    out_entry->size = 0;
    return ZI_STATUS_SUCCESS;
  }
  size_t logical_index = history->count - history->navigation_offset;
  size_t index = (history->first_entry + logical_index) % history->entry_capacity;
  out_entry->data = history->storage + (index * history->entry_size);
  out_entry->size = bounded_string_size(out_entry->data, history->entry_size);
  return ZI_STATUS_SUCCESS;
}

static size_t physical_line(const ZiTerminalBuffer* terminal, size_t logical_line) {
  return (terminal->first_line + logical_line) % terminal->line_capacity;
}

static ZiTerminalCell* mutable_line(ZiTerminalBuffer* terminal, size_t logical_line) {
  return terminal->cells + (physical_line(terminal, logical_line) * terminal->columns);
}

static void clear_line(ZiTerminalBuffer* terminal, size_t logical_line) {
  size_t index = physical_line(terminal, logical_line);
  ZiTerminalCell* line = terminal->cells + (index * terminal->columns);
  for (size_t column = 0; column < terminal->columns; ++column) {
    line[column].scalar = ' ';
    line[column].combining[0] = 0;
    line[column].combining[1] = 0;
    line[column].foreground = terminal->foreground;
    line[column].background = terminal->background;
    line[column].combining_count = 0;
    line[column].width = 1;
    line[column].flags = 0;
    line[column].reserved = 0;
  }
  terminal->used_columns[index] = 0;
}

static void append_line(ZiTerminalBuffer* terminal) {
  if (terminal->line_count < terminal->line_capacity) {
    ++terminal->line_count;
  } else {
    terminal->first_line = (terminal->first_line + 1) % terminal->line_capacity;
  }
  terminal->cursor_column = 0;
  terminal->viewport_offset = 0;
  clear_line(terminal, terminal->line_count - 1);
}

static ZiTerminalCell* previous_base_cell(ZiTerminalBuffer* terminal) {
  if (terminal->cursor_column == 0) {
    return NULL;
  }
  ZiTerminalCell* line = mutable_line(terminal, terminal->line_count - 1);
  size_t column = terminal->cursor_column - 1;
  if ((line[column].flags & ZI_TERMINAL_CELL_CONTINUATION) != 0 && column > 0) {
    --column;
  }
  return &line[column];
}

static size_t bounded_string_size(const char* text, size_t capacity) {
  size_t size = 0;
  while (size < capacity && text[size] != '\0') {
    ++size;
  }
  return size;
}
