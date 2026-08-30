// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/framebuffer_console.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/display.h"
#include "zi/font.h"
#include "zi/terminal.h"
#include "zizium/status.h"
#include "zizium/theme.h"
#include "zizium/types.h"

#define ZI_FRAMEBUFFER_MAX_COLUMNS 256u
#define ZI_FRAMEBUFFER_SCROLLBACK_LINES 160u

static ZiFramebuffer g_framebuffer;
static ZiScaleFactor g_scale;
static ZiTerminalCell g_cells[ZI_FRAMEBUFFER_MAX_COLUMNS * ZI_FRAMEBUFFER_SCROLLBACK_LINES];
static size_t g_used_columns[ZI_FRAMEBUFFER_SCROLLBACK_LINES];
static ZiTerminalBuffer g_terminal;
static size_t g_visible_lines;
static uint32_t g_font_width;
static uint32_t g_font_height;
static bool g_ready;

static uint32_t scaled_edge(uint32_t value);
static uint32_t pack_colour(ZiColour colour);
static void
fill_rectangle(uint32_t x, uint32_t y, uint32_t width, uint32_t height, ZiColour colour);
static void render_glyph(uint32_t cell_x, uint32_t cell_y, const ZiTerminalCell* cell);
static void render_cursor(size_t logical_line, size_t first_visible_line);

ZiStatus zi_framebuffer_console_initialise(const ZiFramebuffer* framebuffer, ZiScaleFactor scale) {
  g_ready = false;
  if (framebuffer == NULL || framebuffer->address == NULL || framebuffer->bits_per_pixel != 32 ||
      framebuffer->pixel_format != ZI_FRAMEBUFFER_PIXEL_FORMAT_RGB || framebuffer->width == 0 ||
      framebuffer->height < 3 || framebuffer->pitch < (framebuffer->width * sizeof(uint32_t)) ||
      framebuffer->size < ((size_t)framebuffer->pitch * framebuffer->height) ||
      framebuffer->red_mask_size == 0 || framebuffer->green_mask_size == 0 ||
      framebuffer->blue_mask_size == 0 || framebuffer->red_mask_size > 8 ||
      framebuffer->green_mask_size > 8 || framebuffer->blue_mask_size > 8 ||
      framebuffer->red_mask_shift + framebuffer->red_mask_size > 32 ||
      framebuffer->green_mask_shift + framebuffer->green_mask_size > 32 ||
      framebuffer->blue_mask_shift + framebuffer->blue_mask_size > 32 || scale.numerator == 0 ||
      scale.denominator == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  g_framebuffer = *framebuffer;
  g_scale = scale;
  g_font_width = scaled_edge(ZI_EARLY_FONT_WIDTH);
  g_font_height = scaled_edge(ZI_EARLY_FONT_HEIGHT);
  if (g_font_width == 0 || g_font_height == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  size_t columns = framebuffer->width / g_font_width;
  if (columns > ZI_FRAMEBUFFER_MAX_COLUMNS) {
    columns = ZI_FRAMEBUFFER_MAX_COLUMNS;
  }
  g_visible_lines = framebuffer->height / g_font_height;
  if (g_visible_lines > ZI_FRAMEBUFFER_SCROLLBACK_LINES) {
    g_visible_lines = ZI_FRAMEBUFFER_SCROLLBACK_LINES;
  }
  if (columns == 0 || g_visible_lines == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  ZiStatus status = zi_terminal_initialise(&g_terminal,
                                           g_cells,
                                           g_used_columns,
                                           columns,
                                           ZI_FRAMEBUFFER_SCROLLBACK_LINES,
                                           ZI_COLOUR_TEXT,
                                           ZI_COLOUR_BACKGROUND);
  if (ZiFailed(status)) {
    return status;
  }
  g_ready = true;
  zi_framebuffer_console_clear();
  return ZI_STATUS_SUCCESS;
}

bool zi_framebuffer_console_is_ready(void) {
  return g_ready;
}

void zi_framebuffer_console_write(const char* text, size_t text_size) {
  if (!g_ready || (text == NULL && text_size != 0)) {
    return;
  }
  if (ZiSucceeded(zi_terminal_write_utf8(&g_terminal, text, text_size))) {
    zi_framebuffer_console_redraw();
  }
}

void zi_framebuffer_console_clear(void) {
  if (!g_ready) {
    return;
  }
  zi_terminal_clear(&g_terminal);
  fill_rectangle(0, 0, g_framebuffer.width, g_framebuffer.height, ZI_COLOUR_BACKGROUND);
  fill_rectangle(0, 0, g_framebuffer.width, 3, ZI_COLOUR_PRIMARY);
  zi_framebuffer_console_redraw();
}

void zi_framebuffer_console_redraw(void) {
  if (!g_ready) {
    return;
  }
  fill_rectangle(0, 3, g_framebuffer.width, g_framebuffer.height - 3, ZI_COLOUR_BACKGROUND);

  size_t visible_count = g_terminal.line_count;
  if (visible_count > g_visible_lines) {
    visible_count = g_visible_lines;
  }
  size_t end_line = g_terminal.line_count - g_terminal.viewport_offset;
  if (end_line < visible_count) {
    visible_count = end_line;
  }
  size_t first_line = end_line - visible_count;
  for (size_t row = 0; row < visible_count; ++row) {
    size_t used_columns = 0;
    const ZiTerminalCell* line = zi_terminal_get_line(&g_terminal, first_line + row, &used_columns);
    if (line == NULL) {
      continue;
    }
    if (used_columns > g_terminal.columns) {
      used_columns = g_terminal.columns;
    }
    for (size_t column = 0; column < used_columns; ++column) {
      render_glyph((uint32_t)column, (uint32_t)row, &line[column]);
    }
  }
  if (g_terminal.viewport_offset == 0) {
    render_cursor(g_terminal.line_count - 1, first_line);
  }
}

static uint32_t scaled_edge(uint32_t value) {
  return ((value * g_scale.numerator) + g_scale.denominator - 1u) / g_scale.denominator;
}

static uint32_t pack_colour(ZiColour colour) {
  uint32_t red = (colour >> 16u) & 0xffu;
  uint32_t green = (colour >> 8u) & 0xffu;
  uint32_t blue = colour & 0xffu;
  uint32_t red_max = (UINT32_C(1) << g_framebuffer.red_mask_size) - 1u;
  uint32_t green_max = (UINT32_C(1) << g_framebuffer.green_mask_size) - 1u;
  uint32_t blue_max = (UINT32_C(1) << g_framebuffer.blue_mask_size) - 1u;
  red = ((red * red_max) + 127u) / 255u;
  green = ((green * green_max) + 127u) / 255u;
  blue = ((blue * blue_max) + 127u) / 255u;
  return (red << g_framebuffer.red_mask_shift) | (green << g_framebuffer.green_mask_shift) |
         (blue << g_framebuffer.blue_mask_shift);
}

static void
fill_rectangle(uint32_t x, uint32_t y, uint32_t width, uint32_t height, ZiColour colour) {
  if (x >= g_framebuffer.width || y >= g_framebuffer.height) {
    return;
  }
  if (width > g_framebuffer.width - x) {
    width = g_framebuffer.width - x;
  }
  if (height > g_framebuffer.height - y) {
    height = g_framebuffer.height - y;
  }
  uint32_t pixel = pack_colour(colour);
  unsigned char* base = g_framebuffer.address;
  for (uint32_t row = 0; row < height; ++row) {
    uint32_t* pixels = (uint32_t*)(base + ((size_t)(y + row) * g_framebuffer.pitch));
    for (uint32_t column = 0; column < width; ++column) {
      pixels[x + column] = pixel;
    }
  }
}

static void render_glyph(uint32_t cell_x, uint32_t cell_y, const ZiTerminalCell* cell) {
  uint32_t destination_x = cell_x * g_font_width;
  uint32_t destination_y = 3u + (cell_y * g_font_height);
  fill_rectangle(destination_x, destination_y, g_font_width, g_font_height, cell->background);
  if ((cell->flags & ZI_TERMINAL_CELL_CONTINUATION) != 0) {
    return;
  }

  const uint8_t* glyph = zi_font_glyph(cell->scalar);
  for (uint32_t source_y = 0; source_y < ZI_EARLY_FONT_HEIGHT; ++source_y) {
    uint32_t top = scaled_edge(source_y);
    uint32_t bottom = scaled_edge(source_y + 1u);
    for (uint32_t source_x = 0; source_x < ZI_EARLY_FONT_WIDTH; ++source_x) {
      if ((glyph[source_y] & (UINT8_C(0x80) >> source_x)) == 0) {
        continue;
      }
      uint32_t left = scaled_edge(source_x);
      uint32_t right = scaled_edge(source_x + 1u);
      fill_rectangle(destination_x + left,
                     destination_y + top,
                     right - left,
                     bottom - top,
                     cell->foreground);
    }
  }
}

static void render_cursor(size_t logical_line, size_t first_visible_line) {
  if (logical_line < first_visible_line || logical_line - first_visible_line >= g_visible_lines) {
    return;
  }
  uint32_t x = (uint32_t)g_terminal.cursor_column * g_font_width;
  uint32_t y = 3u + ((uint32_t)(logical_line - first_visible_line) * g_font_height);
  uint32_t cursor_height = g_font_height >= 3u ? 2u : 1u;
  fill_rectangle(x,
                 y + g_font_height - cursor_height,
                 g_font_width,
                 cursor_height,
                 ZI_COLOUR_PRIMARY);
}
