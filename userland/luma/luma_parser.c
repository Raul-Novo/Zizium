// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>

#include "zi/luma.h"
#include "zi/unicode.h"
#include "zizium/status.h"
#include "zizium/types.h"

static bool is_space(char character);

// NOLINTNEXTLINE(readability-function-cognitive-complexity) -- quoting states remain explicit.
ZiStatus zi_luma_tokenise(char* line,
                          size_t line_size,
                          ZiStringView* arguments,
                          size_t argument_capacity,
                          size_t* out_argument_count) {
  if (line == NULL || arguments == NULL || out_argument_count == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_utf8_validate(line, line_size);
  if (ZiFailed(status)) {
    return status;
  }

  size_t read_offset = 0;
  size_t write_offset = 0;
  size_t argument_count = 0;
  while (read_offset < line_size) {
    while (read_offset < line_size && is_space(line[read_offset])) {
      ++read_offset;
    }
    if (read_offset == line_size) {
      break;
    }
    if (argument_count >= argument_capacity) {
      return ZI_STATUS_BUFFER_TOO_SMALL;
    }

    size_t argument_start = write_offset;
    bool is_quoted = false;
    if (line[read_offset] == '"') {
      is_quoted = true;
      ++read_offset;
    }

    bool closed_quote = false;
    if (!is_quoted) {
      closed_quote = true;
    }
    while (read_offset < line_size) {
      char character = line[read_offset];
      if (is_quoted && character == '"') {
        ++read_offset;
        closed_quote = true;
        break;
      }
      if (!is_quoted && is_space(character)) {
        break;
      }
      if (is_quoted && character == '\\' && read_offset + 1 < line_size &&
          (line[read_offset + 1] == '"' || line[read_offset + 1] == '\\')) {
        ++read_offset;
        character = line[read_offset];
      }
      line[write_offset] = character;
      ++write_offset;
      ++read_offset;
    }

    if (!closed_quote) {
      return ZI_STATUS_INVALID_ARGUMENT;
    }
    if (read_offset < line_size && !is_space(line[read_offset])) {
      return ZI_STATUS_INVALID_ARGUMENT;
    }

    arguments[argument_count].data = line + argument_start;
    arguments[argument_count].size = write_offset - argument_start;
    ++argument_count;
  }

  *out_argument_count = argument_count;
  return ZI_STATUS_SUCCESS;
}

static bool is_space(char character) {
  return (bool)(character == ' ' || character == '\t');
}
