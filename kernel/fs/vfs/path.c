// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/path.h"

#include <stdbool.h>
#include <stddef.h>

#include "zi/byte_order.h"
#include "zi/unicode.h"
#include "zizium/status.h"
#include "zizium/types.h"

static bool is_ascii_letter(char character);
static bool is_dot_component(const char* data, size_t size);

ZiStatus zi_path_parse_absolute(const char* path,
                                size_t path_size,
                                ZiStringView* component_storage,
                                size_t component_capacity,
                                ZiParsedPath* out_path) {
  if (path == NULL || component_storage == NULL || out_path == NULL || path_size < 3) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (!is_ascii_letter(path[0]) || path[1] != ':' || path[2] != '\\') {
    return ZI_STATUS_INVALID_PATH;
  }

  ZiStatus status = zi_utf8_validate(path, path_size);
  if (ZiFailed(status)) {
    return status;
  }

  for (size_t index = 0; index < path_size; ++index) {
    if (path[index] == '\0' || path[index] == '/') {
      return ZI_STATUS_INVALID_PATH;
    }
  }

  size_t component_count = 0;
  size_t component_start = 3;
  for (size_t index = 3; index <= path_size; ++index) {
    bool at_end = index == path_size;
    if (!at_end && path[index] != '\\') {
      continue;
    }

    size_t component_size = index - component_start;
    if (component_size == 0) {
      if (at_end && component_start == 3) {
        break;
      }
      return ZI_STATUS_INVALID_PATH;
    }
    if (is_dot_component(path + component_start, component_size)) {
      return ZI_STATUS_INVALID_PATH;
    }
    if (component_count >= component_capacity) {
      return ZI_STATUS_BUFFER_TOO_SMALL;
    }

    component_storage[component_count].data = path + component_start;
    component_storage[component_count].size = component_size;
    ++component_count;
    component_start = index + 1;
  }

  out_path->drive_letter = path[0];
  out_path->components = component_storage;
  out_path->component_count = component_count;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_path_compare_component(ZiStringView left, ZiStringView right, int* out_comparison) {
  if ((left.data == NULL && left.size != 0) || (right.data == NULL && right.size != 0) ||
      out_comparison == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  ZiStatus status = zi_utf8_validate(left.data, left.size);
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_utf8_validate(right.data, right.size);
  if (ZiFailed(status)) {
    return status;
  }

  size_t common_size = left.size < right.size ? left.size : right.size;
  int comparison = zi_memory_compare(left.data, right.data, common_size);
  if (comparison == 0) {
    if (left.size < right.size) {
      comparison = -1;
    } else if (left.size > right.size) {
      comparison = 1;
    }
  }

  *out_comparison = comparison;
  return ZI_STATUS_SUCCESS;
}

static bool is_ascii_letter(char character) {
  return (bool)((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z'));
}

static bool is_dot_component(const char* data, size_t size) {
  return (bool)((size == 1 && data[0] == '.') || (size == 2 && data[0] == '.' && data[1] == '.'));
}
