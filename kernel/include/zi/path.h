// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>

#include "zizium/status.h"
#include "zizium/types.h"

typedef struct ZiParsedPath {
  char drive_letter;
  ZiStringView* components;
  size_t component_count;
} ZiParsedPath;

ZiStatus zi_path_parse_absolute(const char* path,
                                size_t path_size,
                                ZiStringView* component_storage,
                                size_t component_capacity,
                                ZiParsedPath* out_path);
ZiStatus zi_path_compare_component(ZiStringView left, ZiStringView right, int* out_comparison);
