// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

#define ZI_PROCESS_PARAMETERS_VERSION 1u

typedef struct ZiProcessParameters {
  uint32_t struct_size;
  uint32_t version;
  uint32_t flags;
  uint32_t argument_count;
  uint32_t environment_count;
  uint32_t reserved;
  uint64_t arguments;
  uint64_t environment;
  uint64_t command_line;
  uint64_t command_line_size;
  uint64_t image_path;
  uint64_t image_path_size;
} ZiProcessParameters;

_Static_assert(sizeof(ZiProcessParameters) == 72, "ZiProcessParameters size mismatch");
