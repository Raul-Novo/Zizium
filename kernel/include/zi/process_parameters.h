// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zizium/process.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_PROCESS_PARAMETER_INPUT_VERSION 1u
#define ZI_PROCESS_ARGUMENT_LIMIT 32u
#define ZI_PROCESS_ENVIRONMENT_LIMIT 32u
#define ZI_PROCESS_PARAMETER_STRING_LIMIT 4096u
#define ZI_PROCESS_PARAMETER_BLOCK_LIMIT 65536u

typedef struct ZiProcessParameterInput {
  uint32_t struct_size;
  uint32_t version;
  ZiStringView image_path;
  ZiStringView command_line;
  const ZiStringView* arguments;
  size_t argument_count;
  const ZiStringView* environment;
  size_t environment_count;
} ZiProcessParameterInput;

ZiStatus zi_process_parameters_measure(const ZiProcessParameterInput* input,
                                       size_t* out_required_size);
ZiStatus zi_process_parameters_serialise(const ZiProcessParameterInput* input,
                                         uint64_t user_base,
                                         void* output,
                                         size_t output_capacity,
                                         size_t* out_used_size,
                                         uint64_t* out_parameters_address);
