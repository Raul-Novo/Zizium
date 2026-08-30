// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>

#include "zizium/status.h"
#include "zizium/types.h"

ZiStatus zi_luma_tokenise(char* line,
                          size_t line_size,
                          ZiStringView* arguments,
                          size_t argument_capacity,
                          size_t* out_argument_count);
