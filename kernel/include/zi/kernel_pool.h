// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>

#include "zi/pool.h"
#include "zizium/status.h"

ZiStatus zi_kernel_pool_initialise(void);
ZiStatus zi_kernel_pool_allocate(size_t size, void** out_allocation);
ZiStatus zi_kernel_pool_free(void* allocation);
ZiStatus zi_kernel_pool_validate(void);
ZiStatus zi_kernel_pool_statistics(ZiPoolStatistics* out_statistics);
ZiStatus zi_kernel_pool_self_test(void);
