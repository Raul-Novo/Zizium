// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "zi/dma.h"
#include "zizium/status.h"

ZiStatus zi_kernel_dma_initialise(void);
const ZiDmaAllocator* zi_kernel_dma_allocator(void);
