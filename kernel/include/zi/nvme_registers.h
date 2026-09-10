// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

#include "zizium/status.h"

// Validate the MMIO window for the polling driver's admin queue and I/O queue 1.
// A stride of four validates BAR0 before CAP is readable; validate again using
// CAP.DSTRD before any doorbell access. No hardware is touched by this function.
ZiStatus zi_nvme_register_window_validate(uint64_t base, uint64_t size, uint32_t stride);
