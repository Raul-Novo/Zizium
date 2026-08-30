// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

uint32_t zi_crc32c(uint32_t initial_value, const void* data, size_t size);
