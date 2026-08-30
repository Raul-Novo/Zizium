// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

uint32_t zi_crc32(uint32_t seed, const void* data, size_t size);
