// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/crc32c.h"

#include <stddef.h>
#include <stdint.h>

uint32_t zi_crc32c(uint32_t initial_value, const void* data, size_t size) {
  const unsigned char* bytes = data;
  uint32_t crc = ~initial_value;

  for (size_t index = 0; index < size; ++index) {
    crc ^= bytes[index];
    for (unsigned bit = 0; bit < 8u; ++bit) {
      uint32_t mask = (uint32_t)(0u - (crc & 1u));
      crc = (crc >> 1u) ^ (0x82f63b78u & mask);
    }
  }

  return ~crc;
}
