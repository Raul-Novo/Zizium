// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/crc32.h"

#include <stddef.h>
#include <stdint.h>

uint32_t zi_crc32(uint32_t seed, const void* data, size_t size) {
  if (data == NULL && size != 0) {
    return 0;
  }

  const unsigned char* bytes = data;
  uint32_t crc = ~seed;
  for (size_t index = 0; index < size; ++index) {
    crc ^= bytes[index];
    for (uint32_t bit = 0; bit < 8; ++bit) {
      uint32_t mask = (uint32_t)-(int32_t)(crc & UINT32_C(1));
      crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & mask);
    }
  }
  return ~crc;
}
