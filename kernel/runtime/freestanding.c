// SPDX-License-Identifier: GPL-3.0-or-later

#include <stddef.h>

#include "zi/byte_order.h"

// These freestanding CRT symbols deliberately provide the declarations normally supplied by libc.
// NOLINTBEGIN(misc-include-cleaner)
void* memcpy(void* destination, const void* source, size_t size) {
  zi_memory_copy(destination, source, size);
  return destination;
}

void* memset(void* destination, int value, size_t size) {
  unsigned char* bytes = destination;
  for (size_t index = 0; index < size; ++index) {
    bytes[index] = (unsigned char)value;
  }
  return destination;
}

int memcmp(const void* left, const void* right, size_t size) {
  return zi_memory_compare(left, right, size);
}
// NOLINTEND(misc-include-cleaner)
