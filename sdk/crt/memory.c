// SPDX-License-Identifier: GPL-3.0-or-later

#define ZI_BUILD_ZICRT 1

#include <stddef.h>
#include <string.h>

// MSVC's internal declaration parameter names are external and intentionally not mirrored.
// NOLINTBEGIN(readability-inconsistent-declaration-parameter-name)

void* memcpy(void* destination, const void* source, size_t size) {
  unsigned char* destination_bytes = destination;
  const unsigned char* source_bytes = source;
  for (size_t index = 0; index < size; ++index) {
    destination_bytes[index] = source_bytes[index];
  }
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
  const unsigned char* left_bytes = left;
  const unsigned char* right_bytes = right;
  for (size_t index = 0; index < size; ++index) {
    if (left_bytes[index] != right_bytes[index]) {
      return left_bytes[index] < right_bytes[index] ? -1 : 1;
    }
  }
  return 0;
}

// NOLINTEND(readability-inconsistent-declaration-parameter-name)
