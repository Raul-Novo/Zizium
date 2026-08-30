// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/byte_order.h"

#include <stddef.h>
#include <stdint.h>

uint16_t zi_read_u16_le(const unsigned char* data) {
  return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8u));
}

uint32_t zi_read_u32_le(const unsigned char* data) {
  return (uint32_t)data[0] | ((uint32_t)data[1] << 8u) | ((uint32_t)data[2] << 16u) |
         ((uint32_t)data[3] << 24u);
}

uint64_t zi_read_u64_le(const unsigned char* data) {
  uint64_t low = zi_read_u32_le(data);
  uint64_t high = zi_read_u32_le(data + 4);
  return low | (high << 32u);
}

void zi_write_u16_le(unsigned char* data, uint16_t value) {
  data[0] = (unsigned char)(value & 0xffu);
  data[1] = (unsigned char)((value >> 8u) & 0xffu);
}

void zi_write_u32_le(unsigned char* data, uint32_t value) {
  data[0] = (unsigned char)(value & 0xffu);
  data[1] = (unsigned char)((value >> 8u) & 0xffu);
  data[2] = (unsigned char)((value >> 16u) & 0xffu);
  data[3] = (unsigned char)((value >> 24u) & 0xffu);
}

void zi_write_u64_le(unsigned char* data, uint64_t value) {
  zi_write_u32_le(data, (uint32_t)(value & UINT32_MAX));
  zi_write_u32_le(data + 4, (uint32_t)(value >> 32u));
}

void zi_memory_zero(void* memory, size_t size) {
  unsigned char* bytes = memory;
  for (size_t index = 0; index < size; ++index) {
    bytes[index] = 0;
  }
}

void zi_memory_copy(void* destination, const void* source, size_t size) {
  unsigned char* destination_bytes = destination;
  const unsigned char* source_bytes = source;
  for (size_t index = 0; index < size; ++index) {
    destination_bytes[index] = source_bytes[index];
  }
}

int zi_memory_compare(const void* left, const void* right, size_t size) {
  const unsigned char* left_bytes = left;
  const unsigned char* right_bytes = right;
  for (size_t index = 0; index < size; ++index) {
    if (left_bytes[index] < right_bytes[index]) {
      return -1;
    }
    if (left_bytes[index] > right_bytes[index]) {
      return 1;
    }
  }
  return 0;
}
