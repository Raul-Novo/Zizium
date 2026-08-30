// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

uint16_t zi_read_u16_le(const unsigned char* data);
uint32_t zi_read_u32_le(const unsigned char* data);
uint64_t zi_read_u64_le(const unsigned char* data);
void zi_write_u16_le(unsigned char* data, uint16_t value);
void zi_write_u32_le(unsigned char* data, uint32_t value);
void zi_write_u64_le(unsigned char* data, uint64_t value);
void zi_memory_zero(void* memory, size_t size);
void zi_memory_copy(void* destination, const void* source, size_t size);
int zi_memory_compare(const void* left, const void* right, size_t size);
