// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"

#define ZI_UNICODE_REPLACEMENT_CHARACTER UINT32_C(0x0000fffd)

typedef struct ZiUtf8DecodeResult {
  uint32_t scalar;
  size_t consumed;
} ZiUtf8DecodeResult;

ZiStatus zi_utf8_decode(const char* text, size_t text_size, ZiUtf8DecodeResult* out_result);
ZiStatus zi_utf8_validate(const char* text, size_t text_size);
ZiStatus zi_utf8_encode(uint32_t scalar, char* output, size_t output_capacity, size_t* out_size);
ZiStatus zi_utf8_to_utf16(const char* text,
                          size_t text_size,
                          uint16_t* output,
                          size_t output_capacity,
                          size_t* out_size);
bool zi_unicode_is_scalar(uint32_t value);
bool zi_unicode_is_combining(uint32_t scalar);
uint8_t zi_unicode_cell_width(uint32_t scalar);
