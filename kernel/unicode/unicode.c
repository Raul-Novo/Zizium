// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/unicode.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"

static bool is_continuation(unsigned char byte);
static bool is_wide(uint32_t scalar);

// NOLINTNEXTLINE(readability-function-cognitive-complexity) -- UTF-8 validity branches are explicit.
ZiStatus zi_utf8_decode(const char* text, size_t text_size, ZiUtf8DecodeResult* out_result) {
  if (text == NULL || out_result == NULL || text_size == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  const unsigned char* bytes = (const unsigned char*)text;
  unsigned char first = bytes[0];
  uint32_t scalar = 0;
  size_t consumed = 0;

  if (first <= 0x7fu) {
    scalar = first;
    consumed = 1;
  } else if (first >= 0xc2u && first <= 0xdfu) {
    if (text_size < 2 || !is_continuation(bytes[1])) {
      return ZI_STATUS_INVALID_ENCODING;
    }
    scalar = ((uint32_t)(first & 0x1fu) << 6u) | (uint32_t)(bytes[1] & 0x3fu);
    consumed = 2;
  } else if (first >= 0xe0u && first <= 0xefu) {
    if (text_size < 3 || !is_continuation(bytes[1]) || !is_continuation(bytes[2])) {
      return ZI_STATUS_INVALID_ENCODING;
    }
    if ((first == 0xe0u && bytes[1] < 0xa0u) || (first == 0xedu && bytes[1] >= 0xa0u)) {
      return ZI_STATUS_INVALID_ENCODING;
    }
    scalar = ((uint32_t)(first & 0x0fu) << 12u) | ((uint32_t)(bytes[1] & 0x3fu) << 6u) |
             (uint32_t)(bytes[2] & 0x3fu);
    consumed = 3;
  } else if (first >= 0xf0u && first <= 0xf4u) {
    if (text_size < 4 || !is_continuation(bytes[1]) || !is_continuation(bytes[2]) ||
        !is_continuation(bytes[3])) {
      return ZI_STATUS_INVALID_ENCODING;
    }
    if ((first == 0xf0u && bytes[1] < 0x90u) || (first == 0xf4u && bytes[1] >= 0x90u)) {
      return ZI_STATUS_INVALID_ENCODING;
    }
    scalar = ((uint32_t)(first & 0x07u) << 18u) | ((uint32_t)(bytes[1] & 0x3fu) << 12u) |
             ((uint32_t)(bytes[2] & 0x3fu) << 6u) | (uint32_t)(bytes[3] & 0x3fu);
    consumed = 4;
  } else {
    return ZI_STATUS_INVALID_ENCODING;
  }

  if (!zi_unicode_is_scalar(scalar)) {
    return ZI_STATUS_INVALID_ENCODING;
  }

  out_result->scalar = scalar;
  out_result->consumed = consumed;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_utf8_validate(const char* text, size_t text_size) {
  if (text == NULL && text_size != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  size_t offset = 0;
  while (offset < text_size) {
    ZiUtf8DecodeResult result = {0};
    ZiStatus status = zi_utf8_decode(text + offset, text_size - offset, &result);
    if (ZiFailed(status)) {
      return status;
    }
    offset += result.consumed;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_utf8_encode(uint32_t scalar, char* output, size_t output_capacity, size_t* out_size) {
  if (out_size == NULL || !zi_unicode_is_scalar(scalar)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  size_t required_size = 0;
  if (scalar <= 0x7fu) {
    required_size = 1;
  } else if (scalar <= 0x7ffu) {
    required_size = 2;
  } else if (scalar <= 0xffffu) {
    required_size = 3;
  } else {
    required_size = 4;
  }

  *out_size = required_size;
  if (output == NULL || output_capacity < required_size) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }

  if (required_size == 1) {
    output[0] = (char)scalar;
  } else if (required_size == 2) {
    output[0] = (char)(0xc0u | (scalar >> 6u));
    output[1] = (char)(0x80u | (scalar & 0x3fu));
  } else if (required_size == 3) {
    output[0] = (char)(0xe0u | (scalar >> 12u));
    output[1] = (char)(0x80u | ((scalar >> 6u) & 0x3fu));
    output[2] = (char)(0x80u | (scalar & 0x3fu));
  } else {
    output[0] = (char)(0xf0u | (scalar >> 18u));
    output[1] = (char)(0x80u | ((scalar >> 12u) & 0x3fu));
    output[2] = (char)(0x80u | ((scalar >> 6u) & 0x3fu));
    output[3] = (char)(0x80u | (scalar & 0x3fu));
  }

  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_utf8_to_utf16(const char* text,
                          size_t text_size,
                          uint16_t* output,
                          size_t output_capacity,
                          size_t* out_size) {
  if ((text == NULL && text_size != 0) || out_size == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  size_t input_offset = 0;
  size_t output_offset = 0;
  while (input_offset < text_size) {
    ZiUtf8DecodeResult result = {0};
    ZiStatus status = zi_utf8_decode(text + input_offset, text_size - input_offset, &result);
    if (ZiFailed(status)) {
      return status;
    }

    size_t required_units = result.scalar <= 0xffffu ? 1u : 2u;
    if (output != NULL && output_offset + required_units <= output_capacity) {
      if (required_units == 1) {
        output[output_offset] = (uint16_t)result.scalar;
      } else {
        uint32_t adjusted = result.scalar - 0x10000u;
        output[output_offset] = (uint16_t)(0xd800u | (adjusted >> 10u));
        output[output_offset + 1] = (uint16_t)(0xdc00u | (adjusted & 0x3ffu));
      }
    }

    output_offset += required_units;
    input_offset += result.consumed;
  }

  *out_size = output_offset;
  if (output == NULL || output_capacity < output_offset) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  return ZI_STATUS_SUCCESS;
}

bool zi_unicode_is_scalar(uint32_t value) {
  return (bool)(value <= 0x10ffffu && !(value >= 0xd800u && value <= 0xdfffu));
}

bool zi_unicode_is_combining(uint32_t scalar) {
  return (
      bool)((scalar >= 0x0300u && scalar <= 0x036fu) || (scalar >= 0x1ab0u && scalar <= 0x1affu) ||
            (scalar >= 0x1dc0u && scalar <= 0x1dffu) || (scalar >= 0x20d0u && scalar <= 0x20ffu) ||
            (scalar >= 0xfe20u && scalar <= 0xfe2fu));
}

uint8_t zi_unicode_cell_width(uint32_t scalar) {
  if (!zi_unicode_is_scalar(scalar) || scalar == 0) {
    return 0;
  }
  if (zi_unicode_is_combining(scalar)) {
    return 0;
  }
  if (is_wide(scalar)) {
    return 2;
  }
  return 1;
}

static bool is_continuation(unsigned char byte) {
  return (byte & 0xc0u) == 0x80u;
}

static bool is_wide(uint32_t scalar) {
  return (
      bool)(scalar >= 0x1100u &&
            (scalar <= 0x115fu || scalar == 0x2329u || scalar == 0x232au ||
             (scalar >= 0x2e80u && scalar <= 0xa4cfu && scalar != 0x303fu) ||
             (scalar >= 0xac00u && scalar <= 0xd7a3u) || (scalar >= 0xf900u && scalar <= 0xfaffu) ||
             (scalar >= 0xfe10u && scalar <= 0xfe19u) || (scalar >= 0xfe30u && scalar <= 0xfe6fu) ||
             (scalar >= 0xff00u && scalar <= 0xff60u) || (scalar >= 0xffe0u && scalar <= 0xffe6u) ||
             (scalar >= 0x1f300u && scalar <= 0x1faffu) ||
             (scalar >= 0x20000u && scalar <= 0x3fffdu)));
}
