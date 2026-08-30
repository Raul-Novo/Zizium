// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zizium/types.h"

typedef struct ZiScaleFactor {
  uint16_t numerator;
  uint16_t denominator;
} ZiScaleFactor;

typedef struct ZiDisplayMode {
  uint32_t width;
  uint32_t height;
  uint32_t refresh_millihertz;
  uint16_t bits_per_pixel;
} ZiDisplayMode;

typedef struct ZiFramebuffer {
  void* address;
  size_t size;
  uint32_t width;
  uint32_t height;
  uint32_t pitch;
  uint16_t bits_per_pixel;
  uint8_t pixel_format;
  uint8_t red_mask_size;
  uint8_t red_mask_shift;
  uint8_t green_mask_size;
  uint8_t green_mask_shift;
  uint8_t blue_mask_size;
  uint8_t blue_mask_shift;
} ZiFramebuffer;

#define ZI_FRAMEBUFFER_PIXEL_FORMAT_RGB UINT8_C(1)

typedef struct ZiDisplayOutput {
  uint64_t output_id;
  ZiDisplayMode active_mode;
  ZiScaleFactor scale;
  ZiFramebuffer framebuffer;
} ZiDisplayOutput;

typedef struct ZiDisplayAdapter {
  uint64_t adapter_id;
  ZiDisplayOutput* outputs;
  size_t output_count;
} ZiDisplayAdapter;

ZiScaleFactor zi_display_default_scale(uint32_t pixel_height);
uint32_t zi_scale_u32(uint32_t value, ZiScaleFactor scale);
