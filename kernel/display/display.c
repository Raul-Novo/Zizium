// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/display.h"

#include <stdint.h>

ZiScaleFactor zi_display_default_scale(uint32_t pixel_height) {
  ZiScaleFactor scale = {1, 1};
  if (pixel_height <= 1080u) {
    return scale;
  }
  if (pixel_height <= 1440u) {
    scale.numerator = 5;
    scale.denominator = 4;
    return scale;
  }
  if (pixel_height <= 2160u) {
    scale.numerator = 2;
    scale.denominator = 1;
    return scale;
  }
  scale.numerator = 5;
  scale.denominator = 2;
  return scale;
}

uint32_t zi_scale_u32(uint32_t value, ZiScaleFactor scale) {
  if (scale.denominator == 0) {
    return 0;
  }
  uint64_t scaled = (uint64_t)value * scale.numerator;
  return (uint32_t)((scaled + (scale.denominator / 2u)) / scale.denominator);
}
