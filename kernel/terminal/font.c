// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/font.h"

#include <stdint.h>

extern const uint8_t k_zi_font_spleen_8x16[128][ZI_EARLY_FONT_HEIGHT];

const uint8_t* zi_font_glyph(uint32_t scalar) {
  if (scalar >= 32u && scalar <= 126u) {
    return k_zi_font_spleen_8x16[scalar];
  }
  return k_zi_font_spleen_8x16[127];
}
