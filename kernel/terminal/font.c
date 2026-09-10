// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/font.h"

#include <stdint.h>

const uint8_t* zi_font_glyph(uint32_t scalar) {
  if (scalar >= 32u && scalar <= 126u) {
    return k_zi_font_spleen_8x16[scalar];
  }
  return k_zi_font_spleen_8x16[127];
}
