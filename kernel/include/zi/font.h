// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

#define ZI_EARLY_FONT_WIDTH 8u
#define ZI_EARLY_FONT_HEIGHT 16u

// Generated from the pinned Spleen data; shared by the generator and glyph lookup.
extern const uint8_t k_zi_font_spleen_8x16[128][ZI_EARLY_FONT_HEIGHT];

const uint8_t* zi_font_glyph(uint32_t scalar);
