// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

#define ZI_EARLY_FONT_WIDTH 8u
#define ZI_EARLY_FONT_HEIGHT 16u

const uint8_t* zi_font_glyph(uint32_t scalar);
