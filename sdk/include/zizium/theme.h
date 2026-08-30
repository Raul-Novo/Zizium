// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "zizium/types.h"

#define ZI_COLOUR_PRIMARY ((ZiColour)0x006496E6u)
#define ZI_COLOUR_SOFT_ACCENT ((ZiColour)0x00D1ECFCu)
#define ZI_COLOUR_BACKGROUND ((ZiColour)0x00F7FBFFu)
#define ZI_COLOUR_TEXT ((ZiColour)0x00172033u)
#define ZI_COLOUR_MUTED_TEXT ((ZiColour)0x005F6F8Au)
#define ZI_COLOUR_PANEL_BORDER ((ZiColour)0x00D7E7F8u)
#define ZI_COLOUR_SUCCESS ((ZiColour)0x0063C785u)
#define ZI_COLOUR_WARNING ((ZiColour)0x00E6B864u)
#define ZI_COLOUR_ERROR ((ZiColour)0x00E66F6Fu)

typedef struct ZiThemeColours {
  uint32_t struct_size;
  uint32_t version;
  ZiColour primary;
  ZiColour soft_accent;
  ZiColour background;
  ZiColour text;
  ZiColour muted_text;
  ZiColour panel_border;
  ZiColour success;
  ZiColour warning;
  ZiColour error;
} ZiThemeColours;
