// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>

#include "zi/display.h"
#include "zizium/status.h"

ZiStatus zi_framebuffer_console_initialise(const ZiFramebuffer* framebuffer, ZiScaleFactor scale);
bool zi_framebuffer_console_is_ready(void);
void zi_framebuffer_console_write(const char* text, size_t text_size);
void zi_framebuffer_console_clear(void);
void zi_framebuffer_console_redraw(void);
