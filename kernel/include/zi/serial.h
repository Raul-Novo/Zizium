// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"

ZiStatus zi_serial_initialise(void);
bool zi_serial_is_ready(void);
void zi_serial_write(const char* text, size_t text_size);
void zi_serial_write_byte(uint8_t value);
bool zi_serial_try_read(uint8_t* out_value);
