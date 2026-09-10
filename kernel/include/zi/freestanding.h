// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>

// C compiler support symbols supplied by the kernel without a hosted CRT.
void* memcpy(void* destination, const void* source, size_t size);
void* memset(void* destination, int value, size_t size);
int memcmp(const void* left, const void* right, size_t size);
