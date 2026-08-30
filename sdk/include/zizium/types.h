// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef uint64_t ZiHandle;
typedef uint32_t ZiChar;
typedef uint32_t ZiColour;
typedef uint32_t ZiAccessMask;

#define ZI_INVALID_HANDLE ((ZiHandle)0)

typedef struct ZiStringView {
  const char* data;
  size_t size;
} ZiStringView;

typedef struct ZiMutableBuffer {
  void* data;
  size_t size;
} ZiMutableBuffer;

typedef struct ZiConstBuffer {
  const void* data;
  size_t size;
} ZiConstBuffer;
