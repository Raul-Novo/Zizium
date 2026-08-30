// SPDX-License-Identifier: GPL-3.0-or-later

#define ZI_BUILD_ZICRT 1

#include <stddef.h>
#include <stdio.h>

#include "zizium/status.h"
#include "zizium/zx.h"

// This standard C runtime export is resolved by ordinary user programmes.
// The host UCRT prototype uses a toolchain-owned parameter spelling.
// NOLINTNEXTLINE(misc-use-internal-linkage, readability-inconsistent-declaration-parameter-name)
int puts(const char* text) {
  if (text == NULL) {
    return -1;
  }
  size_t size = 0;
  while (text[size] != '\0') {
    ++size;
  }
  if (ZiFailed(ZxDebugWrite(text, size)) || ZiFailed(ZxDebugWrite("\n", 1))) {
    return -1;
  }
  return 0;
}
