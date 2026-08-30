// SPDX-License-Identifier: GPL-3.0-or-later

#include "zizium/status.h"
#include "zizium/zia.h"

int main(void) {
  static const char k_message[] = "Hello through the optional ZIA library.\n";
  ZiStatus status = ZiConsoleWrite(k_message, sizeof k_message - 1u);
  if (ZiSucceeded(status)) {
    return 23;
  }
  return 1;
}
