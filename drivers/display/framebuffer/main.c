// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/driver.h"
#include "zizium/status.h"

ZiStatus ZiDriverMain(ZiDriverObject* driver, ZiDriverContext* context) {
  if (driver == NULL || context == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return ZI_STATUS_NOT_IMPLEMENTED;
}
