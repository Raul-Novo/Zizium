// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/driver.h"

#include "zi/io.h"
#include "zizium/status.h"
#include "zizium/types.h"

ZiStatus zi_driver_attach_device(ZiDeviceObject* upper, ZiDeviceObject* lower) {
  if (upper == NULL || lower == NULL || upper == lower || upper->attached_below != NULL ||
      lower->attached_above != NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  upper->attached_below = lower;
  lower->attached_above = upper;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_driver_detach_device(ZiDeviceObject* upper, ZiDeviceObject* lower) {
  if (upper == NULL || lower == NULL || upper == lower || upper->attached_below != lower ||
      lower->attached_above != upper) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  upper->attached_below = NULL;
  lower->attached_above = NULL;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_driver_load_image(ZiStringView path, ZiDriverObject** out_driver) {
  if (path.data == NULL || path.size == 0 || out_driver == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_driver = NULL;
  return ZI_STATUS_NOT_IMPLEMENTED;
}

ZiStatus zi_driver_unload(ZiDriverObject* driver) {
  if (driver == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return ZI_STATUS_NOT_IMPLEMENTED;
}
