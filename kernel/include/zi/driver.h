// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/io.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_DRIVER_OBJECT_VERSION 1u
#define ZI_DEVICE_OBJECT_VERSION 1u

enum ZiDriverKind {
  ZI_DRIVER_BUS = 1,
  ZI_DRIVER_FUNCTION = 2,
  ZI_DRIVER_FILTER = 3,
};

enum ZiDevicePowerState {
  ZI_DEVICE_POWER_ON = 0,
  ZI_DEVICE_POWER_IDLE = 1,
  ZI_DEVICE_POWER_SLEEP = 2,
  ZI_DEVICE_POWER_OFF = 3,
};

typedef struct ZiDriverContext {
  uint32_t struct_size;
  uint32_t version;
  const void* image_base;
  size_t image_size;
  const void* service_manifest;
} ZiDriverContext;

typedef struct ZiDriverObject {
  uint32_t struct_size;
  uint32_t version;
  ZiStringView name;
  uint32_t driver_kind;
  uint32_t flags;
  ZiDriverDispatchRoutine dispatch[ZI_IRP_OPERATION_COUNT];
  ZiDeviceObject* devices;
  void* driver_extension;
} ZiDriverObject;

struct ZiDeviceObject {
  uint32_t struct_size;
  uint32_t version;
  ZiStringView name;
  ZiDriverObject* driver;
  ZiDeviceObject* attached_above;
  ZiDeviceObject* attached_below;
  ZiDeviceObject* next_driver_device;
  uint32_t device_type;
  uint32_t flags;
  uint32_t power_state;
  void* device_extension;
};

typedef ZiDriverObject ZiBusDriver;
typedef ZiDriverObject ZiFunctionDriver;
typedef ZiDriverObject ZiFilterDriver;

typedef struct ZiPlugAndPlayManager {
  uint32_t struct_size;
  uint32_t version;
  uint64_t generation;
  uint32_t state;
} ZiPlugAndPlayManager;

typedef struct ZiPowerManager {
  uint32_t struct_size;
  uint32_t version;
  uint32_t system_state;
  uint32_t flags;
} ZiPowerManager;

ZiStatus ZiDriverMain(ZiDriverObject* driver, ZiDriverContext* context);
ZiStatus zi_driver_attach_device(ZiDeviceObject* upper, ZiDeviceObject* lower);
ZiStatus zi_driver_detach_device(ZiDeviceObject* upper, ZiDeviceObject* lower);
ZiStatus zi_driver_load_image(ZiStringView path, ZiDriverObject** out_driver);
ZiStatus zi_driver_unload(ZiDriverObject* driver);
