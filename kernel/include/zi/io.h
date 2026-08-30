// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/block.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_IRP_VERSION 2u
#define ZI_IO_REQUEST_INITIALISER_VERSION 2u
#define ZI_IO_MAXIMUM_DEVICE_STACK_DEPTH 32u
#define ZI_IO_MAXIMUM_PUBLISHED_DEVICES 128u
#define ZI_IO_MAXIMUM_ACTIVE_REQUESTS 128u

typedef struct ZiDeviceObject ZiDeviceObject;  // NOLINT(readability-identifier-naming)
struct ZiIrp;

enum ZiIrpMajorOperation {
  ZI_IRP_CREATE = 0,
  ZI_IRP_CLOSE = 1,
  ZI_IRP_READ = 2,
  ZI_IRP_WRITE = 3,
  ZI_IRP_DEVICE_CONTROL = 4,
  ZI_IRP_QUERY_INFORMATION = 5,
  ZI_IRP_SET_INFORMATION = 6,
  ZI_IRP_POWER = 7,
  ZI_IRP_PLUG_AND_PLAY = 8,
  ZI_IRP_FLUSH = 9,
  ZI_IRP_OPERATION_COUNT = 10,
};

enum ZiIrpState {
  ZI_IRP_STATE_UNINITIALISED = 0,
  ZI_IRP_STATE_INITIALISED = 1,
  ZI_IRP_STATE_SUBMITTED = 2,
  ZI_IRP_STATE_PENDING = 3,
  ZI_IRP_STATE_COMPLETING = 4,
  ZI_IRP_STATE_COMPLETED = 5,
};

enum ZiIrpFlags {
  ZI_IRP_FLAG_NONE = 0,
  ZI_IRP_FLAG_CANCEL_REQUESTED = 1u << 0,
  ZI_IRP_FLAG_TIMEOUT_REQUESTED = 1u << 1,
};

typedef struct ZiIoStatusBlock {
  ZiStatus status;
  size_t information;
} ZiIoStatusBlock;

typedef ZiStatus (*ZiDriverDispatchRoutine)(ZiDeviceObject* device, struct ZiIrp* request);
typedef void (*ZiIoCompletionRoutine)(struct ZiIrp* request, void* context);
typedef void (*ZiIoCancelRoutine)(struct ZiIrp* request, void* context);

typedef struct ZiIoRequestInitialiser {
  uint32_t struct_size;
  uint32_t version;
  uint32_t major_operation;
  uint32_t minor_operation;
  ZiMutableBuffer buffer;
  uint64_t offset;
  uint64_t deadline_ticks;
  void* owner_context;
  ZiIoCompletionRoutine completion;
  void* completion_context;
  ZiIoCancelRoutine cancel;
  void* cancel_context;
  ZiConstBuffer input_buffer;
} ZiIoRequestInitialiser;

typedef struct ZiIrp {
  uint32_t struct_size;
  uint32_t version;
  volatile uint32_t state;
  volatile uint32_t flags;
  uint32_t major_operation;
  uint32_t minor_operation;
  ZiIoStatusBlock io_status;
  ZiMutableBuffer buffer;
  uint64_t offset;
  uint64_t deadline_ticks;
  void* owner_context;
  ZiIoCompletionRoutine completion;
  void* completion_context;
  ZiIoCancelRoutine cancel;
  void* cancel_context;
  ZiDeviceObject* current_device;
  struct ZiIrp* next;
  ZiConstBuffer input_buffer;
} ZiIrp;

typedef struct ZiDeviceStack {
  ZiDeviceObject* top;
  ZiDeviceObject* bottom;
  size_t depth;
} ZiDeviceStack;

typedef struct ZiFileObject {
  ZiHandle handle;
  ZiDeviceObject* device;
  uint64_t current_offset;
  ZiAccessMask granted_access;
  uint32_t flags;
} ZiFileObject;

typedef struct ZiVolumeObject {
  ZiDeviceObject* device;
  ZiBlockDevice* block_device;
  char drive_letter;
  uint32_t flags;
} ZiVolumeObject;

ZiStatus zi_io_initialise(void);
ZiStatus zi_io_request_initialise(ZiIrp* request, const ZiIoRequestInitialiser* initialiser);
ZiStatus zi_io_publish_device(ZiDeviceObject* device);
ZiStatus zi_io_unpublish_device(ZiDeviceObject* device);
ZiStatus zi_io_find_device(ZiStringView name, ZiDeviceObject** out_device);
ZiStatus zi_io_submit(ZiDeviceObject* device, ZiIrp* request);
ZiStatus zi_io_complete(ZiIrp* request, ZiStatus status, size_t information);
ZiStatus zi_io_cancel(ZiIrp* request);
ZiStatus zi_io_expire(ZiIrp* request, uint64_t current_ticks);
ZiStatus zi_io_cancel_owner(void* owner_context, size_t* out_cancelled_count);
