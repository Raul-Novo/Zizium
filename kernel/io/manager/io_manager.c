// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/driver.h"
#include "zi/executive_lock.h"
#include "zi/io.h"
#include "zi/unicode.h"
#include "zizium/status.h"
#include "zizium/types.h"

static ZiExecutiveLock s_io_lock;
static ZiDeviceObject* s_devices[ZI_IO_MAXIMUM_PUBLISHED_DEVICES];
static ZiIrp* s_active_requests[ZI_IO_MAXIMUM_ACTIVE_REQUESTS];
static bool s_io_initialised;

static bool request_is_valid(const ZiIrp* request);
static bool device_is_valid(const ZiDeviceObject* device);
static bool string_equal(ZiStringView left, ZiStringView right);
static ZiStatus active_request_add(ZiIrp* request);
static void active_request_remove(ZiIrp* request);
static ZiStatus begin_completion(ZiIrp* request, uint32_t request_flag, ZiStatus status);

ZiStatus zi_io_initialise(void) {
  if (s_io_initialised) {
    return ZI_STATUS_INVALID_STATE;
  }
  for (size_t index = 0; index < ZI_IO_MAXIMUM_PUBLISHED_DEVICES; ++index) {
    s_devices[index] = NULL;
  }
  for (size_t index = 0; index < ZI_IO_MAXIMUM_ACTIVE_REQUESTS; ++index) {
    s_active_requests[index] = NULL;
  }
  zi_executive_lock_initialise(&s_io_lock);
  s_io_initialised = true;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_io_request_initialise(ZiIrp* request, const ZiIoRequestInitialiser* initialiser) {
  if (request == NULL || initialiser == NULL || initialiser->struct_size < sizeof *initialiser ||
      initialiser->version != ZI_IO_REQUEST_INITIALISER_VERSION ||
      initialiser->major_operation >= ZI_IRP_OPERATION_COUNT ||
      (initialiser->buffer.size != 0 && initialiser->buffer.data == NULL) ||
      (initialiser->input_buffer.size != 0 && initialiser->input_buffer.data == NULL)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiIrp result = {0};
  result.struct_size = sizeof result;
  result.version = ZI_IRP_VERSION;
  result.state = ZI_IRP_STATE_INITIALISED;
  result.major_operation = initialiser->major_operation;
  result.minor_operation = initialiser->minor_operation;
  result.io_status.status = ZI_STATUS_PENDING;
  result.buffer = initialiser->buffer;
  result.offset = initialiser->offset;
  result.deadline_ticks = initialiser->deadline_ticks;
  result.owner_context = initialiser->owner_context;
  result.completion = initialiser->completion;
  result.completion_context = initialiser->completion_context;
  result.cancel = initialiser->cancel;
  result.cancel_context = initialiser->cancel_context;
  result.input_buffer = initialiser->input_buffer;
  *request = result;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_io_publish_device(ZiDeviceObject* device) {
  if (!s_io_initialised || !device_is_valid(device) || device->name.data == NULL ||
      device->name.size == 0 || ZiFailed(zi_utf8_validate(device->name.data, device->name.size))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_executive_lock_acquire(&s_io_lock);
  size_t empty_index = ZI_IO_MAXIMUM_PUBLISHED_DEVICES;
  for (size_t index = 0; index < ZI_IO_MAXIMUM_PUBLISHED_DEVICES; ++index) {
    if (s_devices[index] == NULL) {
      if (empty_index == ZI_IO_MAXIMUM_PUBLISHED_DEVICES) {
        empty_index = index;
      }
      continue;
    }
    if (s_devices[index] == device || string_equal(s_devices[index]->name, device->name)) {
      zi_executive_lock_release(&s_io_lock);
      return ZI_STATUS_ALREADY_EXISTS;
    }
  }
  if (empty_index == ZI_IO_MAXIMUM_PUBLISHED_DEVICES) {
    zi_executive_lock_release(&s_io_lock);
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  s_devices[empty_index] = device;
  zi_executive_lock_release(&s_io_lock);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_io_unpublish_device(ZiDeviceObject* device) {
  if (!s_io_initialised || !device_is_valid(device)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_executive_lock_acquire(&s_io_lock);
  for (size_t index = 0; index < ZI_IO_MAXIMUM_PUBLISHED_DEVICES; ++index) {
    if (s_devices[index] == device) {
      s_devices[index] = NULL;
      zi_executive_lock_release(&s_io_lock);
      return ZI_STATUS_SUCCESS;
    }
  }
  zi_executive_lock_release(&s_io_lock);
  return ZI_STATUS_NOT_FOUND;
}

ZiStatus zi_io_find_device(ZiStringView name, ZiDeviceObject** out_device) {
  if (!s_io_initialised || name.data == NULL || name.size == 0 || out_device == NULL ||
      ZiFailed(zi_utf8_validate(name.data, name.size))) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_device = NULL;
  zi_executive_lock_acquire(&s_io_lock);
  for (size_t index = 0; index < ZI_IO_MAXIMUM_PUBLISHED_DEVICES; ++index) {
    if (s_devices[index] != NULL && string_equal(s_devices[index]->name, name)) {
      *out_device = s_devices[index];
      break;
    }
  }
  zi_executive_lock_release(&s_io_lock);
  return *out_device == NULL ? ZI_STATUS_NOT_FOUND : ZI_STATUS_SUCCESS;
}

ZiStatus zi_io_submit(ZiDeviceObject* device, ZiIrp* request) {
  if (!s_io_initialised || !device_is_valid(device) || !request_is_valid(request) ||
      request->major_operation >= ZI_IRP_OPERATION_COUNT) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint32_t expected = ZI_IRP_STATE_INITIALISED;
  if (!__atomic_compare_exchange_n(&request->state,
                                   &expected,
                                   ZI_IRP_STATE_SUBMITTED,
                                   false,
                                   __ATOMIC_ACQ_REL,
                                   __ATOMIC_ACQUIRE)) {
    return ZI_STATUS_INVALID_STATE;
  }
  ZiStatus status = active_request_add(request);
  if (ZiFailed(status)) {
    __atomic_store_n(&request->state, ZI_IRP_STATE_INITIALISED, __ATOMIC_RELEASE);
    return status;
  }

  ZiDeviceObject* target = device;
  size_t depth = 1;
  while (target->attached_above != NULL) {
    if (++depth > ZI_IO_MAXIMUM_DEVICE_STACK_DEPTH || !device_is_valid(target->attached_above)) {
      (void)zi_io_complete(request, ZI_STATUS_INVALID_STATE, 0);
      return ZI_STATUS_INVALID_STATE;
    }
    target = target->attached_above;
  }
  request->current_device = target;
  ZiDriverDispatchRoutine dispatch = target->driver->dispatch[request->major_operation];
  if (dispatch == NULL) {
    (void)zi_io_complete(request, ZI_STATUS_NOT_IMPLEMENTED, 0);
    return ZI_STATUS_NOT_IMPLEMENTED;
  }

  status = dispatch(target, request);
  uint32_t state = __atomic_load_n(&request->state, __ATOMIC_ACQUIRE);
  if (state == ZI_IRP_STATE_COMPLETED) {
    return request->io_status.status;
  }
  if (status == ZI_STATUS_PENDING) {
    expected = ZI_IRP_STATE_SUBMITTED;
    if (__atomic_compare_exchange_n(&request->state,
                                    &expected,
                                    ZI_IRP_STATE_PENDING,
                                    false,
                                    __ATOMIC_ACQ_REL,
                                    __ATOMIC_ACQUIRE)) {
      return ZI_STATUS_PENDING;
    }
    return request->state == ZI_IRP_STATE_COMPLETED ? request->io_status.status
                                                    : ZI_STATUS_INVALID_STATE;
  }
  ZiStatus completion_status = zi_io_complete(request, status, request->io_status.information);
  if (ZiFailed(completion_status)) {
    return completion_status;
  }
  return status;
}

ZiStatus zi_io_complete(ZiIrp* request, ZiStatus status, size_t information) {
  if (!s_io_initialised || !request_is_valid(request) || status == ZI_STATUS_PENDING) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint32_t state = __atomic_load_n(&request->state, __ATOMIC_ACQUIRE);
  for (;;) {
    if (state != ZI_IRP_STATE_SUBMITTED && state != ZI_IRP_STATE_PENDING) {
      return ZI_STATUS_INVALID_STATE;
    }
    if (__atomic_compare_exchange_n(&request->state,
                                    &state,
                                    ZI_IRP_STATE_COMPLETING,
                                    false,
                                    __ATOMIC_ACQ_REL,
                                    __ATOMIC_ACQUIRE)) {
      break;
    }
  }
  request->io_status.status = status;
  request->io_status.information = information;
  active_request_remove(request);
  __atomic_store_n(&request->state, ZI_IRP_STATE_COMPLETED, __ATOMIC_RELEASE);
  if (request->completion != NULL) {
    request->completion(request, request->completion_context);
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_io_cancel(ZiIrp* request) {
  return begin_completion(request, ZI_IRP_FLAG_CANCEL_REQUESTED, ZI_STATUS_CANCELLED);
}

ZiStatus zi_io_expire(ZiIrp* request, uint64_t current_ticks) {
  if (!request_is_valid(request)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (request->deadline_ticks == 0 || current_ticks < request->deadline_ticks) {
    return ZI_STATUS_NOT_FOUND;
  }
  return begin_completion(request, ZI_IRP_FLAG_TIMEOUT_REQUESTED, ZI_STATUS_TIMEOUT);
}

ZiStatus zi_io_cancel_owner(void* owner_context, size_t* out_cancelled_count) {
  if (!s_io_initialised || owner_context == NULL || out_cancelled_count == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_cancelled_count = 0;
  ZiIrp* requests[ZI_IO_MAXIMUM_ACTIVE_REQUESTS] = {0};
  size_t count = 0;
  zi_executive_lock_acquire(&s_io_lock);
  for (size_t index = 0; index < ZI_IO_MAXIMUM_ACTIVE_REQUESTS; ++index) {
    if (s_active_requests[index] != NULL &&
        s_active_requests[index]->owner_context == owner_context) {
      requests[count++] = s_active_requests[index];
    }
  }
  zi_executive_lock_release(&s_io_lock);
  for (size_t index = 0; index < count; ++index) {
    if (ZiSucceeded(zi_io_cancel(requests[index]))) {
      ++*out_cancelled_count;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static bool request_is_valid(const ZiIrp* request) {
  return (bool)((request != NULL && request->struct_size >= sizeof *request &&
                 request->version == ZI_IRP_VERSION) != 0);
}

static bool device_is_valid(const ZiDeviceObject* device) {
  return (bool)((device != NULL && device->struct_size >= sizeof *device &&
                 device->version == ZI_DEVICE_OBJECT_VERSION && device->driver != NULL &&
                 device->driver->struct_size >= sizeof *device->driver &&
                 device->driver->version == ZI_DRIVER_OBJECT_VERSION) != 0);
}

static bool string_equal(ZiStringView left, ZiStringView right) {
  if (left.size != right.size || (left.size != 0 && (left.data == NULL || right.data == NULL))) {
    return false;
  }
  for (size_t index = 0; index < left.size; ++index) {
    if (left.data[index] != right.data[index]) {
      return false;
    }
  }
  return true;
}

static ZiStatus active_request_add(ZiIrp* request) {
  zi_executive_lock_acquire(&s_io_lock);
  for (size_t index = 0; index < ZI_IO_MAXIMUM_ACTIVE_REQUESTS; ++index) {
    if (s_active_requests[index] == NULL) {
      s_active_requests[index] = request;
      zi_executive_lock_release(&s_io_lock);
      return ZI_STATUS_SUCCESS;
    }
  }
  zi_executive_lock_release(&s_io_lock);
  return ZI_STATUS_QUEUE_FULL;
}

static void active_request_remove(ZiIrp* request) {
  zi_executive_lock_acquire(&s_io_lock);
  for (size_t index = 0; index < ZI_IO_MAXIMUM_ACTIVE_REQUESTS; ++index) {
    if (s_active_requests[index] == request) {
      s_active_requests[index] = NULL;
      break;
    }
  }
  zi_executive_lock_release(&s_io_lock);
}

static ZiStatus begin_completion(ZiIrp* request, uint32_t request_flag, ZiStatus status) {
  if (!s_io_initialised || !request_is_valid(request)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint32_t state = __atomic_load_n(&request->state, __ATOMIC_ACQUIRE);
  if (state != ZI_IRP_STATE_SUBMITTED && state != ZI_IRP_STATE_PENDING) {
    return ZI_STATUS_INVALID_STATE;
  }
  (void)__atomic_fetch_or(&request->flags, request_flag, __ATOMIC_ACQ_REL);
  if (request->cancel != NULL) {
    request->cancel(request, request->cancel_context);
  }
  if (__atomic_load_n(&request->state, __ATOMIC_ACQUIRE) == ZI_IRP_STATE_COMPLETED) {
    return ZI_STATUS_SUCCESS;
  }
  return zi_io_complete(request, status, 0);
}
