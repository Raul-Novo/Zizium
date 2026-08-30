// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "phase5_tests.h"
#include "zi/driver.h"
#include "zi/io.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define PHASE5_IO_ASSERT(expression)                                                               \
  do {                                                                                             \
    ++assertions;                                                                                  \
    if (!(expression)) {                                                                           \
      (void)fprintf_s(stderr, "%s:%d: assertion failed: %s\n", __FILE__, __LINE__, #expression);   \
      *out_assertion_count = assertions;                                                           \
      return false;                                                                                \
    }                                                                                              \
  } while (false)

typedef struct IoFixture {
  ZiStatus dispatch_status;
  size_t information;
  size_t dispatch_count;
  size_t completion_count;
  size_t cancel_count;
  ZiStatus last_completion_status;
} IoFixture;

static ZiStatus dispatch_read(ZiDeviceObject* device, ZiIrp* request);
static void completion(ZiIrp* request, void* context);
static void cancel(ZiIrp* request, void* context);
static ZiIoRequestInitialiser
request_initialiser(IoFixture* fixture, uint64_t deadline, void* owner);

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
bool phase5_io_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  size_t assertions = 0;
  *out_assertion_count = 0;
  PHASE5_IO_ASSERT(ZiSucceeded(zi_io_initialise()));

  IoFixture fixture = {ZI_STATUS_SUCCESS, 21, 0, 0, 0, ZI_STATUS_PENDING};
  ZiDriverObject lower_driver = {0};
  lower_driver.struct_size = sizeof lower_driver;
  lower_driver.version = ZI_DRIVER_OBJECT_VERSION;
  lower_driver.driver_kind = ZI_DRIVER_BUS;
  ZiDriverObject upper_driver = {0};
  upper_driver.struct_size = sizeof upper_driver;
  upper_driver.version = ZI_DRIVER_OBJECT_VERSION;
  upper_driver.driver_kind = ZI_DRIVER_FUNCTION;
  upper_driver.driver_extension = &fixture;
  upper_driver.dispatch[ZI_IRP_READ] = dispatch_read;

  const char lower_name[] = "\\System\\Devices\\PCI\\Temp";
  const char upper_name[] = "\\System\\Devices\\Storage\\NVMe0";
  ZiDeviceObject lower = {0};
  lower.struct_size = sizeof lower;
  lower.version = ZI_DEVICE_OBJECT_VERSION;
  lower.name = (ZiStringView){lower_name, sizeof lower_name - 1u};
  lower.driver = &lower_driver;
  ZiDeviceObject upper = {0};
  upper.struct_size = sizeof upper;
  upper.version = ZI_DEVICE_OBJECT_VERSION;
  upper.name = (ZiStringView){upper_name, sizeof upper_name - 1u};
  upper.driver = &upper_driver;
  PHASE5_IO_ASSERT(ZiSucceeded(zi_driver_attach_device(&upper, &lower)));
  PHASE5_IO_ASSERT(ZiSucceeded(zi_io_publish_device(&lower)));
  PHASE5_IO_ASSERT(ZiSucceeded(zi_io_publish_device(&upper)));

  ZiDeviceObject* found = NULL;
  PHASE5_IO_ASSERT(ZiSucceeded(zi_io_find_device(lower.name, &found)) && found == &lower);
  const ZiStringView wrong_case = {"\\System\\Devices\\PCI\\temp",
                                   sizeof "\\System\\Devices\\PCI\\temp" - 1u};
  PHASE5_IO_ASSERT(zi_io_find_device(wrong_case, &found) == ZI_STATUS_NOT_FOUND && found == NULL);

  ZiIrp synchronous = {0};
  ZiIoRequestInitialiser initialiser = request_initialiser(&fixture, 0, &fixture);
  PHASE5_IO_ASSERT(ZiSucceeded(zi_io_request_initialise(&synchronous, &initialiser)));
  PHASE5_IO_ASSERT(ZiSucceeded(zi_io_submit(&lower, &synchronous)));
  PHASE5_IO_ASSERT(synchronous.current_device == &upper &&
                   synchronous.state == ZI_IRP_STATE_COMPLETED &&
                   synchronous.io_status.information == 21);
  PHASE5_IO_ASSERT(fixture.dispatch_count == 1 && fixture.completion_count == 1 &&
                   fixture.last_completion_status == ZI_STATUS_SUCCESS);
  PHASE5_IO_ASSERT(zi_io_submit(&lower, &synchronous) == ZI_STATUS_INVALID_STATE);

  fixture.dispatch_status = ZI_STATUS_PENDING;
  ZiIrp cancelled = {0};
  initialiser = request_initialiser(&fixture, 0, &fixture);
  PHASE5_IO_ASSERT(ZiSucceeded(zi_io_request_initialise(&cancelled, &initialiser)));
  PHASE5_IO_ASSERT(zi_io_submit(&lower, &cancelled) == ZI_STATUS_PENDING &&
                   cancelled.state == ZI_IRP_STATE_PENDING);
  PHASE5_IO_ASSERT(ZiSucceeded(zi_io_cancel(&cancelled)) &&
                   cancelled.io_status.status == ZI_STATUS_CANCELLED &&
                   (cancelled.flags & ZI_IRP_FLAG_CANCEL_REQUESTED) != 0);
  PHASE5_IO_ASSERT(fixture.cancel_count == 1 && fixture.completion_count == 2);
  PHASE5_IO_ASSERT(zi_io_complete(&cancelled, ZI_STATUS_SUCCESS, 0) == ZI_STATUS_INVALID_STATE);

  ZiIrp timed_out = {0};
  initialiser = request_initialiser(&fixture, 42, &fixture);
  PHASE5_IO_ASSERT(ZiSucceeded(zi_io_request_initialise(&timed_out, &initialiser)));
  PHASE5_IO_ASSERT(zi_io_submit(&lower, &timed_out) == ZI_STATUS_PENDING);
  PHASE5_IO_ASSERT(zi_io_expire(&timed_out, 41) == ZI_STATUS_NOT_FOUND);
  PHASE5_IO_ASSERT(ZiSucceeded(zi_io_expire(&timed_out, 42)) &&
                   timed_out.io_status.status == ZI_STATUS_TIMEOUT &&
                   (timed_out.flags & ZI_IRP_FLAG_TIMEOUT_REQUESTED) != 0);

  int owner = 0;
  ZiIrp owned[2] = {0};
  for (size_t index = 0; index < 2; ++index) {
    initialiser = request_initialiser(&fixture, 0, &owner);
    PHASE5_IO_ASSERT(ZiSucceeded(zi_io_request_initialise(&owned[index], &initialiser)));
    PHASE5_IO_ASSERT(zi_io_submit(&lower, &owned[index]) == ZI_STATUS_PENDING);
  }
  size_t cancelled_count = 0;
  PHASE5_IO_ASSERT(ZiSucceeded(zi_io_cancel_owner(&owner, &cancelled_count)) &&
                   cancelled_count == 2);
  PHASE5_IO_ASSERT(owned[0].io_status.status == ZI_STATUS_CANCELLED &&
                   owned[1].io_status.status == ZI_STATUS_CANCELLED);

  ZiDeviceObject duplicate = lower;
  duplicate.attached_above = NULL;
  PHASE5_IO_ASSERT(zi_io_publish_device(&duplicate) == ZI_STATUS_ALREADY_EXISTS);
  PHASE5_IO_ASSERT(ZiSucceeded(zi_io_unpublish_device(&upper)));
  PHASE5_IO_ASSERT(ZiSucceeded(zi_io_unpublish_device(&lower)));
  PHASE5_IO_ASSERT(zi_io_find_device(lower.name, &found) == ZI_STATUS_NOT_FOUND);
  *out_assertion_count = assertions;
  return true;
}

static ZiStatus dispatch_read(ZiDeviceObject* device, ZiIrp* request) {
  if (device == NULL || request == NULL || device->driver == NULL ||
      device->driver->driver_extension == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  IoFixture* fixture = device->driver->driver_extension;
  ++fixture->dispatch_count;
  request->io_status.information = fixture->information;
  return fixture->dispatch_status;
}

static void completion(ZiIrp* request, void* context) {
  IoFixture* fixture = context;
  if (request != NULL && fixture != NULL) {
    ++fixture->completion_count;
    fixture->last_completion_status = request->io_status.status;
  }
}

static void cancel(ZiIrp* request, void* context) {
  IoFixture* fixture = context;
  if (request != NULL && fixture != NULL) {
    ++fixture->cancel_count;
  }
}

static ZiIoRequestInitialiser
request_initialiser(IoFixture* fixture, uint64_t deadline, void* owner) {
  ZiIoRequestInitialiser initialiser = {0};
  initialiser.struct_size = sizeof initialiser;
  initialiser.version = ZI_IO_REQUEST_INITIALISER_VERSION;
  initialiser.major_operation = ZI_IRP_READ;
  initialiser.deadline_ticks = deadline;
  initialiser.owner_context = owner;
  initialiser.completion = completion;
  initialiser.completion_context = fixture;
  initialiser.cancel = cancel;
  initialiser.cancel_context = fixture;
  return initialiser;
}
