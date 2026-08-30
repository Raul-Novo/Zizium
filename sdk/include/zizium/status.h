// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef int32_t ZiStatus;

#define ZI_STATUS_SUCCESS ((ZiStatus)0)
#define ZI_STATUS_PENDING ((ZiStatus)1)
#define ZI_STATUS_NOT_FOUND ((ZiStatus) - 1)
#define ZI_STATUS_ACCESS_DENIED ((ZiStatus) - 2)
#define ZI_STATUS_INVALID_HANDLE ((ZiStatus) - 3)
#define ZI_STATUS_INVALID_ARGUMENT ((ZiStatus) - 4)
#define ZI_STATUS_NO_MEMORY ((ZiStatus) - 5)
#define ZI_STATUS_BAD_IMAGE_FORMAT ((ZiStatus) - 6)
#define ZI_STATUS_INVALID_PATH ((ZiStatus) - 7)
#define ZI_STATUS_CASE_MISMATCH ((ZiStatus) - 8)
#define ZI_STATUS_NOT_IMPLEMENTED ((ZiStatus) - 9)
#define ZI_STATUS_DEVICE_ERROR ((ZiStatus) - 10)
#define ZI_STATUS_TIMEOUT ((ZiStatus) - 11)
#define ZI_STATUS_BUFFER_TOO_SMALL ((ZiStatus) - 12)
#define ZI_STATUS_INVALID_ENCODING ((ZiStatus) - 13)
#define ZI_STATUS_CHECKSUM_MISMATCH ((ZiStatus) - 14)
#define ZI_STATUS_CORRUPT_FILESYSTEM ((ZiStatus) - 15)
#define ZI_STATUS_ALREADY_EXISTS ((ZiStatus) - 16)
#define ZI_STATUS_INVALID_STATE ((ZiStatus) - 17)
#define ZI_STATUS_OUT_OF_BOUNDS ((ZiStatus) - 18)
#define ZI_STATUS_END_OF_FILE ((ZiStatus) - 19)
#define ZI_STATUS_ADDRESS_CONFLICT ((ZiStatus) - 20)
#define ZI_STATUS_PAGE_NOT_MAPPED ((ZiStatus) - 21)
#define ZI_STATUS_MEMORY_CORRUPTION ((ZiStatus) - 22)
#define ZI_STATUS_ALIGNMENT_ERROR ((ZiStatus) - 23)
#define ZI_STATUS_RESOURCE_IN_USE ((ZiStatus) - 24)
#define ZI_STATUS_INVALID_USER_BUFFER ((ZiStatus) - 25)
#define ZI_STATUS_PROCESS_TERMINATED ((ZiStatus) - 26)
#define ZI_STATUS_PRIVILEGE_VIOLATION ((ZiStatus) - 27)
#define ZI_STATUS_IMAGE_RELOCATION_FAILED ((ZiStatus) - 28)
#define ZI_STATUS_IMAGE_DEPENDENCY_CYCLE ((ZiStatus) - 29)
#define ZI_STATUS_IMAGE_IMPORT_NOT_FOUND ((ZiStatus) - 30)
#define ZI_STATUS_INVALID_PROCESS_PARAMETERS ((ZiStatus) - 31)
#define ZI_STATUS_CANCELLED ((ZiStatus) - 32)
#define ZI_STATUS_HANDLE_TABLE_FULL ((ZiStatus) - 33)
#define ZI_STATUS_QUEUE_FULL ((ZiStatus) - 34)
#define ZI_STATUS_PEER_CLOSED ((ZiStatus) - 35)
#define ZI_STATUS_INVALID_MESSAGE ((ZiStatus) - 36)
#define ZI_STATUS_RESOURCE_LEAK ((ZiStatus) - 37)
#define ZI_STATUS_INVALID_SERVICE_MANIFEST ((ZiStatus) - 38)
#define ZI_STATUS_SERVICE_DEPENDENCY_CYCLE ((ZiStatus) - 39)
#define ZI_STATUS_SERVICE_RESTART_LIMIT ((ZiStatus) - 40)
#define ZI_STATUS_READ_ONLY_FILESYSTEM ((ZiStatus) - 41)
#define ZI_STATUS_RECOVERY_REQUIRED ((ZiStatus) - 42)
#define ZI_STATUS_VOLUME_FULL ((ZiStatus) - 43)
#define ZI_STATUS_JOURNAL_FULL ((ZiStatus) - 44)

static inline bool ZiSucceeded(ZiStatus status) {
  return status >= ZI_STATUS_SUCCESS;
}

static inline bool ZiFailed(ZiStatus status) {
  return status < ZI_STATUS_SUCCESS;
}
