// SPDX-License-Identifier: GPL-3.0-or-later

#define ZI_BUILD_ZIA 1
#include "zizium/zia.h"

#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"
#include "zizium/types.h"
#include "zizium/zx.h"

ZiStatus ZiCloseHandle(ZiHandle handle) {
  return ZxCloseHandle(handle);
}

ZiStatus ZiConsoleWrite(const char* text, size_t text_size) {
  return ZxDebugWrite(text, text_size);
}

ZiStatus ZiCreateFile(ZiStringView path, const ZiFileOpenOptions* options, ZiHandle* out_handle) {
  if (path.data == NULL || path.size == 0 || options == NULL || out_handle == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_handle = ZI_INVALID_HANDLE;
  return ZI_STATUS_NOT_IMPLEMENTED;
}

ZiStatus ZiOpenFile(ZiStringView path, ZiAccessMask desired_access, ZiHandle* out_handle) {
  if (path.data == NULL || path.size == 0 || desired_access == 0 || out_handle == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_handle = ZI_INVALID_HANDLE;
  return ZI_STATUS_NOT_IMPLEMENTED;
}

ZiStatus ZiReadFile(ZiHandle handle,
                    void* buffer,
                    size_t buffer_size,
                    uint64_t offset,
                    ZiIoResult* out_result) {
  (void)offset;
  if (handle == ZI_INVALID_HANDLE || buffer == NULL || buffer_size == 0 || out_result == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  out_result->status = ZI_STATUS_NOT_IMPLEMENTED;
  out_result->transferred = 0;
  return ZI_STATUS_NOT_IMPLEMENTED;
}

ZiStatus ZiWriteFile(ZiHandle handle,
                     const void* buffer,
                     size_t buffer_size,
                     uint64_t offset,
                     ZiIoResult* out_result) {
  (void)offset;
  if (handle == ZI_INVALID_HANDLE || buffer == NULL || buffer_size == 0 || out_result == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  out_result->status = ZI_STATUS_NOT_IMPLEMENTED;
  out_result->transferred = 0;
  return ZI_STATUS_NOT_IMPLEMENTED;
}

ZiStatus ZiAllocateMemory(size_t size, void** out_memory) {
  if (out_memory == NULL || size == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_memory = NULL;
  return ZxAllocateVirtualMemory(out_memory, size, 0);
}

ZiStatus ZiFreeMemory(void* memory) {
  if (memory == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return ZI_STATUS_NOT_IMPLEMENTED;
}

ZiStatus ZiCreateProcess(ZiStringView image_path, ZiHandle* out_process) {
  if (image_path.data == NULL || image_path.size == 0 || out_process == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_process = ZI_INVALID_HANDLE;
  return ZxCreateProcess(image_path.data, image_path.size, out_process);
}

ZiStatus ZiCreateThread(ZiHandle process, ZiHandle* out_thread) {
  if (process == ZI_INVALID_HANDLE || out_thread == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_thread = ZI_INVALID_HANDLE;
  return ZI_STATUS_NOT_IMPLEMENTED;
}

ZiStatus ZiWaitForObject(ZiHandle handle, uint64_t timeout) {
  if (handle == ZI_INVALID_HANDLE) {
    return ZI_STATUS_INVALID_HANDLE;
  }
  int32_t exit_code = 0;
  return ZxWaitForObject(handle, timeout, &exit_code);
}

ZiStatus ZiWaitForProcess(ZiHandle process, uint64_t timeout, int32_t* out_exit_code) {
  if (process == ZI_INVALID_HANDLE || out_exit_code == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return ZxWaitForObject(process, timeout, out_exit_code);
}

ZiStatus ZiQuerySystemInformation(uint32_t information_class,
                                  void* buffer,
                                  size_t buffer_size,
                                  size_t* out_required_size) {
  (void)information_class;
  (void)buffer;
  (void)buffer_size;
  if (out_required_size == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_required_size = 0;
  return ZI_STATUS_NOT_IMPLEMENTED;
}
