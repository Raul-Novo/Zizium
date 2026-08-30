// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"
#include "zizium/types.h"

#if defined(_WIN32) && defined(ZI_BUILD_ZIA)
#define ZI_API __declspec(dllexport)
#elif defined(_WIN32)
#define ZI_API __declspec(dllimport)
#else
#define ZI_API
#endif

typedef struct ZiIoResult {
  ZiStatus status;
  size_t transferred;
} ZiIoResult;

typedef struct ZiFileOpenOptions {
  uint32_t struct_size;
  uint32_t version;
  ZiAccessMask desired_access;
  uint32_t disposition;
  uint32_t flags;
} ZiFileOpenOptions;

ZI_API ZiStatus ZiCloseHandle(ZiHandle handle);
ZI_API ZiStatus ZiConsoleWrite(const char* text, size_t text_size);
ZI_API ZiStatus ZiCreateFile(ZiStringView path,
                             const ZiFileOpenOptions* options,
                             ZiHandle* out_handle);
ZI_API ZiStatus ZiOpenFile(ZiStringView path, ZiAccessMask desired_access, ZiHandle* out_handle);
ZI_API ZiStatus ZiReadFile(ZiHandle handle,
                           void* buffer,
                           size_t buffer_size,
                           uint64_t offset,
                           ZiIoResult* out_result);
ZI_API ZiStatus ZiWriteFile(ZiHandle handle,
                            const void* buffer,
                            size_t buffer_size,
                            uint64_t offset,
                            ZiIoResult* out_result);
ZI_API ZiStatus ZiAllocateMemory(size_t size, void** out_memory);
ZI_API ZiStatus ZiFreeMemory(void* memory);
ZI_API ZiStatus ZiCreateProcess(ZiStringView image_path, ZiHandle* out_process);
ZI_API ZiStatus ZiCreateThread(ZiHandle process, ZiHandle* out_thread);
ZI_API ZiStatus ZiWaitForObject(ZiHandle handle, uint64_t timeout);
ZI_API ZiStatus ZiWaitForProcess(ZiHandle process, uint64_t timeout, int32_t* out_exit_code);
ZI_API ZiStatus ZiQuerySystemInformation(uint32_t information_class,
                                         void* buffer,
                                         size_t buffer_size,
                                         size_t* out_required_size);
