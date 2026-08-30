// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zizium/ipc.h"
#include "zizium/status.h"
#include "zizium/types.h"

enum ZiSyscallNumber {
  ZI_SYSCALL_CLOSE_HANDLE = 0x0000,
  ZI_SYSCALL_WAIT_FOR_OBJECT = 0x0001,
  ZI_SYSCALL_EXIT_PROCESS = 0x0100,
  ZI_SYSCALL_CREATE_PROCESS = 0x0101,
  ZI_SYSCALL_CREATE_THREAD = 0x0102,
  ZI_SYSCALL_ALLOCATE_VIRTUAL_MEMORY = 0x0200,
  ZI_SYSCALL_FREE_VIRTUAL_MEMORY = 0x0201,
  ZI_SYSCALL_CREATE_FILE = 0x0300,
  ZI_SYSCALL_READ_FILE = 0x0301,
  ZI_SYSCALL_WRITE_FILE = 0x0302,
  ZI_SYSCALL_DEVICE_IO_CONTROL = 0x0400,
  ZI_SYSCALL_SEND_CHANNEL = 0x0500,
  ZI_SYSCALL_RECEIVE_CHANNEL = 0x0501,
  ZI_SYSCALL_GET_BOOTSTRAP_CHANNEL = 0x0502,
  ZI_SYSCALL_QUERY_TIME = 0x0600,
  ZI_SYSCALL_ACCESS_CHECK = 0x0700,
  ZI_SYSCALL_QUERY_SYSTEM_INFORMATION = 0x0800,
  ZI_SYSCALL_DEBUG_WRITE = 0x0900,
};

ZiStatus ZxCloseHandle(ZiHandle handle);
ZiStatus ZxWaitForObject(ZiHandle handle, uint64_t timeout, int32_t* out_exit_code);
ZiStatus ZxExitProcess(int32_t exit_code);
ZiStatus ZxCreateProcess(const char* image_path, size_t image_path_size, ZiHandle* out_process);
ZiStatus ZxAllocateVirtualMemory(void** inout_address, size_t size, uint32_t flags);
ZiStatus ZxSendChannel(ZiHandle channel, const ZiChannelMessage* message);
ZiStatus ZxReceiveChannel(ZiHandle channel, ZiChannelMessage* out_message);
ZiStatus ZxGetBootstrapChannel(ZiHandle* out_channel);
ZiStatus ZxDebugWrite(const char* text, size_t text_size);
