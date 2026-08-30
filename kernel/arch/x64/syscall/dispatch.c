// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stdint.h>

#include "zi/address_space.h"
#include "zi/syscall.h"
#include "zizium/status.h"

#ifdef ZI_KERNEL
#include "zi/user_process.h"
#endif

#define ZI_X64_USER_RFLAGS_ALLOWED UINT64_C(0x0000000000240ed7)

bool zi_x64_syscall_return_is_safe(const ZiSyscallFrame* frame) {
  if (frame == NULL || frame->struct_size != sizeof *frame ||
      frame->version != ZI_X64_SYSCALL_FRAME_VERSION ||
      !zi_user_range_is_valid(frame->user_instruction_pointer, 1) ||
      !zi_user_range_is_valid(frame->user_stack_pointer, 1) ||
      (frame->user_flags & UINT64_C(0x202)) != UINT64_C(0x202) ||
      (frame->user_flags & ~ZI_X64_USER_RFLAGS_ALLOWED) != 0) {
    return false;
  }
  return true;
}

ZiStatus ZkDispatchSyscall(ZiSyscallFrame* frame) {
  if (frame == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
#ifdef ZI_KERNEL
  return zi_user_process_dispatch_syscall(frame);
#else
  return ZI_STATUS_NOT_IMPLEMENTED;
#endif
}
