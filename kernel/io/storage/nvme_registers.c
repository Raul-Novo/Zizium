// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/nvme_registers.h"

#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"

ZiStatus zi_nvme_register_window_validate(uint64_t base, uint64_t size, uint32_t stride) {
  if (base == 0 || (base & (sizeof(uint64_t) - 1u)) != 0 || size < UINT64_C(0x2000) ||
      size > UINT64_C(128) * 1024u * 1024u || size > SIZE_MAX || base > UINT64_MAX - size ||
      stride < 4u || stride > (UINT32_C(1) << 17u) || (stride & (stride - 1u)) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t last_doorbell = UINT64_C(0x1000) + (UINT64_C(3) * stride);
  if (last_doorbell > size - sizeof(uint32_t)) {
    return ZI_STATUS_NOT_IMPLEMENTED;
  }
  return ZI_STATUS_SUCCESS;
}
