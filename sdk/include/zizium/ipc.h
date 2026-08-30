// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zizium/types.h"

#define ZI_CHANNEL_MESSAGE_VERSION 1u
#define ZI_CHANNEL_INLINE_PAYLOAD_CAPACITY 192u

typedef struct ZiChannelMessage {
  uint32_t struct_size;
  uint32_t version;
  uint64_t message_id;
  uint64_t correlation_id;
  uint32_t message_type;
  uint32_t flags;
  size_t payload_size;
  ZiHandle transferred_handle;
  ZiAccessMask transferred_access;
  uint32_t reserved;
  unsigned char inline_payload[ZI_CHANNEL_INLINE_PAYLOAD_CAPACITY];
} ZiChannelMessage;

_Static_assert(sizeof(ZiChannelMessage) == 248, "ZiChannelMessage size mismatch");
