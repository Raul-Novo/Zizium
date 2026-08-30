// SPDX-License-Identifier: GPL-3.0-or-later

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "zizium/ipc.h"
#include "zizium/session.h"
#include "zizium/status.h"
#include "zizium/types.h"
#include "zizium/zx.h"

static const char k_ready_payload[] = "SessionReady";
static const char k_command_payload[] =
    "Start-Process \"C:\\Program Files\\Zizium\\Hello Seed.exe\"";

static ZiStatus send_message(ZiHandle channel,
                             uint64_t message_id,
                             uint32_t message_type,
                             const char* payload,
                             size_t payload_size);

int main(void) {
  ZiHandle channel = ZI_INVALID_HANDLE;
  ZiStatus status = ZxGetBootstrapChannel(&channel);
  if (ZiSucceeded(status)) {
    status = send_message(channel,
                          1,
                          ZI_SESSION_MESSAGE_READY,
                          k_ready_payload,
                          sizeof k_ready_payload - 1u);
  }
  if (ZiSucceeded(status)) {
    status = send_message(channel,
                          2,
                          ZI_SESSION_MESSAGE_COMMAND,
                          k_command_payload,
                          sizeof k_command_payload - 1u);
  }
  if (ZiFailed(status)) {
    return 1;
  }
  puts("SessionHost published the bounded Luma bootstrap contract.");
  return 0;
}

static ZiStatus send_message(ZiHandle channel,
                             uint64_t message_id,
                             uint32_t message_type,
                             const char* payload,
                             size_t payload_size) {
  if (payload == NULL || payload_size > ZI_CHANNEL_INLINE_PAYLOAD_CAPACITY) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiChannelMessage message = {
      sizeof(ZiChannelMessage),
      ZI_CHANNEL_MESSAGE_VERSION,
      message_id,
      0,
      message_type,
      0,
      payload_size,
      ZI_INVALID_HANDLE,
      0,
      0,
      {0},
  };
  for (size_t index = 0; index < payload_size; ++index) {
    message.inline_payload[index] = (unsigned char)payload[index];
  }
  return ZxSendChannel(channel, &message);
}
