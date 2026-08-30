// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "zi/luma.h"
#include "zizium/ipc.h"
#include "zizium/session.h"
#include "zizium/status.h"
#include "zizium/types.h"
#include "zizium/zia.h"
#include "zizium/zx.h"

#define LUMA_ARGUMENT_CAPACITY 4u

static const char k_ready_payload[] = "SessionReady";
static const char k_start_command[] = "Start-Process";
static const char k_expected_path[] = "C:\\Program Files\\Zizium\\Hello Seed.exe";
static const char k_wrong_case_path[] = "C:\\Program Files\\Zizium\\hello Seed.exe";

static bool bytes_equal(const void* left, const void* right, size_t size);
static ZiStatus
receive_message(ZiHandle channel, uint32_t expected_type, ZiChannelMessage* out_message);

int main(void) {
  ZiHandle channel = ZI_INVALID_HANDLE;
  ZiStatus status = ZxGetBootstrapChannel(&channel);
  if (ZiFailed(status)) {
    return 1;
  }

  ZiChannelMessage message = {0};
  status = receive_message(channel, ZI_SESSION_MESSAGE_READY, &message);
  if (ZiFailed(status) || message.payload_size != sizeof k_ready_payload - 1u ||
      !bytes_equal(message.inline_payload, k_ready_payload, sizeof k_ready_payload - 1u)) {
    return 2;
  }
  status = receive_message(channel, ZI_SESSION_MESSAGE_COMMAND, &message);
  if (ZiFailed(status) || message.payload_size == 0 ||
      message.payload_size > ZI_CHANNEL_INLINE_PAYLOAD_CAPACITY) {
    return 3;
  }

  char line[ZI_CHANNEL_INLINE_PAYLOAD_CAPACITY] = {0};
  for (size_t index = 0; index < message.payload_size; ++index) {
    line[index] = (char)message.inline_payload[index];
  }
  ZiStringView arguments[LUMA_ARGUMENT_CAPACITY] = {0};
  size_t argument_count = 0;
  status = zi_luma_tokenise(line,
                            message.payload_size,
                            arguments,
                            LUMA_ARGUMENT_CAPACITY,
                            &argument_count);
  if (ZiFailed(status) || argument_count != 2 || arguments[0].size != sizeof k_start_command - 1u ||
      !bytes_equal(arguments[0].data, k_start_command, sizeof k_start_command - 1u) ||
      arguments[1].size != sizeof k_expected_path - 1u ||
      !bytes_equal(arguments[1].data, k_expected_path, sizeof k_expected_path - 1u)) {
    return 4;
  }

  ZiHandle process = ZI_INVALID_HANDLE;
  status =
      ZiCreateProcess((ZiStringView){k_wrong_case_path, sizeof k_wrong_case_path - 1u}, &process);
  if (status != ZI_STATUS_NOT_FOUND || process != ZI_INVALID_HANDLE) {
    return 5;
  }
  status = ZiCreateProcess(arguments[1], &process);
  if (ZiFailed(status) || process == ZI_INVALID_HANDLE) {
    return 6;
  }

  int32_t exit_code = 0;
  status = ZiWaitForProcess(process, 0, &exit_code);
  if (status != ZI_STATUS_TIMEOUT) {
    (void)ZiCloseHandle(process);
    return 7;
  }
  status = ZiWaitForProcess(process, UINT64_MAX, &exit_code);
  if (ZiFailed(status) || exit_code != 21) {
    (void)ZiCloseHandle(process);
    return 8;
  }
  status = ZiCloseHandle(process);
  if (ZiFailed(status)) {
    return 9;
  }
  if (ZiCloseHandle(process) != ZI_STATUS_INVALID_HANDLE) {
    return 10;
  }

  puts("Luma parsed a quoted path and completed a child process.");
  return 0;
}

static bool bytes_equal(const void* left, const void* right, size_t size) {
  if (left == NULL || right == NULL) {
    return false;
  }
  const unsigned char* left_bytes = left;
  const unsigned char* right_bytes = right;
  for (size_t index = 0; index < size; ++index) {
    if (left_bytes[index] != right_bytes[index]) {
      return false;
    }
  }
  return true;
}

static ZiStatus
receive_message(ZiHandle channel, uint32_t expected_type, ZiChannelMessage* out_message) {
  *out_message = (ZiChannelMessage){
      sizeof(ZiChannelMessage),
      ZI_CHANNEL_MESSAGE_VERSION,
      0,
      0,
      0,
      0,
      0,
      ZI_INVALID_HANDLE,
      0,
      0,
      {0},
  };
  ZiStatus status = ZxReceiveChannel(channel, out_message);
  if (ZiFailed(status)) {
    return status;
  }
  return out_message->message_type == expected_type ? ZI_STATUS_SUCCESS : ZI_STATUS_INVALID_MESSAGE;
}
