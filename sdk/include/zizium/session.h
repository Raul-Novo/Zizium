// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

#define ZI_SESSION_PROTOCOL_VERSION 1u

enum ZiSessionMessageType {
  ZI_SESSION_MESSAGE_READY = 1,
  ZI_SESSION_MESSAGE_COMMAND = 2,
};
