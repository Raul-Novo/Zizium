// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/serial.h"

#include <stddef.h>
#include <stdint.h>

#include "zi/arch_x64.h"
#include "zizium/status.h"

#define COM1_BASE UINT16_C(0x03f8)
#define COM1_DATA (COM1_BASE + 0u)
#define COM1_INTERRUPT_ENABLE (COM1_BASE + 1u)
#define COM1_FIFO_CONTROL (COM1_BASE + 2u)
#define COM1_LINE_CONTROL (COM1_BASE + 3u)
#define COM1_MODEM_CONTROL (COM1_BASE + 4u)
#define COM1_LINE_STATUS (COM1_BASE + 5u)

static bool g_serial_ready;

static bool wait_for_transmitter(void);

ZiStatus zi_serial_initialise(void) {
  g_serial_ready = false;
  ZkArchOut8(COM1_INTERRUPT_ENABLE, 0x00);
  ZkArchOut8(COM1_LINE_CONTROL, 0x80);
  ZkArchOut8(COM1_DATA, 0x01);
  ZkArchOut8(COM1_INTERRUPT_ENABLE, 0x00);
  ZkArchOut8(COM1_LINE_CONTROL, 0x03);
  ZkArchOut8(COM1_FIFO_CONTROL, 0xc7);
  ZkArchOut8(COM1_MODEM_CONTROL, 0x1e);
  ZkArchOut8(COM1_DATA, 0xae);
  if (ZkArchIn8(COM1_DATA) != 0xae) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  ZkArchOut8(COM1_MODEM_CONTROL, 0x0f);
  g_serial_ready = true;
  return ZI_STATUS_SUCCESS;
}

bool zi_serial_is_ready(void) {
  return g_serial_ready;
}

void zi_serial_write(const char* text, size_t text_size) {
  if (text == NULL || !g_serial_ready) {
    return;
  }
  for (size_t index = 0; index < text_size; ++index) {
    zi_serial_write_byte((uint8_t)text[index]);
  }
}

void zi_serial_write_byte(uint8_t value) {
  if (!g_serial_ready || !wait_for_transmitter()) {
    return;
  }
  ZkArchOut8(COM1_DATA, value);
}

bool zi_serial_try_read(uint8_t* out_value) {
  if (!g_serial_ready || out_value == NULL || (ZkArchIn8(COM1_LINE_STATUS) & 0x01u) == 0) {
    return false;
  }
  *out_value = ZkArchIn8(COM1_DATA);
  return true;
}

static bool wait_for_transmitter(void) {
  for (uint32_t attempt = 0; attempt < UINT32_C(1000000); ++attempt) {
    if ((ZkArchIn8(COM1_LINE_STATUS) & 0x20u) != 0) {
      return true;
    }
    ZkArchPause();
  }
  g_serial_ready = false;
  return false;
}
