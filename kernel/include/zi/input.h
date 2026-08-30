// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zizium/status.h"
#include "zizium/types.h"

typedef uint32_t ZiScancode;
typedef uint32_t ZiKeycode;
typedef uint32_t ZiModifierState;

#define ZI_MODIFIER_SHIFT UINT32_C(0x0001)
#define ZI_MODIFIER_CONTROL UINT32_C(0x0002)
#define ZI_MODIFIER_ALT UINT32_C(0x0004)
#define ZI_MODIFIER_ALT_GR UINT32_C(0x0008)
#define ZI_MODIFIER_CAPS_LOCK UINT32_C(0x0010)
#define ZI_MODIFIER_NUM_LOCK UINT32_C(0x0020)

enum ZiInputDeviceType {
  ZI_INPUT_DEVICE_KEYBOARD = 1,
  ZI_INPUT_DEVICE_MOUSE = 2,
  ZI_INPUT_DEVICE_TOUCH = 3,
};

typedef struct ZiInputDevice {
  uint32_t struct_size;
  uint32_t version;
  uint64_t device_id;
  uint32_t device_type;
  uint32_t flags;
  const char* debug_name;
} ZiInputDevice;

typedef struct ZiKeyEvent {
  uint64_t timestamp;
  uint64_t device_id;
  ZiScancode scancode;
  ZiKeycode keycode;
  ZiModifierState modifiers;
  uint32_t is_pressed;
  uint32_t is_repeat;
} ZiKeyEvent;

typedef struct ZiTextInputEvent {
  uint64_t timestamp;
  uint64_t device_id;
  uint32_t scalar;
  uint32_t flags;
} ZiTextInputEvent;

typedef struct ZiKeyboardLayout {
  uint32_t struct_size;
  uint32_t version;
  ZiStringView locale_name;
  const void* translation_table;
  size_t translation_table_size;
} ZiKeyboardLayout;

typedef struct ZiCompositionState {
  uint32_t struct_size;
  uint32_t version;
  uint32_t pending_scalars[8];
  size_t pending_count;
  uint32_t flags;
} ZiCompositionState;

typedef struct ZiKeyboardDevice {
  ZiInputDevice input_device;
  const ZiKeyboardLayout* active_layout;
  ZiModifierState modifiers;
  ZiCompositionState composition;
} ZiKeyboardDevice;

typedef struct ZiMouseDevice {
  ZiInputDevice input_device;
  int32_t x;
  int32_t y;
  uint32_t buttons;
} ZiMouseDevice;

ZiStatus zi_input_translate_key(const ZiKeyboardDevice* keyboard,
                                const ZiKeyEvent* key_event,
                                ZiTextInputEvent* out_text_event);
