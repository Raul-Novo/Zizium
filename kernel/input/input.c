// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/input.h"

#include "zizium/status.h"

ZiStatus zi_input_translate_key(const ZiKeyboardDevice* keyboard,
                                const ZiKeyEvent* key_event,
                                ZiTextInputEvent* out_text_event) {
  if (keyboard == NULL || key_event == NULL || out_text_event == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return ZI_STATUS_NOT_IMPLEMENTED;
}
