// SPDX-License-Identifier: GPL-3.0-or-later

#include <stddef.h>
#include <stdint.h>

#include "zi/x64_interrupt.h"

_Static_assert(sizeof(ZiX64InterruptFrame) == 176, "x64 interrupt frame size mismatch");
_Static_assert(offsetof(ZiX64InterruptFrame, r15) == 0, "x64 interrupt frame R15 offset mismatch");
_Static_assert(offsetof(ZiX64InterruptFrame, rax) == 112,
               "x64 interrupt frame RAX offset mismatch");
_Static_assert(offsetof(ZiX64InterruptFrame, vector) == 120,
               "x64 interrupt frame vector offset mismatch");
_Static_assert(offsetof(ZiX64InterruptFrame, error_code) == 128,
               "x64 interrupt frame error offset mismatch");
_Static_assert(offsetof(ZiX64InterruptFrame, rip) == 136,
               "x64 interrupt frame RIP offset mismatch");
_Static_assert(offsetof(ZiX64InterruptFrame, cs) == 144, "x64 interrupt frame CS offset mismatch");
_Static_assert(offsetof(ZiX64InterruptFrame, rflags) == 152,
               "x64 interrupt frame RFLAGS offset mismatch");
_Static_assert(offsetof(ZiX64InterruptFrame, rsp) == 160,
               "x64 interrupt frame RSP offset mismatch");
_Static_assert(offsetof(ZiX64InterruptFrame, ss) == 168, "x64 interrupt frame SS offset mismatch");
_Static_assert(offsetof(ZiX64ThreadContext, fx_state) == 0,
               "x64 floating-point state must begin at the context base");
_Static_assert(_Alignof(ZiX64ThreadContext) >= 16, "x64 floating-point state alignment mismatch");

bool zi_x64_exception_uses_error_code(uint32_t vector) {
  switch (vector) {
    case 8:
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
    case 17:
    case 21:
    case 29:
    case 30:
      return true;
    default:
      return false;
  }
}

const char* zi_x64_exception_name(uint32_t vector) {
  static const char* const k_names[ZI_X64_EXCEPTION_COUNT] = {
      "Divide error",
      "Debug",
      "Non-maskable interrupt",
      "Breakpoint",
      "Overflow",
      "Bound-range exceeded",
      "Invalid opcode",
      "Device not available",
      "Double fault",
      "Coprocessor segment overrun",
      "Invalid task state segment",
      "Segment not present",
      "Stack-segment fault",
      "General-protection fault",
      "Page fault",
      "Reserved exception",
      "x87 floating-point exception",
      "Alignment check",
      "Machine check",
      "SIMD floating-point exception",
      "Virtualisation exception",
      "Control-protection exception",
      "Reserved exception",
      "Reserved exception",
      "Reserved exception",
      "Reserved exception",
      "Reserved exception",
      "Reserved exception",
      "Hypervisor-injection exception",
      "VMM communication exception",
      "Security exception",
      "Reserved exception",
  };
  return vector < ZI_X64_EXCEPTION_COUNT ? k_names[vector] : "External interrupt";
}
