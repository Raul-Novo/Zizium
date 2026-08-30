// SPDX-License-Identifier: GPL-3.0-or-later

#include <stddef.h>
#include <stdint.h>

#include "zi/x64_descriptor.h"

_Static_assert(sizeof(ZiX64SystemDescriptor) == 16, "x64 system descriptor size mismatch");
_Static_assert(sizeof(ZiX64IdtGate) == 16, "x64 IDT gate size mismatch");
_Static_assert(offsetof(ZiX64IdtGate, offset_low) == 0, "x64 IDT gate low-offset mismatch");
_Static_assert(offsetof(ZiX64IdtGate, selector) == 2, "x64 IDT gate selector mismatch");
_Static_assert(offsetof(ZiX64IdtGate, ist) == 4, "x64 IDT gate IST mismatch");
_Static_assert(offsetof(ZiX64IdtGate, attributes) == 5, "x64 IDT gate attributes mismatch");
_Static_assert(offsetof(ZiX64IdtGate, offset_middle) == 6, "x64 IDT gate middle-offset mismatch");
_Static_assert(offsetof(ZiX64IdtGate, offset_high) == 8, "x64 IDT gate high-offset mismatch");
_Static_assert(offsetof(ZiX64IdtGate, reserved) == 12, "x64 IDT gate reserved field mismatch");

uint64_t zi_x64_encode_segment_descriptor(uint32_t limit, uint8_t access, uint8_t flags) {
  uint64_t descriptor = (uint64_t)(limit & UINT32_C(0xffff));
  descriptor |= (uint64_t)access << 40u;
  descriptor |= (uint64_t)((limit >> 16u) & UINT32_C(0x0f)) << 48u;
  descriptor |= (uint64_t)(flags & UINT8_C(0x0f)) << 52u;
  return descriptor;
}

ZiX64SystemDescriptor zi_x64_encode_tss_descriptor(uint64_t base, uint32_t limit) {
  ZiX64SystemDescriptor descriptor = {0};
  descriptor.low = (uint64_t)(limit & UINT32_C(0xffff));
  descriptor.low |= (base & UINT64_C(0xffffff)) << 16u;
  descriptor.low |= UINT64_C(0x89) << 40u;
  descriptor.low |= (uint64_t)((limit >> 16u) & UINT32_C(0x0f)) << 48u;
  descriptor.low |= ((base >> 24u) & UINT64_C(0xff)) << 56u;
  descriptor.high = base >> 32u;
  return descriptor;
}

ZiX64IdtGate
zi_x64_encode_idt_gate(uint64_t offset, uint16_t selector, uint8_t ist, uint8_t attributes) {
  ZiX64IdtGate gate = {0};
  gate.offset_low = (uint16_t)(offset & UINT64_C(0xffff));
  gate.selector = selector;
  gate.ist = (uint8_t)(ist & UINT8_C(0x07));
  gate.attributes = attributes;
  gate.offset_middle = (uint16_t)((offset >> 16u) & UINT64_C(0xffff));
  gate.offset_high = (uint32_t)(offset >> 32u);
  return gate;
}
