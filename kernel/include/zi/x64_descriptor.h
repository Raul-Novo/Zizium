// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

#include "zizium/status.h"

#define ZI_X64_GDT_KERNEL_CODE_SELECTOR 0x08u
#define ZI_X64_GDT_KERNEL_DATA_SELECTOR 0x10u
#define ZI_X64_GDT_USER_DATA_SELECTOR 0x1bu
#define ZI_X64_GDT_USER_CODE_SELECTOR 0x23u
#define ZI_X64_GDT_TSS_SELECTOR 0x28u

typedef struct ZiX64SystemDescriptor {
  uint64_t low;
  uint64_t high;
} ZiX64SystemDescriptor;

typedef struct ZiX64IdtGate {
  uint16_t offset_low;
  uint16_t selector;
  uint8_t ist;
  uint8_t attributes;
  uint16_t offset_middle;
  uint32_t offset_high;
  uint32_t reserved;
} ZiX64IdtGate;

uint64_t zi_x64_encode_segment_descriptor(uint32_t limit, uint8_t access, uint8_t flags);
ZiX64SystemDescriptor zi_x64_encode_tss_descriptor(uint64_t base, uint32_t limit);
ZiX64IdtGate
zi_x64_encode_idt_gate(uint64_t offset, uint16_t selector, uint8_t ist, uint8_t attributes);
ZiStatus zi_x64_descriptor_set_rsp0(uint64_t rsp0);
uint64_t zi_x64_descriptor_rsp0(void);
