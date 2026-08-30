// SPDX-License-Identifier: GPL-3.0-or-later

#include <stddef.h>
#include <stdint.h>

#include "x64_internal.h"
#include "zi/arch_x64.h"
#include "zi/byte_order.h"
#include "zi/x64_descriptor.h"
#include "zizium/status.h"

#define ZI_X64_TSS_SIZE 104u
#define ZI_X64_IST_STACK_SIZE 32768u

enum ZiX64TssOffset {
  ZI_X64_TSS_RSP0_OFFSET = 4,
  ZI_X64_TSS_IST1_OFFSET = 36,
  ZI_X64_TSS_IST2_OFFSET = 44,
  ZI_X64_TSS_IST3_OFFSET = 52,
  ZI_X64_TSS_IO_MAP_OFFSET = 102,
};

_Alignas(16) static uint64_t s_gdt[7];
_Alignas(16) static unsigned char s_tss[ZI_X64_TSS_SIZE];
_Alignas(16) static unsigned char s_double_fault_stack[ZI_X64_IST_STACK_SIZE];
_Alignas(16) static unsigned char s_nmi_stack[ZI_X64_IST_STACK_SIZE];
_Alignas(16) static unsigned char s_machine_check_stack[ZI_X64_IST_STACK_SIZE];

static uint64_t stack_top(unsigned char* stack, size_t size);

ZiStatus zi_x64_descriptor_tables_initialise(void) {
  zi_memory_zero(s_gdt, sizeof s_gdt);
  zi_memory_zero(s_tss, sizeof s_tss);

  s_gdt[1] = zi_x64_encode_segment_descriptor(UINT32_C(0xfffff), UINT8_C(0x9a), UINT8_C(0x0a));
  s_gdt[2] = zi_x64_encode_segment_descriptor(UINT32_C(0xfffff), UINT8_C(0x92), UINT8_C(0x0c));
  s_gdt[3] = zi_x64_encode_segment_descriptor(UINT32_C(0xfffff), UINT8_C(0xf2), UINT8_C(0x0c));
  s_gdt[4] = zi_x64_encode_segment_descriptor(UINT32_C(0xfffff), UINT8_C(0xfa), UINT8_C(0x0a));

  uint64_t bootstrap_stack_top = ZkArchBootstrapStackTop();
  zi_write_u64_le(s_tss + ZI_X64_TSS_RSP0_OFFSET, bootstrap_stack_top);
  zi_write_u64_le(s_tss + ZI_X64_TSS_IST1_OFFSET,
                  stack_top(s_double_fault_stack, sizeof s_double_fault_stack));
  zi_write_u64_le(s_tss + ZI_X64_TSS_IST2_OFFSET, stack_top(s_nmi_stack, sizeof s_nmi_stack));
  zi_write_u64_le(s_tss + ZI_X64_TSS_IST3_OFFSET,
                  stack_top(s_machine_check_stack, sizeof s_machine_check_stack));
  zi_write_u16_le(s_tss + ZI_X64_TSS_IO_MAP_OFFSET, (uint16_t)sizeof s_tss);

  ZiX64SystemDescriptor tss_descriptor =
      zi_x64_encode_tss_descriptor((uint64_t)(uintptr_t)s_tss, (uint32_t)sizeof s_tss - 1u);
  s_gdt[5] = tss_descriptor.low;
  s_gdt[6] = tss_descriptor.high;

  ZkArchLoadGdt(s_gdt, (uint16_t)(sizeof s_gdt - 1u), ZI_X64_GDT_TSS_SELECTOR);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_x64_descriptor_tables_set_stacks(uint64_t rsp0,
                                             uint64_t double_fault_stack,
                                             uint64_t nmi_stack,
                                             uint64_t machine_check_stack) {
  if (rsp0 == 0 || double_fault_stack == 0 || nmi_stack == 0 || machine_check_stack == 0 ||
      (rsp0 & UINT64_C(0x0f)) != 0 || (double_fault_stack & UINT64_C(0x0f)) != 0 ||
      (nmi_stack & UINT64_C(0x0f)) != 0 || (machine_check_stack & UINT64_C(0x0f)) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_write_u64_le(s_tss + ZI_X64_TSS_RSP0_OFFSET, rsp0);
  zi_write_u64_le(s_tss + ZI_X64_TSS_IST1_OFFSET, double_fault_stack);
  zi_write_u64_le(s_tss + ZI_X64_TSS_IST2_OFFSET, nmi_stack);
  zi_write_u64_le(s_tss + ZI_X64_TSS_IST3_OFFSET, machine_check_stack);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_x64_descriptor_set_rsp0(uint64_t rsp0) {
  if (rsp0 == 0 || (rsp0 & UINT64_C(0x0f)) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_write_u64_le(s_tss + ZI_X64_TSS_RSP0_OFFSET, rsp0);
  return ZI_STATUS_SUCCESS;
}

uint64_t zi_x64_descriptor_rsp0(void) {
  return zi_read_u64_le(s_tss + ZI_X64_TSS_RSP0_OFFSET);
}

static uint64_t stack_top(unsigned char* stack, size_t size) {
  return (uint64_t)(uintptr_t)(stack + size);
}
