// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

#include "zi/x64_interrupt.h"
#include "zizium/status.h"

ZiStatus zi_x64_descriptor_tables_initialise(void);
ZiStatus zi_x64_descriptor_tables_set_stacks(uint64_t rsp0,
                                             uint64_t double_fault_stack,
                                             uint64_t nmi_stack,
                                             uint64_t machine_check_stack);
ZiStatus zi_x64_idt_initialise(void);
ZiStatus zi_x64_apic_initialise(uint64_t apic_virtual_address);
ZiStatus zi_x64_apic_timer_start(uint32_t frequency_hz);
void zi_x64_apic_end_of_interrupt(void);
bool zi_x64_apic_is_initialised(void);
uint64_t zi_x64_apic_calibration_tsc_ticks(void);
ZiStatus zi_x64_preemption_initialise(void);
ZiStatus zi_x64_preemption_verify(void);
ZiX64InterruptFrame* zi_x64_preemption_handle_tick(ZiX64InterruptFrame* frame);
