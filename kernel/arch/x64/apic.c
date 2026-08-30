// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "x64_internal.h"
#include "zi/arch_x64.h"
#include "zi/x64_interrupt.h"
#include "zizium/status.h"

#define ZI_X64_CPUID_APIC (UINT32_C(1) << 9u)
#define ZI_X64_CPUID_X2APIC (UINT32_C(1) << 21u)
#define ZI_X64_MSR_APIC_BASE 0x1bu
#define ZI_X64_MSR_APIC_ENABLE (UINT64_C(1) << 11u)
#define ZI_X64_MSR_APIC_X2_ENABLE (UINT64_C(1) << 10u)
#define ZI_X64_MSR_APIC_ADDRESS_MASK UINT64_C(0x000ffffffffff000)
#define ZI_X64_MSR_X2APIC_BASE 0x800u

#define ZI_X64_APIC_REGISTER_TPR 0x080u
#define ZI_X64_APIC_REGISTER_EOI 0x0b0u
#define ZI_X64_APIC_REGISTER_SPURIOUS 0x0f0u
#define ZI_X64_APIC_REGISTER_ESR 0x280u
#define ZI_X64_APIC_REGISTER_LVT_TIMER 0x320u
#define ZI_X64_APIC_REGISTER_LVT_LINT0 0x350u
#define ZI_X64_APIC_REGISTER_LVT_LINT1 0x360u
#define ZI_X64_APIC_REGISTER_LVT_ERROR 0x370u
#define ZI_X64_APIC_REGISTER_INITIAL_COUNT 0x380u
#define ZI_X64_APIC_REGISTER_CURRENT_COUNT 0x390u
#define ZI_X64_APIC_REGISTER_DIVIDE 0x3e0u

#define ZI_X64_APIC_SOFTWARE_ENABLE (UINT32_C(1) << 8u)
#define ZI_X64_APIC_LVT_MASKED (UINT32_C(1) << 16u)
#define ZI_X64_APIC_TIMER_PERIODIC (UINT32_C(1) << 17u)
#define ZI_X64_APIC_DIVIDE_BY_16 0x03u

#define ZI_PIT_FREQUENCY_HZ 1193182u
#define ZI_PIT_CALIBRATION_HZ 100u
#define ZI_PIT_CALIBRATION_POLL_LIMIT UINT32_C(100000000)

enum ZiX64ApicMode {
  ZI_X64_APIC_MODE_NONE = 0,
  ZI_X64_APIC_MODE_XAPIC = 1,
  ZI_X64_APIC_MODE_X2APIC = 2,
};

static volatile uint32_t* s_apic_mmio;
static uint32_t s_apic_mode;
static uint32_t s_apic_ticks_per_calibration;
static uint64_t s_tsc_ticks_per_calibration;

static uint32_t apic_read(uint32_t offset);
static void apic_write(uint32_t offset, uint32_t value);
static ZiStatus calibrate_timer(void);
static void mask_legacy_pic(void);

ZiStatus zi_x64_apic_initialise(uint64_t apic_virtual_address) {
  ZiX64CpuidResult features = {0};
  ZkArchCpuid(1, 0, &features);
  if ((features.edx & ZI_X64_CPUID_APIC) == 0) {
    return ZI_STATUS_NOT_IMPLEMENTED;
  }

  uint64_t apic_base = ZkArchReadMsr(ZI_X64_MSR_APIC_BASE);
  if ((apic_base & ZI_X64_MSR_APIC_ENABLE) == 0) {
    apic_base |= ZI_X64_MSR_APIC_ENABLE;
    ZkArchWriteMsr(ZI_X64_MSR_APIC_BASE, apic_base);
  }

  if ((features.ecx & ZI_X64_CPUID_X2APIC) != 0) {
    apic_base |= ZI_X64_MSR_APIC_ENABLE | ZI_X64_MSR_APIC_X2_ENABLE;
    ZkArchWriteMsr(ZI_X64_MSR_APIC_BASE, apic_base);
    s_apic_mode = ZI_X64_APIC_MODE_X2APIC;
  } else {
    uint64_t physical_base = apic_base & ZI_X64_MSR_APIC_ADDRESS_MASK;
    if (physical_base == 0 || apic_virtual_address == 0) {
      return ZI_STATUS_INVALID_STATE;
    }
    s_apic_mmio = (volatile uint32_t*)(uintptr_t)apic_virtual_address;
    s_apic_mode = ZI_X64_APIC_MODE_XAPIC;
  }

  mask_legacy_pic();
  apic_write(ZI_X64_APIC_REGISTER_TPR, 0);
  apic_write(ZI_X64_APIC_REGISTER_LVT_TIMER,
             ZI_X64_APIC_LVT_MASKED | ZI_X64_INTERRUPT_VECTOR_TIMER);
  apic_write(ZI_X64_APIC_REGISTER_LVT_LINT0, ZI_X64_APIC_LVT_MASKED);
  apic_write(ZI_X64_APIC_REGISTER_LVT_LINT1, ZI_X64_APIC_LVT_MASKED);
  apic_write(ZI_X64_APIC_REGISTER_LVT_ERROR, ZI_X64_INTERRUPT_VECTOR_APIC_ERROR);
  apic_write(ZI_X64_APIC_REGISTER_ESR, 0);
  (void)apic_read(ZI_X64_APIC_REGISTER_ESR);
  uint32_t spurious = apic_read(ZI_X64_APIC_REGISTER_SPURIOUS);
  spurious &= ~UINT32_C(0xff);
  spurious |= ZI_X64_APIC_SOFTWARE_ENABLE | ZI_X64_INTERRUPT_VECTOR_SPURIOUS;
  apic_write(ZI_X64_APIC_REGISTER_SPURIOUS, spurious);

  return calibrate_timer();
}

ZiStatus zi_x64_apic_timer_start(uint32_t frequency_hz) {
  if (s_apic_mode == ZI_X64_APIC_MODE_NONE || s_apic_ticks_per_calibration == 0 ||
      frequency_hz < 10u || frequency_hz > 1000u) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  uint64_t scaled_count =
      (uint64_t)s_apic_ticks_per_calibration * ZI_PIT_CALIBRATION_HZ / frequency_hz;
  if (scaled_count == 0 || scaled_count > UINT32_MAX) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  apic_write(ZI_X64_APIC_REGISTER_DIVIDE, ZI_X64_APIC_DIVIDE_BY_16);
  apic_write(ZI_X64_APIC_REGISTER_LVT_TIMER,
             ZI_X64_APIC_TIMER_PERIODIC | ZI_X64_INTERRUPT_VECTOR_TIMER);
  apic_write(ZI_X64_APIC_REGISTER_INITIAL_COUNT, (uint32_t)scaled_count);
  return ZI_STATUS_SUCCESS;
}

void zi_x64_apic_end_of_interrupt(void) {
  if (s_apic_mode != ZI_X64_APIC_MODE_NONE) {
    apic_write(ZI_X64_APIC_REGISTER_EOI, 0);
  }
}

bool zi_x64_apic_is_initialised(void) {
  return (bool)(s_apic_mode != ZI_X64_APIC_MODE_NONE && s_apic_ticks_per_calibration != 0);
}

uint64_t zi_x64_apic_calibration_tsc_ticks(void) {
  return s_tsc_ticks_per_calibration;
}

static uint32_t apic_read(uint32_t offset) {
  if (s_apic_mode == ZI_X64_APIC_MODE_X2APIC) {
    return (uint32_t)ZkArchReadMsr(ZI_X64_MSR_X2APIC_BASE + (offset / 16u));
  }
  return s_apic_mmio[offset / sizeof(uint32_t)];
}

static void apic_write(uint32_t offset, uint32_t value) {
  if (s_apic_mode == ZI_X64_APIC_MODE_X2APIC) {
    ZkArchWriteMsr(ZI_X64_MSR_X2APIC_BASE + (offset / 16u), value);
    return;
  }
  s_apic_mmio[offset / sizeof(uint32_t)] = value;
  (void)s_apic_mmio[ZI_X64_APIC_REGISTER_TPR / sizeof(uint32_t)];
}

static ZiStatus calibrate_timer(void) {
  apic_write(ZI_X64_APIC_REGISTER_DIVIDE, ZI_X64_APIC_DIVIDE_BY_16);
  apic_write(ZI_X64_APIC_REGISTER_LVT_TIMER,
             ZI_X64_APIC_LVT_MASKED | ZI_X64_INTERRUPT_VECTOR_TIMER);
  apic_write(ZI_X64_APIC_REGISTER_INITIAL_COUNT, UINT32_MAX);

  uint8_t speaker_control = ZkArchIn8(UINT16_C(0x61));
  ZkArchOut8(UINT16_C(0x61), (uint8_t)(speaker_control & UINT8_C(0xfc)));
  ZkArchOut8(UINT16_C(0x43), UINT8_C(0xb0));
  uint32_t pit_count = (ZI_PIT_FREQUENCY_HZ + (ZI_PIT_CALIBRATION_HZ / 2u)) / ZI_PIT_CALIBRATION_HZ;
  ZkArchOut8(UINT16_C(0x42), (uint8_t)(pit_count & UINT32_C(0xff)));
  ZkArchOut8(UINT16_C(0x42), (uint8_t)(pit_count >> 8u));
  uint64_t start_tsc = ZkArchReadTimestamp();
  ZkArchOut8(UINT16_C(0x61), (uint8_t)((speaker_control & UINT8_C(0xfc)) | UINT8_C(0x01)));

  uint32_t polls = 0;
  while ((ZkArchIn8(UINT16_C(0x61)) & UINT8_C(0x20)) == 0 &&
         polls < ZI_PIT_CALIBRATION_POLL_LIMIT) {
    ++polls;
    ZkArchPause();
  }
  uint64_t end_tsc = ZkArchReadTimestamp();
  uint32_t current_count = apic_read(ZI_X64_APIC_REGISTER_CURRENT_COUNT);
  apic_write(ZI_X64_APIC_REGISTER_INITIAL_COUNT, 0);
  ZkArchOut8(UINT16_C(0x61), speaker_control);

  if (polls == ZI_PIT_CALIBRATION_POLL_LIMIT || end_tsc <= start_tsc ||
      current_count == UINT32_MAX) {
    return ZI_STATUS_TIMEOUT;
  }
  s_apic_ticks_per_calibration = UINT32_MAX - current_count;
  s_tsc_ticks_per_calibration = end_tsc - start_tsc;
  if (s_apic_ticks_per_calibration < 100u || s_tsc_ticks_per_calibration < 100u) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  return ZI_STATUS_SUCCESS;
}

static void mask_legacy_pic(void) {
  ZkArchOut8(UINT16_C(0x21), UINT8_MAX);
  ZkArchOut8(UINT16_C(0xa1), UINT8_MAX);
}
