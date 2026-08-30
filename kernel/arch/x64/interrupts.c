// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "x64_internal.h"
#include "zi/arch_x64.h"
#include "zi/kernel_stack.h"
#include "zi/log.h"
#include "zi/serial.h"
#include "zi/user_process.h"
#include "zi/x64_descriptor.h"
#include "zi/x64_interrupt.h"
#include "zizium/status.h"

#define ZI_X64_IDT_INTERRUPT_GATE 0x8eu
#define ZI_X64_IDT_USER_INTERRUPT_GATE 0xeeu

extern const void* const ZkX64InterruptStubTable[ZI_X64_INTERRUPT_VECTOR_COUNT];

_Alignas(16) static ZiX64IdtGate s_idt[ZI_X64_INTERRUPT_VECTOR_COUNT];
static volatile uint32_t s_current_interrupt_level = ZI_X64_IRQL_HIGH;
static volatile uint32_t s_exception_depth;

static ZiX64InterruptFrame* handle_exception(ZiX64InterruptFrame* frame);
static _Noreturn void handle_kernel_exception(const ZiX64InterruptFrame* frame);
static void log_hex_value(const char* name, uint64_t value);
static void log_page_fault_access(uint64_t error_code);
static size_t append_text(char* output, size_t capacity, size_t offset, const char* text);
static size_t append_hex_u64(char* output, size_t capacity, size_t offset, uint64_t value);

ZiStatus zi_x64_idt_initialise(void) {
  for (uint32_t vector = 0; vector < ZI_X64_INTERRUPT_VECTOR_COUNT; ++vector) {
    uint8_t ist = 0;
    if (vector == 8u) {
      ist = 1;
    } else if (vector == 2u) {
      ist = 2;
    } else if (vector == 18u) {
      ist = 3;
    }
    uint8_t attributes =
        vector == 3u || vector == 4u ? ZI_X64_IDT_USER_INTERRUPT_GATE : ZI_X64_IDT_INTERRUPT_GATE;
    s_idt[vector] = zi_x64_encode_idt_gate((uint64_t)(uintptr_t)ZkX64InterruptStubTable[vector],
                                           ZI_X64_GDT_KERNEL_CODE_SELECTOR,
                                           ist,
                                           attributes);
  }
  ZkArchLoadIdt(s_idt, (uint16_t)(sizeof s_idt - 1u));
  s_current_interrupt_level = ZI_X64_IRQL_PASSIVE;
  return ZI_STATUS_SUCCESS;
}

ZiX64InterruptGuard zi_x64_interrupt_guard_acquire(uint32_t level) {
  ZiX64InterruptGuard guard = {0};
  guard.flags = ZkArchDisableInterrupts();
  guard.previous_level = s_current_interrupt_level;
  if (level > ZI_X64_IRQL_HIGH) {
    level = ZI_X64_IRQL_HIGH;
  }
  if (level > s_current_interrupt_level) {
    s_current_interrupt_level = level;
  }
  return guard;
}

void zi_x64_interrupt_guard_release(ZiX64InterruptGuard guard) {
  s_current_interrupt_level = guard.previous_level;
  ZkArchRestoreInterrupts(guard.flags);
}

uint32_t zi_x64_current_interrupt_level(void) {
  return s_current_interrupt_level;
}

ZiX64InterruptFrame* ZkX64InterruptDispatch(ZiX64InterruptFrame* frame) {
  if (frame == NULL || frame->vector >= ZI_X64_INTERRUPT_VECTOR_COUNT) {
    ZkArchHalt();
  }
  if (frame->vector < ZI_X64_EXCEPTION_COUNT) {
    return handle_exception(frame);
  }

  uint32_t previous_level = s_current_interrupt_level;
  if (frame->vector == ZI_X64_INTERRUPT_VECTOR_TIMER) {
    s_current_interrupt_level = ZI_X64_IRQL_CLOCK;
    ZiX64InterruptFrame* next_frame = zi_x64_preemption_handle_tick(frame);
    zi_x64_apic_end_of_interrupt();
    s_current_interrupt_level = previous_level;
    return next_frame;
  }
  if (frame->vector == ZI_X64_INTERRUPT_VECTOR_SPURIOUS) {
    return frame;
  }

  s_current_interrupt_level = ZI_X64_IRQL_HIGH;
  zi_log_write(ZI_LOG_WARNING, "Interrupt", "An unexpected external interrupt was ignored.");
  if (zi_x64_apic_is_initialised()) {
    zi_x64_apic_end_of_interrupt();
  }
  s_current_interrupt_level = previous_level;
  return frame;
}

static ZiX64InterruptFrame* handle_exception(ZiX64InterruptFrame* frame) {
  if ((frame->cs & UINT64_C(3)) == 3u && zi_user_process_is_active()) {
    ZiX64InterruptFrame* contained_frame = zi_user_process_handle_exception(frame);
    if (contained_frame != NULL) {
      return contained_frame;
    }
  }
  handle_kernel_exception(frame);
}

static _Noreturn void handle_kernel_exception(const ZiX64InterruptFrame* frame) {
  if (s_exception_depth != 0) {
    static const char k_recursive_marker[] = "[ZI:BOOT:EXCEPTION_RECURSIVE]\r\n";
    zi_serial_write(k_recursive_marker, sizeof k_recursive_marker - 1u);
    ZkArchHalt();
  }
  s_exception_depth = 1;
  s_current_interrupt_level = ZI_X64_IRQL_HIGH;
  zi_log_set_sink(NULL);
  zi_log_boot_marker("EXCEPTION_DIAGNOSTIC");

  uint32_t vector = (uint32_t)frame->vector;
  uint64_t page_fault_address = 0;
  if (vector == 14u) {
    page_fault_address = ZkArchReadCr2();
  }
  if (vector == 6u) {
    zi_log_boot_marker("EXCEPTION_INVALID_OPCODE");
  } else if (vector == 8u) {
    zi_log_boot_marker("EXCEPTION_DOUBLE_FAULT");
  } else if (vector == 13u) {
    zi_log_boot_marker("EXCEPTION_GENERAL_PROTECTION");
  } else if (vector == 14u) {
    zi_log_boot_marker("EXCEPTION_PAGE_FAULT");
    if (zi_kernel_stack_guard_contains(page_fault_address)) {
      zi_log_boot_marker("MEMORY_GUARD_FAULT");
      zi_log_write(ZI_LOG_FATAL, "Memory", "A kernel stack crossed its unmapped guard page.");
    }
  }

  zi_log_write(ZI_LOG_FATAL, "Exception", zi_x64_exception_name(vector));
  log_hex_value("Vector", frame->vector);
  log_hex_value("Error", frame->error_code);
  log_hex_value("RIP", frame->rip);
  log_hex_value("CS", frame->cs);
  log_hex_value("RFLAGS", frame->rflags);
  log_hex_value("RSP", frame->rsp);
  log_hex_value("SS", frame->ss);
  log_hex_value("RAX", frame->rax);
  log_hex_value("RBX", frame->rbx);
  log_hex_value("RCX", frame->rcx);
  log_hex_value("RDX", frame->rdx);
  log_hex_value("RSI", frame->rsi);
  log_hex_value("RDI", frame->rdi);
  log_hex_value("RBP", frame->rbp);
  log_hex_value("R8", frame->r8);
  log_hex_value("R9", frame->r9);
  log_hex_value("R10", frame->r10);
  log_hex_value("R11", frame->r11);
  log_hex_value("R12", frame->r12);
  log_hex_value("R13", frame->r13);
  log_hex_value("R14", frame->r14);
  log_hex_value("R15", frame->r15);
  if (vector == 14u) {
    log_hex_value("CR2", page_fault_address);
    log_page_fault_access(frame->error_code);
  }
  zi_panic("An unhandled x64 exception stopped the kernel safely.");
}

static void log_hex_value(const char* name, uint64_t value) {
  char message[48] = {0};
  size_t offset = append_text(message, sizeof message, 0, name);
  offset = append_text(message, sizeof message, offset, "=0x");
  offset = append_hex_u64(message, sizeof message, offset, value);
  message[offset < sizeof message ? offset : sizeof message - 1u] = '\0';
  zi_log_write(ZI_LOG_FATAL, "Exception", message);
}

static void log_page_fault_access(uint64_t error_code) {
  char message[112] = {0};
  size_t offset = append_text(message, sizeof message, 0, "Page fault: ");
  offset = append_text(message,
                       sizeof message,
                       offset,
                       (error_code & UINT64_C(1)) != 0 ? "protection" : "not-present");
  offset = append_text(message,
                       sizeof message,
                       offset,
                       (error_code & UINT64_C(2)) != 0 ? ", write" : ", read");
  offset = append_text(message,
                       sizeof message,
                       offset,
                       (error_code & UINT64_C(4)) != 0 ? ", user" : ", supervisor");
  offset = append_text(message,
                       sizeof message,
                       offset,
                       (error_code & UINT64_C(16)) != 0 ? ", instruction" : ", data");
  message[offset < sizeof message ? offset : sizeof message - 1u] = '\0';
  zi_log_write(ZI_LOG_FATAL, "Exception", message);
}

static size_t append_text(char* output, size_t capacity, size_t offset, const char* text) {
  if (output == NULL || text == NULL || capacity == 0) {
    return 0;
  }
  while (offset + 1u < capacity && *text != '\0') {
    output[offset++] = *text++;
  }
  output[offset] = '\0';
  return offset;
}

static size_t append_hex_u64(char* output, size_t capacity, size_t offset, uint64_t value) {
  static const char k_digits[] = "0123456789abcdef";
  for (uint32_t shift = 64u; shift > 0; shift -= 4u) {
    if (offset + 1u >= capacity) {
      break;
    }
    output[offset++] = k_digits[(value >> (shift - 4u)) & UINT64_C(0x0f)];
  }
  output[offset < capacity ? offset : capacity - 1u] = '\0';
  return offset;
}
