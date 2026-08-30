// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/executive_lock.h"
#include "zi/scheduler.h"
#include "zizium/status.h"

#define ZI_WAIT_OPERATION_VERSION 1u
#define ZI_WAIT_INDEX_NONE UINT32_MAX

enum ZiDispatcherObjectType {
  ZI_DISPATCHER_OBJECT_PROCESS_TERMINATION = 1,
  ZI_DISPATCHER_OBJECT_EVENT = 2,
  ZI_DISPATCHER_OBJECT_MUTEX = 3,
  ZI_DISPATCHER_OBJECT_SEMAPHORE = 4,
  ZI_DISPATCHER_OBJECT_TIMER = 5,
  ZI_DISPATCHER_OBJECT_PORT = 6,
  ZI_DISPATCHER_OBJECT_CHANNEL = 7,
};

enum ZiEventResetType {
  ZI_EVENT_NOTIFICATION = 0,
  ZI_EVENT_SYNCHRONISATION = 1,
};

enum ZiWaitType {
  ZI_WAIT_ANY = 0,
  ZI_WAIT_ALL = 1,
};

enum ZiWaitState {
  ZI_WAIT_STATE_UNUSED = 0,
  ZI_WAIT_STATE_PENDING = 1,
  ZI_WAIT_STATE_COMPLETED = 2,
};

struct ZiDispatcherDomain {
  ZiExecutiveLock lock;
};

struct ZiWaitOperation {
  uint32_t struct_size;
  uint32_t version;
  ZxScheduler* scheduler;
  ZxThread* thread;
  ZxWaitBlock* blocks;
  size_t object_count;
  uint32_t wait_type;
  uint32_t state;
  ZiStatus completion_status;
  uint32_t satisfied_index;
  uint32_t has_deadline;
  uint64_t deadline;
};

void zi_dispatcher_domain_initialise(ZiDispatcherDomain* domain);
ZiStatus zi_dispatcher_header_initialise(ZxDispatcherHeader* header,
                                         ZiDispatcherDomain* domain,
                                         uint32_t object_type,
                                         uint32_t signal_state);
ZiStatus zi_dispatcher_set_signal_state(ZxDispatcherHeader* header, uint32_t signal_state);
/* The caller must hold header->domain->lock. */
ZiStatus zi_dispatcher_set_signal_state_locked(ZxDispatcherHeader* header, uint32_t signal_state);
ZiStatus zi_dispatcher_wait(ZiWaitOperation* operation,
                            ZxWaitBlock* block_storage,
                            ZxDispatcherHeader* const* objects,
                            size_t object_count,
                            uint32_t wait_type,
                            uint64_t timeout_ticks,
                            uint64_t current_tick,
                            ZxScheduler* scheduler,
                            ZxThread* thread);
ZiStatus zi_dispatcher_query_wait(const ZiWaitOperation* operation, uint32_t* out_satisfied_index);
ZiStatus zi_dispatcher_cancel_wait(ZiWaitOperation* operation);
ZiStatus zi_dispatcher_expire_wait(ZiWaitOperation* operation, uint64_t current_tick);

ZiStatus zi_event_initialise(ZxEvent* event,
                             ZiDispatcherDomain* domain,
                             uint32_t reset_type,
                             bool initially_signalled);
ZiStatus zi_event_set(ZxEvent* event);
ZiStatus zi_event_reset(ZxEvent* event);

ZiStatus zi_mutex_initialise(ZxMutex* mutex, ZiDispatcherDomain* domain);
ZiStatus zi_mutex_release(ZxMutex* mutex, ZxThread* owner);

ZiStatus zi_semaphore_initialise(ZxSemaphore* semaphore,
                                 ZiDispatcherDomain* domain,
                                 uint32_t initial_count,
                                 uint32_t limit);
ZiStatus
zi_semaphore_release(ZxSemaphore* semaphore, uint32_t release_count, uint32_t* out_previous_count);

ZiStatus zi_timer_initialise(ZxTimer* timer, ZiDispatcherDomain* domain);
ZiStatus zi_timer_set(ZxTimer* timer, uint64_t due_tick, uint64_t period, uint64_t current_tick);
ZiStatus zi_timer_cancel(ZxTimer* timer);
ZiStatus zi_timer_tick(ZxTimer* timer, uint64_t current_tick);
