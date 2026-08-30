// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/executive_lock.h"
#include "zi/security.h"
#include "zizium/status.h"

#define ZI_SCHEDULER_PRIORITY_COUNT 32u
#define ZI_SCHEDULER_DYNAMIC_PRIORITY_MAX 15u
#define ZI_SCHEDULER_REALTIME_PRIORITY_MIN 16u
#define ZI_SCHEDULER_DEFAULT_QUANTUM 2u
#define ZI_EXECUTIVE_PROCESS_VERSION 1u

enum ZiProcessState {
  ZI_PROCESS_INITIALISED = 0,
  ZI_PROCESS_RUNNING = 1,
  ZI_PROCESS_TERMINATING = 2,
  ZI_PROCESS_TERMINATED = 3,
};

enum ZiThreadState {
  ZI_THREAD_INITIALISED = 0,
  ZI_THREAD_READY = 1,
  ZI_THREAD_RUNNING = 2,
  ZI_THREAD_WAITING = 3,
  ZI_THREAD_TRANSITION = 4,
  ZI_THREAD_TERMINATED = 5,
};

enum ZiSchedulerClass {
  ZI_SCHEDULER_CLASS_REALTIME = 0,
  ZI_SCHEDULER_CLASS_HIGH = 1,
  ZI_SCHEDULER_CLASS_ABOVE_NORMAL = 2,
  ZI_SCHEDULER_CLASS_NORMAL = 3,
  ZI_SCHEDULER_CLASS_BELOW_NORMAL = 4,
  ZI_SCHEDULER_CLASS_BACKGROUND = 5,
  ZI_SCHEDULER_CLASS_IDLE = 6,
};

typedef struct ZxThread ZxThread;
// NOLINTNEXTLINE(readability-identifier-naming) -- frozen Zi public type prefix.
typedef struct ZiDispatcherDomain ZiDispatcherDomain;
// NOLINTNEXTLINE(readability-identifier-naming) -- frozen Zi public type prefix.
typedef struct ZiWaitOperation ZiWaitOperation;
typedef struct ZxDispatcherHeader ZxDispatcherHeader;

typedef struct ZxReadyQueue {
  ZxThread* head;
  ZxThread* tail;
  size_t count;
} ZxReadyQueue;

typedef struct ZxWaitBlock {
  ZxDispatcherHeader* wait_object;
  ZxThread* thread;
  ZiWaitOperation* operation;
  struct ZxWaitBlock* previous;
  struct ZxWaitBlock* next;
  uint32_t wait_key;
} ZxWaitBlock;

struct ZxDispatcherHeader {
  uint32_t object_type;
  uint32_t signal_state;
  ZxWaitBlock* waiters;
  ZiDispatcherDomain* domain;
};

typedef struct ZxProcess {
  uint32_t struct_size;
  uint32_t version;
  uint64_t process_id;
  uint32_t base_priority;
  uint32_t state;
  uint64_t affinity_mask;
  int32_t exit_status;
  uint32_t reserved;
  void* address_space;
  const ZiAccessToken* security_token;
  ZxDispatcherHeader termination_event;
} ZxProcess;

struct ZxThread {
  uint64_t thread_id;
  ZxProcess* process;
  ZxThread* ready_previous;
  ZxThread* ready_next;
  ZxWaitBlock* wait_block;
  uint64_t affinity_mask;
  uint32_t priority;
  uint32_t base_priority;
  uint32_t quantum;
  uint32_t quantum_remaining;
  uint32_t state;
  uint32_t scheduler_class;
  uint32_t is_queued;
  void* architecture_context;
};

typedef struct ZxScheduler {
  ZxReadyQueue ready_queues[ZI_SCHEDULER_PRIORITY_COUNT];
  uint32_t ready_bitmap;
  uint32_t cpu_index;
  ZxThread* current_thread;
  ZxThread* idle_thread;
  ZiExecutiveLock dispatcher_lock;
  uint64_t tick_count;
  uint64_t quantum_expiry_count;
  uint64_t context_switch_count;
} ZxScheduler;

typedef struct ZiSchedulerDispatch {
  ZxThread* previous_thread;
  ZxThread* next_thread;
  uint32_t quantum_expired;
  uint32_t did_switch;
} ZiSchedulerDispatch;

typedef struct ZxEvent {
  ZxDispatcherHeader header;
  uint32_t reset_type;
} ZxEvent;

typedef struct ZxMutex {
  ZxDispatcherHeader header;
  ZxThread* owner;
  struct ZxScheduler* owner_scheduler;
  uint32_t recursion_count;
} ZxMutex;

typedef struct ZxSemaphore {
  ZxDispatcherHeader header;
  uint32_t limit;
} ZxSemaphore;

typedef struct ZxTimer {
  ZxDispatcherHeader header;
  uint64_t due_time;
  uint64_t period;
  uint32_t is_active;
} ZxTimer;

void zi_scheduler_initialise(ZxScheduler* scheduler, uint32_t cpu_index, ZxThread* idle_thread);
ZiStatus zi_scheduler_enqueue(ZxScheduler* scheduler, ZxThread* thread);
ZiStatus zi_scheduler_remove(ZxScheduler* scheduler, ZxThread* thread);
ZxThread* zi_scheduler_select_next(ZxScheduler* scheduler);
ZiStatus zi_scheduler_on_tick(ZxScheduler* scheduler, ZiSchedulerDispatch* out_dispatch);
void zi_scheduler_boost_priority(ZxThread* thread, uint32_t increment);
void zi_scheduler_decay_priority(ZxThread* thread);
ZiStatus zi_scheduler_inherit_priority(ZxScheduler* scheduler,
                                       ZxThread* thread,
                                       uint32_t inherited_priority);
ZiStatus zi_scheduler_restore_base_priority(ZxScheduler* scheduler, ZxThread* thread);
