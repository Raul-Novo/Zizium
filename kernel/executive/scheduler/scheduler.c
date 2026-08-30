// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/scheduler.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/executive_lock.h"
#include "zizium/status.h"

static uint32_t highest_ready_priority(uint32_t bitmap);
static bool thread_can_run_on_cpu(const ZxThread* thread, uint32_t cpu_index);

void zi_scheduler_initialise(ZxScheduler* scheduler, uint32_t cpu_index, ZxThread* idle_thread) {
  if (scheduler == NULL) {
    return;
  }
  for (size_t index = 0; index < ZI_SCHEDULER_PRIORITY_COUNT; ++index) {
    scheduler->ready_queues[index].head = NULL;
    scheduler->ready_queues[index].tail = NULL;
    scheduler->ready_queues[index].count = 0;
  }
  scheduler->ready_bitmap = 0;
  scheduler->cpu_index = cpu_index;
  scheduler->current_thread = idle_thread;
  scheduler->idle_thread = idle_thread;
  zi_executive_lock_initialise(&scheduler->dispatcher_lock);
  scheduler->tick_count = 0;
  scheduler->quantum_expiry_count = 0;
  scheduler->context_switch_count = 0;
}

ZiStatus zi_scheduler_enqueue(ZxScheduler* scheduler, ZxThread* thread) {
  if (scheduler == NULL || thread == NULL || thread->priority >= ZI_SCHEDULER_PRIORITY_COUNT ||
      thread->is_queued != 0 || thread->state == ZI_THREAD_TERMINATED) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  ZxReadyQueue* queue = &scheduler->ready_queues[thread->priority];
  thread->ready_previous = queue->tail;
  thread->ready_next = NULL;
  if (queue->tail != NULL) {
    queue->tail->ready_next = thread;
  } else {
    queue->head = thread;
  }
  queue->tail = thread;
  ++queue->count;
  thread->is_queued = 1;
  thread->state = ZI_THREAD_READY;
  scheduler->ready_bitmap |= UINT32_C(1) << thread->priority;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_scheduler_remove(ZxScheduler* scheduler, ZxThread* thread) {
  if (scheduler == NULL || thread == NULL || thread->priority >= ZI_SCHEDULER_PRIORITY_COUNT ||
      thread->is_queued == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  ZxReadyQueue* queue = &scheduler->ready_queues[thread->priority];
  if (thread->ready_previous != NULL) {
    thread->ready_previous->ready_next = thread->ready_next;
  } else {
    queue->head = thread->ready_next;
  }
  if (thread->ready_next != NULL) {
    thread->ready_next->ready_previous = thread->ready_previous;
  } else {
    queue->tail = thread->ready_previous;
  }

  thread->ready_previous = NULL;
  thread->ready_next = NULL;
  thread->is_queued = 0;
  --queue->count;
  if (queue->count == 0) {
    scheduler->ready_bitmap &= ~(UINT32_C(1) << thread->priority);
  }
  return ZI_STATUS_SUCCESS;
}

ZxThread* zi_scheduler_select_next(ZxScheduler* scheduler) {
  if (scheduler == NULL) {
    return NULL;
  }

  uint32_t remaining_bitmap = scheduler->ready_bitmap;
  while (remaining_bitmap != 0) {
    uint32_t priority = highest_ready_priority(remaining_bitmap);
    ZxReadyQueue* queue = &scheduler->ready_queues[priority];
    for (ZxThread* thread = queue->head; thread != NULL; thread = thread->ready_next) {
      if (!thread_can_run_on_cpu(thread, scheduler->cpu_index)) {
        continue;
      }
      if (ZiFailed(zi_scheduler_remove(scheduler, thread))) {
        return NULL;
      }
      thread->state = ZI_THREAD_RUNNING;
      scheduler->current_thread = thread;
      return thread;
    }
    remaining_bitmap &= ~(UINT32_C(1) << priority);
  }

  scheduler->current_thread = scheduler->idle_thread;
  if (scheduler->idle_thread != NULL) {
    scheduler->idle_thread->state = ZI_THREAD_RUNNING;
  }
  return scheduler->idle_thread;
}

ZiStatus zi_scheduler_on_tick(ZxScheduler* scheduler, ZiSchedulerDispatch* out_dispatch) {
  if (scheduler == NULL || out_dispatch == NULL || scheduler->current_thread == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }

  out_dispatch->previous_thread = scheduler->current_thread;
  out_dispatch->next_thread = scheduler->current_thread;
  out_dispatch->quantum_expired = 0;
  out_dispatch->did_switch = 0;
  ++scheduler->tick_count;

  ZxThread* current = scheduler->current_thread;
  bool should_dispatch = (bool)(current == scheduler->idle_thread && scheduler->ready_bitmap != 0);
  if (current != scheduler->idle_thread && current->state == ZI_THREAD_RUNNING) {
    if (current->quantum == 0) {
      current->quantum = ZI_SCHEDULER_DEFAULT_QUANTUM;
    }
    if (current->quantum_remaining == 0) {
      current->quantum_remaining = current->quantum;
    }
    --current->quantum_remaining;
    if (current->quantum_remaining == 0) {
      out_dispatch->quantum_expired = 1;
      ++scheduler->quantum_expiry_count;
      should_dispatch = true;
    } else if (scheduler->ready_bitmap != 0 &&
               highest_ready_priority(scheduler->ready_bitmap) > current->priority) {
      should_dispatch = true;
    }
  } else if (current->state != ZI_THREAD_RUNNING) {
    should_dispatch = true;
  }

  if (!should_dispatch) {
    return ZI_STATUS_SUCCESS;
  }

  if (current != scheduler->idle_thread && current->state == ZI_THREAD_RUNNING) {
    current->quantum_remaining = current->quantum;
    ZiStatus status = zi_scheduler_enqueue(scheduler, current);
    if (ZiFailed(status)) {
      return status;
    }
  }

  ZxThread* next = zi_scheduler_select_next(scheduler);
  if (next == NULL) {
    return ZI_STATUS_INVALID_STATE;
  }
  if (next->quantum == 0) {
    next->quantum = ZI_SCHEDULER_DEFAULT_QUANTUM;
  }
  if (next->quantum_remaining == 0) {
    next->quantum_remaining = next->quantum;
  }
  out_dispatch->next_thread = next;
  if (next != current) {
    out_dispatch->did_switch = 1;
    ++scheduler->context_switch_count;
  }
  return ZI_STATUS_SUCCESS;
}

void zi_scheduler_boost_priority(ZxThread* thread, uint32_t increment) {
  if (thread == NULL || thread->priority >= ZI_SCHEDULER_REALTIME_PRIORITY_MIN) {
    return;
  }
  uint32_t maximum_increment = ZI_SCHEDULER_DYNAMIC_PRIORITY_MAX - thread->priority;
  thread->priority += increment < maximum_increment ? increment : maximum_increment;
}

void zi_scheduler_decay_priority(ZxThread* thread) {
  if (thread == NULL || thread->priority >= ZI_SCHEDULER_REALTIME_PRIORITY_MIN) {
    return;
  }
  if (thread->priority > thread->base_priority) {
    --thread->priority;
  }
}

ZiStatus zi_scheduler_inherit_priority(ZxScheduler* scheduler,
                                       ZxThread* thread,
                                       uint32_t inherited_priority) {
  if (scheduler == NULL || thread == NULL || inherited_priority >= ZI_SCHEDULER_PRIORITY_COUNT) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (thread->priority >= ZI_SCHEDULER_REALTIME_PRIORITY_MIN) {
    return ZI_STATUS_SUCCESS;
  }
  uint32_t target = inherited_priority < ZI_SCHEDULER_REALTIME_PRIORITY_MIN
                        ? inherited_priority
                        : ZI_SCHEDULER_DYNAMIC_PRIORITY_MAX;
  if (target <= thread->priority) {
    return ZI_STATUS_SUCCESS;
  }
  bool was_queued = thread->is_queued != 0;
  if (was_queued && ZiFailed(zi_scheduler_remove(scheduler, thread))) {
    return ZI_STATUS_INVALID_STATE;
  }
  thread->priority = target;
  if (was_queued) {
    return zi_scheduler_enqueue(scheduler, thread);
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_scheduler_restore_base_priority(ZxScheduler* scheduler, ZxThread* thread) {
  if (scheduler == NULL || thread == NULL || thread->base_priority >= ZI_SCHEDULER_PRIORITY_COUNT) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (thread->priority == thread->base_priority ||
      thread->priority >= ZI_SCHEDULER_REALTIME_PRIORITY_MIN) {
    return ZI_STATUS_SUCCESS;
  }
  bool was_queued = thread->is_queued != 0;
  if (was_queued && ZiFailed(zi_scheduler_remove(scheduler, thread))) {
    return ZI_STATUS_INVALID_STATE;
  }
  thread->priority = thread->base_priority;
  if (was_queued) {
    return zi_scheduler_enqueue(scheduler, thread);
  }
  return ZI_STATUS_SUCCESS;
}

static uint32_t highest_ready_priority(uint32_t bitmap) {
  for (uint32_t priority = ZI_SCHEDULER_PRIORITY_COUNT; priority > 0; --priority) {
    uint32_t candidate = priority - 1;
    if ((bitmap & (UINT32_C(1) << candidate)) != 0) {
      return candidate;
    }
  }
  return 0;
}

static bool thread_can_run_on_cpu(const ZxThread* thread, uint32_t cpu_index) {
  if (cpu_index >= 64u) {
    return false;
  }
  return (thread->affinity_mask & (UINT64_C(1) << cpu_index)) != 0;
}
