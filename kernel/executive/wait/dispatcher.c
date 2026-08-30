// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/dispatcher.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/executive_lock.h"
#include "zi/scheduler.h"
#include "zizium/status.h"

static bool dispatcher_type_is_supported(uint32_t object_type);
static bool object_is_ready(const ZxDispatcherHeader* header, const ZxThread* thread);
static void consume_object(ZxDispatcherHeader* header, ZxScheduler* scheduler, ZxThread* thread);
static bool operation_can_complete(const ZiWaitOperation* operation, uint32_t* out_index);
static void consume_operation(ZiWaitOperation* operation, uint32_t satisfied_index);
static void link_wait_block(ZxDispatcherHeader* header, ZxWaitBlock* block);
static void unlink_wait_block(ZxWaitBlock* block);
static ZiStatus
complete_operation(ZiWaitOperation* operation, ZiStatus status, uint32_t satisfied_index);
static ZiStatus wake_satisfied_waiters(ZxDispatcherHeader* header);
static void refresh_mutex_inheritance(ZxMutex* mutex);

void zi_dispatcher_domain_initialise(ZiDispatcherDomain* domain) {
  if (domain != NULL) {
    zi_executive_lock_initialise(&domain->lock);
  }
}

ZiStatus zi_dispatcher_header_initialise(ZxDispatcherHeader* header,
                                         ZiDispatcherDomain* domain,
                                         uint32_t object_type,
                                         uint32_t signal_state) {
  if (header == NULL || domain == NULL || !dispatcher_type_is_supported(object_type)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  header->object_type = object_type;
  header->signal_state = signal_state;
  header->waiters = NULL;
  header->domain = domain;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_dispatcher_set_signal_state(ZxDispatcherHeader* header, uint32_t signal_state) {
  if (header == NULL || header->domain == NULL ||
      !dispatcher_type_is_supported(header->object_type)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_executive_lock_acquire(&header->domain->lock);
  ZiStatus status = zi_dispatcher_set_signal_state_locked(header, signal_state);
  zi_executive_lock_release(&header->domain->lock);
  return status;
}

ZiStatus zi_dispatcher_set_signal_state_locked(ZxDispatcherHeader* header, uint32_t signal_state) {
  if (header == NULL || header->domain == NULL ||
      !dispatcher_type_is_supported(header->object_type)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  header->signal_state = signal_state;
  return signal_state == 0 ? ZI_STATUS_SUCCESS : wake_satisfied_waiters(header);
}

// Wait registration, rollback, and scheduler hand-off form one lock-scoped transaction.
// NOLINTNEXTLINE(readability-function-size)
ZiStatus zi_dispatcher_wait(ZiWaitOperation* operation,
                            ZxWaitBlock* block_storage,
                            ZxDispatcherHeader* const* objects,
                            size_t object_count,
                            uint32_t wait_type,
                            uint64_t timeout_ticks,
                            uint64_t current_tick,
                            ZxScheduler* scheduler,
                            ZxThread* thread) {
  if (operation == NULL || block_storage == NULL || objects == NULL || object_count == 0 ||
      object_count > UINT32_MAX || (wait_type != ZI_WAIT_ANY && wait_type != ZI_WAIT_ALL) ||
      scheduler == NULL || thread == NULL || thread->is_queued != 0 ||
      thread->state == ZI_THREAD_WAITING || thread->state == ZI_THREAD_TERMINATED) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiDispatcherDomain* domain = objects[0] != NULL ? objects[0]->domain : NULL;
  if (domain == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  for (size_t index = 0; index < object_count; ++index) {
    if (objects[index] == NULL || objects[index]->domain != domain ||
        !dispatcher_type_is_supported(objects[index]->object_type)) {
      return ZI_STATUS_INVALID_ARGUMENT;
    }
    for (size_t previous = 0; previous < index; ++previous) {
      if (objects[previous] == objects[index]) {
        return ZI_STATUS_INVALID_ARGUMENT;
      }
    }
  }
  if (timeout_ticks != UINT64_MAX && current_tick > UINT64_MAX - timeout_ticks) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }

  operation->struct_size = sizeof *operation;
  operation->version = ZI_WAIT_OPERATION_VERSION;
  operation->scheduler = scheduler;
  operation->thread = thread;
  operation->blocks = block_storage;
  operation->object_count = object_count;
  operation->wait_type = wait_type;
  operation->state = ZI_WAIT_STATE_UNUSED;
  operation->completion_status = ZI_STATUS_PENDING;
  operation->satisfied_index = ZI_WAIT_INDEX_NONE;
  operation->has_deadline = timeout_ticks == UINT64_MAX ? 0u : 1u;
  operation->deadline = timeout_ticks == UINT64_MAX ? 0 : current_tick + timeout_ticks;
  for (size_t index = 0; index < object_count; ++index) {
    block_storage[index].wait_object = objects[index];
    block_storage[index].thread = thread;
    block_storage[index].operation = operation;
    block_storage[index].previous = NULL;
    block_storage[index].next = NULL;
    block_storage[index].wait_key = (uint32_t)index;
  }

  zi_executive_lock_acquire(&domain->lock);
  uint32_t satisfied_index = ZI_WAIT_INDEX_NONE;
  if (operation_can_complete(operation, &satisfied_index)) {
    consume_operation(operation, satisfied_index);
    operation->state = ZI_WAIT_STATE_COMPLETED;
    operation->completion_status = ZI_STATUS_SUCCESS;
    operation->satisfied_index = satisfied_index;
    zi_executive_lock_release(&domain->lock);
    return ZI_STATUS_SUCCESS;
  }
  if (timeout_ticks == 0) {
    operation->state = ZI_WAIT_STATE_COMPLETED;
    operation->completion_status = ZI_STATUS_TIMEOUT;
    zi_executive_lock_release(&domain->lock);
    return ZI_STATUS_TIMEOUT;
  }

  for (size_t index = 0; index < object_count; ++index) {
    link_wait_block(objects[index], &block_storage[index]);
  }
  operation->state = ZI_WAIT_STATE_PENDING;
  thread->wait_block = block_storage;
  thread->state = ZI_THREAD_WAITING;
  for (size_t index = 0; index < object_count; ++index) {
    if (objects[index]->object_type == ZI_DISPATCHER_OBJECT_MUTEX) {
      refresh_mutex_inheritance((ZxMutex*)objects[index]);
    }
  }
  zi_executive_lock_release(&domain->lock);
  return ZI_STATUS_PENDING;
}

ZiStatus zi_dispatcher_query_wait(const ZiWaitOperation* operation, uint32_t* out_satisfied_index) {
  if (operation == NULL || operation->struct_size != sizeof *operation ||
      operation->version != ZI_WAIT_OPERATION_VERSION || out_satisfied_index == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_satisfied_index = operation->satisfied_index;
  return operation->state == ZI_WAIT_STATE_PENDING ? ZI_STATUS_PENDING
                                                   : operation->completion_status;
}

ZiStatus zi_dispatcher_cancel_wait(ZiWaitOperation* operation) {
  if (operation == NULL || operation->struct_size != sizeof *operation ||
      operation->version != ZI_WAIT_OPERATION_VERSION || operation->blocks == NULL ||
      operation->object_count == 0 || operation->blocks[0].wait_object == NULL ||
      operation->blocks[0].wait_object->domain == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiDispatcherDomain* domain = operation->blocks[0].wait_object->domain;
  zi_executive_lock_acquire(&domain->lock);
  ZiStatus status = operation->state == ZI_WAIT_STATE_PENDING
                        ? complete_operation(operation, ZI_STATUS_CANCELLED, ZI_WAIT_INDEX_NONE)
                        : ZI_STATUS_INVALID_STATE;
  zi_executive_lock_release(&domain->lock);
  return status;
}

ZiStatus zi_dispatcher_expire_wait(ZiWaitOperation* operation, uint64_t current_tick) {
  if (operation == NULL || operation->struct_size != sizeof *operation ||
      operation->version != ZI_WAIT_OPERATION_VERSION || operation->blocks == NULL ||
      operation->object_count == 0 || operation->blocks[0].wait_object == NULL ||
      operation->blocks[0].wait_object->domain == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiDispatcherDomain* domain = operation->blocks[0].wait_object->domain;
  zi_executive_lock_acquire(&domain->lock);
  ZiStatus status = ZI_STATUS_PENDING;
  if (operation->state != ZI_WAIT_STATE_PENDING) {
    status = ZI_STATUS_INVALID_STATE;
  } else if (operation->has_deadline != 0 && current_tick >= operation->deadline) {
    status = complete_operation(operation, ZI_STATUS_TIMEOUT, ZI_WAIT_INDEX_NONE);
  }
  zi_executive_lock_release(&domain->lock);
  return status;
}

ZiStatus zi_event_initialise(ZxEvent* event,
                             ZiDispatcherDomain* domain,
                             uint32_t reset_type,
                             bool initially_signalled) {
  if (event == NULL ||
      (reset_type != ZI_EVENT_NOTIFICATION && reset_type != ZI_EVENT_SYNCHRONISATION)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  event->reset_type = reset_type;
  uint32_t initial_signal_state = 0;
  if (initially_signalled) {
    initial_signal_state = 1;
  }
  return zi_dispatcher_header_initialise(&event->header,
                                         domain,
                                         ZI_DISPATCHER_OBJECT_EVENT,
                                         initial_signal_state);
}

ZiStatus zi_event_set(ZxEvent* event) {
  return event == NULL ? ZI_STATUS_INVALID_ARGUMENT
                       : zi_dispatcher_set_signal_state(&event->header, 1);
}

ZiStatus zi_event_reset(ZxEvent* event) {
  return event == NULL ? ZI_STATUS_INVALID_ARGUMENT
                       : zi_dispatcher_set_signal_state(&event->header, 0);
}

ZiStatus zi_mutex_initialise(ZxMutex* mutex, ZiDispatcherDomain* domain) {
  if (mutex == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  mutex->owner = NULL;
  mutex->owner_scheduler = NULL;
  mutex->recursion_count = 0;
  return zi_dispatcher_header_initialise(&mutex->header, domain, ZI_DISPATCHER_OBJECT_MUTEX, 1);
}

ZiStatus zi_mutex_release(ZxMutex* mutex, ZxThread* owner) {
  if (mutex == NULL || owner == NULL || mutex->header.domain == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_executive_lock_acquire(&mutex->header.domain->lock);
  if (mutex->owner != owner || mutex->recursion_count == 0) {
    zi_executive_lock_release(&mutex->header.domain->lock);
    return ZI_STATUS_ACCESS_DENIED;
  }
  --mutex->recursion_count;
  if (mutex->recursion_count != 0) {
    zi_executive_lock_release(&mutex->header.domain->lock);
    return ZI_STATUS_SUCCESS;
  }
  ZxScheduler* owner_scheduler = mutex->owner_scheduler;
  mutex->owner = NULL;
  mutex->owner_scheduler = NULL;
  mutex->header.signal_state = 1;
  ZiStatus status = ZI_STATUS_SUCCESS;
  if (owner_scheduler != NULL) {
    status = zi_scheduler_restore_base_priority(owner_scheduler, owner);
  }
  if (ZiSucceeded(status)) {
    status = wake_satisfied_waiters(&mutex->header);
  }
  zi_executive_lock_release(&mutex->header.domain->lock);
  return status;
}

ZiStatus zi_semaphore_initialise(ZxSemaphore* semaphore,
                                 ZiDispatcherDomain* domain,
                                 uint32_t initial_count,
                                 uint32_t limit) {
  if (semaphore == NULL || limit == 0 || initial_count > limit) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  semaphore->limit = limit;
  return zi_dispatcher_header_initialise(&semaphore->header,
                                         domain,
                                         ZI_DISPATCHER_OBJECT_SEMAPHORE,
                                         initial_count);
}

ZiStatus
zi_semaphore_release(ZxSemaphore* semaphore, uint32_t release_count, uint32_t* out_previous_count) {
  if (semaphore == NULL || semaphore->header.domain == NULL || release_count == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_executive_lock_acquire(&semaphore->header.domain->lock);
  uint32_t previous_count = semaphore->header.signal_state;
  if (release_count > semaphore->limit - previous_count) {
    zi_executive_lock_release(&semaphore->header.domain->lock);
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  semaphore->header.signal_state += release_count;
  if (out_previous_count != NULL) {
    *out_previous_count = previous_count;
  }
  ZiStatus status = wake_satisfied_waiters(&semaphore->header);
  zi_executive_lock_release(&semaphore->header.domain->lock);
  return status;
}

ZiStatus zi_timer_initialise(ZxTimer* timer, ZiDispatcherDomain* domain) {
  if (timer == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  timer->due_time = 0;
  timer->period = 0;
  timer->is_active = 0;
  return zi_dispatcher_header_initialise(&timer->header, domain, ZI_DISPATCHER_OBJECT_TIMER, 0);
}

ZiStatus zi_timer_set(ZxTimer* timer, uint64_t due_tick, uint64_t period, uint64_t current_tick) {
  if (timer == NULL || timer->header.domain == NULL || due_tick <= current_tick ||
      (period != 0 && due_tick > UINT64_MAX - period)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_executive_lock_acquire(&timer->header.domain->lock);
  timer->due_time = due_tick;
  timer->period = period;
  timer->is_active = 1;
  timer->header.signal_state = 0;
  zi_executive_lock_release(&timer->header.domain->lock);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_timer_cancel(ZxTimer* timer) {
  if (timer == NULL || timer->header.domain == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_executive_lock_acquire(&timer->header.domain->lock);
  timer->is_active = 0;
  timer->header.signal_state = 0;
  zi_executive_lock_release(&timer->header.domain->lock);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_timer_tick(ZxTimer* timer, uint64_t current_tick) {
  if (timer == NULL || timer->header.domain == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_executive_lock_acquire(&timer->header.domain->lock);
  if (timer->is_active == 0 || current_tick < timer->due_time) {
    zi_executive_lock_release(&timer->header.domain->lock);
    return ZI_STATUS_PENDING;
  }
  timer->header.signal_state = 1;
  if (timer->period == 0 || current_tick > UINT64_MAX - timer->period) {
    timer->is_active = 0;
  } else {
    timer->due_time = current_tick + timer->period;
  }
  ZiStatus status = wake_satisfied_waiters(&timer->header);
  zi_executive_lock_release(&timer->header.domain->lock);
  return status;
}

static bool dispatcher_type_is_supported(uint32_t object_type) {
  return (bool)(object_type >= ZI_DISPATCHER_OBJECT_PROCESS_TERMINATION &&
                object_type <= ZI_DISPATCHER_OBJECT_CHANNEL);
}

static bool object_is_ready(const ZxDispatcherHeader* header, const ZxThread* thread) {
  if (header->object_type == ZI_DISPATCHER_OBJECT_MUTEX) {
    const ZxMutex* mutex = (const ZxMutex*)header;
    return (bool)(mutex->owner == NULL || mutex->owner == thread);
  }
  return header->signal_state != 0;
}

static void consume_object(ZxDispatcherHeader* header, ZxScheduler* scheduler, ZxThread* thread) {
  switch (header->object_type) {
    case ZI_DISPATCHER_OBJECT_EVENT:
      if (((ZxEvent*)header)->reset_type == ZI_EVENT_SYNCHRONISATION) {
        header->signal_state = 0;
      }
      break;
    case ZI_DISPATCHER_OBJECT_MUTEX: {
      ZxMutex* mutex = (ZxMutex*)header;
      mutex->owner = thread;
      mutex->owner_scheduler = scheduler;
      ++mutex->recursion_count;
      header->signal_state = 0;
      break;
    }
    case ZI_DISPATCHER_OBJECT_SEMAPHORE:
      --header->signal_state;
      break;
    case ZI_DISPATCHER_OBJECT_TIMER:
      header->signal_state = 0;
      break;
    default:
      break;
  }
}

static bool operation_can_complete(const ZiWaitOperation* operation, uint32_t* out_index) {
  if (operation->wait_type == ZI_WAIT_ANY) {
    for (size_t index = 0; index < operation->object_count; ++index) {
      if (object_is_ready(operation->blocks[index].wait_object, operation->thread)) {
        *out_index = (uint32_t)index;
        return true;
      }
    }
    return false;
  }
  for (size_t index = 0; index < operation->object_count; ++index) {
    if (!object_is_ready(operation->blocks[index].wait_object, operation->thread)) {
      return false;
    }
  }
  *out_index = ZI_WAIT_INDEX_NONE;
  return true;
}

static void consume_operation(ZiWaitOperation* operation, uint32_t satisfied_index) {
  if (operation->wait_type == ZI_WAIT_ANY) {
    consume_object(operation->blocks[satisfied_index].wait_object,
                   operation->scheduler,
                   operation->thread);
    return;
  }
  for (size_t index = 0; index < operation->object_count; ++index) {
    consume_object(operation->blocks[index].wait_object, operation->scheduler, operation->thread);
  }
}

static void link_wait_block(ZxDispatcherHeader* header, ZxWaitBlock* block) {
  block->previous = NULL;
  block->next = header->waiters;
  if (header->waiters != NULL) {
    header->waiters->previous = block;
  }
  header->waiters = block;
}

static void unlink_wait_block(ZxWaitBlock* block) {
  if (block->previous != NULL) {
    block->previous->next = block->next;
  } else if (block->wait_object != NULL) {
    block->wait_object->waiters = block->next;
  }
  if (block->next != NULL) {
    block->next->previous = block->previous;
  }
  block->previous = NULL;
  block->next = NULL;
}

static ZiStatus
complete_operation(ZiWaitOperation* operation, ZiStatus status, uint32_t satisfied_index) {
  for (size_t index = 0; index < operation->object_count; ++index) {
    unlink_wait_block(&operation->blocks[index]);
  }
  operation->state = ZI_WAIT_STATE_COMPLETED;
  operation->completion_status = status;
  operation->satisfied_index = satisfied_index;
  operation->thread->wait_block = NULL;
  operation->thread->state = ZI_THREAD_TRANSITION;
  for (size_t index = 0; index < operation->object_count; ++index) {
    ZxDispatcherHeader* header = operation->blocks[index].wait_object;
    if (header->object_type == ZI_DISPATCHER_OBJECT_MUTEX) {
      refresh_mutex_inheritance((ZxMutex*)header);
    }
  }
  ZiStatus enqueue_status = zi_scheduler_enqueue(operation->scheduler, operation->thread);
  if (ZiFailed(enqueue_status)) {
    return enqueue_status;
  }
  return status;
}

static ZiStatus wake_satisfied_waiters(ZxDispatcherHeader* header) {
  ZiStatus first_failure = ZI_STATUS_SUCCESS;
  ZxWaitBlock* block = header->waiters;
  while (block != NULL) {
    ZxWaitBlock* next = block->next;
    ZiWaitOperation* operation = block->operation;
    uint32_t satisfied_index = ZI_WAIT_INDEX_NONE;
    if (operation != NULL && operation->state == ZI_WAIT_STATE_PENDING &&
        operation_can_complete(operation, &satisfied_index)) {
      consume_operation(operation, satisfied_index);
      ZiStatus status = complete_operation(operation, ZI_STATUS_SUCCESS, satisfied_index);
      if (ZiFailed(status) && ZiSucceeded(first_failure)) {
        first_failure = status;
      }
    }
    block = next;
  }
  return first_failure;
}

static void refresh_mutex_inheritance(ZxMutex* mutex) {
  if (mutex->owner == NULL || mutex->owner_scheduler == NULL) {
    return;
  }
  uint32_t inherited_priority = mutex->owner->base_priority;
  for (const ZxWaitBlock* block = mutex->header.waiters; block != NULL; block = block->next) {
    if (block->thread != NULL && block->thread->priority > inherited_priority) {
      inherited_priority = block->thread->priority;
    }
  }
  if (inherited_priority > mutex->owner->base_priority) {
    (void)zi_scheduler_inherit_priority(mutex->owner_scheduler, mutex->owner, inherited_priority);
  } else {
    (void)zi_scheduler_restore_base_priority(mutex->owner_scheduler, mutex->owner);
  }
}
