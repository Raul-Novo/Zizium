// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/process_record.h"

#include <stddef.h>
#include <stdint.h>

#include "zi/byte_order.h"
#include "zi/dispatcher.h"
#include "zi/scheduler.h"
#include "zi/security.h"
#include "zizium/status.h"

ZiStatus zi_process_record_initialise(ZxProcess* process,
                                      uint64_t process_id,
                                      uint32_t base_priority,
                                      uint64_t affinity_mask,
                                      const ZiAccessToken* token,
                                      ZiDispatcherDomain* dispatcher_domain) {
  if (process == NULL || process_id == 0 || base_priority >= ZI_SCHEDULER_PRIORITY_COUNT ||
      affinity_mask == 0 || ZiFailed(zi_security_token_validate(token)) ||
      dispatcher_domain == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  zi_memory_zero(process, sizeof *process);
  process->struct_size = sizeof *process;
  process->version = ZI_EXECUTIVE_PROCESS_VERSION;
  process->process_id = process_id;
  process->base_priority = base_priority;
  process->state = ZI_PROCESS_INITIALISED;
  process->affinity_mask = affinity_mask;
  process->exit_status = ZI_STATUS_PROCESS_TERMINATED;
  process->security_token = token;
  return zi_dispatcher_header_initialise(&process->termination_event,
                                         dispatcher_domain,
                                         ZI_DISPATCHER_OBJECT_PROCESS_TERMINATION,
                                         0);
}

ZiStatus zi_process_record_mark_running(ZxProcess* process) {
  if (process == NULL || process->struct_size != sizeof *process ||
      process->version != ZI_EXECUTIVE_PROCESS_VERSION || process->security_token == NULL ||
      process->state != ZI_PROCESS_INITIALISED || process->termination_event.signal_state != 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  process->state = ZI_PROCESS_RUNNING;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_process_record_terminate(ZxProcess* process, int32_t exit_status) {
  if (process == NULL || process->struct_size != sizeof *process ||
      process->version != ZI_EXECUTIVE_PROCESS_VERSION ||
      (process->state != ZI_PROCESS_RUNNING && process->state != ZI_PROCESS_TERMINATING) ||
      process->termination_event.signal_state != 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  process->state = ZI_PROCESS_TERMINATED;
  process->exit_status = exit_status;
  return zi_dispatcher_set_signal_state(&process->termination_event, 1);
}

ZiStatus
zi_process_record_wait(const ZxProcess* process, uint64_t timeout, int32_t* out_exit_status) {
  if (process == NULL || out_exit_status == NULL || process->struct_size != sizeof *process ||
      process->version != ZI_EXECUTIVE_PROCESS_VERSION) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (process->state == ZI_PROCESS_TERMINATED && process->termination_event.signal_state != 0) {
    *out_exit_status = process->exit_status;
    return ZI_STATUS_SUCCESS;
  }
  if (timeout == 0) {
    return ZI_STATUS_TIMEOUT;
  }
  return ZI_STATUS_NOT_IMPLEMENTED;
}
