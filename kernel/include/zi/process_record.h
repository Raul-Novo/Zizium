// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

#include "zi/dispatcher.h"
#include "zi/scheduler.h"
#include "zi/security.h"
#include "zizium/status.h"

ZiStatus zi_process_record_initialise(ZxProcess* process,
                                      uint64_t process_id,
                                      uint32_t base_priority,
                                      uint64_t affinity_mask,
                                      const ZiAccessToken* token,
                                      ZiDispatcherDomain* dispatcher_domain);
ZiStatus zi_process_record_mark_running(ZxProcess* process);
ZiStatus zi_process_record_terminate(ZxProcess* process, int32_t exit_status);
ZiStatus
zi_process_record_wait(const ZxProcess* process, uint64_t timeout, int32_t* out_exit_status);
