// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

#include "zizium/status.h"

#define ZI_PHASE4_ACCEPTANCE_RESULT_VERSION 1u

enum ZiPhase4AcceptanceFlags {
  ZI_PHASE4_ACCEPTANCE_OBJECT_NAMESPACE = UINT32_C(0x00000001),
  ZI_PHASE4_ACCEPTANCE_HANDLE_ACCESS = UINT32_C(0x00000002),
  ZI_PHASE4_ACCEPTANCE_WAIT_OBJECTS = UINT32_C(0x00000004),
  ZI_PHASE4_ACCEPTANCE_IPC_EXCHANGE = UINT32_C(0x00000008),
  ZI_PHASE4_ACCEPTANCE_HANDLE_TRANSFER = UINT32_C(0x00000010),
};

typedef struct ZiUserProcess ZiUserProcess;
typedef struct ZiDispatcherDomain ZiDispatcherDomain;

typedef struct ZiPhase4AcceptanceResult {
  uint32_t struct_size;
  uint32_t version;
  uint32_t completed_mask;
  uint32_t reserved;
} ZiPhase4AcceptanceResult;

ZiStatus zi_phase4_acceptance_run(ZiUserProcess* client_process,
                                  ZiUserProcess* server_process,
                                  ZiDispatcherDomain* dispatcher_domain,
                                  ZiPhase4AcceptanceResult* out_result);
ZiStatus zi_phase4_acceptance_verify_process_cleanup(void);
