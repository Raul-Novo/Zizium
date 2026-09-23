// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/zifs.h"
#include "zizium/status.h"

// Internal test contract, never production enrolment or a public account ABI.
typedef struct ZiIdentityAcceptanceParameters {
  uint64_t stage;
  uint64_t record_index;
  uint64_t file_id;
} ZiIdentityAcceptanceParameters;

// Trusted boot C string, terminated within 1024 bytes; NULL means no request.
// Exact token: zi.identity=stage:record_index:file_id. Stages are 1 through 6.
// Outputs are unchanged on failure; absent token produces a zero stage.
ZiStatus zi_identity_acceptance_parse(const char* command_line,
                                      ZiIdentityAcceptanceParameters* out_parameters);
// Caller serialises the volume and supplies the ordinary store workspace.
// Only explicit disposable test images may use this fixed fixture authority.
ZiStatus zi_identity_acceptance_run(ZiFsVolume* volume,
                                    const ZiIdentityAcceptanceParameters* parameters,
                                    void* workspace,
                                    size_t workspace_size);
