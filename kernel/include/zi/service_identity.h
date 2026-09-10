// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "zi/security.h"
#include "zi/service.h"
#include "zizium/status.h"

// Trusted bootstrap policy, not a public token-issuance API or durable NID database.
// Inputs must remain readable and stable for this call. Outputs change only on success.
// Non-SYSTEM tokens borrow group_storage until the process takes its own copy.
ZiStatus zi_service_bootstrap_token_create(const ZiServiceManifest* manifest,
                                           ZiSecurityId* group_storage,
                                           ZiAccessToken* out_token);
