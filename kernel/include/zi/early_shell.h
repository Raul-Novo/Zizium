// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "zi/boot.h"
#include "zi/zifs.h"

typedef struct ZiEarlyShellContext {
  const ZiBootContext* boot_context;
  const ZiFsVolume* root_volume;
} ZiEarlyShellContext;

_Noreturn void zi_early_luma_run(const ZiEarlyShellContext* context);
