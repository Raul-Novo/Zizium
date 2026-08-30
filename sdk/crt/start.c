// SPDX-License-Identifier: GPL-3.0-or-later

#include <stddef.h>
#include <stdint.h>

#include "zizium/process.h"
#include "zizium/status.h"
#include "zizium/zcrt.h"
#include "zizium/zx.h"

extern int ZiCrtInvokeMain(int argument_count, char** arguments);

static const char k_zicrt_image_identity[] = "ZiCRT";
static const char* volatile s_zicrt_relocation_anchor = k_zicrt_image_identity;

// The assembly start-up object resolves this external PE entry bridge by name.
// NOLINTNEXTLINE(misc-use-internal-linkage)
_Noreturn void ZiCrtStartC(const ZiProcessParameters* parameters) {
  ZiStatus status = s_zicrt_relocation_anchor != NULL ? ZiCrtInitialiseProcess(parameters)
                                                      : ZI_STATUS_BAD_IMAGE_FORMAT;
  int exit_code = (int)status;
  if (ZiSucceeded(status)) {
    exit_code =
        ZiCrtInvokeMain((int)parameters->argument_count, (char**)(uintptr_t)parameters->arguments);
  }
  (void)ZxExitProcess((int32_t)exit_code);
  for (;;) {
  }
}
