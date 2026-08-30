// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/service.h"
#include "zi/user_process.h"
#include "zi/zifs.h"
#include "zi/zifs_image_source.h"
#include "zizium/status.h"

#define ZI_SYSTEM_BOOTSTRAP_VERSION 1u

typedef struct ZiSystemBootstrap {
  uint32_t struct_size;
  uint32_t version;
  const ZiFsVolume* root_volume;
  void* block_buffer;
  size_t block_buffer_size;
  ZiUserProcessManager* process_manager;
  ZiFsImageSourceAllocator image_allocator;
} ZiSystemBootstrap;

ZiStatus zi_system_bootstrap_initialise(ZiSystemBootstrap* bootstrap,
                                        const ZiFsVolume* root_volume,
                                        void* block_buffer,
                                        size_t block_buffer_size,
                                        ZiUserProcessManager* process_manager);
ZiStatus zi_system_bootstrap_run(ZiSystemBootstrap* bootstrap,
                                 const ZiServiceManifest* manifests,
                                 size_t manifest_count,
                                 const size_t* start_order,
                                 size_t start_order_count);
