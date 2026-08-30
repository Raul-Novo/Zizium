// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zi/dispatcher.h"
#include "zi/handle.h"
#include "zi/object.h"
#include "zi/security.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define ZI_IPC_MESSAGE_VERSION 1u
#define ZI_IPC_CHANNEL_OPTIONS_VERSION 1u
#define ZI_IPC_INLINE_PAYLOAD_CAPACITY 192u
#define ZI_IPC_QUEUE_CAPACITY 8u

enum ZiMessageFlags {
  ZI_MESSAGE_TRANSFER_HANDLE = 0x00000001,
};

enum ZiChannelState {
  ZI_CHANNEL_OPEN = 1,
  ZI_CHANNEL_CLOSED = 2,
};

typedef struct ZiMessage {
  uint32_t struct_size;
  uint32_t version;
  uint64_t message_id;
  uint64_t correlation_id;
  uint32_t message_type;
  uint32_t flags;
  size_t payload_size;
  ZiHandle transferred_handle;
  ZiAccessMask transferred_access;
  uint32_t reserved;
  unsigned char inline_payload[ZI_IPC_INLINE_PAYLOAD_CAPACITY];
} ZiMessage;

typedef struct ZiChannel ZiChannel;

typedef struct ZiPort {
  ZiObjectHeader object;
  ZxDispatcherHeader dispatcher;
  ZiChannel* pending_channels[ZI_IPC_QUEUE_CAPACITY];
  size_t queue_limit;
  size_t queue_head;
  size_t queue_count;
  uint32_t is_closed;
} ZiPort;

struct ZiChannel {
  ZiObjectHeader object;
  ZxDispatcherHeader dispatcher;
  ZiChannel* peer;
  ZiHandleTable* owner_table;
  const ZiAccessToken* owner_token;
  ZiMessage messages[ZI_IPC_QUEUE_CAPACITY];
  size_t queue_limit;
  size_t queue_head;
  size_t queue_count;
  uint32_t state;
  uint32_t peer_is_closed;
};

typedef struct ZiSharedSection {
  ZiObjectHeader object;
  void* backing;
  size_t size;
  ZiAccessMask maximum_access;
  uint32_t flags;
} ZiSharedSection;

typedef struct ZiRpcEndpoint {
  ZiHandle port;
  ZiStringView interface_name;
  uint32_t interface_version;
  uint32_t flags;
} ZiRpcEndpoint;

typedef struct ZiIpcChannelPairOptions {
  uint32_t struct_size;
  uint32_t version;
  ZiDispatcherDomain* dispatcher_domain;
  ZiStringView client_name;
  ZiStringView server_name;
  size_t queue_limit;
  ZiHandleTable* client_table;
  ZiHandleTable* server_table;
  const ZiAccessToken* client_token;
  const ZiAccessToken* server_token;
  const ZiSecurityDescriptor* client_security;
  const ZiSecurityDescriptor* server_security;
} ZiIpcChannelPairOptions;

const ZiObjectType* zi_ipc_port_object_type(void);
const ZiObjectType* zi_ipc_channel_object_type(void);
const ZiObjectType* zi_ipc_shared_section_object_type(void);

ZiStatus zi_ipc_port_initialise(ZiPort* port,
                                ZiDispatcherDomain* dispatcher_domain,
                                ZiStringView name,
                                size_t queue_limit,
                                const ZiSecurityDescriptor* security_descriptor);
ZiStatus zi_ipc_connect(ZiPort* port,
                        const ZiIpcChannelPairOptions* options,
                        ZiChannel* client_channel,
                        ZiChannel* server_channel);
ZiStatus zi_ipc_accept(ZiPort* port, ZiChannel** out_channel);
ZiStatus zi_ipc_port_close(ZiPort* port);

ZiStatus zi_ipc_channel_pair_initialise(const ZiIpcChannelPairOptions* options,
                                        ZiChannel* client_channel,
                                        ZiChannel* server_channel);
ZiStatus zi_ipc_send(ZiChannel* channel, const ZiMessage* message);
ZiStatus zi_ipc_receive(ZiChannel* channel, ZiMessage* out_message);
ZiStatus zi_ipc_channel_close(ZiChannel* channel);

ZiStatus zi_ipc_shared_section_initialise(ZiSharedSection* section,
                                          ZiStringView name,
                                          void* backing,
                                          size_t size,
                                          ZiAccessMask maximum_access,
                                          const ZiSecurityDescriptor* security_descriptor);
ZiStatus zi_ipc_shared_section_open(ZiSharedSection* section,
                                    ZiHandleTable* table,
                                    const ZiAccessToken* token,
                                    ZiAccessMask requested_access,
                                    ZiHandle* out_handle);
