// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/ipc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/dispatcher.h"
#include "zi/executive_lock.h"
#include "zi/handle.h"
#include "zi/object.h"
#include "zi/scheduler.h"
#include "zi/security.h"
#include "zizium/status.h"
#include "zizium/types.h"

static void port_destroy(ZiObjectHeader* object);
static void channel_destroy(ZiObjectHeader* object);
static void shared_section_destroy(ZiObjectHeader* object);
static void port_last_handle_closed(ZiObjectHeader* object);
static void channel_last_handle_closed(ZiObjectHeader* object);
static ZiStatus channel_initialise(ZiChannel* channel,
                                   ZiDispatcherDomain* dispatcher_domain,
                                   ZiStringView name,
                                   size_t queue_limit,
                                   ZiHandleTable* owner_table,
                                   const ZiAccessToken* owner_token,
                                   const ZiSecurityDescriptor* security_descriptor);
static bool channel_options_are_valid(const ZiIpcChannelPairOptions* options);
static bool message_is_valid(const ZiMessage* message);
static void copy_message(ZiMessage* destination, const ZiMessage* source);
static ZiStatus close_transferred_handle(ZiHandleTable* table, ZiHandle handle);

static const ZiObjectOperations k_port_operations = {sizeof(ZiObjectOperations),
                                                     ZI_OBJECT_OPERATIONS_VERSION,
                                                     port_destroy,
                                                     port_last_handle_closed};
static const ZiObjectOperations k_channel_operations = {sizeof(ZiObjectOperations),
                                                        ZI_OBJECT_OPERATIONS_VERSION,
                                                        channel_destroy,
                                                        channel_last_handle_closed};
static const ZiObjectOperations k_shared_section_operations = {sizeof(ZiObjectOperations),
                                                               ZI_OBJECT_OPERATIONS_VERSION,
                                                               shared_section_destroy,
                                                               NULL};
static const ZiObjectType k_port_type = {0x100u, {"Port", 4}, &k_port_operations, 0};
static const ZiObjectType k_channel_type = {0x101u, {"Channel", 7}, &k_channel_operations, 0};
static const ZiObjectType k_shared_section_type = {0x102u,
                                                   {"SharedSection", 13},
                                                   &k_shared_section_operations,
                                                   0};

const ZiObjectType* zi_ipc_port_object_type(void) {
  return &k_port_type;
}

const ZiObjectType* zi_ipc_channel_object_type(void) {
  return &k_channel_type;
}

const ZiObjectType* zi_ipc_shared_section_object_type(void) {
  return &k_shared_section_type;
}

ZiStatus zi_ipc_port_initialise(ZiPort* port,
                                ZiDispatcherDomain* dispatcher_domain,
                                ZiStringView name,
                                size_t queue_limit,
                                const ZiSecurityDescriptor* security_descriptor) {
  if (port == NULL || dispatcher_domain == NULL || name.data == NULL || name.size == 0 ||
      queue_limit == 0 || queue_limit > ZI_IPC_QUEUE_CAPACITY || security_descriptor == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_object_initialise(&port->object,
                                         &k_port_type,
                                         name,
                                         NULL,
                                         security_descriptor,
                                         "IPC port");
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_dispatcher_header_initialise(&port->dispatcher,
                                           dispatcher_domain,
                                           ZI_DISPATCHER_OBJECT_PORT,
                                           0);
  if (ZiFailed(status)) {
    (void)zi_object_dereference(&port->object);
    return status;
  }
  for (size_t index = 0; index < ZI_IPC_QUEUE_CAPACITY; ++index) {
    port->pending_channels[index] = NULL;
  }
  port->queue_limit = queue_limit;
  port->queue_head = 0;
  port->queue_count = 0;
  port->is_closed = 0;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_ipc_connect(ZiPort* port,
                        const ZiIpcChannelPairOptions* options,
                        ZiChannel* client_channel,
                        ZiChannel* server_channel) {
  if (port == NULL || port->dispatcher.domain == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_ipc_channel_pair_initialise(options, client_channel, server_channel);
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_object_reference(&server_channel->object);
  if (ZiFailed(status)) {
    (void)zi_ipc_channel_close(client_channel);
    (void)zi_object_dereference(&client_channel->object);
    (void)zi_object_dereference(&server_channel->object);
    return status;
  }

  ZiDispatcherDomain* domain = port->dispatcher.domain;
  zi_executive_lock_acquire(&domain->lock);
  bool is_closed = port->is_closed != 0;
  if (is_closed || port->queue_count == port->queue_limit) {
    zi_executive_lock_release(&domain->lock);
    (void)zi_ipc_channel_close(client_channel);
    (void)zi_object_dereference(&server_channel->object);
    (void)zi_object_dereference(&client_channel->object);
    (void)zi_object_dereference(&server_channel->object);
    if (is_closed) {
      return ZI_STATUS_PEER_CLOSED;
    }
    return ZI_STATUS_QUEUE_FULL;
  }
  size_t tail = (port->queue_head + port->queue_count) % port->queue_limit;
  port->pending_channels[tail] = server_channel;
  ++port->queue_count;
  uint32_t signal_state = (uint32_t)port->queue_count;
  status = zi_dispatcher_set_signal_state_locked(&port->dispatcher, signal_state);
  zi_executive_lock_release(&domain->lock);
  return status;
}

ZiStatus zi_ipc_accept(ZiPort* port, ZiChannel** out_channel) {
  if (port == NULL || out_channel == NULL || port->dispatcher.domain == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_channel = NULL;
  ZiDispatcherDomain* domain = port->dispatcher.domain;
  zi_executive_lock_acquire(&domain->lock);
  if (port->queue_count == 0) {
    ZiStatus status = port->is_closed != 0 ? ZI_STATUS_PEER_CLOSED : ZI_STATUS_TIMEOUT;
    zi_executive_lock_release(&domain->lock);
    return status;
  }
  ZiChannel* channel = port->pending_channels[port->queue_head];
  port->pending_channels[port->queue_head] = NULL;
  port->queue_head = (port->queue_head + 1) % port->queue_limit;
  --port->queue_count;
  port->dispatcher.signal_state = (uint32_t)port->queue_count;
  zi_executive_lock_release(&domain->lock);
  *out_channel = channel;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_ipc_port_close(ZiPort* port) {
  if (port == NULL || port->dispatcher.domain == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiChannel* pending[ZI_IPC_QUEUE_CAPACITY] = {0};
  size_t pending_count = 0;
  ZiDispatcherDomain* domain = port->dispatcher.domain;
  zi_executive_lock_acquire(&domain->lock);
  if (port->is_closed != 0) {
    zi_executive_lock_release(&domain->lock);
    return ZI_STATUS_SUCCESS;
  }
  port->is_closed = 1;
  while (port->queue_count != 0) {
    pending[pending_count] = port->pending_channels[port->queue_head];
    port->pending_channels[port->queue_head] = NULL;
    port->queue_head = (port->queue_head + 1) % port->queue_limit;
    --port->queue_count;
    ++pending_count;
  }
  ZiStatus result = zi_dispatcher_set_signal_state_locked(&port->dispatcher, 1);
  zi_executive_lock_release(&domain->lock);
  for (size_t index = 0; index < pending_count; ++index) {
    (void)zi_ipc_channel_close(pending[index]);
    ZiStatus status = zi_object_dereference(&pending[index]->object);
    if (ZiSucceeded(result) && ZiFailed(status)) {
      result = status;
    }
  }
  return result;
}

ZiStatus zi_ipc_channel_pair_initialise(const ZiIpcChannelPairOptions* options,
                                        ZiChannel* client_channel,
                                        ZiChannel* server_channel) {
  if (!channel_options_are_valid(options) || client_channel == NULL || server_channel == NULL ||
      client_channel == server_channel) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = channel_initialise(client_channel,
                                       options->dispatcher_domain,
                                       options->client_name,
                                       options->queue_limit,
                                       options->client_table,
                                       options->client_token,
                                       options->client_security);
  if (ZiFailed(status)) {
    return status;
  }
  status = channel_initialise(server_channel,
                              options->dispatcher_domain,
                              options->server_name,
                              options->queue_limit,
                              options->server_table,
                              options->server_token,
                              options->server_security);
  if (ZiFailed(status)) {
    (void)zi_object_dereference(&client_channel->object);
    return status;
  }
  client_channel->peer = server_channel;
  server_channel->peer = client_channel;
  status = zi_object_reference(&server_channel->object);
  if (ZiFailed(status)) {
    client_channel->peer = NULL;
    server_channel->peer = NULL;
    (void)zi_object_dereference(&client_channel->object);
    (void)zi_object_dereference(&server_channel->object);
    return status;
  }
  status = zi_object_reference(&client_channel->object);
  if (ZiFailed(status)) {
    client_channel->peer = NULL;
    server_channel->peer = NULL;
    (void)zi_object_dereference(&server_channel->object);
    (void)zi_object_dereference(&client_channel->object);
    (void)zi_object_dereference(&server_channel->object);
    return status;
  }
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_ipc_send(ZiChannel* channel, const ZiMessage* message) {
  if (channel == NULL || !message_is_valid(message) || channel->dispatcher.domain == NULL ||
      channel->owner_table == NULL || channel->owner_token == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiDispatcherDomain* domain = channel->dispatcher.domain;
  zi_executive_lock_acquire(&domain->lock);
  ZiChannel* peer = channel->peer;
  bool peer_closed = (bool)(channel->state != ZI_CHANNEL_OPEN || channel->peer_is_closed != 0 ||
                            peer == NULL || peer->state != ZI_CHANNEL_OPEN ||
                            peer->owner_table == NULL || peer->owner_token == NULL);
  ZiStatus status = ZI_STATUS_PEER_CLOSED;
  if (!peer_closed) {
    status = zi_object_reference(&peer->object);
  }
  zi_executive_lock_release(&domain->lock);
  if (ZiFailed(status)) {
    return status;
  }

  ZiMessage queued = {0};
  copy_message(&queued, message);
  if ((message->flags & ZI_MESSAGE_TRANSFER_HANDLE) != 0) {
    status = zi_handle_duplicate(channel->owner_table,
                                 message->transferred_handle,
                                 peer->owner_table,
                                 peer->owner_token,
                                 message->transferred_access,
                                 0,
                                 &queued.transferred_handle);
    if (ZiFailed(status)) {
      (void)zi_object_dereference(&peer->object);
      return status;
    }
  }

  zi_executive_lock_acquire(&domain->lock);
  peer_closed = (bool)(channel->state != ZI_CHANNEL_OPEN || channel->peer_is_closed != 0 ||
                       channel->peer != peer || peer->state != ZI_CHANNEL_OPEN);
  if (peer_closed || peer->queue_count == peer->queue_limit) {
    zi_executive_lock_release(&domain->lock);
    if ((queued.flags & ZI_MESSAGE_TRANSFER_HANDLE) != 0) {
      (void)close_transferred_handle(peer->owner_table, queued.transferred_handle);
    }
    (void)zi_object_dereference(&peer->object);
    if (peer_closed) {
      return ZI_STATUS_PEER_CLOSED;
    }
    return ZI_STATUS_QUEUE_FULL;
  }
  size_t tail = (peer->queue_head + peer->queue_count) % peer->queue_limit;
  peer->messages[tail] = queued;
  ++peer->queue_count;
  uint32_t signal_state = (uint32_t)peer->queue_count;
  status = zi_dispatcher_set_signal_state_locked(&peer->dispatcher, signal_state);
  zi_executive_lock_release(&domain->lock);
  ZiStatus dereference_status = zi_object_dereference(&peer->object);
  if (ZiFailed(status)) {
    return status;
  }
  return dereference_status;
}

ZiStatus zi_ipc_receive(ZiChannel* channel, ZiMessage* out_message) {
  if (channel == NULL || out_message == NULL || channel->dispatcher.domain == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiDispatcherDomain* domain = channel->dispatcher.domain;
  zi_executive_lock_acquire(&domain->lock);
  if (channel->queue_count == 0) {
    ZiStatus status = channel->peer_is_closed != 0 || channel->state != ZI_CHANNEL_OPEN
                          ? ZI_STATUS_PEER_CLOSED
                          : ZI_STATUS_TIMEOUT;
    zi_executive_lock_release(&domain->lock);
    return status;
  }
  *out_message = channel->messages[channel->queue_head];
  channel->messages[channel->queue_head] = (ZiMessage){0};
  channel->queue_head = (channel->queue_head + 1) % channel->queue_limit;
  --channel->queue_count;
  channel->dispatcher.signal_state = channel->queue_count != 0 || channel->peer_is_closed != 0
                                         ? (uint32_t)channel->queue_count + 1u
                                         : 0u;
  zi_executive_lock_release(&domain->lock);
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_ipc_channel_close(ZiChannel* channel) {
  if (channel == NULL || channel->dispatcher.domain == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiHandle handles[ZI_IPC_QUEUE_CAPACITY] = {0};
  size_t handle_count = 0;
  ZiChannel* peer = NULL;
  bool peer_holds_channel = false;
  ZiDispatcherDomain* domain = channel->dispatcher.domain;
  zi_executive_lock_acquire(&domain->lock);
  if (channel->state == ZI_CHANNEL_CLOSED) {
    zi_executive_lock_release(&domain->lock);
    return ZI_STATUS_SUCCESS;
  }
  channel->state = ZI_CHANNEL_CLOSED;
  while (channel->queue_count != 0) {
    ZiMessage* message = &channel->messages[channel->queue_head];
    if ((message->flags & ZI_MESSAGE_TRANSFER_HANDLE) != 0) {
      handles[handle_count] = message->transferred_handle;
      ++handle_count;
    }
    *message = (ZiMessage){0};
    channel->queue_head = (channel->queue_head + 1) % channel->queue_limit;
    --channel->queue_count;
  }
  peer = channel->peer;
  channel->peer = NULL;
  if (peer != NULL) {
    peer->peer_is_closed = 1;
    peer_holds_channel = peer->peer == channel;
    if (peer_holds_channel) {
      peer->peer = NULL;
    }
  }
  ZiStatus result = zi_dispatcher_set_signal_state_locked(&channel->dispatcher, 1);
  if (peer != NULL) {
    ZiStatus status = zi_dispatcher_set_signal_state_locked(&peer->dispatcher, 1);
    if (ZiSucceeded(result) && ZiFailed(status)) {
      result = status;
    }
  }
  zi_executive_lock_release(&domain->lock);
  for (size_t index = 0; index < handle_count; ++index) {
    ZiStatus status = close_transferred_handle(channel->owner_table, handles[index]);
    if (ZiSucceeded(result) && ZiFailed(status)) {
      result = status;
    }
  }
  if (peer != NULL) {
    ZiStatus status = zi_object_dereference(&peer->object);
    if (ZiSucceeded(result) && ZiFailed(status)) {
      result = status;
    }
  }
  if (peer_holds_channel) {
    ZiStatus status = zi_object_dereference(&channel->object);
    if (ZiSucceeded(result) && ZiFailed(status)) {
      result = status;
    }
  }
  return result;
}

ZiStatus zi_ipc_shared_section_initialise(ZiSharedSection* section,
                                          ZiStringView name,
                                          void* backing,
                                          size_t size,
                                          ZiAccessMask maximum_access,
                                          const ZiSecurityDescriptor* security_descriptor) {
  if (section == NULL || name.data == NULL || name.size == 0 || backing == NULL || size == 0 ||
      maximum_access == 0 || security_descriptor == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = zi_object_initialise(&section->object,
                                         &k_shared_section_type,
                                         name,
                                         NULL,
                                         security_descriptor,
                                         "IPC shared section");
  if (ZiFailed(status)) {
    return status;
  }
  section->backing = backing;
  section->size = size;
  section->maximum_access = maximum_access;
  section->flags = 0;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_ipc_shared_section_open(ZiSharedSection* section,
                                    ZiHandleTable* table,
                                    const ZiAccessToken* token,
                                    ZiAccessMask requested_access,
                                    ZiHandle* out_handle) {
  if (out_handle == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_handle = ZI_INVALID_HANDLE;
  if (section == NULL || table == NULL || token == NULL || requested_access == 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  if (section->object.type != &k_shared_section_type || section->object.is_destroyed != 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  if ((requested_access & ~section->maximum_access) != 0) {
    return ZI_STATUS_ACCESS_DENIED;
  }
  return zi_handle_open(table, &section->object, token, requested_access, out_handle);
}

static void port_destroy(ZiObjectHeader* object) {
  (void)zi_ipc_port_close((ZiPort*)object);
}

static void channel_destroy(ZiObjectHeader* object) {
  (void)zi_ipc_channel_close((ZiChannel*)object);
}

static void shared_section_destroy(ZiObjectHeader* object) {
  ZiSharedSection* section = (ZiSharedSection*)object;
  section->backing = NULL;
  section->size = 0;
  section->maximum_access = 0;
}

static void port_last_handle_closed(ZiObjectHeader* object) {
  (void)zi_ipc_port_close((ZiPort*)object);
}

static void channel_last_handle_closed(ZiObjectHeader* object) {
  (void)zi_ipc_channel_close((ZiChannel*)object);
}

static ZiStatus channel_initialise(ZiChannel* channel,
                                   ZiDispatcherDomain* dispatcher_domain,
                                   ZiStringView name,
                                   size_t queue_limit,
                                   ZiHandleTable* owner_table,
                                   const ZiAccessToken* owner_token,
                                   const ZiSecurityDescriptor* security_descriptor) {
  ZiStatus status = zi_object_initialise(&channel->object,
                                         &k_channel_type,
                                         name,
                                         NULL,
                                         security_descriptor,
                                         "IPC channel");
  if (ZiFailed(status)) {
    return status;
  }
  status = zi_dispatcher_header_initialise(&channel->dispatcher,
                                           dispatcher_domain,
                                           ZI_DISPATCHER_OBJECT_CHANNEL,
                                           0);
  if (ZiFailed(status)) {
    (void)zi_object_dereference(&channel->object);
    return status;
  }
  channel->peer = NULL;
  channel->owner_table = owner_table;
  channel->owner_token = owner_token;
  for (size_t index = 0; index < ZI_IPC_QUEUE_CAPACITY; ++index) {
    channel->messages[index] = (ZiMessage){0};
  }
  channel->queue_limit = queue_limit;
  channel->queue_head = 0;
  channel->queue_count = 0;
  channel->state = ZI_CHANNEL_OPEN;
  channel->peer_is_closed = 0;
  return ZI_STATUS_SUCCESS;
}

static bool channel_options_are_valid(const ZiIpcChannelPairOptions* options) {
  return (bool)(options != NULL && options->struct_size == sizeof *options &&
                options->version == ZI_IPC_CHANNEL_OPTIONS_VERSION &&
                options->dispatcher_domain != NULL && options->client_name.data != NULL &&
                options->client_name.size != 0 && options->server_name.data != NULL &&
                options->server_name.size != 0 && options->queue_limit != 0 &&
                options->queue_limit <= ZI_IPC_QUEUE_CAPACITY && options->client_table != NULL &&
                options->server_table != NULL &&
                ZiSucceeded(zi_security_token_validate(options->client_token)) &&
                ZiSucceeded(zi_security_token_validate(options->server_token)) &&
                options->client_security != NULL && options->server_security != NULL);
}

static bool message_is_valid(const ZiMessage* message) {
  if (message == NULL || message->struct_size != sizeof *message ||
      message->version != ZI_IPC_MESSAGE_VERSION ||
      message->payload_size > ZI_IPC_INLINE_PAYLOAD_CAPACITY ||
      (message->flags & ~ZI_MESSAGE_TRANSFER_HANDLE) != 0 || message->reserved != 0) {
    return false;
  }
  if ((message->flags & ZI_MESSAGE_TRANSFER_HANDLE) != 0) {
    return (bool)(message->transferred_handle != ZI_INVALID_HANDLE &&
                  message->transferred_access != 0 &&
                  (message->transferred_access & ~ZI_ACCESS_FULL_CONTROL) == 0);
  }
  return (bool)(message->transferred_handle == ZI_INVALID_HANDLE &&
                message->transferred_access == 0);
}

static void copy_message(ZiMessage* destination, const ZiMessage* source) {
  *destination = (ZiMessage){0};
  destination->struct_size = sizeof *destination;
  destination->version = ZI_IPC_MESSAGE_VERSION;
  destination->message_id = source->message_id;
  destination->correlation_id = source->correlation_id;
  destination->message_type = source->message_type;
  destination->flags = source->flags;
  destination->payload_size = source->payload_size;
  destination->transferred_handle = source->transferred_handle;
  destination->transferred_access = source->transferred_access;
  for (size_t index = 0; index < source->payload_size; ++index) {
    destination->inline_payload[index] = source->inline_payload[index];
  }
}

static ZiStatus close_transferred_handle(ZiHandleTable* table, ZiHandle handle) {
  ZiStatus status = zi_handle_close(table, handle);
  return status == ZI_STATUS_INVALID_HANDLE ? ZI_STATUS_SUCCESS : status;
}
