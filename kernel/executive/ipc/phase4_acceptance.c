// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/phase4_acceptance.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/dispatcher.h"
#include "zi/handle.h"
#include "zi/ipc.h"
#include "zi/object.h"
#include "zi/scheduler.h"
#include "zi/security.h"
#include "zi/user_process.h"
#include "zizium/status.h"
#include "zizium/types.h"

static void acceptance_object_destroy(ZiObjectHeader* object);
static void cleanup_object_destroy(ZiObjectHeader* object);
static ZiStatus verify_object_namespace(void);
static ZiStatus verify_handle_access(ZiUserProcess* process);
static ZiStatus verify_wait_objects(ZiUserProcess* process, ZiDispatcherDomain* domain);
static ZiStatus verify_ipc(ZiUserProcess* client,
                           ZiUserProcess* server,
                           ZiDispatcherDomain* domain,
                           uint32_t* completed_mask);
static ZiStatus arm_process_cleanup_check(ZiUserProcess* client, ZiUserProcess* server);
static ZiSecurityDescriptor
make_descriptor(ZiAcl* acl, ZiAce* entries, size_t entry_count, ZiSecurityId owner);
static void
initialise_thread(ZxThread* thread, ZxProcess* process, uint64_t thread_id, uint32_t priority);
static bool payload_is_seed(const ZiMessage* message);

static const ZiObjectOperations k_acceptance_operations = {
    sizeof(ZiObjectOperations),
    ZI_OBJECT_OPERATIONS_VERSION,
    acceptance_object_destroy,
    NULL,
};
static const ZiObjectOperations k_cleanup_operations = {
    sizeof(ZiObjectOperations),
    ZI_OBJECT_OPERATIONS_VERSION,
    cleanup_object_destroy,
    NULL,
};
static const ZiObjectType k_directory_type = {
    UINT32_C(0x53454501),
    {"Directory", sizeof "Directory" - 1u},
    &k_acceptance_operations,
    ZI_OBJECT_TYPE_DIRECTORY,
};
static const ZiObjectType k_acceptance_type = {
    UINT32_C(0x53454502),
    {"SeedAcceptance", sizeof "SeedAcceptance" - 1u},
    &k_acceptance_operations,
    0,
};
static const ZiObjectType k_cleanup_type = {
    UINT32_C(0x53454503),
    {"ProcessCleanup", sizeof "ProcessCleanup" - 1u},
    &k_cleanup_operations,
    0,
};

static ZiObjectHeader s_cleanup_object;
static ZiAce s_cleanup_aces[2];
static ZiAcl s_cleanup_acl;
static ZiSecurityDescriptor s_cleanup_descriptor;
static uint32_t s_cleanup_is_armed;
static uint32_t s_cleanup_destroy_count;

ZiStatus zi_phase4_acceptance_run(ZiUserProcess* client_process,
                                  ZiUserProcess* server_process,
                                  ZiDispatcherDomain* dispatcher_domain,
                                  ZiPhase4AcceptanceResult* out_result) {
  if (client_process == NULL || server_process == NULL || client_process == server_process ||
      dispatcher_domain == NULL || out_result == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_result = (ZiPhase4AcceptanceResult){
      sizeof(ZiPhase4AcceptanceResult),
      ZI_PHASE4_ACCEPTANCE_RESULT_VERSION,
      0,
      0,
  };

  ZiStatus status = verify_object_namespace();
  if (ZiFailed(status)) {
    return status;
  }
  out_result->completed_mask |= ZI_PHASE4_ACCEPTANCE_OBJECT_NAMESPACE;

  status = verify_handle_access(client_process);
  if (ZiFailed(status)) {
    return status;
  }
  out_result->completed_mask |= ZI_PHASE4_ACCEPTANCE_HANDLE_ACCESS;

  status = verify_wait_objects(server_process, dispatcher_domain);
  if (ZiFailed(status)) {
    return status;
  }
  out_result->completed_mask |= ZI_PHASE4_ACCEPTANCE_WAIT_OBJECTS;

  status =
      verify_ipc(client_process, server_process, dispatcher_domain, &out_result->completed_mask);
  if (ZiFailed(status)) {
    return status;
  }
  return arm_process_cleanup_check(client_process, server_process);
}

ZiStatus zi_phase4_acceptance_verify_process_cleanup(void) {
  if (s_cleanup_is_armed == 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  s_cleanup_is_armed = 0;
  if (s_cleanup_object.handle_count != 0 || s_cleanup_object.reference_count != 1 ||
      s_cleanup_object.is_destroyed != 0 || s_cleanup_destroy_count != 0) {
    return ZI_STATUS_RESOURCE_LEAK;
  }
  ZiStatus status = zi_object_dereference(&s_cleanup_object);
  if (ZiFailed(status) || s_cleanup_object.is_destroyed == 0 || s_cleanup_destroy_count != 1) {
    return ZI_STATUS_INVALID_STATE;
  }
  return ZI_STATUS_SUCCESS;
}

static void acceptance_object_destroy(ZiObjectHeader* object) {
  (void)object;
}

static void cleanup_object_destroy(ZiObjectHeader* object) {
  if (object != NULL) {
    ++s_cleanup_destroy_count;
  }
}

// This deliberately exercises the real type registry and exact UTF-8 namespace implementation.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static ZiStatus verify_object_namespace(void) {
  const ZiObjectType* types[2] = {0};
  ZiObjectTypeRegistry registry = {0};
  ZiStatus status = zi_object_type_registry_initialise(&registry, types, 2);
  if (ZiSucceeded(status)) {
    status = zi_object_type_register(&registry, &k_directory_type);
  }
  if (ZiSucceeded(status)) {
    status = zi_object_type_register(&registry, &k_acceptance_type);
  }
  const ZiObjectType* found_type = NULL;
  if (ZiSucceeded(status)) {
    status =
        zi_object_type_find_by_name(&registry,
                                    (ZiStringView){"SeedAcceptance", sizeof "SeedAcceptance" - 1u},
                                    &found_type);
  }
  if (ZiSucceeded(status) && found_type != &k_acceptance_type) {
    status = ZI_STATUS_INVALID_STATE;
  }
  if (ZiSucceeded(status) &&
      zi_object_type_find_by_name(&registry,
                                  (ZiStringView){"seedacceptance", sizeof "seedacceptance" - 1u},
                                  &found_type) != ZI_STATUS_NOT_FOUND) {
    status = ZI_STATUS_CASE_MISMATCH;
  }

  ZiObjectDirectoryEntry root_entries[1] = {0};
  ZiObjectDirectoryEntry system_entries[2] = {0};
  ZiObjectDirectory root = {0};
  ZiObjectDirectory system = {0};
  ZiObjectHeader upper = {0};
  ZiObjectHeader lower = {0};
  bool root_initialised = false;
  bool system_initialised = false;
  bool upper_initialised = false;
  bool lower_initialised = false;
  if (ZiSucceeded(status)) {
    status = zi_object_directory_initialise(&root,
                                            &k_directory_type,
                                            (ZiStringView){NULL, 0},
                                            root_entries,
                                            1,
                                            NULL,
                                            "Phase 4 root namespace");
    root_initialised = ZiSucceeded(status);
  }
  if (ZiSucceeded(status)) {
    status = zi_object_directory_initialise(&system,
                                            &k_directory_type,
                                            (ZiStringView){"System", sizeof "System" - 1u},
                                            system_entries,
                                            2,
                                            NULL,
                                            "Phase 4 system namespace");
    system_initialised = ZiSucceeded(status);
  }
  if (ZiSucceeded(status)) {
    status = zi_object_initialise(&upper,
                                  &k_acceptance_type,
                                  (ZiStringView){"Temp", sizeof "Temp" - 1u},
                                  NULL,
                                  NULL,
                                  "Phase 4 upper-case object");
    upper_initialised = ZiSucceeded(status);
  }
  if (ZiSucceeded(status)) {
    status = zi_object_initialise(&lower,
                                  &k_acceptance_type,
                                  (ZiStringView){"temp", sizeof "temp" - 1u},
                                  NULL,
                                  NULL,
                                  "Phase 4 lower-case object");
    lower_initialised = ZiSucceeded(status);
  }
  if (ZiSucceeded(status)) {
    status = zi_object_directory_insert(&root, &system.header);
  }
  if (ZiSucceeded(status)) {
    status = zi_object_directory_insert(&system, &upper);
  }
  if (ZiSucceeded(status)) {
    status = zi_object_directory_insert(&system, &lower);
  }

  ZiObjectHeader* found = NULL;
  if (ZiSucceeded(status)) {
    status =
        zi_object_namespace_lookup(&root,
                                   (ZiStringView){"\\System\\Temp", sizeof "\\System\\Temp" - 1u},
                                   &found);
    if (ZiSucceeded(status) && found != &upper) {
      status = ZI_STATUS_CASE_MISMATCH;
    }
    if (found != NULL) {
      (void)zi_object_dereference(found);
      found = NULL;
    }
  }
  if (ZiSucceeded(status)) {
    status =
        zi_object_namespace_lookup(&root,
                                   (ZiStringView){"\\System\\temp", sizeof "\\System\\temp" - 1u},
                                   &found);
    if (ZiSucceeded(status) && found != &lower) {
      status = ZI_STATUS_CASE_MISMATCH;
    }
    if (found != NULL) {
      (void)zi_object_dereference(found);
      found = NULL;
    }
  }
  if (ZiSucceeded(status) &&
      zi_object_namespace_lookup(&root,
                                 (ZiStringView){"\\system\\Temp", sizeof "\\system\\Temp" - 1u},
                                 &found) != ZI_STATUS_NOT_FOUND) {
    status = ZI_STATUS_CASE_MISMATCH;
  }

  if (upper.parent == &system.header) {
    (void)zi_object_directory_remove(&system, (ZiStringView){"Temp", sizeof "Temp" - 1u}, NULL);
  }
  if (lower.parent == &system.header) {
    (void)zi_object_directory_remove(&system, (ZiStringView){"temp", sizeof "temp" - 1u}, NULL);
  }
  if (system.header.parent == &root.header) {
    (void)zi_object_directory_remove(&root, (ZiStringView){"System", sizeof "System" - 1u}, NULL);
  }
  if (lower_initialised) {
    (void)zi_object_dereference(&lower);
  }
  if (upper_initialised) {
    (void)zi_object_dereference(&upper);
  }
  if (system_initialised) {
    (void)zi_object_dereference(&system.header);
  }
  if (root_initialised) {
    (void)zi_object_dereference(&root.header);
  }
  return status;
}

static ZiStatus verify_handle_access(ZiUserProcess* process) {
  ZiAce ace = {
      ZI_ACE_ALLOW,
      0,
      0,
      ZI_ACCESS_READ,
      process->token.user,
  };
  ZiAcl acl = {0};
  ZiSecurityDescriptor descriptor = make_descriptor(&acl, &ace, 1, process->token.user);
  ZiObjectHeader object = {0};
  ZiStatus status = zi_object_initialise(&object,
                                         &k_acceptance_type,
                                         (ZiStringView){"Secured", sizeof "Secured" - 1u},
                                         NULL,
                                         &descriptor,
                                         "Phase 4 secured handle object");
  if (ZiFailed(status)) {
    return status;
  }

  ZiHandle first = ZI_INVALID_HANDLE;
  ZiHandle second = ZI_INVALID_HANDLE;
  ZiHandle stale = ZI_INVALID_HANDLE;
  status = zi_handle_open(&process->handle_table, &object, &process->token, ZI_ACCESS_READ, &first);
  ZiObjectHeader* referenced = NULL;
  if (ZiSucceeded(status)) {
    status = zi_handle_lookup(&process->handle_table,
                              first,
                              ZI_ACCESS_WRITE,
                              &k_acceptance_type,
                              &referenced) == ZI_STATUS_ACCESS_DENIED
                 ? ZI_STATUS_SUCCESS
                 : ZI_STATUS_INVALID_STATE;
  }
  if (ZiSucceeded(status)) {
    stale = first;
    status = zi_handle_close(&process->handle_table, first);
    first = ZI_INVALID_HANDLE;
  }
  if (ZiSucceeded(status)) {
    status = zi_handle_lookup(&process->handle_table,
                              stale,
                              ZI_ACCESS_READ,
                              &k_acceptance_type,
                              &referenced) == ZI_STATUS_INVALID_HANDLE
                 ? ZI_STATUS_SUCCESS
                 : ZI_STATUS_INVALID_STATE;
  }
  if (ZiSucceeded(status)) {
    status =
        zi_handle_open(&process->handle_table, &object, &process->token, ZI_ACCESS_READ, &second);
  }
  if (ZiSucceeded(status) && second == stale) {
    status = ZI_STATUS_INVALID_STATE;
  }
  if (second != ZI_INVALID_HANDLE) {
    ZiStatus close_status = zi_handle_close(&process->handle_table, second);
    if (ZiSucceeded(status) && ZiFailed(close_status)) {
      status = close_status;
    }
  }
  if (first != ZI_INVALID_HANDLE) {
    (void)zi_handle_close(&process->handle_table, first);
  }
  ZiStatus dereference_status = zi_object_dereference(&object);
  if (ZiFailed(status)) {
    return status;
  }
  return dereference_status;
}

static ZiStatus verify_wait_objects(ZiUserProcess* process, ZiDispatcherDomain* domain) {
  ZxThread idle = {0};
  ZxThread waiter = {0};
  initialise_thread(&idle, NULL, 0, 0);
  idle.state = ZI_THREAD_RUNNING;
  initialise_thread(&waiter, &process->executive_process, UINT64_C(0x53454544), 8);
  ZxScheduler scheduler = {0};
  zi_scheduler_initialise(&scheduler, 0, &idle);
  ZxEvent event = {0};
  ZiStatus status = zi_event_initialise(&event, domain, ZI_EVENT_SYNCHRONISATION, false);
  ZiWaitOperation operation = {0};
  ZxWaitBlock block = {0};
  ZxDispatcherHeader* objects[] = {&event.header};
  if (ZiSucceeded(status)) {
    status =
        zi_dispatcher_wait(&operation, &block, objects, 1, ZI_WAIT_ANY, 21, 0, &scheduler, &waiter);
    if (status != ZI_STATUS_PENDING) {
      status = ZI_STATUS_INVALID_STATE;
    }
  }
  if (status == ZI_STATUS_INVALID_STATE) {
    return status;
  }
  status = zi_event_set(&event);
  if (ZiSucceeded(status) && (waiter.state != ZI_THREAD_READY || waiter.is_queued == 0 ||
                              event.header.signal_state != 0)) {
    status = ZI_STATUS_INVALID_STATE;
  }
  if (waiter.is_queued != 0) {
    ZiStatus remove_status = zi_scheduler_remove(&scheduler, &waiter);
    if (ZiSucceeded(status) && ZiFailed(remove_status)) {
      status = remove_status;
    }
  }
  return status;
}

// This boot acceptance is intentionally bounded; exhaustive malformed-input coverage is host-side.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static ZiStatus verify_ipc(ZiUserProcess* client,
                           ZiUserProcess* server,
                           ZiDispatcherDomain* domain,
                           uint32_t* completed_mask) {
  ZiAce entries[2] = {
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_READ | ZI_ACCESS_WRITE, client->token.user},
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_READ | ZI_ACCESS_WRITE, server->token.user},
  };
  ZiAcl acl = {0};
  ZiSecurityDescriptor descriptor = make_descriptor(&acl, entries, 2, client->token.user);
  ZiPort port = {0};
  ZiChannel client_channel = {0};
  ZiChannel server_channel = {0};
  ZiSharedSection section = {0};
  bool port_initialised = false;
  bool channels_initialised = false;
  bool section_initialised = false;
  ZiHandle source_handle = ZI_INVALID_HANDLE;
  ZiHandle received_handle = ZI_INVALID_HANDLE;
  size_t client_handles_before = client->handle_table.active_count;
  size_t server_handles_before = server->handle_table.active_count;

  ZiStatus status = zi_ipc_port_initialise(&port,
                                           domain,
                                           (ZiStringView){"SeedPort", sizeof "SeedPort" - 1u},
                                           1,
                                           &descriptor);
  port_initialised = ZiSucceeded(status);
  ZiIpcChannelPairOptions options = {
      sizeof(ZiIpcChannelPairOptions),
      ZI_IPC_CHANNEL_OPTIONS_VERSION,
      domain,
      {"SeedClient", sizeof "SeedClient" - 1u},
      {"SeedServer", sizeof "SeedServer" - 1u},
      2,
      &client->handle_table,
      &server->handle_table,
      &client->token,
      &server->token,
      &descriptor,
      &descriptor,
  };
  if (ZiSucceeded(status)) {
    status = zi_ipc_connect(&port, &options, &client_channel, &server_channel);
    channels_initialised = ZiSucceeded(status);
  }
  ZiChannel* accepted = NULL;
  if (ZiSucceeded(status)) {
    status = zi_ipc_accept(&port, &accepted);
    if (ZiSucceeded(status) && accepted != &server_channel) {
      status = ZI_STATUS_INVALID_STATE;
    }
    if (accepted != NULL) {
      (void)zi_object_dereference(&accepted->object);
    }
  }

  ZxThread idle = {0};
  ZxThread receiver = {0};
  initialise_thread(&idle, NULL, 0, 0);
  idle.state = ZI_THREAD_RUNNING;
  initialise_thread(&receiver, &server->executive_process, UINT64_C(0x495043), 8);
  ZxScheduler scheduler = {0};
  zi_scheduler_initialise(&scheduler, 0, &idle);
  ZiWaitOperation wait = {0};
  ZxWaitBlock wait_block = {0};
  ZxDispatcherHeader* wait_objects[] = {&server_channel.dispatcher};
  if (ZiSucceeded(status)) {
    status = zi_dispatcher_wait(&wait,
                                &wait_block,
                                wait_objects,
                                1,
                                ZI_WAIT_ANY,
                                21,
                                0,
                                &scheduler,
                                &receiver);
    if (status != ZI_STATUS_PENDING) {
      status = ZI_STATUS_INVALID_STATE;
    }
  }

  ZiMessage message = {0};
  message.struct_size = sizeof message;
  message.version = ZI_IPC_MESSAGE_VERSION;
  message.message_id = 21;
  message.message_type = 1;
  message.payload_size = 4;
  message.inline_payload[0] = 'S';
  message.inline_payload[1] = 'e';
  message.inline_payload[2] = 'e';
  message.inline_payload[3] = 'd';
  if (status == ZI_STATUS_PENDING) {
    status = zi_ipc_send(&client_channel, &message);
  }
  if (ZiSucceeded(status) && receiver.is_queued != 0) {
    status = zi_scheduler_remove(&scheduler, &receiver);
  }
  ZiMessage received = {0};
  if (ZiSucceeded(status)) {
    status = zi_ipc_receive(&server_channel, &received);
  }
  if (ZiSucceeded(status) && !payload_is_seed(&received)) {
    status = ZI_STATUS_INVALID_MESSAGE;
  }
  if (ZiSucceeded(status)) {
    *completed_mask |= ZI_PHASE4_ACCEPTANCE_IPC_EXCHANGE;
  }

  unsigned char backing[64] = {0};
  if (ZiSucceeded(status)) {
    status = zi_ipc_shared_section_initialise(&section,
                                              (ZiStringView){"Shared", sizeof "Shared" - 1u},
                                              backing,
                                              sizeof backing,
                                              ZI_ACCESS_READ,
                                              &descriptor);
    section_initialised = ZiSucceeded(status);
  }
  if (ZiSucceeded(status)) {
    status = zi_ipc_shared_section_open(&section,
                                        &client->handle_table,
                                        &client->token,
                                        ZI_ACCESS_READ,
                                        &source_handle);
  }
  message.flags = ZI_MESSAGE_TRANSFER_HANDLE;
  message.transferred_handle = source_handle;
  message.transferred_access = ZI_ACCESS_READ;
  if (ZiSucceeded(status)) {
    status = zi_ipc_send(&client_channel, &message);
  }
  if (ZiSucceeded(status)) {
    status = zi_ipc_receive(&server_channel, &received);
    received_handle = received.transferred_handle;
  }
  ZiObjectHeader* transferred = NULL;
  if (ZiSucceeded(status)) {
    status = zi_handle_lookup(&server->handle_table,
                              received_handle,
                              ZI_ACCESS_READ,
                              zi_ipc_shared_section_object_type(),
                              &transferred);
  }
  if (ZiSucceeded(status) && transferred != &section.object) {
    status = ZI_STATUS_INVALID_STATE;
  }
  if (transferred != NULL) {
    (void)zi_object_dereference(transferred);
  }
  if (ZiSucceeded(status) && zi_handle_lookup(&server->handle_table,
                                              received_handle,
                                              ZI_ACCESS_WRITE,
                                              zi_ipc_shared_section_object_type(),
                                              &transferred) != ZI_STATUS_ACCESS_DENIED) {
    status = ZI_STATUS_INVALID_STATE;
  }
  if (received_handle != ZI_INVALID_HANDLE) {
    ZiStatus close_status = zi_handle_close(&server->handle_table, received_handle);
    if (ZiSucceeded(status) && ZiFailed(close_status)) {
      status = close_status;
    }
  }
  if (ZiSucceeded(status)) {
    *completed_mask |= ZI_PHASE4_ACCEPTANCE_HANDLE_TRANSFER;
    status = zi_ipc_send(&client_channel, &message);
  }
  if (ZiSucceeded(status) && server->handle_table.active_count != server_handles_before + 1u) {
    status = ZI_STATUS_RESOURCE_LEAK;
  }
  if (channels_initialised) {
    ZiStatus close_status = zi_ipc_channel_close(&server_channel);
    if (ZiSucceeded(status) && ZiFailed(close_status)) {
      status = close_status;
    }
  }
  if (ZiSucceeded(status) && server->handle_table.active_count != server_handles_before) {
    status = ZI_STATUS_RESOURCE_LEAK;
  }
  if (source_handle != ZI_INVALID_HANDLE) {
    ZiStatus close_status = zi_handle_close(&client->handle_table, source_handle);
    if (ZiSucceeded(status) && ZiFailed(close_status)) {
      status = close_status;
    }
  }
  if (channels_initialised) {
    (void)zi_ipc_channel_close(&client_channel);
    (void)zi_object_dereference(&client_channel.object);
    (void)zi_object_dereference(&server_channel.object);
  }
  if (port_initialised) {
    (void)zi_ipc_port_close(&port);
    (void)zi_object_dereference(&port.object);
  }
  if (section_initialised) {
    (void)zi_object_dereference(&section.object);
  }
  if (client->handle_table.active_count != client_handles_before ||
      server->handle_table.active_count != server_handles_before) {
    return ZI_STATUS_RESOURCE_LEAK;
  }
  return status;
}

static ZiStatus arm_process_cleanup_check(ZiUserProcess* client, ZiUserProcess* server) {
  if (s_cleanup_is_armed != 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  s_cleanup_aces[0] = (ZiAce){
      ZI_ACE_ALLOW,
      0,
      0,
      ZI_ACCESS_READ,
      client->token.user,
  };
  s_cleanup_aces[1] = (ZiAce){
      ZI_ACE_ALLOW,
      0,
      0,
      ZI_ACCESS_READ,
      server->token.user,
  };
  s_cleanup_descriptor = make_descriptor(&s_cleanup_acl, s_cleanup_aces, 2, client->token.user);
  s_cleanup_destroy_count = 0;
  ZiStatus status =
      zi_object_initialise(&s_cleanup_object,
                           &k_cleanup_type,
                           (ZiStringView){"ProcessCleanup", sizeof "ProcessCleanup" - 1u},
                           NULL,
                           &s_cleanup_descriptor,
                           "Phase 4 process cleanup sentinel");
  if (ZiFailed(status)) {
    return status;
  }
  ZiHandle client_handle = ZI_INVALID_HANDLE;
  ZiHandle server_handle = ZI_INVALID_HANDLE;
  status = zi_handle_open(&client->handle_table,
                          &s_cleanup_object,
                          &client->token,
                          ZI_ACCESS_READ,
                          &client_handle);
  if (ZiSucceeded(status)) {
    status = zi_handle_open(&server->handle_table,
                            &s_cleanup_object,
                            &server->token,
                            ZI_ACCESS_READ,
                            &server_handle);
  }
  if (ZiFailed(status)) {
    if (server_handle != ZI_INVALID_HANDLE) {
      (void)zi_handle_close(&server->handle_table, server_handle);
    }
    if (client_handle != ZI_INVALID_HANDLE) {
      (void)zi_handle_close(&client->handle_table, client_handle);
    }
    (void)zi_object_dereference(&s_cleanup_object);
    return status;
  }
  s_cleanup_is_armed = 1;
  return ZI_STATUS_SUCCESS;
}

static ZiSecurityDescriptor
make_descriptor(ZiAcl* acl, ZiAce* entries, size_t entry_count, ZiSecurityId owner) {
  *acl = (ZiAcl){
      sizeof(ZiAcl),
      ZI_ACL_VERSION,
      entries,
      entry_count,
  };
  return (ZiSecurityDescriptor){
      sizeof(ZiSecurityDescriptor),
      ZI_SECURITY_DESCRIPTOR_VERSION,
      owner,
      {ZI_SECURITY_AUTHORITY_GROUP, 1},
      acl,
      0,
  };
}

static void
initialise_thread(ZxThread* thread, ZxProcess* process, uint64_t thread_id, uint32_t priority) {
  *thread = (ZxThread){0};
  thread->thread_id = thread_id;
  thread->process = process;
  thread->affinity_mask = UINT64_MAX;
  thread->priority = priority;
  thread->base_priority = priority;
  thread->quantum = ZI_SCHEDULER_DEFAULT_QUANTUM;
  thread->quantum_remaining = ZI_SCHEDULER_DEFAULT_QUANTUM;
  thread->state = ZI_THREAD_INITIALISED;
  thread->scheduler_class = priority == 0 ? ZI_SCHEDULER_CLASS_IDLE : ZI_SCHEDULER_CLASS_NORMAL;
}

static bool payload_is_seed(const ZiMessage* message) {
  return (bool)(message != NULL && message->message_id == 21 && message->payload_size == 4 &&
                message->inline_payload[0] == 'S' && message->inline_payload[1] == 'e' &&
                message->inline_payload[2] == 'e' && message->inline_payload[3] == 'd');
}
