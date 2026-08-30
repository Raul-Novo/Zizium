// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "phase4_tests.h"
#include "zi/dispatcher.h"
#include "zi/handle.h"
#include "zi/ipc.h"
#include "zi/object.h"
#include "zi/scheduler.h"
#include "zi/security.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define PHASE4_ASSERT(expression)                                                                  \
  do {                                                                                             \
    ++assertions;                                                                                  \
    if (!(expression)) {                                                                           \
      (void)fprintf_s(stderr, "%s:%d: assertion failed: %s\n", __FILE__, __LINE__, #expression);   \
      *out_assertion_count = assertions;                                                           \
      return false;                                                                                \
    }                                                                                              \
  } while (false)

static size_t s_destroy_count;

static void count_destroy(ZiObjectHeader* object);
static void no_destroy(ZiObjectHeader* object);
static ZiAccessToken make_token(uint32_t user_value);
static ZiSecurityDescriptor
make_descriptor(const ZiAce* entries, size_t entry_count, ZiAcl* out_acl);
static void initialise_thread(ZxThread* thread, uint64_t id, uint32_t priority);
static bool bytes_equal(const unsigned char* left, const unsigned char* right, size_t size);

// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
bool phase4_object_namespace_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  size_t assertions = 0;
  *out_assertion_count = 0;
  const ZiObjectOperations operations = {sizeof(ZiObjectOperations),
                                         ZI_OBJECT_OPERATIONS_VERSION,
                                         no_destroy,
                                         NULL};
  const ZiObjectType directory_type = {1, {"Directory", 9}, &operations, ZI_OBJECT_TYPE_DIRECTORY};
  const ZiObjectType object_type = {2, {"Object", 6}, &operations, 0};
  const ZiObjectType case_type = {3, {"object", 6}, &operations, 0};
  const ZiObjectType duplicate_id = {2, {"Alternate", 9}, &operations, 0};
  const ZiObjectType duplicate_name = {4, {"Object", 6}, &operations, 0};
  const ZiObjectType* type_storage[4] = {0};
  ZiObjectTypeRegistry registry = {0};
  PHASE4_ASSERT(ZiSucceeded(zi_object_type_registry_initialise(&registry, type_storage, 4)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_type_register(&registry, &directory_type)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_type_register(&registry, &object_type)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_type_register(&registry, &case_type)));
  PHASE4_ASSERT(zi_object_type_register(&registry, &duplicate_id) == ZI_STATUS_ALREADY_EXISTS);
  PHASE4_ASSERT(zi_object_type_register(&registry, &duplicate_name) == ZI_STATUS_ALREADY_EXISTS);
  const ZiObjectType* found_type = NULL;
  PHASE4_ASSERT(ZiSucceeded(zi_object_type_find_by_id(&registry, 2, &found_type)) &&
                found_type == &object_type);
  PHASE4_ASSERT(
      ZiSucceeded(
          zi_object_type_find_by_name(&registry, (ZiStringView){"object", 6}, &found_type)) &&
      found_type == &case_type);
  PHASE4_ASSERT(zi_object_type_find_by_name(&registry, (ZiStringView){"OBJECT", 6}, &found_type) ==
                ZI_STATUS_NOT_FOUND);

  ZiObjectDirectoryEntry root_entries[3] = {0};
  ZiObjectDirectoryEntry system_entries[3] = {0};
  ZiObjectDirectory root = {0};
  ZiObjectDirectory system = {0};
  ZiObjectHeader upper = {0};
  ZiObjectHeader lower = {0};
  PHASE4_ASSERT(ZiSucceeded(zi_object_directory_initialise(&root,
                                                           &directory_type,
                                                           (ZiStringView){NULL, 0},
                                                           root_entries,
                                                           3,
                                                           NULL,
                                                           "root namespace")));
  PHASE4_ASSERT(ZiSucceeded(zi_object_directory_initialise(&system,
                                                           &directory_type,
                                                           (ZiStringView){"System", 6},
                                                           system_entries,
                                                           3,
                                                           NULL,
                                                           "system namespace")));
  PHASE4_ASSERT(ZiSucceeded(zi_object_initialise(&upper,
                                                 &object_type,
                                                 (ZiStringView){"Temp", 4},
                                                 NULL,
                                                 NULL,
                                                 "upper-case object")));
  PHASE4_ASSERT(ZiSucceeded(zi_object_initialise(&lower,
                                                 &object_type,
                                                 (ZiStringView){"temp", 4},
                                                 NULL,
                                                 NULL,
                                                 "lower-case object")));
  PHASE4_ASSERT(ZiSucceeded(zi_object_directory_insert(&root, &system.header)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_directory_insert(&system, &upper)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_directory_insert(&system, &lower)));
  PHASE4_ASSERT(zi_object_directory_insert(&system, &upper) == ZI_STATUS_ALREADY_EXISTS);

  ZiObjectHeader* found = NULL;
  PHASE4_ASSERT(
      ZiSucceeded(
          zi_object_namespace_lookup(&root, (ZiStringView){"\\System\\Temp", 12}, &found)) &&
      found == &upper);
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(found)));
  PHASE4_ASSERT(
      ZiSucceeded(
          zi_object_namespace_lookup(&root, (ZiStringView){"\\System\\temp", 12}, &found)) &&
      found == &lower);
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(found)));
  PHASE4_ASSERT(zi_object_namespace_lookup(&root, (ZiStringView){"\\system\\Temp", 12}, &found) ==
                ZI_STATUS_NOT_FOUND);
  PHASE4_ASSERT(zi_object_namespace_lookup(&root, (ZiStringView){"\\System\\\\Temp", 13}, &found) ==
                ZI_STATUS_INVALID_PATH);
  PHASE4_ASSERT(zi_object_namespace_lookup(&root, (ZiStringView){"\\System\\Temp\\", 13}, &found) ==
                ZI_STATUS_INVALID_PATH);
  const char invalid_path[] = {'\\', 'S', (char)0xc0, (char)0xaf};
  PHASE4_ASSERT(zi_object_namespace_lookup(&root,
                                           (ZiStringView){invalid_path, sizeof invalid_path},
                                           &found) == ZI_STATUS_INVALID_PATH);

  ZiObjectHeader* removed = NULL;
  PHASE4_ASSERT(
      ZiSucceeded(zi_object_directory_remove(&system, (ZiStringView){"Temp", 4}, &removed)) &&
      removed == &upper && upper.parent == NULL);
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(removed)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_directory_remove(&system, (ZiStringView){"temp", 4}, NULL)));
  PHASE4_ASSERT(
      ZiSucceeded(zi_object_directory_remove(&root, (ZiStringView){"System", 6}, &removed)) &&
      removed == &system.header);
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(removed)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(&upper)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(&lower)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(&system.header)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(&root.header)));

  *out_assertion_count = assertions;
  return true;
}

// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
bool phase4_handle_table_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  size_t assertions = 0;
  *out_assertion_count = 0;
  s_destroy_count = 0;
  const ZiObjectOperations operations = {sizeof(ZiObjectOperations),
                                         ZI_OBJECT_OPERATIONS_VERSION,
                                         count_destroy,
                                         NULL};
  const ZiObjectType type = {21, {"HandleObject", 12}, &operations, 0};
  const ZiObjectType wrong_type = {22, {"WrongObject", 11}, &operations, 0};
  ZiAccessToken owner_token = make_token(21);
  ZiAccessToken other_token = make_token(22);
  const ZiAce entries[] = {
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_READ | ZI_ACCESS_WRITE, {ZI_SECURITY_AUTHORITY_USER, 21}},
  };
  ZiAcl acl = {0};
  ZiSecurityDescriptor descriptor = make_descriptor(entries, 1, &acl);
  ZiObjectHeader object = {0};
  PHASE4_ASSERT(ZiSucceeded(zi_object_initialise(&object,
                                                 &type,
                                                 (ZiStringView){"Secured", 7},
                                                 NULL,
                                                 &descriptor,
                                                 "secured handle object")));
  ZiHandleTableEntry owner_entries[2] = {0};
  ZiHandleTableEntry target_entries[2] = {0};
  ZiHandleTable owner_table = {0};
  ZiHandleTable target_table = {0};
  PHASE4_ASSERT(ZiSucceeded(zi_handle_table_initialise(&owner_table, owner_entries, 2)));
  PHASE4_ASSERT(ZiSucceeded(zi_handle_table_initialise(&target_table, target_entries, 2)));

  ZiHandle read_handle = ZI_INVALID_HANDLE;
  PHASE4_ASSERT(ZiSucceeded(
      zi_handle_open(&owner_table, &object, &owner_token, ZI_ACCESS_READ, &read_handle)));
  PHASE4_ASSERT(read_handle != ZI_INVALID_HANDLE && object.handle_count == 1);
  ZiObjectHeader* referenced = NULL;
  PHASE4_ASSERT(
      ZiSucceeded(
          zi_handle_lookup(&owner_table, read_handle, ZI_ACCESS_READ, &type, &referenced)) &&
      referenced == &object);
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(referenced)));
  PHASE4_ASSERT(zi_handle_lookup(&owner_table, read_handle, ZI_ACCESS_WRITE, &type, &referenced) ==
                ZI_STATUS_ACCESS_DENIED);
  PHASE4_ASSERT(
      zi_handle_lookup(&owner_table, read_handle, ZI_ACCESS_READ, &wrong_type, &referenced) ==
      ZI_STATUS_INVALID_HANDLE);
  ZiHandle denied_handle = ZI_INVALID_HANDLE;
  PHASE4_ASSERT(
      zi_handle_open(&target_table, &object, &other_token, ZI_ACCESS_READ, &denied_handle) ==
      ZI_STATUS_ACCESS_DENIED);

  ZiHandle duplicate = ZI_INVALID_HANDLE;
  PHASE4_ASSERT(ZiSucceeded(zi_handle_duplicate(&owner_table,
                                                read_handle,
                                                &target_table,
                                                &owner_token,
                                                ZI_ACCESS_READ,
                                                0,
                                                &duplicate)));
  PHASE4_ASSERT(zi_handle_duplicate(&owner_table,
                                    read_handle,
                                    &target_table,
                                    &owner_token,
                                    ZI_ACCESS_WRITE,
                                    0,
                                    &denied_handle) == ZI_STATUS_ACCESS_DENIED);
  PHASE4_ASSERT(ZiSucceeded(zi_handle_close(&owner_table, read_handle)));
  PHASE4_ASSERT(zi_handle_lookup(&owner_table, read_handle, ZI_ACCESS_READ, &type, &referenced) ==
                ZI_STATUS_INVALID_HANDLE);

  ZiHandle replacement = ZI_INVALID_HANDLE;
  PHASE4_ASSERT(ZiSucceeded(
      zi_handle_open(&owner_table, &object, &owner_token, ZI_ACCESS_READ, &replacement)));
  PHASE4_ASSERT(replacement != read_handle);
  ZiHandle second = ZI_INVALID_HANDLE;
  PHASE4_ASSERT(
      ZiSucceeded(zi_handle_open(&owner_table, &object, &owner_token, ZI_ACCESS_WRITE, &second)));
  PHASE4_ASSERT(
      zi_handle_open(&owner_table, &object, &owner_token, ZI_ACCESS_READ, &denied_handle) ==
      ZI_STATUS_HANDLE_TABLE_FULL);
  PHASE4_ASSERT(ZiSucceeded(zi_handle_close(&target_table, duplicate)));

  ZiHandleTableEntry retirement_entries[1] = {0};
  ZiHandleTable retirement_table = {0};
  PHASE4_ASSERT(ZiSucceeded(zi_handle_table_initialise(&retirement_table, retirement_entries, 1)));
  retirement_entries[0].generation = UINT32_MAX;
  ZiHandle retirement_handle = ZI_INVALID_HANDLE;
  PHASE4_ASSERT(ZiSucceeded(zi_handle_open(&retirement_table,
                                           &object,
                                           &owner_token,
                                           ZI_ACCESS_READ,
                                           &retirement_handle)) &&
                (uint32_t)(retirement_handle >> 32u) == UINT32_MAX);
  PHASE4_ASSERT(ZiSucceeded(zi_handle_close(&retirement_table, retirement_handle)) &&
                retirement_entries[0].generation == 0);
  PHASE4_ASSERT(zi_handle_open(&retirement_table,
                               &object,
                               &owner_token,
                               ZI_ACCESS_READ,
                               &retirement_handle) == ZI_STATUS_HANDLE_TABLE_FULL);

  PHASE4_ASSERT(ZiSucceeded(zi_handle_table_close_all(&owner_table)) &&
                owner_table.active_count == 0);
  PHASE4_ASSERT(
      zi_handle_open(&owner_table, &object, &owner_token, ZI_ACCESS_READ, &denied_handle) ==
      ZI_STATUS_PROCESS_TERMINATED);
  PHASE4_ASSERT(zi_handle_lookup(&owner_table, replacement, ZI_ACCESS_READ, &type, &referenced) ==
                ZI_STATUS_PROCESS_TERMINATED);
  PHASE4_ASSERT(zi_handle_close(&owner_table, replacement) == ZI_STATUS_INVALID_HANDLE);
  PHASE4_ASSERT(object.handle_count == 0 && object.reference_count == 1);
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(&object)) && s_destroy_count == 1);
  PHASE4_ASSERT(zi_object_dereference(&object) == ZI_STATUS_INVALID_STATE && s_destroy_count == 1);

  *out_assertion_count = assertions;
  return true;
}

// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
bool phase4_dispatcher_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  size_t assertions = 0;
  *out_assertion_count = 0;
  ZiDispatcherDomain domain = {0};
  zi_dispatcher_domain_initialise(&domain);
  ZxThread idle = {0};
  initialise_thread(&idle, 0, 0);
  idle.state = ZI_THREAD_RUNNING;
  ZxScheduler scheduler = {0};
  zi_scheduler_initialise(&scheduler, 0, &idle);
  ZxThread waiter = {0};
  initialise_thread(&waiter, 1, 8);

  ZxEvent event = {0};
  PHASE4_ASSERT(ZiSucceeded(zi_event_initialise(&event, &domain, ZI_EVENT_SYNCHRONISATION, false)));
  ZiWaitOperation operation = {0};
  ZxWaitBlock block = {0};
  ZxDispatcherHeader* objects[] = {&event.header};
  PHASE4_ASSERT(zi_dispatcher_wait(&operation,
                                   &block,
                                   objects,
                                   1,
                                   ZI_WAIT_ANY,
                                   20,
                                   100,
                                   &scheduler,
                                   &waiter) == ZI_STATUS_PENDING);
  PHASE4_ASSERT(waiter.state == ZI_THREAD_WAITING && event.header.waiters == &block);
  uint32_t index = ZI_WAIT_INDEX_NONE;
  PHASE4_ASSERT(zi_dispatcher_query_wait(&operation, &index) == ZI_STATUS_PENDING);
  PHASE4_ASSERT(ZiSucceeded(zi_event_set(&event)) && waiter.state == ZI_THREAD_READY &&
                waiter.is_queued != 0 && event.header.signal_state == 0);
  PHASE4_ASSERT(ZiSucceeded(zi_dispatcher_query_wait(&operation, &index)) && index == 0);
  PHASE4_ASSERT(ZiSucceeded(zi_scheduler_remove(&scheduler, &waiter)));
  waiter.state = ZI_THREAD_RUNNING;

  PHASE4_ASSERT(zi_dispatcher_wait(&operation,
                                   &block,
                                   objects,
                                   1,
                                   ZI_WAIT_ANY,
                                   5,
                                   200,
                                   &scheduler,
                                   &waiter) == ZI_STATUS_PENDING);
  PHASE4_ASSERT(zi_dispatcher_expire_wait(&operation, 204) == ZI_STATUS_PENDING);
  PHASE4_ASSERT(zi_dispatcher_expire_wait(&operation, 205) == ZI_STATUS_TIMEOUT);
  PHASE4_ASSERT(zi_dispatcher_query_wait(&operation, &index) == ZI_STATUS_TIMEOUT &&
                waiter.state == ZI_THREAD_READY);
  PHASE4_ASSERT(ZiSucceeded(zi_scheduler_remove(&scheduler, &waiter)));
  waiter.state = ZI_THREAD_RUNNING;
  PHASE4_ASSERT(zi_dispatcher_wait(&operation,
                                   &block,
                                   objects,
                                   1,
                                   ZI_WAIT_ANY,
                                   UINT64_MAX,
                                   0,
                                   &scheduler,
                                   &waiter) == ZI_STATUS_PENDING);
  PHASE4_ASSERT(zi_dispatcher_cancel_wait(&operation) == ZI_STATUS_CANCELLED);
  PHASE4_ASSERT(zi_dispatcher_query_wait(&operation, &index) == ZI_STATUS_CANCELLED);
  PHASE4_ASSERT(ZiSucceeded(zi_scheduler_remove(&scheduler, &waiter)));
  waiter.state = ZI_THREAD_RUNNING;

  ZxEvent first = {0};
  ZxEvent second_event = {0};
  PHASE4_ASSERT(ZiSucceeded(zi_event_initialise(&first, &domain, ZI_EVENT_SYNCHRONISATION, true)));
  PHASE4_ASSERT(
      ZiSucceeded(zi_event_initialise(&second_event, &domain, ZI_EVENT_SYNCHRONISATION, false)));
  ZxDispatcherHeader* all_objects[] = {&first.header, &second_event.header};
  ZxWaitBlock all_blocks[2] = {0};
  ZxDispatcherHeader* duplicate_objects[] = {&first.header, &first.header};
  PHASE4_ASSERT(zi_dispatcher_wait(&operation,
                                   all_blocks,
                                   duplicate_objects,
                                   2,
                                   ZI_WAIT_ALL,
                                   10,
                                   0,
                                   &scheduler,
                                   &waiter) == ZI_STATUS_INVALID_ARGUMENT);
  PHASE4_ASSERT(zi_dispatcher_wait(&operation,
                                   all_blocks,
                                   all_objects,
                                   (size_t)UINT32_MAX + 1u,
                                   ZI_WAIT_ALL,
                                   10,
                                   0,
                                   &scheduler,
                                   &waiter) == ZI_STATUS_INVALID_ARGUMENT);
  PHASE4_ASSERT(zi_dispatcher_wait(&operation,
                                   all_blocks,
                                   all_objects,
                                   2,
                                   ZI_WAIT_ALL,
                                   10,
                                   0,
                                   &scheduler,
                                   &waiter) == ZI_STATUS_PENDING);
  PHASE4_ASSERT(ZiSucceeded(zi_event_set(&second_event)) && waiter.state == ZI_THREAD_READY &&
                first.header.signal_state == 0 && second_event.header.signal_state == 0);
  PHASE4_ASSERT(ZiSucceeded(zi_scheduler_remove(&scheduler, &waiter)));
  waiter.state = ZI_THREAD_RUNNING;

  ZxSemaphore semaphore = {0};
  PHASE4_ASSERT(ZiSucceeded(zi_semaphore_initialise(&semaphore, &domain, 1, 2)));
  ZxDispatcherHeader* semaphore_object[] = {&semaphore.header};
  PHASE4_ASSERT(ZiSucceeded(zi_dispatcher_wait(&operation,
                                               &block,
                                               semaphore_object,
                                               1,
                                               ZI_WAIT_ANY,
                                               0,
                                               0,
                                               &scheduler,
                                               &waiter)) &&
                semaphore.header.signal_state == 0);
  PHASE4_ASSERT(zi_dispatcher_wait(&operation,
                                   &block,
                                   semaphore_object,
                                   1,
                                   ZI_WAIT_ANY,
                                   0,
                                   0,
                                   &scheduler,
                                   &waiter) == ZI_STATUS_TIMEOUT);
  uint32_t previous_count = UINT32_MAX;
  PHASE4_ASSERT(ZiSucceeded(zi_semaphore_release(&semaphore, 2, &previous_count)) &&
                previous_count == 0 && semaphore.header.signal_state == 2);
  PHASE4_ASSERT(zi_semaphore_release(&semaphore, 1, NULL) == ZI_STATUS_OUT_OF_BOUNDS);

  ZxMutex mutex = {0};
  PHASE4_ASSERT(ZiSucceeded(zi_mutex_initialise(&mutex, &domain)));
  ZxThread low = {0};
  ZxThread high = {0};
  initialise_thread(&low, 2, 4);
  initialise_thread(&high, 3, 12);
  ZxDispatcherHeader* mutex_object[] = {&mutex.header};
  PHASE4_ASSERT(ZiSucceeded(zi_dispatcher_wait(&operation,
                                               &block,
                                               mutex_object,
                                               1,
                                               ZI_WAIT_ANY,
                                               0,
                                               0,
                                               &scheduler,
                                               &low)) &&
                mutex.owner == &low && mutex.recursion_count == 1);
  ZiWaitOperation high_operation = {0};
  ZxWaitBlock high_block = {0};
  PHASE4_ASSERT(zi_dispatcher_wait(&high_operation,
                                   &high_block,
                                   mutex_object,
                                   1,
                                   ZI_WAIT_ANY,
                                   10,
                                   0,
                                   &scheduler,
                                   &high) == ZI_STATUS_PENDING);
  PHASE4_ASSERT(low.priority == 12);
  PHASE4_ASSERT(ZiSucceeded(zi_mutex_release(&mutex, &low)) && low.priority == low.base_priority &&
                mutex.owner == &high && high.state == ZI_THREAD_READY);
  PHASE4_ASSERT(ZiSucceeded(zi_scheduler_remove(&scheduler, &high)));
  high.state = ZI_THREAD_RUNNING;
  PHASE4_ASSERT(ZiSucceeded(zi_mutex_release(&mutex, &high)) && mutex.owner == NULL);
  PHASE4_ASSERT(zi_mutex_release(&mutex, &low) == ZI_STATUS_ACCESS_DENIED);

  ZxTimer timer = {0};
  PHASE4_ASSERT(ZiSucceeded(zi_timer_initialise(&timer, &domain)));
  PHASE4_ASSERT(ZiSucceeded(zi_timer_set(&timer, 50, 10, 40)));
  ZxDispatcherHeader* timer_object[] = {&timer.header};
  waiter.state = ZI_THREAD_RUNNING;
  PHASE4_ASSERT(zi_dispatcher_wait(&operation,
                                   &block,
                                   timer_object,
                                   1,
                                   ZI_WAIT_ANY,
                                   20,
                                   40,
                                   &scheduler,
                                   &waiter) == ZI_STATUS_PENDING);
  PHASE4_ASSERT(zi_timer_tick(&timer, 49) == ZI_STATUS_PENDING);
  PHASE4_ASSERT(ZiSucceeded(zi_timer_tick(&timer, 50)) && waiter.state == ZI_THREAD_READY &&
                timer.is_active != 0 && timer.due_time == 60);
  PHASE4_ASSERT(ZiSucceeded(zi_scheduler_remove(&scheduler, &waiter)));
  PHASE4_ASSERT(ZiSucceeded(zi_timer_cancel(&timer)) && timer.is_active == 0);

  *out_assertion_count = assertions;
  return true;
}

// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
bool phase4_ipc_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  size_t assertions = 0;
  *out_assertion_count = 0;
  ZiAccessToken client_token = make_token(31);
  ZiAccessToken server_token = make_token(32);
  const ZiAce entries[] = {
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_READ | ZI_ACCESS_WRITE, {ZI_SECURITY_AUTHORITY_USER, 31}},
      {ZI_ACE_ALLOW, 0, 0, ZI_ACCESS_READ | ZI_ACCESS_WRITE, {ZI_SECURITY_AUTHORITY_USER, 32}},
  };
  ZiAcl acl = {0};
  ZiSecurityDescriptor descriptor = make_descriptor(entries, 2, &acl);
  ZiHandleTableEntry client_entries[8] = {0};
  ZiHandleTableEntry server_entries[8] = {0};
  ZiHandleTable client_table = {0};
  ZiHandleTable server_table = {0};
  PHASE4_ASSERT(ZiSucceeded(zi_handle_table_initialise(&client_table, client_entries, 8)));
  PHASE4_ASSERT(ZiSucceeded(zi_handle_table_initialise(&server_table, server_entries, 8)));
  ZiDispatcherDomain domain = {0};
  zi_dispatcher_domain_initialise(&domain);
  ZiPort port = {0};
  PHASE4_ASSERT(ZiSucceeded(
      zi_ipc_port_initialise(&port, &domain, (ZiStringView){"SeedPort", 8}, 2, &descriptor)));
  ZiIpcChannelPairOptions options = {
      sizeof(ZiIpcChannelPairOptions),
      ZI_IPC_CHANNEL_OPTIONS_VERSION,
      &domain,
      {"Client", 6},
      {"Server", 6},
      2,
      &client_table,
      &server_table,
      &client_token,
      &server_token,
      &descriptor,
      &descriptor,
  };
  ZiChannel client = {0};
  ZiChannel server = {0};
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_connect(&port, &options, &client, &server)));
  PHASE4_ASSERT(client.object.reference_count == 2 && server.object.reference_count == 3);
  ZiChannel* accepted = NULL;
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_accept(&port, &accepted)) && accepted == &server);
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(&accepted->object)));
  PHASE4_ASSERT(client.object.reference_count == 2 && server.object.reference_count == 2);
  PHASE4_ASSERT(zi_ipc_accept(&port, &accepted) == ZI_STATUS_TIMEOUT);

  ZxThread idle = {0};
  initialise_thread(&idle, 0, 0);
  idle.state = ZI_THREAD_RUNNING;
  ZxScheduler scheduler = {0};
  zi_scheduler_initialise(&scheduler, 0, &idle);
  ZxThread receiver = {0};
  initialise_thread(&receiver, 40, 8);
  ZiWaitOperation wait = {0};
  ZxWaitBlock wait_block = {0};
  ZxDispatcherHeader* channel_object[] = {&server.dispatcher};
  PHASE4_ASSERT(zi_dispatcher_wait(&wait,
                                   &wait_block,
                                   channel_object,
                                   1,
                                   ZI_WAIT_ANY,
                                   10,
                                   0,
                                   &scheduler,
                                   &receiver) == ZI_STATUS_PENDING);
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
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_send(&client, &message)) && receiver.state == ZI_THREAD_READY);
  PHASE4_ASSERT(ZiSucceeded(zi_scheduler_remove(&scheduler, &receiver)));
  ZiMessage received = {0};
  const unsigned char seed[] = {'S', 'e', 'e', 'd'};
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_receive(&server, &received)) && received.message_id == 21 &&
                received.payload_size == sizeof seed &&
                bytes_equal(received.inline_payload, seed, sizeof seed));
  PHASE4_ASSERT(zi_ipc_receive(&server, &received) == ZI_STATUS_TIMEOUT);

  PHASE4_ASSERT(ZiSucceeded(zi_ipc_send(&client, &message)));
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_send(&client, &message)));
  PHASE4_ASSERT(zi_ipc_send(&client, &message) == ZI_STATUS_QUEUE_FULL);
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_receive(&server, &received)));
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_receive(&server, &received)));
  message.payload_size = ZI_IPC_INLINE_PAYLOAD_CAPACITY + 1u;
  PHASE4_ASSERT(zi_ipc_send(&client, &message) == ZI_STATUS_INVALID_ARGUMENT);
  message.payload_size = 4;
  message.version = ZI_IPC_MESSAGE_VERSION + 1u;
  PHASE4_ASSERT(zi_ipc_send(&client, &message) == ZI_STATUS_INVALID_ARGUMENT);
  message.version = ZI_IPC_MESSAGE_VERSION;
  message.flags = UINT32_C(0x80000000);
  PHASE4_ASSERT(zi_ipc_send(&client, &message) == ZI_STATUS_INVALID_ARGUMENT);
  message.flags = 0;
  message.reserved = 1;
  PHASE4_ASSERT(zi_ipc_send(&client, &message) == ZI_STATUS_INVALID_ARGUMENT);
  message.reserved = 0;

  unsigned char section_backing[64] = {0};
  ZiSharedSection section = {0};
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_shared_section_initialise(&section,
                                                             (ZiStringView){"Shared", 6},
                                                             section_backing,
                                                             sizeof section_backing,
                                                             ZI_ACCESS_READ,
                                                             &descriptor)));
  ZiHandle section_handle = ZI_INVALID_HANDLE;
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_shared_section_open(&section,
                                                       &client_table,
                                                       &client_token,
                                                       ZI_ACCESS_READ,
                                                       &section_handle)));
  PHASE4_ASSERT(zi_ipc_shared_section_open(&section,
                                           &client_table,
                                           &client_token,
                                           ZI_ACCESS_WRITE,
                                           &received.transferred_handle) ==
                ZI_STATUS_ACCESS_DENIED);
  message.flags = ZI_MESSAGE_TRANSFER_HANDLE;
  message.transferred_handle = section_handle;
  message.transferred_access = UINT32_C(0x00000100);
  PHASE4_ASSERT(zi_ipc_send(&client, &message) == ZI_STATUS_INVALID_ARGUMENT);
  message.transferred_access = ZI_ACCESS_READ;
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_send(&client, &message)));
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_receive(&server, &received)) &&
                received.transferred_handle != ZI_INVALID_HANDLE);
  ZiObjectHeader* transferred = NULL;
  PHASE4_ASSERT(ZiSucceeded(zi_handle_lookup(&server_table,
                                             received.transferred_handle,
                                             ZI_ACCESS_READ,
                                             zi_ipc_shared_section_object_type(),
                                             &transferred)) &&
                transferred == &section.object);
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(transferred)));
  PHASE4_ASSERT(zi_handle_lookup(&server_table,
                                 received.transferred_handle,
                                 ZI_ACCESS_WRITE,
                                 zi_ipc_shared_section_object_type(),
                                 &transferred) == ZI_STATUS_ACCESS_DENIED);
  PHASE4_ASSERT(ZiSucceeded(zi_handle_close(&server_table, received.transferred_handle)));
  message.transferred_access = ZI_ACCESS_WRITE;
  PHASE4_ASSERT(zi_ipc_send(&client, &message) == ZI_STATUS_ACCESS_DENIED);

  message.transferred_access = ZI_ACCESS_READ;
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_send(&client, &message)));
  PHASE4_ASSERT(server_table.active_count == 1);
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_channel_close(&server)) && server_table.active_count == 0);
  PHASE4_ASSERT(client.object.reference_count == 1 && server.object.reference_count == 1);
  PHASE4_ASSERT(zi_ipc_send(&client, &message) == ZI_STATUS_PEER_CLOSED);
  PHASE4_ASSERT(zi_ipc_receive(&client, &received) == ZI_STATUS_PEER_CLOSED);
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_channel_close(&client)));
  PHASE4_ASSERT(ZiSucceeded(zi_handle_close(&client_table, section_handle)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(&section.object)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(&client.object)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(&server.object)));

  ZiChannel abandoned_client = {0};
  ZiChannel abandoned_server = {0};
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_connect(&port, &options, &abandoned_client, &abandoned_server)));
  PHASE4_ASSERT(port.queue_count == 1);
  message.flags = 0;
  message.transferred_handle = ZI_INVALID_HANDLE;
  message.transferred_access = 0;
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_port_close(&port)) && port.queue_count == 0);
  PHASE4_ASSERT(zi_ipc_send(&abandoned_client, &message) == ZI_STATUS_PEER_CLOSED);
  PHASE4_ASSERT(ZiSucceeded(zi_ipc_channel_close(&abandoned_client)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(&abandoned_client.object)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(&abandoned_server.object)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(&port.object)));
  PHASE4_ASSERT(ZiSucceeded(zi_handle_table_close_all(&client_table)) &&
                ZiSucceeded(zi_handle_table_close_all(&server_table)));

  ZiHandleTableEntry crash_client_entries[1] = {0};
  ZiHandleTableEntry crash_server_entries[1] = {0};
  ZiHandleTable crash_client_table = {0};
  ZiHandleTable crash_server_table = {0};
  PHASE4_ASSERT(
      ZiSucceeded(zi_handle_table_initialise(&crash_client_table, crash_client_entries, 1)));
  PHASE4_ASSERT(
      ZiSucceeded(zi_handle_table_initialise(&crash_server_table, crash_server_entries, 1)));
  ZiIpcChannelPairOptions crash_options = options;
  crash_options.client_table = &crash_client_table;
  crash_options.server_table = &crash_server_table;
  ZiChannel crash_client = {0};
  ZiChannel crash_server = {0};
  PHASE4_ASSERT(
      ZiSucceeded(zi_ipc_channel_pair_initialise(&crash_options, &crash_client, &crash_server)));
  ZiHandle crash_client_handle = ZI_INVALID_HANDLE;
  ZiHandle crash_server_handle = ZI_INVALID_HANDLE;
  PHASE4_ASSERT(ZiSucceeded(zi_handle_open(&crash_client_table,
                                           &crash_client.object,
                                           &client_token,
                                           ZI_ACCESS_READ,
                                           &crash_client_handle)));
  PHASE4_ASSERT(ZiSucceeded(zi_handle_open(&crash_server_table,
                                           &crash_server.object,
                                           &server_token,
                                           ZI_ACCESS_READ,
                                           &crash_server_handle)));
  PHASE4_ASSERT(ZiSucceeded(zi_object_dereference(&crash_client.object)) &&
                ZiSucceeded(zi_object_dereference(&crash_server.object)));
  PHASE4_ASSERT(ZiSucceeded(zi_handle_table_close_all(&crash_client_table)) &&
                crash_client.object.is_destroyed != 0 && crash_server.peer_is_closed != 0 &&
                crash_server.object.reference_count == 1 && crash_server.object.handle_count == 1);
  PHASE4_ASSERT(ZiSucceeded(zi_handle_table_close_all(&crash_server_table)) &&
                crash_server.object.is_destroyed != 0);

  *out_assertion_count = assertions;
  return true;
}

static void count_destroy(ZiObjectHeader* object) {
  if (object != NULL) {
    ++s_destroy_count;
  }
}

static void no_destroy(ZiObjectHeader* object) {
  (void)object;
}

static ZiAccessToken make_token(uint32_t user_value) {
  ZiAccessToken token = {
      sizeof(ZiAccessToken),
      ZI_ACCESS_TOKEN_VERSION,
      {ZI_SECURITY_AUTHORITY_USER, user_value},
      NULL,
      0,
      0,
  };
  return token;
}

static ZiSecurityDescriptor
make_descriptor(const ZiAce* entries, size_t entry_count, ZiAcl* out_acl) {
  out_acl->struct_size = sizeof *out_acl;
  out_acl->version = ZI_ACL_VERSION;
  out_acl->entries = entries;
  out_acl->entry_count = entry_count;
  ZiSecurityDescriptor descriptor = {
      sizeof(ZiSecurityDescriptor),
      ZI_SECURITY_DESCRIPTOR_VERSION,
      {ZI_SECURITY_AUTHORITY_SYSTEM, 1},
      {ZI_SECURITY_AUTHORITY_GROUP, 1},
      out_acl,
      0,
  };
  return descriptor;
}

static void initialise_thread(ZxThread* thread, uint64_t id, uint32_t priority) {
  *thread = (ZxThread){0};
  thread->thread_id = id;
  thread->affinity_mask = UINT64_C(1);
  thread->priority = priority;
  thread->base_priority = priority;
  thread->quantum = ZI_SCHEDULER_DEFAULT_QUANTUM;
  thread->quantum_remaining = ZI_SCHEDULER_DEFAULT_QUANTUM;
  thread->state = ZI_THREAD_RUNNING;
}

static bool bytes_equal(const unsigned char* left, const unsigned char* right, size_t size) {
  for (size_t index = 0; index < size; ++index) {
    if (left[index] != right[index]) {
      return false;
    }
  }
  return true;
}
