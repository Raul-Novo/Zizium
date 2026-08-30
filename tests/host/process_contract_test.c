// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "phase3_tests.h"
#include "zi/byte_order.h"
#include "zi/dispatcher.h"
#include "zi/process_parameters.h"
#include "zi/process_record.h"
#include "zi/scheduler.h"
#include "zi/security.h"
#include "zizium/process.h"
#include "zizium/status.h"
#include "zizium/types.h"

#define PHASE3_ASSERT(expression)                                                                  \
  do {                                                                                             \
    ++assertions;                                                                                  \
    if (!(expression)) {                                                                           \
      (void)fprintf_s(stderr, "%s:%d: assertion failed: %s\n", __FILE__, __LINE__, #expression);   \
      *out_assertion_count = assertions;                                                           \
      return false;                                                                                \
    }                                                                                              \
  } while (false)

static bool buffer_string_equal(const unsigned char* buffer,
                                size_t buffer_size,
                                uint64_t user_base,
                                uint64_t user_address,
                                const char* expected,
                                size_t expected_size);

// This test deliberately keeps valid and hostile forms beside the serialised layout checks.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
bool phase3_process_parameters_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  size_t assertions = 0;
  *out_assertion_count = 0;
  const ZiStringView arguments[] = {
      {"C:\\Zizium\\System\\argument test.exe",
       sizeof "C:\\Zizium\\System\\argument test.exe" - 1u},
      {"C:\\Program Files\\Calm Tool", sizeof "C:\\Program Files\\Calm Tool" - 1u},
      {"azul claro", sizeof "azul claro" - 1u},
  };
  const ZiStringView environment[] = {
      {"SystemRoot=C:\\Zizium", sizeof "SystemRoot=C:\\Zizium" - 1u},
      {"systemroot=case-sensitive", sizeof "systemroot=case-sensitive" - 1u},
  };
  ZiProcessParameterInput input = {
      sizeof(ZiProcessParameterInput),
      ZI_PROCESS_PARAMETER_INPUT_VERSION,
      arguments[0],
      {"\"C:\\Zizium\\System\\argument test.exe\" \"C:\\Program Files\\Calm Tool\" "
       "\"azul claro\"",
       sizeof "\"C:\\Zizium\\System\\argument test.exe\" \"C:\\Program Files\\Calm "
              "Tool\" \"azul claro\"" -
           1u},
      arguments,
      sizeof arguments / sizeof arguments[0],
      environment,
      sizeof environment / sizeof environment[0],
  };

  size_t required_size = 0;
  PHASE3_ASSERT(ZiSucceeded(zi_process_parameters_measure(&input, &required_size)));
  PHASE3_ASSERT(required_size > sizeof(ZiProcessParameters) &&
                required_size < ZI_PROCESS_PARAMETER_BLOCK_LIMIT);
  unsigned char buffer[1024] = {0};
  const uint64_t user_base = UINT64_C(0x10000000);
  size_t used_size = 0;
  uint64_t parameters_address = 0;
  PHASE3_ASSERT(ZiSucceeded(zi_process_parameters_serialise(&input,
                                                            user_base,
                                                            buffer,
                                                            sizeof buffer,
                                                            &used_size,
                                                            &parameters_address)));
  PHASE3_ASSERT(used_size == required_size && parameters_address == user_base);

  ZiProcessParameters parameters = {0};
  zi_memory_copy(&parameters, buffer, sizeof parameters);
  PHASE3_ASSERT(parameters.struct_size == sizeof parameters &&
                parameters.version == ZI_PROCESS_PARAMETERS_VERSION && parameters.flags == 0);
  PHASE3_ASSERT(parameters.argument_count == 3 && parameters.environment_count == 2);
  PHASE3_ASSERT(buffer_string_equal(buffer,
                                    used_size,
                                    user_base,
                                    parameters.image_path,
                                    input.image_path.data,
                                    input.image_path.size));
  PHASE3_ASSERT(buffer_string_equal(buffer,
                                    used_size,
                                    user_base,
                                    parameters.command_line,
                                    input.command_line.data,
                                    input.command_line.size));
  PHASE3_ASSERT(parameters.command_line_size == input.command_line.size &&
                parameters.image_path_size == input.image_path.size);

  size_t argument_table_offset = (size_t)(parameters.arguments - user_base);
  size_t environment_table_offset = (size_t)(parameters.environment - user_base);
  PHASE3_ASSERT(argument_table_offset <= used_size - (4u * sizeof(uint64_t)));
  PHASE3_ASSERT(environment_table_offset <= used_size - (3u * sizeof(uint64_t)));
  for (size_t index = 0; index < sizeof arguments / sizeof arguments[0]; ++index) {
    uint64_t address = zi_read_u64_le(buffer + argument_table_offset + (index * sizeof(uint64_t)));
    PHASE3_ASSERT(buffer_string_equal(buffer,
                                      used_size,
                                      user_base,
                                      address,
                                      arguments[index].data,
                                      arguments[index].size));
  }
  PHASE3_ASSERT(zi_read_u64_le(buffer + argument_table_offset + (3u * sizeof(uint64_t))) == 0);
  for (size_t index = 0; index < sizeof environment / sizeof environment[0]; ++index) {
    uint64_t address =
        zi_read_u64_le(buffer + environment_table_offset + (index * sizeof(uint64_t)));
    PHASE3_ASSERT(buffer_string_equal(buffer,
                                      used_size,
                                      user_base,
                                      address,
                                      environment[index].data,
                                      environment[index].size));
  }
  PHASE3_ASSERT(zi_read_u64_le(buffer + environment_table_offset + (2u * sizeof(uint64_t))) == 0);
  PHASE3_ASSERT(zi_process_parameters_serialise(&input,
                                                user_base,
                                                buffer,
                                                required_size - 1u,
                                                &used_size,
                                                &parameters_address) == ZI_STATUS_BUFFER_TOO_SMALL);

  ZiProcessParameterInput invalid = input;
  const ZiStringView wrong_first[] = {{"C:\\Temp\\wrong.exe", sizeof "C:\\Temp\\wrong.exe" - 1u}};
  invalid.arguments = wrong_first;
  invalid.argument_count = 1;
  PHASE3_ASSERT(zi_process_parameters_measure(&invalid, &required_size) ==
                ZI_STATUS_INVALID_PROCESS_PARAMETERS);
  const char embedded_zero[] = {'b', 'a', 'd', '\0', 'x'};
  invalid = input;
  invalid.command_line = (ZiStringView){embedded_zero, sizeof embedded_zero};
  PHASE3_ASSERT(zi_process_parameters_measure(&invalid, &required_size) ==
                ZI_STATUS_INVALID_PROCESS_PARAMETERS);
  const char invalid_utf8[] = {(char)0xc0, (char)0xaf};
  invalid = input;
  invalid.command_line = (ZiStringView){invalid_utf8, sizeof invalid_utf8};
  PHASE3_ASSERT(zi_process_parameters_measure(&invalid, &required_size) ==
                ZI_STATUS_INVALID_PROCESS_PARAMETERS);
  const ZiStringView duplicate_environment[] = {
      {"Name=one", sizeof "Name=one" - 1u},
      {"Name=two", sizeof "Name=two" - 1u},
  };
  invalid = input;
  invalid.environment = duplicate_environment;
  invalid.environment_count = 2;
  PHASE3_ASSERT(zi_process_parameters_measure(&invalid, &required_size) ==
                ZI_STATUS_INVALID_PROCESS_PARAMETERS);
  invalid = input;
  invalid.environment = NULL;
  invalid.environment_count = 1;
  PHASE3_ASSERT(zi_process_parameters_measure(&invalid, &required_size) ==
                ZI_STATUS_INVALID_PROCESS_PARAMETERS);
  invalid = input;
  invalid.argument_count = ZI_PROCESS_ARGUMENT_LIMIT + 1u;
  PHASE3_ASSERT(zi_process_parameters_measure(&invalid, &required_size) ==
                ZI_STATUS_INVALID_PROCESS_PARAMETERS);

  *out_assertion_count = assertions;
  return true;
}

// Lifecycle transitions are intentionally exercised as one ordered contract.
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
bool phase3_process_lifecycle_test(size_t* out_assertion_count) {
  if (out_assertion_count == NULL) {
    return false;
  }
  size_t assertions = 0;
  *out_assertion_count = 0;
  const ZiSecurityId groups[] = {
      {ZI_SECURITY_AUTHORITY_GROUP, 7},
      {ZI_SECURITY_AUTHORITY_GROUP, 21},
  };
  ZiAccessToken token = {
      sizeof(ZiAccessToken),
      ZI_ACCESS_TOKEN_VERSION,
      {ZI_SECURITY_AUTHORITY_USER, 42},
      groups,
      sizeof groups / sizeof groups[0],
      UINT64_C(0x21),
  };
  PHASE3_ASSERT(ZiSucceeded(zi_security_token_validate(&token)));

  ZiDispatcherDomain dispatcher_domain = {0};
  zi_dispatcher_domain_initialise(&dispatcher_domain);
  ZxProcess process = {0};
  PHASE3_ASSERT(ZiSucceeded(
      zi_process_record_initialise(&process, 21, 8, UINT64_C(1), &token, &dispatcher_domain)));
  PHASE3_ASSERT(process.struct_size == sizeof process &&
                process.version == ZI_EXECUTIVE_PROCESS_VERSION && process.process_id == 21);
  PHASE3_ASSERT(process.security_token == &token && process.state == ZI_PROCESS_INITIALISED);
  PHASE3_ASSERT(process.termination_event.object_type == ZI_DISPATCHER_OBJECT_PROCESS_TERMINATION &&
                process.termination_event.signal_state == 0);
  int32_t exit_status = 0;
  PHASE3_ASSERT(zi_process_record_wait(&process, 0, &exit_status) == ZI_STATUS_TIMEOUT);
  PHASE3_ASSERT(zi_process_record_wait(&process, 1, &exit_status) == ZI_STATUS_NOT_IMPLEMENTED);
  PHASE3_ASSERT(ZiSucceeded(zi_process_record_mark_running(&process)));
  PHASE3_ASSERT(zi_process_record_mark_running(&process) == ZI_STATUS_INVALID_STATE);
  PHASE3_ASSERT(ZiSucceeded(zi_process_record_terminate(&process, 73)));
  PHASE3_ASSERT(process.state == ZI_PROCESS_TERMINATED &&
                process.termination_event.signal_state == 1);
  PHASE3_ASSERT(ZiSucceeded(zi_process_record_wait(&process, 0, &exit_status)) &&
                exit_status == 73);
  PHASE3_ASSERT(zi_process_record_terminate(&process, 74) == ZI_STATUS_INVALID_STATE);

  ZiSecurityId duplicate_groups[] = {
      {ZI_SECURITY_AUTHORITY_GROUP, 7},
      {ZI_SECURITY_AUTHORITY_GROUP, 7},
  };
  token.groups = duplicate_groups;
  PHASE3_ASSERT(zi_security_token_validate(&token) == ZI_STATUS_INVALID_ARGUMENT);
  token.groups = groups;
  token.user.value = 0;
  PHASE3_ASSERT(zi_security_token_validate(&token) == ZI_STATUS_INVALID_ARGUMENT);
  token.user.value = 42;
  token.version = ZI_ACCESS_TOKEN_VERSION + 1u;
  PHASE3_ASSERT(zi_security_token_validate(&token) == ZI_STATUS_INVALID_ARGUMENT);
  PHASE3_ASSERT(
      zi_process_record_initialise(&process, 22, 8, UINT64_C(1), &token, &dispatcher_domain) ==
      ZI_STATUS_INVALID_ARGUMENT);

  *out_assertion_count = assertions;
  return true;
}

static bool buffer_string_equal(const unsigned char* buffer,
                                size_t buffer_size,
                                uint64_t user_base,
                                uint64_t user_address,
                                const char* expected,
                                size_t expected_size) {
  if (buffer == NULL || expected == NULL || user_address < user_base ||
      user_address - user_base > SIZE_MAX) {
    return false;
  }
  size_t offset = (size_t)(user_address - user_base);
  if (offset > buffer_size || expected_size + 1u > buffer_size - offset ||
      buffer[offset + expected_size] != '\0') {
    return false;
  }
  return zi_memory_compare(buffer + offset, expected, expected_size) == 0;
}
