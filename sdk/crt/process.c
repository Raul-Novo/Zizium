// SPDX-License-Identifier: GPL-3.0-or-later

#define ZI_BUILD_ZICRT 1

#include "zizium/process.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "zizium/status.h"
#include "zizium/zcrt.h"

#define ZI_CRT_ARGUMENT_LIMIT 32u
#define ZI_CRT_ENVIRONMENT_LIMIT 32u
#define ZI_CRT_STRING_LIMIT 4096u

static const ZiProcessParameters* s_parameters;

static bool bounded_string_size(const char* text, size_t limit, size_t* out_size);
static bool strings_equal(const char* left, size_t left_size, const char* right, size_t right_size);
static bool name_is_valid(const char* name, size_t* out_size);

ZiStatus ZiCrtInitialiseProcess(const ZiProcessParameters* parameters) {
  if (parameters == NULL || parameters->struct_size != sizeof *parameters ||
      parameters->version != ZI_PROCESS_PARAMETERS_VERSION || parameters->flags != 0 ||
      parameters->argument_count == 0 || parameters->argument_count > ZI_CRT_ARGUMENT_LIMIT ||
      parameters->environment_count > ZI_CRT_ENVIRONMENT_LIMIT || parameters->arguments == 0 ||
      parameters->environment == 0 || parameters->command_line == 0 ||
      parameters->command_line_size == 0 || parameters->command_line_size > ZI_CRT_STRING_LIMIT ||
      parameters->image_path == 0 || parameters->image_path_size == 0 ||
      parameters->image_path_size > ZI_CRT_STRING_LIMIT) {
    return ZI_STATUS_INVALID_PROCESS_PARAMETERS;
  }
  char* const* arguments = (char* const*)(uintptr_t)parameters->arguments;
  char* const* environment = (char* const*)(uintptr_t)parameters->environment;
  if (arguments[parameters->argument_count] != NULL ||
      environment[parameters->environment_count] != NULL) {
    return ZI_STATUS_INVALID_PROCESS_PARAMETERS;
  }
  size_t command_line_size = 0;
  size_t image_path_size = 0;
  const char* command_line = (const char*)(uintptr_t)parameters->command_line;
  const char* image_path = (const char*)(uintptr_t)parameters->image_path;
  if (!bounded_string_size(command_line, ZI_CRT_STRING_LIMIT, &command_line_size) ||
      command_line_size != parameters->command_line_size ||
      !bounded_string_size(image_path, ZI_CRT_STRING_LIMIT, &image_path_size) ||
      image_path_size != parameters->image_path_size) {
    return ZI_STATUS_INVALID_PROCESS_PARAMETERS;
  }
  for (uint32_t index = 0; index < parameters->argument_count; ++index) {
    size_t argument_size = 0;
    if (!bounded_string_size(arguments[index], ZI_CRT_STRING_LIMIT, &argument_size) ||
        (index == 0 &&
         !strings_equal(arguments[index], argument_size, image_path, image_path_size))) {
      return ZI_STATUS_INVALID_PROCESS_PARAMETERS;
    }
  }
  for (uint32_t index = 0; index < parameters->environment_count; ++index) {
    size_t entry_size = 0;
    if (!bounded_string_size(environment[index], ZI_CRT_STRING_LIMIT, &entry_size)) {
      return ZI_STATUS_INVALID_PROCESS_PARAMETERS;
    }
    size_t separator = 0;
    while (separator < entry_size && environment[index][separator] != '=') {
      ++separator;
    }
    if (entry_size == 0 || separator == 0 || separator == entry_size) {
      return ZI_STATUS_INVALID_PROCESS_PARAMETERS;
    }
  }
  s_parameters = parameters;
  return ZI_STATUS_SUCCESS;
}

char* getenv(const char* name) {
  size_t name_size = 0;
  if (s_parameters == NULL || !name_is_valid(name, &name_size)) {
    return NULL;
  }
  char* const* environment = (char* const*)(uintptr_t)s_parameters->environment;
  for (uint32_t index = 0; index < s_parameters->environment_count; ++index) {
    char* entry = environment[index];
    size_t entry_size = 0;
    if (!bounded_string_size(entry, ZI_CRT_STRING_LIMIT, &entry_size)) {
      return NULL;
    }
    size_t separator = 0;
    while (separator < entry_size && entry[separator] != '=') {
      ++separator;
    }
    if (separator != name_size) {
      continue;
    }
    bool matches = true;
    for (size_t character = 0; character < name_size; ++character) {
      if (entry[character] != name[character]) {
        matches = false;
        break;
      }
    }
    if (matches) {
      return entry + separator + 1u;
    }
  }
  return NULL;
}

static bool bounded_string_size(const char* text, size_t limit, size_t* out_size) {
  if (text == NULL || out_size == NULL) {
    return false;
  }
  for (size_t index = 0; index < limit; ++index) {
    if (text[index] == '\0') {
      *out_size = index;
      return true;
    }
  }
  return false;
}

static bool
strings_equal(const char* left, size_t left_size, const char* right, size_t right_size) {
  if (left == NULL || right == NULL || left_size != right_size) {
    return false;
  }
  for (size_t index = 0; index < left_size; ++index) {
    if (left[index] != right[index]) {
      return false;
    }
  }
  return true;
}

static bool name_is_valid(const char* name, size_t* out_size) {
  if (name == NULL || out_size == NULL) {
    return false;
  }
  size_t size = 0;
  if (!bounded_string_size(name, ZI_CRT_STRING_LIMIT, &size) || size == 0) {
    return false;
  }
  for (size_t index = 0; index < size; ++index) {
    if (name[index] == '=') {
      return false;
    }
  }
  *out_size = size;
  return true;
}
