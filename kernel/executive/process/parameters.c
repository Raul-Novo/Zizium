// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/address_space.h"
#include "zi/byte_order.h"
#include "zi/process_parameters.h"
#include "zi/unicode.h"
#include "zizium/process.h"
#include "zizium/status.h"
#include "zizium/types.h"

typedef struct ParameterWriter {
  unsigned char* output;
  size_t capacity;
  size_t cursor;
  uint64_t user_base;
} ParameterWriter;

static ZiStatus validate_input(const ZiProcessParameterInput* input);
static ZiStatus validate_text(ZiStringView text, bool allow_empty);
static ZiStatus validate_environment(const ZiProcessParameterInput* input);
static bool string_views_equal(ZiStringView left, ZiStringView right);
static bool environment_names_equal(ZiStringView left, ZiStringView right);
static ZiStatus add_size(size_t left, size_t right, size_t* out_value);
static ZiStatus align_size(size_t value, size_t alignment, size_t* out_value);
static ZiStatus write_string(ParameterWriter* writer, ZiStringView text, uint64_t* out_address);
static ZiStatus write_pointer(ParameterWriter* writer, size_t offset, uint64_t value);

ZiStatus zi_process_parameters_measure(const ZiProcessParameterInput* input,
                                       size_t* out_required_size) {
  if (out_required_size == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = validate_input(input);
  if (ZiFailed(status)) {
    return status;
  }
  size_t size = sizeof(ZiProcessParameters);
  status = align_size(size, sizeof(uint64_t), &size);
  if (ZiSucceeded(status)) {
    status = add_size(size, (input->argument_count + 1u) * sizeof(uint64_t), &size);
  }
  if (ZiSucceeded(status)) {
    status = add_size(size, (input->environment_count + 1u) * sizeof(uint64_t), &size);
  }
  const ZiStringView fixed[] = {input->image_path, input->command_line};
  for (size_t index = 0; ZiSucceeded(status) && index < 2; ++index) {
    status = add_size(size, fixed[index].size + 1u, &size);
  }
  for (size_t index = 0; ZiSucceeded(status) && index < input->argument_count; ++index) {
    status = add_size(size, input->arguments[index].size + 1u, &size);
  }
  for (size_t index = 0; ZiSucceeded(status) && index < input->environment_count; ++index) {
    status = add_size(size, input->environment[index].size + 1u, &size);
  }
  if (ZiFailed(status) || size > ZI_PROCESS_PARAMETER_BLOCK_LIMIT) {
    if (ZiFailed(status)) {
      return status;
    }
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  *out_required_size = size;
  return ZI_STATUS_SUCCESS;
}

ZiStatus zi_process_parameters_serialise(const ZiProcessParameterInput* input,
                                         uint64_t user_base,
                                         void* output,
                                         size_t output_capacity,
                                         size_t* out_used_size,
                                         uint64_t* out_parameters_address) {
  if (output == NULL || out_used_size == NULL || out_parameters_address == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  size_t required_size = 0;
  ZiStatus status = zi_process_parameters_measure(input, &required_size);
  if (ZiFailed(status)) {
    return status;
  }
  if (output_capacity < required_size || !zi_user_range_is_valid(user_base, required_size)) {
    return ZI_STATUS_BUFFER_TOO_SMALL;
  }
  zi_memory_zero(output, output_capacity);
  ParameterWriter writer = {output, output_capacity, sizeof(ZiProcessParameters), user_base};
  status = align_size(writer.cursor, sizeof(uint64_t), &writer.cursor);
  size_t arguments_offset = writer.cursor;
  if (ZiSucceeded(status)) {
    status =
        add_size(writer.cursor, (input->argument_count + 1u) * sizeof(uint64_t), &writer.cursor);
  }
  size_t environment_offset = writer.cursor;
  if (ZiSucceeded(status)) {
    status =
        add_size(writer.cursor, (input->environment_count + 1u) * sizeof(uint64_t), &writer.cursor);
  }

  uint64_t image_path_address = 0;
  uint64_t command_line_address = 0;
  if (ZiSucceeded(status)) {
    status = write_string(&writer, input->image_path, &image_path_address);
  }
  if (ZiSucceeded(status)) {
    status = write_string(&writer, input->command_line, &command_line_address);
  }
  for (size_t index = 0; ZiSucceeded(status) && index < input->argument_count; ++index) {
    uint64_t string_address = 0;
    status = write_string(&writer, input->arguments[index], &string_address);
    if (ZiSucceeded(status)) {
      status =
          write_pointer(&writer, arguments_offset + (index * sizeof(uint64_t)), string_address);
    }
  }
  for (size_t index = 0; ZiSucceeded(status) && index < input->environment_count; ++index) {
    uint64_t string_address = 0;
    status = write_string(&writer, input->environment[index], &string_address);
    if (ZiSucceeded(status)) {
      status =
          write_pointer(&writer, environment_offset + (index * sizeof(uint64_t)), string_address);
    }
  }
  if (ZiFailed(status) || writer.cursor != required_size) {
    zi_memory_zero(output, output_capacity);
    if (ZiFailed(status)) {
      return status;
    }
    return ZI_STATUS_INVALID_STATE;
  }

  ZiProcessParameters parameters = {
      sizeof(ZiProcessParameters),
      ZI_PROCESS_PARAMETERS_VERSION,
      0,
      (uint32_t)input->argument_count,
      (uint32_t)input->environment_count,
      0,
      user_base + arguments_offset,
      user_base + environment_offset,
      command_line_address,
      input->command_line.size,
      image_path_address,
      input->image_path.size,
  };
  zi_memory_copy(output, &parameters, sizeof parameters);
  *out_used_size = required_size;
  *out_parameters_address = user_base;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus validate_input(const ZiProcessParameterInput* input) {
  if (input == NULL || input->struct_size != sizeof *input ||
      input->version != ZI_PROCESS_PARAMETER_INPUT_VERSION || input->arguments == NULL ||
      input->argument_count == 0 || input->argument_count > ZI_PROCESS_ARGUMENT_LIMIT ||
      input->environment_count > ZI_PROCESS_ENVIRONMENT_LIMIT ||
      (input->environment == NULL && input->environment_count != 0)) {
    return ZI_STATUS_INVALID_PROCESS_PARAMETERS;
  }
  ZiStatus status = validate_text(input->image_path, false);
  if (ZiSucceeded(status)) {
    status = validate_text(input->command_line, false);
  }
  if (ZiFailed(status) || !string_views_equal(input->image_path, input->arguments[0])) {
    return ZI_STATUS_INVALID_PROCESS_PARAMETERS;
  }
  for (size_t index = 0; index < input->argument_count; ++index) {
    status = validate_text(input->arguments[index], true);
    if (ZiFailed(status)) {
      return ZI_STATUS_INVALID_PROCESS_PARAMETERS;
    }
  }
  return validate_environment(input);
}

static ZiStatus validate_text(ZiStringView text, bool allow_empty) {
  if (text.data == NULL || (!allow_empty && text.size == 0) ||
      text.size > ZI_PROCESS_PARAMETER_STRING_LIMIT) {
    return ZI_STATUS_INVALID_PROCESS_PARAMETERS;
  }
  for (size_t index = 0; index < text.size; ++index) {
    if (text.data[index] == '\0') {
      return ZI_STATUS_INVALID_PROCESS_PARAMETERS;
    }
  }
  return zi_utf8_validate(text.data, text.size);
}

static ZiStatus validate_environment(const ZiProcessParameterInput* input) {
  for (size_t index = 0; index < input->environment_count; ++index) {
    ZiStringView entry = input->environment[index];
    if (ZiFailed(validate_text(entry, false))) {
      return ZI_STATUS_INVALID_PROCESS_PARAMETERS;
    }
    size_t separator = 0;
    while (separator < entry.size && entry.data[separator] != '=') {
      ++separator;
    }
    if (separator == 0 || separator == entry.size) {
      return ZI_STATUS_INVALID_PROCESS_PARAMETERS;
    }
    for (size_t previous = 0; previous < index; ++previous) {
      if (environment_names_equal(entry, input->environment[previous])) {
        return ZI_STATUS_INVALID_PROCESS_PARAMETERS;
      }
    }
  }
  return ZI_STATUS_SUCCESS;
}

static bool string_views_equal(ZiStringView left, ZiStringView right) {
  if (left.data == NULL || right.data == NULL || left.size != right.size) {
    return false;
  }
  for (size_t index = 0; index < left.size; ++index) {
    if (left.data[index] != right.data[index]) {
      return false;
    }
  }
  return true;
}

static bool environment_names_equal(ZiStringView left, ZiStringView right) {
  size_t left_size = 0;
  while (left_size < left.size && left.data[left_size] != '=') {
    ++left_size;
  }
  size_t right_size = 0;
  while (right_size < right.size && right.data[right_size] != '=') {
    ++right_size;
  }
  if (left_size != right_size) {
    return false;
  }
  for (size_t index = 0; index < left_size; ++index) {
    if (left.data[index] != right.data[index]) {
      return false;
    }
  }
  return true;
}

static ZiStatus add_size(size_t left, size_t right, size_t* out_value) {
  if (out_value == NULL || right > SIZE_MAX - left) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  *out_value = left + right;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus align_size(size_t value, size_t alignment, size_t* out_value) {
  if (out_value == NULL || alignment == 0 || (alignment & (alignment - 1u)) != 0) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  size_t mask = alignment - 1u;
  if (value > SIZE_MAX - mask) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  *out_value = (value + mask) & ~mask;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus write_string(ParameterWriter* writer, ZiStringView text, uint64_t* out_address) {
  if (writer == NULL || writer->output == NULL || out_address == NULL ||
      writer->cursor > writer->capacity || text.size + 1u > writer->capacity - writer->cursor ||
      writer->user_base > UINT64_MAX - writer->cursor) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  *out_address = writer->user_base + writer->cursor;
  zi_memory_copy(writer->output + writer->cursor, text.data, text.size);
  writer->output[writer->cursor + text.size] = '\0';
  writer->cursor += text.size + 1u;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus write_pointer(ParameterWriter* writer, size_t offset, uint64_t value) {
  if (writer == NULL || writer->output == NULL || offset > writer->capacity ||
      sizeof(uint64_t) > writer->capacity - offset) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  zi_write_u64_le(writer->output + offset, value);
  return ZI_STATUS_SUCCESS;
}
