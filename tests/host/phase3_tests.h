// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>

bool phase3_process_parameters_test(size_t* out_assertion_count);
bool phase3_process_lifecycle_test(size_t* out_assertion_count);
bool phase3_pe_linking_test(size_t* out_assertion_count);
