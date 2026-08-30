// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>

bool phase4_object_namespace_test(size_t* out_assertion_count);
bool phase4_handle_table_test(size_t* out_assertion_count);
bool phase4_dispatcher_test(size_t* out_assertion_count);
bool phase4_ipc_test(size_t* out_assertion_count);
