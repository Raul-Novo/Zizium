// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>

bool phase7_zifs_wire_test(size_t* out_assertion_count);
bool phase7_zifs_security_test(size_t* out_assertion_count);
