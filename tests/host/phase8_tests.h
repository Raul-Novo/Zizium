// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>

bool phase8_security_boundary_test(size_t* out_assertion_count);
bool phase8_nvme_window_test(size_t* out_assertion_count);
bool phase8_service_identity_test(size_t* out_assertion_count);
bool phase8_image_authorisation_test(size_t* out_assertion_count);
