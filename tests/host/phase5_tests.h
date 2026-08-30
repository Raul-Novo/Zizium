// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>

bool phase5_acpi_test(size_t* out_assertion_count);
bool phase5_pci_test(size_t* out_assertion_count);
bool phase5_dma_test(size_t* out_assertion_count);
bool phase5_gpt_test(size_t* out_assertion_count);
bool phase5_io_test(size_t* out_assertion_count);
