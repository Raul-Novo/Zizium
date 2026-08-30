// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

typedef struct ZiExecutiveLock {
  volatile uint32_t value;
} ZiExecutiveLock;

void zi_executive_lock_initialise(ZiExecutiveLock* lock);
void zi_executive_lock_acquire(ZiExecutiveLock* lock);
void zi_executive_lock_release(ZiExecutiveLock* lock);
