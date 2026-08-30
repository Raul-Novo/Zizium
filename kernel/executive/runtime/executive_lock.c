// SPDX-License-Identifier: GPL-3.0-or-later

#include "zi/executive_lock.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void zi_executive_lock_initialise(ZiExecutiveLock* lock) {
  if (lock != NULL) {
    __atomic_store_n(&lock->value, 0, __ATOMIC_RELAXED);
  }
}

void zi_executive_lock_acquire(ZiExecutiveLock* lock) {
  if (lock == NULL) {
    return;
  }

  uint32_t expected = 0;
  while (!__atomic_compare_exchange_n(&lock->value,
                                      &expected,
                                      1,
                                      false,
                                      __ATOMIC_ACQUIRE,
                                      __ATOMIC_RELAXED)) {
    expected = 0;
  }
}

void zi_executive_lock_release(ZiExecutiveLock* lock) {
  if (lock != NULL) {
    __atomic_store_n(&lock->value, 0, __ATOMIC_RELEASE);
  }
}
