// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

static bool strings_equal(const char* left, const char* right);

int main(int argument_count, char* arguments[]) {
  if (argument_count == 2 && strings_equal(arguments[1], "--failure-probe")) {
    puts("ServiceHost received the bounded failure probe.");
    return 21;
  }
  puts("ServiceHost completed its Phase 6 bootstrap hand-off.");
  return 0;
}

static bool strings_equal(const char* left, const char* right) {
  if (left == NULL || right == NULL) {
    return false;
  }
  size_t index = 0;
  while (left[index] != '\0' && right[index] != '\0' && left[index] == right[index]) {
    ++index;
  }
  return left[index] == right[index];
}
