// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdio.h>
#include <stdlib.h>

static int text_equal(const char* left, const char* right) {
  if (left == NULL || right == NULL) {
    return 0;
  }
  size_t index = 0;
  while (left[index] != '\0' && right[index] != '\0') {
    if (left[index] != right[index]) {
      return 0;
    }
    ++index;
  }
  return left[index] == right[index];
}

int main(int argc, char* argv[]) {
  if (argc != 3 || argv == NULL ||
      !text_equal(argv[0], "C:\\Zizium\\System\\hello_arguments.exe") ||
      !text_equal(argv[1], "C:\\Program Files\\Zizium Seed") ||
      !text_equal(argv[2], "azul claro")) {
    return 1;
  }
  // ZiCRT is deliberately single-threaded in this acceptance programme.
  // NOLINTNEXTLINE(concurrency-mt-unsafe)
  if (!text_equal(getenv("SystemRoot"), "C:\\Zizium") || getenv("systemroot") != NULL) {
    return 2;
  }
  puts("Arguments and environment reached standard C.");
  return 22;
}
