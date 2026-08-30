// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stdio.h>

// Seed's host-side help and error stream is best effort after command dispatch.
// NOLINTBEGIN(cert-err33-c)

static bool text_equal(const char* left, const char* right);

int main(int argc, char* argv[]) {
  if (argc == 2 && text_equal(argv[1], "--help")) {
    puts("Usage: zcc.exe [options] <source files>");
    puts("ZCC Seed is a host-side compiler-driver scaffold.");
    puts("It does not compile programmes yet; Clang wrapping is the next stage.");
    return 0;
  }
  if (argc == 2 && text_equal(argv[1], "--print-target")) {
    puts("x86_64-pc-zizium-pe");
    return 0;
  }
  fputs("zcc: compilation is not implemented in Zizium 0.1 Seed.\n", stderr);
  fputs("Run 'zcc.exe --help' for the current interface.\n", stderr);
  return 1;
}

static bool text_equal(const char* left, const char* right) {
  size_t index = 0;
  while (left[index] != '\0' && right[index] != '\0') {
    if (left[index] != right[index]) {
      return false;
    }
    ++index;
  }
  return left[index] == right[index];
}
// NOLINTEND(cert-err33-c)
