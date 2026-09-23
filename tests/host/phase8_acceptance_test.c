// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "phase8_tests.h"
#include "zi/identity_acceptance.h"
#include "zizium/status.h"

static bool valid_cases(size_t* count);
static bool invalid_cases(size_t* count);

bool phase8_acceptance_test(size_t* out_assertion_count) {
  size_t count = 0;
  bool result = (bool)(valid_cases(&count) && invalid_cases(&count));
  *out_assertion_count = count;
  return result;
}

static bool valid_cases(size_t* count) {
  const char* inputs[] = {NULL,
                          "",
                          "release=Seed root=C:",
                          "xzi.identity=1:2:3",
                          "zi.identity=1:0:3",
                          "root=C: zi.identity=6:123:124\tother=yes",
                          "zi.identity=2:18446744073709551615:18446744073709551615"};
  const ZiIdentityAcceptanceParameters expected[] = {{0, 0, 0},
                                                     {0, 0, 0},
                                                     {0, 0, 0},
                                                     {0, 0, 0},
                                                     {1, 0, 3},
                                                     {6, 123, 124},
                                                     {2, UINT64_MAX, UINT64_MAX}};
  for (size_t index = 0; index < sizeof inputs / sizeof inputs[0]; ++index) {
    ZiIdentityAcceptanceParameters output = {9, 9, 9};
    ++*count;
    if (zi_identity_acceptance_parse(inputs[index], &output) != ZI_STATUS_SUCCESS ||
        output.stage != expected[index].stage ||
        output.record_index != expected[index].record_index ||
        output.file_id != expected[index].file_id) {
      (void)fprintf_s(stderr, "Identity acceptance valid case %zu failed.\n", index);
      return false;
    }
  }
  return true;
}

static bool invalid_cases(size_t* count) {
  const char* inputs[] = {"zi.identity=",
                          "zi.identity=0:1:2",
                          "zi.identity=7:1:2",
                          "zi.identity=1:2:0",
                          "zi.identity=1:2",
                          "zi.identity=1::2",
                          "zi.identity=1:2:3:4",
                          "zi.identity=-1:2:3",
                          "zi.identity=1:2:x",
                          "zi.identity=1:2:18446744073709551616",
                          "zi.identity=1:2:3 zi.identity=1:2:3"};
  for (size_t index = 0; index < sizeof inputs / sizeof inputs[0]; ++index) {
    ZiIdentityAcceptanceParameters output = {9, 9, 9};
    ++*count;
    if (ZiSucceeded(zi_identity_acceptance_parse(inputs[index], &output)) || output.stage != 9 ||
        output.record_index != 9 || output.file_id != 9) {
      (void)fprintf_s(stderr, "Identity acceptance invalid case %zu failed.\n", index);
      return false;
    }
  }
  char unterminated[1024];
  for (size_t index = 0; index < sizeof unterminated; ++index) {
    unterminated[index] = 'x';
  }
  ZiIdentityAcceptanceParameters output = {9, 9, 9};
  ++*count;
  return (bool)(zi_identity_acceptance_parse(unterminated, &output) == ZI_STATUS_BUFFER_TOO_SMALL &&
                output.stage == 9 &&
                zi_identity_acceptance_parse(NULL, NULL) == ZI_STATUS_INVALID_ARGUMENT);
}
