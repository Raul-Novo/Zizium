// SPDX-License-Identifier: GPL-3.0-or-later

// A non-static probe avoids unused-function warnings when each header is forced into this unit.
// NOLINTNEXTLINE(misc-use-internal-linkage)
int zi_header_probe(void) {
  return 0;
}
