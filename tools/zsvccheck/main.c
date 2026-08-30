// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "zi/service.h"
#include "zizium/status.h"
#include "zizium/types.h"

// Host I/O diagnostics and cleanup on an already-failing path are best effort.
// NOLINTBEGIN(cert-err33-c, clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)

static ZiStatus read_manifest(const char* path, char* buffer, size_t capacity, size_t* out_size);

int main(int argc, char* argv[]) {
  if (argc < 2 || argc > (int)ZI_SERVICE_MAX_MANIFESTS + 1) {
    fprintf(stderr,
            "Usage: zsvccheck.exe <manifest.zsvc>... (at most %u files)\n",
            ZI_SERVICE_MAX_MANIFESTS);
    return 2;
  }

  size_t manifest_count = (size_t)(argc - 1);
  char manifest_data[ZI_SERVICE_MAX_MANIFESTS][ZI_SERVICE_MAX_MANIFEST_BYTES + 1u] = {0};
  ZiServiceDependency dependency_storage[ZI_SERVICE_MAX_MANIFESTS][ZI_SERVICE_MAX_DEPENDENCIES] = {
      0};
  ZiServiceManifest manifests[ZI_SERVICE_MAX_MANIFESTS] = {0};
  for (size_t index = 0; index < manifest_count; ++index) {
    size_t data_size = 0;
    ZiStatus status = read_manifest(argv[index + 1u],
                                    manifest_data[index],
                                    sizeof manifest_data[index],
                                    &data_size);
    if (ZiFailed(status)) {
      fprintf(stderr, "Unable to read service manifest '%s'.\n", argv[index + 1u]);
      return 1;
    }
    status = zi_service_manifest_parse(manifest_data[index],
                                       data_size,
                                       dependency_storage[index],
                                       ZI_SERVICE_MAX_DEPENDENCIES,
                                       &manifests[index]);
    if (ZiFailed(status)) {
      fprintf(stderr,
              "Service manifest '%s' is invalid (status %d).\n",
              argv[index + 1u],
              (int)status);
      return 1;
    }
  }

  size_t order[ZI_SERVICE_MAX_MANIFESTS] = {0};
  size_t order_count = 0;
  ZiStatus status = zi_service_resolve_start_order(manifests,
                                                   manifest_count,
                                                   order,
                                                   ZI_SERVICE_MAX_MANIFESTS,
                                                   &order_count);
  if (ZiFailed(status)) {
    fprintf(stderr, "The service dependency graph is invalid (status %d).\n", (int)status);
    return 1;
  }
  printf("Validated %zu service manifests in dependency order:\n", order_count);
  for (size_t index = 0; index < order_count; ++index) {
    const ZiStringView name = manifests[order[index]].name;
    fputs("  ", stdout);
    (void)fwrite(name.data, 1, name.size, stdout);
    fputc('\n', stdout);
  }
  return 0;
}

static ZiStatus read_manifest(const char* path, char* buffer, size_t capacity, size_t* out_size) {
  if (path == NULL || buffer == NULL || capacity < ZI_SERVICE_MAX_MANIFEST_BYTES + 1u ||
      out_size == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  FILE* file = NULL;
  if (fopen_s(&file, path, "rb") != 0 || file == NULL) {
    return ZI_STATUS_NOT_FOUND;
  }
  size_t size = fread(buffer, 1, capacity, file);
  if (ferror(file) != 0 || fclose(file) != 0 || size == 0 || size > ZI_SERVICE_MAX_MANIFEST_BYTES) {
    return ZI_STATUS_INVALID_SERVICE_MANIFEST;
  }
  buffer[size] = '\0';
  *out_size = size;
  return ZI_STATUS_SUCCESS;
}

// NOLINTEND(cert-err33-c, clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
