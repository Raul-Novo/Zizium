// SPDX-License-Identifier: GPL-3.0-or-later

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "zi/pe.h"
#include "zizium/status.h"

// Command-line diagnostics and cleanup after a fatal inspection error are best effort.
// NOLINTBEGIN(cert-err33-c, clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)

enum PeCheckKind {
  PE_CHECK_KIND_ANY = 0,
  PE_CHECK_KIND_KERNEL = 1,
  PE_CHECK_KIND_PROGRAMME = 2,
  PE_CHECK_KIND_DRIVER = 3,
  PE_CHECK_KIND_LIBRARY = 4,
  PE_CHECK_KIND_INVALID = 5,
};

static int check_image(const char* path, enum PeCheckKind kind);
static bool text_equal(const char* left, const char* right);
static enum PeCheckKind parse_kind(const char* text);
static const char* kind_name(enum PeCheckKind kind);

int main(int argc, char* argv[]) {
  enum PeCheckKind kind = PE_CHECK_KIND_ANY;
  const char* path = NULL;
  if (argc == 2) {
    path = argv[1];
  } else if (argc == 4 && text_equal(argv[1], "--kind")) {
    kind = parse_kind(argv[2]);
    path = argv[3];
  } else {
    fputs("Usage: pecheck.exe [--kind kernel|programme|library|driver] <PE image>\n", stderr);
    return 2;
  }
  if (kind == PE_CHECK_KIND_INVALID) {
    fputs("Unknown PE image kind.\n", stderr);
    return 2;
  }
  return check_image(path, kind);
}

// File acquisition, contract diagnostics, and the report form one linear CLI operation.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static int check_image(const char* path, enum PeCheckKind kind) {
  FILE* file = NULL;
  errno_t open_error = fopen_s(&file, path, "rb");
  if (open_error != 0 || file == NULL) {
    fprintf(stderr, "Unable to open '%s' (error %d).\n", path, (int)open_error);
    return 2;
  }
  if (fseek(file, 0, SEEK_END) != 0) {
    fclose(file);
    return 2;
  }
  long file_size_signed = ftell(file);
  if (file_size_signed <= 0 || fseek(file, 0, SEEK_SET) != 0) {
    fclose(file);
    return 2;
  }
  size_t file_size = (size_t)file_size_signed;
  unsigned char* data = malloc(file_size);
  if (data == NULL) {
    fputs("Not enough memory to inspect the PE image.\n", stderr);
    fclose(file);
    return 2;
  }
  if (fread(data, 1, file_size, file) != file_size || fclose(file) != 0) {
    fputs("Unable to read the complete PE image.\n", stderr);
    free(data);
    return 2;
  }

  ZiPeSection sections[96];
  ZiPeImage image = {0};
  ZiStatus status = zi_pe_parse(data, file_size, sections, 96, &image);
  if (ZiFailed(status)) {
    fprintf(stderr, "Invalid PE image '%s' (Zizium status %d).\n", path, (int)status);
    free(data);
    return 1;
  }

  bool is_valid = true;
  if (image.machine != ZI_PE_MACHINE_AMD64) {
    fputs("The image is not AMD64 PE32+.\n", stderr);
    is_valid = false;
  }
  bool has_library_characteristic = (image.characteristics & ZI_PE_CHARACTERISTIC_DLL) != 0;
  if (kind == PE_CHECK_KIND_KERNEL) {
    if (image.subsystem != ZI_PE_SUBSYSTEM_NATIVE) {
      fputs("A Zizium kernel must use the PE native subsystem.\n", stderr);
      is_valid = false;
    }
    if (zi_pe_has_imports(&image)) {
      fputs("A Limine-loaded Zizium kernel must not contain imports.\n", stderr);
      is_valid = false;
    }
    if (image.relocation_directory.size == 0) {
      fputs("The kernel does not contain a base relocation directory.\n", stderr);
      is_valid = false;
    }
    if (has_library_characteristic) {
      fputs("A Zizium kernel must not have the PE DLL characteristic.\n", stderr);
      is_valid = false;
    }
  }
  if (kind == PE_CHECK_KIND_PROGRAMME) {
    if (image.subsystem != ZI_PE_SUBSYSTEM_NATIVE) {
      fputs("A Zizium programme must use the PE native subsystem.\n", stderr);
      is_valid = false;
    }
    if (has_library_characteristic) {
      fputs("A Zizium programme must not have the PE DLL characteristic.\n", stderr);
      is_valid = false;
    }
  }
  if (kind == PE_CHECK_KIND_DRIVER) {
    if (image.subsystem != ZI_PE_SUBSYSTEM_NATIVE) {
      fputs("A Zizium driver must use the PE native subsystem.\n", stderr);
      is_valid = false;
    }
    if (has_library_characteristic) {
      fputs("A Zizium driver must not have the PE DLL characteristic.\n", stderr);
      is_valid = false;
    }
  }
  if (kind == PE_CHECK_KIND_LIBRARY) {
    if (image.subsystem != ZI_PE_SUBSYSTEM_NATIVE) {
      fputs("A Zizium native library must use the PE native subsystem.\n", stderr);
      is_valid = false;
    }
    if (!zi_pe_has_exports(&image)) {
      fputs("A Zizium native library must contain exports.\n", stderr);
      is_valid = false;
    }
    if (!has_library_characteristic) {
      fputs("A Zizium native library must have the PE DLL characteristic.\n", stderr);
      is_valid = false;
    }
  }

  printf("PE image: %s\n", path);
  printf("  Kind: %s\n", kind_name(kind));
  printf("  Machine: 0x%04x\n", image.machine);
  printf("  Sections: %u\n", image.section_count);
  printf("  Image base: 0x%016llx\n", (unsigned long long)image.image_base);
  printf("  Image size: %u bytes\n", image.image_size);
  printf("  Entry point RVA: 0x%08x\n", image.entry_point_rva);
  const char* import_state = "none";
  if (zi_pe_has_imports(&image)) {
    import_state = "present";
  }
  printf("  Imports: %s\n", import_state);
  printf("  Relocations: %s\n", image.relocation_directory.size == 0 ? "none" : "present");
  free(data);
  if (is_valid) {
    return 0;
  }
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
  return (bool)(left[index] == right[index]);
}

static enum PeCheckKind parse_kind(const char* text) {
  if (text_equal(text, "kernel")) {
    return PE_CHECK_KIND_KERNEL;
  }
  if (text_equal(text, "programme")) {
    return PE_CHECK_KIND_PROGRAMME;
  }
  if (text_equal(text, "driver")) {
    return PE_CHECK_KIND_DRIVER;
  }
  if (text_equal(text, "library")) {
    return PE_CHECK_KIND_LIBRARY;
  }
  return PE_CHECK_KIND_INVALID;
}

static const char* kind_name(enum PeCheckKind kind) {
  switch (kind) {
    case PE_CHECK_KIND_KERNEL:
      return "kernel";
    case PE_CHECK_KIND_PROGRAMME:
      return "programme";
    case PE_CHECK_KIND_DRIVER:
      return "driver";
    case PE_CHECK_KIND_LIBRARY:
      return "library";
    case PE_CHECK_KIND_ANY:
      return "unspecified";
    case PE_CHECK_KIND_INVALID:
      return "invalid";
  }
  return "invalid";
}
// NOLINTEND(cert-err33-c, clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
