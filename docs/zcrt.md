# ZiCRT

ZiCRT is the C runtime bridge between standard C and Zizium. It is not the
public operating-system API and does not force applications to use ZIA.

## Implemented in Seed

The x64 PE start-up object exposes `ZiCrtStart`, validates the process parameter
pointer, establishes a normal C call, invokes ordinary `main`, and forwards its
integer result to `ZxExitProcess`. The assembly call supplies `argc` and `argv`
using the Microsoft x64 ABI; this supports both standard forms:

```c
int main(void);
int main(int argc, char *argv[]);
```

`hello_standard.exe` proves that a source file with `main(void)` links and runs
without `zizium.h`, ZIA, or `ZiMain`. `hello_arguments.exe` proves the second
form receives arguments containing spaces and UTF-8 data.

`zicrt.dll` is a real PE library loaded through the Seed import resolver. Its
`ZiCrtInitialiseProcess` validates the version-one, 72-byte parameter block,
declared string lengths, pointer arrays, image path, and argument zero. The
minimal `getenv` implementation performs exact-case environment-name lookup;
the minimal `puts` sends validated UTF-8 through `ZxDebugWrite`. ZiCRT also
exports bounded freestanding `memcpy`, `memset`, and `memcmp` implementations,
which permit non-trivial user programmes to link without a host runtime.

This is an execution proof, not only a link proof. The three boot acceptance
programmes prove `main(void)`, `main(argc, argv)`, exact-case environment lookup,
and an optional call through `zia.dll`. They return statuses 21, 22, and 23
through the real `ZxExitProcess` path.

The same start-up path now runs ServiceHost, SecurityHost, LogHost, MountHost,
SessionHost, Luma, and Luma's ordinary-C child from ZiFS. The child source uses
only standard `main(void)` and `stdio.h`; it does not include `zizium.h` or use
`ZiMain`.

## Scaffolded

The implemented bootstrap sequence is:

```text
PE entry point
ZiCRT process start
validate the kernel-serialised process parameters
publish argc, argv, and environment
initialise runtime state
call main
ZxExitProcess
```

Stream flushing and destructors are not present. `stdio.h` and `stdlib.h`
contain only the declarations required by this slice; the current `puts` and
`getenv` are not a conforming complete C library.

## Future

Heap allocation, files, complete streams, locale, time, threads, atomics,
floating point, signals or their native replacement, start-up constructors,
destructors, environment mutation, and a conforming C17 library are not
implemented. Process parameters still need stable inheritance and concurrent-
process lifetime rules before public process creation is exposed.
