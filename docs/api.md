# Native API layers

Zizium separates portable C expectations from public native convenience APIs
and the low-level native boundary:

```text
standard C functions -> ZiCRT -> ZIA -> Zx -> syscall -> kernel
native application ----------------^ 
```

## Implemented in Seed

`zizium/status.h`, `types.h`, `theme.h`, `zia.h`, `zx.h`, and optional umbrella
`zizium.h` define fixed-width statuses, handles, string views, colour values,
versioned options, and preliminary entry points. Ordinary C source need not
include any of them.

Phase 7 adds explicit filesystem outcomes for a read-only device, required
recovery, exhausted volume space, and exhausted journal space. They remain
native `ZiStatus` values rather than POSIX `errno`; unsupported work still
returns `ZI_STATUS_NOT_IMPLEMENTED` rather than false success.

The Seed build produces real PE `zx.dll`, `zicrt.dll`, and `zia.dll` images and
import libraries. The bounded loader maps their dependencies and resolves
exports by name or ordinal. User processes actively support `ZxDebugWrite` and
`ZxExitProcess`. The minimal ZiCRT uses those calls to implement `puts` and to
return from ordinary `main`. This is deliberately below ZIA: a standard C
programme remains valid without an operating-system header.

`hello_native.exe` proves the optional native path by importing
`ZiConsoleWrite` from `zia.dll`; that call bridges to `ZxDebugWrite` and crosses
the real syscall boundary. This does not make the rest of ZIA operational.

The Phase 6 process slice activates `ZiCreateProcess`, `ZiWaitForObject`,
`ZiWaitForProcess`, and `ZiCloseHandle` through their Zx wrappers. User-mode
Luma proves exact-case creation from ZiFS, a zero-timeout poll, synchronous
wait with signed exit status, deterministic close, and stale-handle rejection.
The public `ZiChannelMessage` record and `ZxSendChannel`, `ZxReceiveChannel`,
and `ZxGetBootstrapChannel` support the narrow SessionHost bootstrap protocol.

Project-owned public calls use PascalCase prefixes:

- `Zi*` for ZIA;
- `Zx*` for the native syscall-facing layer;
- `ZiFs*` for filesystem operations;
- `Zk*` for kernel architecture/executive entry points.

Implementation-only helpers remain `snake_case`. Required ABI names are the
documented narrow exception to the repository's general clang-tidy naming rule.

## Scaffolded

ZIA declarations cover handle, console, file, memory, process, thread, wait,
and system-information work. Console output and the bounded process/wait/close
slice are verified live. File I/O, thread creation, free, general system
information, and most memory management remain explicit
`ZI_STATUS_NOT_IMPLEMENTED` paths or reserved Zx calls.

## Future

Every function needs a versioned contract for ownership, access checks,
cancellation, asynchronous completion, and buffer sizing. The current core
DLLs are early components loaded eagerly from ZiFS; stable public DLL
versioning, a general loader namespace, shared mappings, and safe unload remain
future work.
