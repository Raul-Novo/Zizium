# Zin and runtime infrastructure

Zin is the future Zizium language, ZinRT its language runtime, and RuntimeHost
the broker for runtime lifecycle and policy. They must use native objects,
security, IPC, and PE integration rather than importing POSIX assumptions.

## Implemented in Seed

`RuntimeHost.exe` is a PE placeholder that links through the current ZiCRT and
core DLL start-up model. The kernel proves that image/import/start-up class with
three dedicated acceptance programmes, but it does not load RuntimeHost or
provide the service, IPC, security, or language-runtime contracts RuntimeHost
requires.

## Scaffolded

`C:\Zizium\Runtime`, `C:\Zizium\System\RuntimeHost.exe`, the RuntimeHost service
manifest, native handles, messages, shared sections, and security identities
reserve integration points.

## Future

The Zin syntax, compiler, bytecode or native-code policy, garbage collection,
metadata, reflection, package integration, debugging, sandboxing, JIT security,
interop, and RuntimeHost implementation are intentionally undefined or
unimplemented. No runtime compatibility promise exists.
