# ZCC compiler plan

ZCC is the future integrated C compiler. The current `zcc.exe` is a Windows-host
driver scaffold, not a compiler.

## Implemented in Seed

The host tool reports its version and frozen target name
`x86_64-pc-zizium-pe`. It rejects compilation with a clear message rather than
pretending to produce an image.

## Scaffolded

Stage one will validate arguments, locate a pinned Clang installation, select
the Zizium PE/COFF target, choose ZiCRT start-up objects, invoke the linker, and
add a ZIA import library only when requested. Quoted Windows-style paths and
spaces must be preserved without shell re-tokenisation.

## Future stages

1. Wrap Clang and the PE linker reproducibly.
2. Understand the Zizium ABI, ZiCRT, SDK layout, and import libraries.
3. Add a custom frontend for an explicitly documented C subset.
4. Grow towards tested C17 and then selected C23 support.
5. Build Zizium from within Zizium.

ZCC will continue to accept standard `main`; it will never require `ZiMain` or
an operating-system header for ordinary C.
