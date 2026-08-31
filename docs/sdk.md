# Zizium SDK

## Intended installed layout

```text
C:\Zizium\SDK\bin
C:\Zizium\SDK\include
C:\Zizium\SDK\lib
C:\Zizium\SDK\crt
C:\Zizium\SDK\tools
C:\Zizium\SDK\examples
C:\Zizium\SDK\docs
```

## Implemented in Seed

The source tree contains public Zizium headers, minimal standard headers, ZiCRT
and syscall assembly start-up objects, three C acceptance examples, and
Windows-host builds of `mkzifs`, `pecheck`, the read-only `zifsinspect`, and the
ZCC scaffold. The normal build emits deterministic `zx.dll`, `zicrt.dll`, and
`zia.dll` images and import libraries together with the three executed
programmes. It also emits scaffolded Luma, RuntimeHost, and two unloaded driver
images.

## Scaffolded

The reserved tool suite is `zcc`, `zld`, `zasm`, `zdbg`, `zpkg`, `mkzifs`,
`pecheck`, `zifsinspect`, `symdump`, `zfmt`, `ztest`, and `zmake`. Only the named
Seed host tools exist; `mkzifs`, `pecheck`, and `zifsinspect` perform
substantive work, while ZCC remains a compiler-driver scaffold.

## Future

Installed headers and libraries require ABI stability, version selection, and
packaging rules. The Seed loader handles only a bounded core dependency graph;
general SDK deployment and library discovery are absent. Debugging, symbols,
assembly, packages, formatting, testing, and native build orchestration remain
future work.

Third-party toolchain material is never silently installed. `make deps` fetches
only the checksummed dependencies declared in `external/dependencies.json`.
