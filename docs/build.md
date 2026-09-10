# Build, dependencies, and execution

The primary host is Windows 11 x64. GNU Make and PowerShell call the same Python
build graph; compilation never downloads dependencies.

The PowerShell build/test entry points load the installed x64 Visual Studio
environment through `vswhere` and `Launch-VsDevShell.ps1` when CRT headers or
the linker are unavailable. They do not download or install tools. Direct
Python build-driver calls still require an x64 Developer PowerShell. An
unconfigured terminal may find Clang but fail on `errno.h` or `string.h`;
the shared helper now prevents that setup failure in ordinary `make` calls.

## Mandatory compiler diagnostics

Every compilation path inherits `-Weverything -Werror` through the central
`source_warning_flags` function in `scripts/build_driver.py`: host tools/tests,
kernel, native programmes/libraries/drivers, header probes, and the optional
Intel C validation path. `clang-cl` forwards these as `/clang:` options.
`/W4 /WX` alone was the earlier policy and is no longer sufficient. Generated
font code also uses the policy because Zizium owns its generator. Limine
headers are passed as external headers; toolchain headers remain system headers.

The host already had LLVM/Clang/Clang-Tidy/clang-format 22.1.8 when this
migration was validated, rather than the previous report's 22.1.6. No toolchain
was downloaded or replaced by this work. The version change is recorded
explicitly: formatting, analysis, host/ASan, full QEMU regression, and repeated
release builds passed with 22.1.8. Revalidate these gates on future updates.

The complete exception inventory is explicit:

| Diagnostic exception | Scope and reason |
| --- | --- |
| `-Wno-declaration-after-statement` | C only. C17 and the style guide require declarations near first use; C90 compatibility is not a target. |
| `-Wno-pre-c11-compat` | C only. C17 requires `_Static_assert`, `_Alignof`, and other C11 features. |
| `-Wno-c++-compat` | C only. C++ source compatibility is not required for C implementations: implicit `void*` conversion, C `wchar_t`, and cleanup jumps remain valid C. Uninitialised-value diagnostics stay enabled. |
| `-Wno-unsafe-buffer-usage` | C only. This raw-buffer migration diagnostic rejects even checked pointer/length operations. The C17 ABI and byte codecs use explicit bounds contracts, not C++ containers. This is not an exemption from range validation, bounds diagnostics, sanitisation, or adversarial tests. |
| `-Wno-padded` | C only. Natural alignment padding in internal structures is intentional. Persistent data uses byte codecs; contractual ABI offsets and sizes use assertions. Packing or adding dummy fields just to silence this diagnostic is forbidden. |
| `-Wno-covered-switch-default` | Only `tools/pecheck/main.c`. An exhaustive kind switch keeps a defensive invalid-value fallback; `-Wswitch-enum` still requires every named kind. |

LLVM documents the raw-buffer diagnostic as part of its
[C++ Safe Buffers model](https://clang.llvm.org/docs/SafeBuffers.html).
No alignment, conversion, aliasing, lifetime, or actual bounds diagnostic is
disabled. C-only exceptions must not be inherited by a future C++ target.
Adding an exception requires an individual architectural justification, not a
passing-build rationale. Check the recorded commands and outcomes in the
progress report before treating this migration as fully validated.

## Commands

```powershell
make deps
make
make test
make image
make run
make boot-test
make storage-test
make zifs-test
make fault-test
make release
make analyse
make sanitise
make intel
```

The normal toolchain is `clang-cl` plus Microsoft `link.exe`; setting
`ZI_USE_LLD_LINK=1` selects the documented `lld-link` development fallback.
NASM owns the small x64 assembly layer. QEMU and EDK2 run the boot image.

Pinned dependencies are declared by URL, version, licence, and SHA-256 in
`external/dependencies.json`. `make deps` downloads only beneath
`external/deps`, verifies each checksum before extraction, and preserves
third-party notices. Required items are Limine 12.5.2, Limine protocol commit
630686a, Spleen 2.2.0, and Unicode 17.0.0 UCD.

`ZI_OVMF_CODE` and `ZI_OVMF_VARS_TEMPLATE` override firmware discovery. The
installed variable template is copied beneath `build/`. QEMU defaults to q35,
TCG, 512 MiB, no network, and the generated GPT disk.

## Implemented

Debug/release builds, host tests, image generation, QEMU smoke testing, format
checking, clang-tidy with project diagnostics treated as errors, sanitised host
tests, and an optional separate Intel compiler validation target are present.
Missing tools and dependencies produce actionable failures.

Every image build runs `zifsinspect.exe` against both the raw root volume and
the frozen-GUID GPT partition. `make test` and `make sanitise` additionally run
thirteen inspector fixtures and compare each fixture's SHA-256 before and after
the tool, proving that validation is non-mutating. Valid metadata exits with zero;
recovery-required or corrupt metadata exits with one; invocation errors exit
with two.

The same host gates build and exercise the separate `zifsrepair.exe`. Its
read-only plan and exclusive apply commands cover raw and GPT containers,
SHA-256 review-token rejection, stale-plan rejection, fixed-point replanning,
fail-closed corruption cases, and Windows UTF-16 paths containing spaces and
non-ASCII characters.

The normal boot test requires architecture, PMM, VMM, temporary mapping,
pool/cache, guarded-stack, memory-stress, timer, pre-emption, ZiFS, framebuffer,
core-service, session-channel, child-process, wait, and user-mode Luma markers
while rejecting panic. The fault test generates separate invalid-opcode,
ordinary page-fault, memory-guard, and user-fault cases. Fatal kernel faults may
not continue; the user-fault case must contain and clean the failed process
before the remaining service/session bootstrap proceeds.

The storage test proves direct QEMU NVMe/GPT mounting and separately contains
an injected controller timeout and dual-GPT corruption. The ZiFS test uses
persistent image copies for thirty-two boots: clean unmount/reboot,
interrupted-unmount diagnosis/recovery, clean create/reboot,
pre-commit power loss/rollback, post-commit power loss/replay, a 30-record
transaction plus a five-record transaction crossing slot 31 to slot 0, clean
rename/move and reboot, bounded regular-file growth plus multi-block directory
expansion and reboot, move crashes requiring rollback and replay, clean
truncate/delete and reboot, then separate truncate and delete crashes on both
sides of commit with matching recovery boots. It rejects a Limine-module
fallback and any recovery action other than the one required by each case. A
deterministic three-block file is injected only into those acceptance images so
truncate can prove partial-tail zeroing and multi-block reclamation; normal
images remain unchanged. The final case corrupts a durable ZiFS security
record, requires fail-closed direct-mount rejection, and permits only an
explicit clean recovery module. A further GPT case applies a reviewed three-
block offline repair, verifies an empty second plan, and reboots directly from
the repaired ZiFS partition without kernel recovery. The suite invokes the read-only inspector
after clean unmount, at an interrupted-unmount boundary, after clean creation,
immediately after the committed pre-checkpoint crash, and after directory
expansion/file growth. Clean checkpoints must validate ordinary on-disk
metadata; interrupted cases must report recovery required, the transaction
crash must validate a memory-only replay overlay, and every inspection must
leave the image byte-for-byte unchanged.

COFF compilation uses `/Brepro`, NASM uses `--reproducible`, and each kernel
link starts with a fresh PDB so its age cannot perturb the PE debug record.
The interrupt-stub pointer table intentionally needs 64-bit COFF relocations;
only that assembly file receives NASM's narrow `reloc-abs-qword` warning
suppression.
Repeated debug and release kernel/image builds have been verified byte-for-byte
identical. The PE time-date field contains the linker's reproducibility digest,
not a wall-clock timestamp. The latest release check also compared all 21
kernel, native PE, import/static library, root-volume, and disk-image artefacts
across consecutive builds without a difference.

## Scaffolded

The Intel target is validation only and never becomes the default or a product
claim. Cross-host support and reproducible signed release packaging need further
work.

The optional Intel target resolves `libircmt.lib` next to the selected `icx`
installation, or uses an explicitly configured matching library path. Adding
only the compiler executable to PATH is insufficient without that runtime.
Failure leaves the normal artefacts intact and reports the missing setup.

## Future

Continuous integration, signed release artefacts, hermetic toolchains, native
Zizium builds, distributed symbols, and supply-chain attestations are not yet
implemented.
