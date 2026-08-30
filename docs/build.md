# Build, dependencies, and execution

The primary host is Windows 11 x64. GNU Make and PowerShell call the same Python
build graph; compilation never downloads dependencies.

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

The normal boot test requires architecture, PMM, VMM, temporary mapping,
pool/cache, guarded-stack, memory-stress, timer, pre-emption, ZiFS, framebuffer,
core-service, session-channel, child-process, wait, and user-mode Luma markers
while rejecting panic. The fault test generates separate invalid-opcode,
ordinary page-fault, memory-guard, and user-fault cases. Fatal kernel faults may
not continue; the user-fault case must contain and clean the failed process
before the remaining service/session bootstrap proceeds.

The storage test proves direct QEMU NVMe/GPT mounting and separately contains
an injected controller timeout and dual-GPT corruption. The ZiFS test uses
persistent image copies for twenty-five boots: clean create/reboot, pre-commit
power loss/rollback, post-commit power loss/replay, a 30-record transaction plus
a five-record transaction crossing slot 31 to slot 0, clean rename/move and
reboot, move crashes requiring rollback and replay, clean truncate/delete and
reboot, then separate truncate and delete crashes on both sides of commit with
matching recovery boots. It rejects a Limine-module fallback and any recovery
action other than the one required by each case. A deterministic three-block
file is injected only into those acceptance images so truncate can prove
partial-tail zeroing and multi-block reclamation; normal images remain
unchanged. The final case corrupts a durable ZiFS security record, requires
fail-closed direct-mount rejection, and permits only an explicit clean recovery
module.

COFF compilation uses `/Brepro`, NASM uses `--reproducible`, and each kernel
link starts with a fresh PDB so its age cannot perturb the PE debug record.
The interrupt-stub pointer table intentionally needs 64-bit COFF relocations;
only that assembly file receives NASM's narrow `reloc-abs-qword` warning
suppression.
Repeated debug and release kernel/image builds have been verified byte-for-byte
identical. The PE time-date field contains the linker's reproducibility digest,
not a wall-clock timestamp.

## Scaffolded

The Intel target is validation only and never becomes the default or a product
claim. Cross-host support and reproducible signed release packaging need further
work.

## Future

Continuous integration, signed release artefacts, hermetic toolchains, native
Zizium builds, distributed symbols, and supply-chain attestations are not yet
implemented.
