# PE/COFF native images

PE32+ is Zizium's native executable and module format: `.efi` for firmware/boot
images, `.exe` for user programmes, `.dll` for libraries, and `.sys` for kernel
drivers. ELF is not a native format.

## Implemented in Seed

The bounded parser validates DOS and PE signatures, AMD64 COFF headers, optional
header size and PE32+ magic, image/header alignment and ranges, section-table
bounds, section raw/virtual ranges, entry point, data directories, and the
minimum import/export directory shapes. It never follows an untrusted offset
beyond the supplied image.

`pecheck.exe` identifies kernel, programme, library, and driver expectations
and gives useful failures for malformed images. It verifies the Native
subsystem, DLL characteristic where required, exports for libraries, imports,
and relocations. The kernel is higher-half based, relocatable, import-free, and
linked without default libraries. Native user artefacts and driver placeholders
are PE32+.

The mapping core zeroes the complete target image, copies bounded headers and
raw section data, and applies checked AMD64 DIR64 base relocations while
rejecting unsupported relocation types and malformed blocks. A generic
versioned image-access interface lets the same bounded relocation and
import/export walkers operate on host buffers and process mappings.

The Seed user loader accepts AMD64 Native-subsystem programmes and DLLs with
4 KiB section alignment. It rejects rounded section overlap and sections that
intrude into header pages, finds deterministic free lower-half ranges, can
force the main image away from its preferred base, applies DIR64 relocations,
and stages mappings writable/non-executable before applying read-only headers
and final W^X section permissions. The entry point must lie in an executable
section.

An image set owns at most eight images. Dependency lookup uses exact-case module
names from an explicit source table. Loading is recursive and detects cycles;
imports and exports resolve by name or ordinal, and a missing dependency or
symbol fails without leaving address-space mappings behind. Forwarded exports
fail explicitly with `ZI_STATUS_NOT_IMPLEMENTED`.

The build produces real `zx.dll`, `zicrt.dll`, and `zia.dll` images and their
import libraries. A bounded filesystem source provider parses absolute native
paths, performs exact-case ZiFS lookup, validates regular-file extents, reads
complete images into kernel-pool allocations, and rolls back every allocation
on failure. The PE mapper clears its borrowed raw-source pointers after import
resolution so source ownership may end before execution.

The QEMU smoke test dynamically maps those dependencies from ZiFS and executes
the three acceptance programmes, four core service hand-off programmes,
SessionHost, user-mode Luma, and Luma's nested child. The main images are
deliberately relocated. No `.exe`, `.dll`, or `.sys` is supplied as a Limine
module or copied separately onto the EFI System Partition.

Host fixtures cover signatures, truncation, overlapping or out-of-range
sections, malformed import and export tables, name and ordinal resolution,
missing symbols and modules, cyclic dependencies, relocation blocks and
entries, mapping rollback, contents, and final permissions. `llvm-readobj` and
`pecheck.exe` independently inspect the release artefacts.

## Scaffolded

The source table and ZiFS reader form a real filesystem-backed loader path, but
not a general image namespace or file-object cache. The fixed image-set
capacity, eager whole-file reads, synchronous ownership,
and exact core DLL graph are suitable for Seed acceptance but not arbitrary
application dependency graphs. Driver-image loading, reference-counted shared
DLL mappings, process-to-process page sharing, unload ordering, and loader-lock
semantics remain scaffolded.

## Future

Additional relocation types, delay imports, export forwarders, TLS, load
configuration, unwind data, debug directories, signatures, ASLR entropy,
API-set/version policy, reference tracking, and unload safety need
implementation and hostile-image tests.
