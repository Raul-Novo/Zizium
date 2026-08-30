# SPDX-License-Identifier: GPL-3.0-or-later
"""Single build graph used by Make and the PowerShell entry points."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

CORE_SOURCES = (
    "kernel/runtime/byte_order.c",
    "kernel/runtime/crc32.c",
    "kernel/runtime/crc32c.c",
    "kernel/mm/pmm/pmm.c",
    "kernel/mm/pool/pool.c",
    "kernel/mm/vmm/x64_paging.c",
    "kernel/arch/x64/descriptor.c",
    "kernel/arch/x64/interrupt_frame.c",
    "kernel/unicode/unicode.c",
    "kernel/fs/vfs/path.c",
    "kernel/display/display.c",
    "kernel/executive/security/access_check.c",
    "kernel/executive/runtime/executive_lock.c",
    "kernel/executive/object/object.c",
    "kernel/executive/wait/dispatcher.c",
    "kernel/executive/scheduler/scheduler.c",
    "kernel/terminal/terminal.c",
    "kernel/terminal/font.c",
    "userland/luma/luma_parser.c",
    "kernel/pe/pe.c",
    "kernel/pe/user_image.c",
    "kernel/pe/zifs_image_source.c",
    "kernel/fs/zifs/zifs.c",
    "kernel/fs/zifs/security.c",
    "kernel/fs/zifs/journal.c",
    "kernel/fs/zifs/transaction.c",
    "kernel/fs/zifs/recovery.c",
    "kernel/io/storage/block.c",
    "kernel/io/storage/gpt.c",
    "kernel/io/bus/acpi.c",
    "kernel/io/bus/pci.c",
    "kernel/input/input.c",
    "kernel/io/manager/io_manager.c",
    "kernel/io/manager/dma.c",
    "kernel/io/driver/driver.c",
    "kernel/executive/ipc/ipc.c",
    "kernel/executive/service/manifest.c",
    "kernel/executive/handle/handle.c",
    "kernel/executive/process/address_space.c",
    "kernel/executive/process/parameters.c",
    "kernel/executive/process/process_record.c",
    "kernel/arch/x64/syscall/dispatch.c",
)

KERNEL_ONLY_SOURCES = (
    "kernel/runtime/freestanding.c",
    "kernel/mm/manager.c",
    "kernel/mm/stress.c",
    "kernel/mm/pool/kernel_pool.c",
    "kernel/mm/vmm/manager.c",
    "kernel/mm/vmm/mmio.c",
    "kernel/mm/stack/stack.c",
    "kernel/executive/process/process.c",
    "kernel/executive/ipc/phase4_acceptance.c",
    "kernel/arch/x64/cpu.c",
    "kernel/arch/x64/descriptor_tables.c",
    "kernel/arch/x64/interrupts.c",
    "kernel/arch/x64/apic.c",
    "kernel/arch/x64/preemption.c",
    "kernel/io/bus/pci_ecam.c",
    "kernel/io/manager/kernel_dma.c",
    "kernel/io/storage/nvme.c",
    "kernel/io/storage/bootstrap.c",
    "kernel/init/system_bootstrap.c",
    "kernel/arch/x64/serial.c",
    "kernel/debug/log.c",
    "kernel/terminal/framebuffer_console.c",
    "boot/limine/adapter.c",
    "kernel/init/main.c",
    "userland/luma/early_shell.c",
)

KERNEL_ASSEMBLY_SOURCES = (
    "kernel/arch/x64/asm/entry.asm",
    "kernel/arch/x64/asm/cpu.asm",
    "kernel/arch/x64/asm/interrupts.asm",
    "kernel/arch/x64/asm/syscall.asm",
)


class BuildFailure(RuntimeError):
    """Raised for an expected, user-actionable build failure."""


def run(
    command: list[str],
    *,
    root: Path,
    capture: bool = False,
    environment: dict[str, str] | None = None,
) -> str:
    print("+ " + subprocess.list2cmdline(command), flush=True)
    result = subprocess.run(
        command,
        cwd=root,
        check=False,
        text=True,
        env=environment,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    if result.returncode != 0:
        if result.stdout:
            print(result.stdout, end="")
        raise BuildFailure(f"Command failed with exit code {result.returncode}.")
    return result.stdout or ""


def require_tool(name: str, installation_hint: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise BuildFailure(f"Required tool '{name}' was not found. {installation_hint}")
    return path


def generate_font(root: Path, build_root: Path) -> Path:
    input_path = (
        root / "external" / "deps" / "spleen" / "spleen-2.2.0" / "spleen-8x16.bdf"
    )
    if not input_path.is_file():
        raise BuildFailure(
            "Pinned Spleen 2.2.0 is missing. Run 'make deps' before building."
        )
    output_path = build_root / "generated" / "zi_font_spleen.c"
    run(
        [
            sys.executable,
            str(root / "scripts" / "generate_font.py"),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
        root=root,
    )
    return output_path


def compile_host_source(
    compiler: str,
    root: Path,
    source: Path,
    output: Path,
    configuration: str,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    flags = [
        compiler,
        "/nologo",
        "/c",
        "/std:c17",
        "/utf-8",
        "/W4",
        "/WX",
        "/Brepro",
        f"/I{root / 'sdk' / 'include'}",
        f"/I{root / 'kernel' / 'include'}",
        f"/Fo{output}",
    ]
    if configuration == "release":
        flags.extend(["/O2", "/DNDEBUG"])
    elif configuration == "sanitised":
        flags.extend(["/Od", "/Zi", "/DZI_DEBUG=1", "/fsanitize=address"])
    else:
        flags.extend(["/Od", "/Zi", "/DZI_DEBUG=1"])
    flags.append(str(source))
    run(flags, root=root)


def link_host_executable(
    compiler: str,
    root: Path,
    objects: list[Path],
    output: Path,
    configuration: str,
    sanitised: bool = False,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [compiler, "/nologo", *map(str, objects), f"/Fe{output}"]
    if configuration != "release":
        command.append("/Zi")
    if sanitised:
        command.append("/fsanitize=address")
    run(command, root=root)


def host_build(root: Path, configuration: str, *, sanitised: bool = False) -> Path:
    sanitised = sanitised or configuration == "sanitised"
    compiler = require_tool(
        "clang-cl", "Install LLVM 22 or later and add its bin directory to PATH."
    )
    build_root = root / "build" / configuration
    object_root = build_root / "obj" / "host"
    generated_font = generate_font(root, build_root)
    common_objects: list[Path] = []
    sources = [root / relative_source for relative_source in CORE_SOURCES] + [
        generated_font
    ]
    for source in sources:
        try:
            object_name = source.relative_to(root)
        except ValueError:
            object_name = Path("generated") / source.name
        output = object_root / object_name.with_suffix(".obj")
        compile_host_source(compiler, root, source, output, configuration)
        common_objects.append(output)

    tool_definitions = {
        "mkzifs.exe": (root / "tools" / "mkzifs" / "main.c",),
        "pecheck.exe": (root / "tools" / "pecheck" / "main.c",),
        "zifsinspect.exe": (
            root / "tools" / "zifsinspect" / "main.c",
            root / "tools" / "zifsinspect" / "inspect.c",
        ),
        "zsvccheck.exe": (root / "tools" / "zsvccheck" / "main.c",),
        "zcc.exe": (root / "tools" / "zcc" / "main.c",),
    }
    tool_support_objects: list[Path] = []
    for output_name, tool_sources in tool_definitions.items():
        tool_objects: list[Path] = []
        for source in tool_sources:
            tool_object = (
                object_root / "tools" / f"{source.parent.name}_{source.stem}.obj"
            )
            compile_host_source(compiler, root, source, tool_object, configuration)
            tool_objects.append(tool_object)
            if output_name == "zifsinspect.exe" and source.stem == "inspect":
                tool_support_objects.append(tool_object)
        link_host_executable(
            compiler,
            root,
            common_objects + tool_objects,
            build_root / "host" / output_name,
            configuration,
            sanitised=sanitised,
        )

    test_sources = sorted((root / "tests" / "host").glob("*_test.c"))
    test_main = root / "tests" / "host" / "test_main.c"
    if test_main.exists():
        test_sources.append(test_main)
        test_objects: list[Path] = []
        for test_source in test_sources:
            test_object = object_root / "tests" / test_source.with_suffix(".obj").name
            compile_host_source(compiler, root, test_source, test_object, configuration)
            test_objects.append(test_object)
        link_host_executable(
            compiler,
            root,
            common_objects + tool_support_objects + test_objects,
            build_root / "tests" / "zizium_host_tests.exe",
            configuration,
            sanitised=sanitised,
        )
    return build_root


def compile_kernel_source(
    compiler: str,
    root: Path,
    source: Path,
    output: Path,
    configuration: str,
    *,
    extra_flags: tuple[str, ...] = (),
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        compiler,
        "/nologo",
        "/c",
        "/std:c17",
        "/utf-8",
        "/W4",
        "/WX",
        "/Brepro",
        "/GS-",
        "/Zl",
        "/DZI_KERNEL=1",
        "/clang:-ffreestanding",
        "/clang:-fno-builtin",
        *extra_flags,
        f"/I{root / 'sdk' / 'include'}",
        f"/I{root / 'kernel' / 'include'}",
        f"/I{root / 'external' / 'deps' / 'limine-protocol'}",
        f"/Fo{output}",
    ]
    if configuration == "release":
        command.extend(["/O2", "/DNDEBUG"])
    else:
        command.extend(["/O1", "/Zi", "/DZI_DEBUG=1"])
    command.append(str(source))
    run(command, root=root)


def kernel_build(
    root: Path, configuration: str, build_root: Path | None = None
) -> Path:
    compiler = require_tool(
        "clang-cl", "Install LLVM 22 or later and add its bin directory to PATH."
    )
    assembler = require_tool("nasm", "Install NASM 3 or later and add it to PATH.")
    if build_root is None:
        build_root = root / "build" / configuration
    protocol_header = root / "external" / "deps" / "limine-protocol" / "limine.h"
    if not protocol_header.is_file():
        raise BuildFailure(
            "Pinned Limine protocol headers are missing. Run 'make deps'."
        )
    generated_font = generate_font(root, build_root)
    object_root = build_root / "obj" / "kernel"
    objects: list[Path] = []
    sources = [root / source for source in CORE_SOURCES + KERNEL_ONLY_SOURCES]
    sources.append(generated_font)
    for source in sources:
        try:
            object_name = source.relative_to(root)
        except ValueError:
            object_name = Path("generated") / source.name
        output = object_root / object_name.with_suffix(".obj")
        compile_kernel_source(compiler, root, source, output, configuration)
        objects.append(output)

    for relative_source in KERNEL_ASSEMBLY_SOURCES:
        assembly_source = root / relative_source
        assembly_object = object_root / Path(relative_source).with_suffix(".obj")
        assembly_object.parent.mkdir(parents=True, exist_ok=True)
        warning_options = ["-w-reloc-rel-dword"]
        if assembly_source.name == "interrupts.asm":
            # The table deliberately stores one 64-bit COFF relocation per stub.
            warning_options.append("-w-reloc-abs-qword")
        run(
            [
                assembler,
                "-f",
                "win64",
                "-Wall",
                "-Werror",
                "--reproducible",
                *warning_options,
                "-o",
                str(assembly_object),
                str(assembly_source),
            ],
            root=root,
        )
        objects.append(assembly_object)

    use_lld = os.environ.get("ZI_USE_LLD_LINK") == "1"
    linker_name = "lld-link" if use_lld else "link"
    linker = shutil.which(linker_name)
    if linker is None and not use_lld:
        linker = shutil.which("lld-link")
        if linker is not None:
            print(
                "MSVC link.exe was not found; using the documented lld-link fallback."
            )
    if linker is None:
        raise BuildFailure(
            "Neither MSVC link.exe nor lld-link is available. Install Visual Studio Build Tools or LLVM."
        )
    kernel_directory = build_root / "kernel"
    kernel_directory.mkdir(parents=True, exist_ok=True)
    kernel_path = kernel_directory / "zizium.efi"
    pdb_path = kernel_directory / "zizium.pdb"
    # Reusing an existing PDB increments its age and changes the PE debug record,
    # even with /Brepro. Start a fresh deterministic symbol database each time.
    if pdb_path.exists():
        pdb_path.unlink()
    link_command = [
        linker,
        "/nologo",
        "/machine:x64",
        "/subsystem:native",
        "/entry:ZkBootEntry",
        "/nodefaultlib",
        "/dynamicbase",
        "/fixed:no",
        "/base:0xfffff80000000000",
        "/filealign:512",
        "/incremental:no",
        "/opt:ref",
        "/opt:icf",
        "/Brepro",
        "/debug:full",
        f"/pdb:{pdb_path}",
        f"/out:{kernel_path}",
        "/include:g_limine_requests_start_marker",
        "/include:g_limine_requests_end_marker",
        "/include:g_limine_base_revision",
        "/include:g_zk_relocation_anchor",
        *map(str, objects),
    ]
    run(link_command, root=root)
    return kernel_path


def native_artifacts_build(
    root: Path, configuration: str, build_root: Path
) -> list[Path]:
    compiler = require_tool(
        "clang-cl", "Install LLVM 22 or later and add its bin directory to PATH."
    )
    assembler = require_tool("nasm", "Install NASM 3 or later and add it to PATH.")
    linker = shutil.which("link") or shutil.which("lld-link")
    if linker is None:
        raise BuildFailure("Native PE scaffolds require MSVC link.exe or lld-link.")
    object_root = build_root / "obj" / "native"
    object_root.mkdir(parents=True, exist_ok=True)
    crt_include = f"/I{root / 'sdk' / 'crt' / 'include'}"

    crt_start_source = root / "sdk" / "crt" / "start.c"
    crt_start_object = object_root / "zicrt_start.obj"
    compile_kernel_source(
        compiler,
        root,
        crt_start_source,
        crt_start_object,
        configuration,
        extra_flags=(crt_include,),
    )
    crt_stdio_source = root / "sdk" / "crt" / "stdio.c"
    crt_stdio_object = object_root / "zicrt_stdio.obj"
    compile_kernel_source(
        compiler,
        root,
        crt_stdio_source,
        crt_stdio_object,
        configuration,
        extra_flags=(crt_include,),
    )
    crt_process_source = root / "sdk" / "crt" / "process.c"
    crt_process_object = object_root / "zicrt_process.obj"
    compile_kernel_source(
        compiler,
        root,
        crt_process_source,
        crt_process_object,
        configuration,
        extra_flags=(crt_include,),
    )
    crt_memory_source = root / "sdk" / "crt" / "memory.c"
    crt_memory_object = object_root / "zicrt_memory.obj"
    compile_kernel_source(
        compiler,
        root,
        crt_memory_source,
        crt_memory_object,
        configuration,
        extra_flags=(crt_include,),
    )
    zia_source = root / "sdk" / "zia" / "zia.c"
    zia_object = object_root / "zia.obj"
    compile_kernel_source(compiler, root, zia_source, zia_object, configuration)
    crt_assembly = root / "sdk" / "crt" / "x64" / "start.asm"
    crt_entry = object_root / "zicrt_entry.obj"
    syscall_assembly = root / "sdk" / "zx" / "x64" / "syscall.asm"
    syscall_object = object_root / "zx_syscall.obj"
    nasm_common = [
        assembler,
        "-f",
        "win64",
        "-Wall",
        "-Werror",
        "--reproducible",
        "-w-reloc-rel-dword",
    ]
    run([*nasm_common, "-o", str(crt_entry), str(crt_assembly)], root=root)
    run([*nasm_common, "-o", str(syscall_object), str(syscall_assembly)], root=root)

    output_directory = build_root / "native"
    output_directory.mkdir(parents=True, exist_ok=True)
    outputs: list[Path] = []

    zx_library = output_directory / "zx.dll"
    zx_import_library = output_directory / "zx.lib"
    run(
        [
            linker,
            "/nologo",
            "/dll",
            "/noentry",
            "/machine:x64",
            "/subsystem:native",
            "/nodefaultlib",
            "/dynamicbase",
            "/fixed:no",
            "/base:0x180000000",
            "/incremental:no",
            "/Brepro",
            f"/out:{zx_library}",
            f"/implib:{zx_import_library}",
            "/export:ZxCloseHandle",
            "/export:ZxWaitForObject",
            "/export:ZxExitProcess",
            "/export:ZxCreateProcess",
            "/export:ZxAllocateVirtualMemory",
            "/export:ZxSendChannel",
            "/export:ZxReceiveChannel",
            "/export:ZxGetBootstrapChannel",
            "/export:ZxDebugWrite",
            str(syscall_object),
        ],
        root=root,
    )
    outputs.append(zx_library)

    zicrt_library = output_directory / "zicrt.dll"
    zicrt_import_library = output_directory / "zicrt.lib"
    run(
        [
            linker,
            "/nologo",
            "/dll",
            "/noentry",
            "/machine:x64",
            "/subsystem:native",
            "/nodefaultlib",
            "/dynamicbase",
            "/fixed:no",
            "/base:0x181000000",
            "/incremental:no",
            "/Brepro",
            f"/out:{zicrt_library}",
            f"/implib:{zicrt_import_library}",
            "/export:puts",
            "/export:getenv",
            "/export:memcpy",
            "/export:memset",
            "/export:memcmp",
            "/export:ZiCrtInitialiseProcess",
            str(crt_stdio_object),
            str(crt_process_object),
            str(crt_memory_object),
            str(zx_import_library),
        ],
        root=root,
    )
    outputs.append(zicrt_library)

    zia_library = output_directory / "zia.dll"
    zia_import_library = output_directory / "zia.lib"
    run(
        [
            linker,
            "/nologo",
            "/dll",
            "/noentry",
            "/machine:x64",
            "/subsystem:native",
            "/nodefaultlib",
            "/dynamicbase",
            "/fixed:no",
            "/base:0x182000000",
            "/incremental:no",
            "/Brepro",
            f"/out:{zia_library}",
            f"/implib:{zia_import_library}",
            "/export:ZiCloseHandle",
            "/export:ZiConsoleWrite",
            "/export:ZiCreateFile",
            "/export:ZiOpenFile",
            "/export:ZiReadFile",
            "/export:ZiWriteFile",
            "/export:ZiAllocateMemory",
            "/export:ZiFreeMemory",
            "/export:ZiCreateProcess",
            "/export:ZiCreateThread",
            "/export:ZiWaitForObject",
            "/export:ZiWaitForProcess",
            "/export:ZiQuerySystemInformation",
            str(zia_object),
            str(zx_import_library),
        ],
        root=root,
    )
    outputs.append(zia_library)

    programmes = {
        "hello_standard.exe": root / "userland" / "examples" / "hello_standard.c",
        "hello_arguments.exe": root / "userland" / "examples" / "hello_arguments.c",
        "hello_native.exe": root / "userland" / "examples" / "hello_native.c",
        "luma.exe": root / "userland" / "luma" / "main.c",
        "ServiceHost.exe": root / "userland" / "services" / "service_host" / "main.c",
        "SecurityHost.exe": root / "userland" / "services" / "security_host" / "main.c",
        "LogHost.exe": root / "userland" / "services" / "log_host" / "main.c",
        "MountHost.exe": root / "userland" / "services" / "mount_host" / "main.c",
        "SessionHost.exe": root / "userland" / "services" / "session_host" / "main.c",
        "RuntimeHost.exe": root / "userland" / "services" / "runtime_host" / "main.c",
    }
    luma_support_objects: list[Path] = []
    for support_name, support_source in (
        ("luma_parser", root / "userland" / "luma" / "luma_parser.c"),
        ("luma_unicode", root / "kernel" / "unicode" / "unicode.c"),
    ):
        support_object = object_root / f"{support_name}.obj"
        compile_kernel_source(
            compiler, root, support_source, support_object, configuration
        )
        luma_support_objects.append(support_object)
    for output_name, source in programmes.items():
        source_object = object_root / f"{source.parent.name}_{source.stem}.obj"
        compile_kernel_source(
            compiler,
            root,
            source,
            source_object,
            configuration,
            extra_flags=(crt_include,),
        )
        output = output_directory / output_name
        programme_support = luma_support_objects if output_name == "luma.exe" else []
        run(
            [
                linker,
                "/nologo",
                "/machine:x64",
                "/subsystem:native",
                "/entry:ZiCrtStart",
                "/nodefaultlib",
                "/dynamicbase",
                "/fixed:no",
                "/base:0x140000000",
                "/incremental:no",
                "/Brepro",
                f"/out:{output}",
                str(crt_entry),
                str(crt_start_object),
                str(source_object),
                *map(str, programme_support),
                str(zicrt_import_library),
                str(zx_import_library),
                str(zia_import_library),
            ],
            root=root,
        )
        outputs.append(output)

    drivers = {
        "keyboard.sys": root / "drivers" / "input" / "keyboard" / "main.c",
        "framebuffer.sys": root / "drivers" / "display" / "framebuffer" / "main.c",
    }
    for output_name, source in drivers.items():
        source_object = object_root / f"driver_{source.parent.name}.obj"
        compile_kernel_source(compiler, root, source, source_object, configuration)
        output = output_directory / output_name
        run(
            [
                linker,
                "/nologo",
                "/machine:x64",
                "/subsystem:native",
                "/entry:ZiDriverMain",
                "/nodefaultlib",
                "/dynamicbase",
                "/fixed:no",
                "/base:0x180000000",
                "/incremental:no",
                "/Brepro",
                f"/out:{output}",
                str(source_object),
            ],
            root=root,
        )
        outputs.append(output)
    return outputs


def header_check(root: Path, configuration: str) -> None:
    compiler = require_tool(
        "clang-cl", "Install LLVM 22 or later and add its bin directory to PATH."
    )
    probe = root / "tests" / "host" / "header_probe.c"
    output_root = root / "build" / configuration / "obj" / "header-check"
    output_root.mkdir(parents=True, exist_ok=True)
    headers = sorted((root / "kernel" / "include" / "zi").glob("*.h"))
    headers.extend(sorted((root / "sdk" / "include").rglob("*.h")))
    headers.extend(sorted((root / "sdk" / "crt" / "include").rglob("*.h")))
    for index, header in enumerate(headers):
        output = output_root / f"header_{index:02d}.obj"
        run(
            [
                compiler,
                "/nologo",
                "/c",
                "/std:c17",
                "/utf-8",
                "/W4",
                "/WX",
                f"/I{root / 'sdk' / 'include'}",
                f"/I{root / 'sdk' / 'crt' / 'include'}",
                f"/I{root / 'kernel' / 'include'}",
                f"/FI{header}",
                f"/Fo{output}",
                str(probe),
            ],
            root=root,
        )


def spelling_check(root: Path) -> None:
    run([sys.executable, str(root / "scripts" / "check_spelling.py")], root=root)


def intel_validation(root: Path, configuration: str) -> Path:
    compiler = require_tool(
        "icx", "Install Intel oneAPI DPC++/C++ Compiler 2026 or later."
    )
    build_root = root / "build" / configuration
    generated_font = generate_font(root, build_root)
    output = build_root / "tests" / "zizium_host_tests_intel.exe"
    output.parent.mkdir(parents=True, exist_ok=True)
    sources = [str(root / source) for source in CORE_SOURCES]
    sources.append(str(generated_font))
    sources.extend(
        str(path) for path in sorted((root / "tests" / "host").glob("*_test.c"))
    )
    sources.append(str(root / "tests" / "host" / "test_main.c"))
    command = [
        compiler,
        "/nologo",
        "/std:c17",
        "/utf-8",
        "/W4",
        "/WX",
        "/Brepro",
        f"/I{root / 'sdk' / 'include'}",
        f"/I{root / 'kernel' / 'include'}",
    ]
    if configuration == "release":
        command.extend(["/O2", "/DNDEBUG"])
    else:
        command.extend(["/Od", "/Zi", "/DZI_DEBUG=1"])
    command.extend([*sources, f"/Fe{output}"])
    run(command, root=root)
    run([str(output)], root=root)
    return output


def image_build(
    root: Path,
    configuration: str,
    build_root: Path,
    kernel_path: Path,
    *,
    limine_configuration: Path | None = None,
    image_name: str = "zizium.img",
    native_outputs: list[Path] | None = None,
    additional_zifs_inputs: dict[str, Path] | None = None,
) -> Path:
    image_directory = build_root / "images"
    image_directory.mkdir(parents=True, exist_ok=True)
    zifs_path = image_directory / "zizium-root.zifs"
    mkzifs = build_root / "host" / "mkzifs.exe"
    limine_efi = root / "external" / "deps" / "limine" / "limine-binary" / "BOOTX64.EFI"
    if not limine_efi.is_file():
        raise BuildFailure("Pinned Limine v12.5.2 is missing. Run 'make deps'.")
    if limine_configuration is None:
        limine_configuration = root / "boot" / "limine" / "limine.conf"
    if native_outputs is None:
        native_outputs = list((build_root / "native").glob("*"))
    output_by_name = {path.name: path for path in native_outputs}
    zifs_destinations = {
        "hello_standard.exe": "Zizium/System/hello_standard.exe",
        "hello_arguments.exe": "Zizium/System/hello_arguments.exe",
        "hello_native.exe": "Zizium/System/hello_native.exe",
        "RuntimeHost.exe": "Zizium/System/RuntimeHost.exe",
        "ServiceHost.exe": "Zizium/System/ServiceHost.exe",
        "SecurityHost.exe": "Zizium/System/SecurityHost.exe",
        "LogHost.exe": "Zizium/System/LogHost.exe",
        "MountHost.exe": "Zizium/System/MountHost.exe",
        "SessionHost.exe": "Zizium/System/SessionHost.exe",
        "luma.exe": "Zizium/Shell/luma.exe",
        "zx.dll": "Zizium/System21/Libraries/zx.dll",
        "zicrt.dll": "Zizium/System21/Libraries/zicrt.dll",
        "zia.dll": "Zizium/System21/Libraries/zia.dll",
        "keyboard.sys": "Zizium/Drivers/keyboard.sys",
        "framebuffer.sys": "Zizium/Drivers/framebuffer.sys",
    }
    missing_zifs_files = [
        name for name in zifs_destinations if name not in output_by_name
    ]
    if missing_zifs_files:
        raise BuildFailure(
            "The native build is missing required ZiFS files: "
            + ", ".join(missing_zifs_files)
        )
    zifs_inputs = {
        destination: output_by_name[name]
        for name, destination in zifs_destinations.items()
    }
    zifs_inputs["Program Files/Zizium/Hello Seed.exe"] = output_by_name[
        "hello_standard.exe"
    ]
    for manifest in sorted(
        (root / "userland" / "services" / "manifests").glob("*.zsvc")
    ):
        zifs_inputs[f"Zizium/Services/{manifest.name}"] = manifest
    if additional_zifs_inputs is not None:
        collisions = sorted(set(zifs_inputs).intersection(additional_zifs_inputs))
        if collisions:
            raise BuildFailure(
                "Additional ZiFS inputs collide with system paths: "
                + ", ".join(collisions)
            )
        zifs_inputs.update(additional_zifs_inputs)
    format_command = [str(mkzifs), str(zifs_path), "32"]
    for destination, source in sorted(zifs_inputs.items()):
        native_destination = "C:\\" + destination.replace("/", "\\")
        format_command.extend(["--file", native_destination, str(source)])
    run(format_command, root=root)
    configuration_text = limine_configuration.read_text(encoding="utf-8")
    forbidden_module_suffixes = (".exe", ".dll", ".sys")
    for line in configuration_text.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("module_path:") and stripped.endswith(
            forbidden_module_suffixes
        ):
            raise BuildFailure(
                "Native programmes, libraries, and drivers must come from ZiFS, "
                "not Limine modules."
            )
    output = image_directory / image_name
    command = [
        sys.executable,
        str(root / "scripts" / "make_image.py"),
        "--output",
        str(output),
        "--limine",
        str(limine_efi),
        "--configuration",
        str(limine_configuration),
        "--kernel",
        str(kernel_path),
        "--zifs",
        str(zifs_path),
    ]
    run(command, root=root)
    inspector = build_root / "host" / "zifsinspect.exe"
    run([str(inspector), "--raw", str(zifs_path)], root=root)
    run([str(inspector), "--gpt", str(output)], root=root)
    return output


def locate_firmware() -> tuple[Path, Path]:
    configured_code = os.environ.get("ZI_OVMF_CODE")
    configured_variables = os.environ.get("ZI_OVMF_VARS_TEMPLATE")
    candidates: list[tuple[Path, Path]] = []
    if configured_code and configured_variables:
        candidates.append((Path(configured_code), Path(configured_variables)))
    candidates.extend(
        [
            (
                Path(r"C:\Program Files\qemu\share\edk2-x86_64-code.fd"),
                Path(r"C:\Program Files\qemu\share\edk2-i386-vars.fd"),
            ),
            (
                Path(r"C:\Program Files\qemu\share\OVMF_CODE.fd"),
                Path(r"C:\Program Files\qemu\share\OVMF_VARS.fd"),
            ),
        ]
    )
    for code, variables in candidates:
        if code.is_file() and variables.is_file():
            return code, variables
    raise BuildFailure(
        "EDK2 x86-64 firmware was not found. Set ZI_OVMF_CODE and "
        "ZI_OVMF_VARS_TEMPLATE to installed firmware files."
    )


def qemu_base_command(
    root: Path,
    build_root: Path,
    image_path: Path,
    variables_path: Path,
    *,
    disk_snapshot: bool = False,
    boot_image_path: Path | None = None,
) -> list[str]:
    del root
    qemu = require_tool(
        "qemu-system-x86_64",
        "Install QEMU 11 or later and ensure qemu-system-x86_64 is on PATH.",
    )
    code_path, _ = locate_firmware()
    disk_options = "if=none,id=zi_storage,format=raw"
    if disk_snapshot:
        disk_options += ",snapshot=on"
    disk_options += f",file={image_path}"
    command = [
        qemu,
        "-machine",
        "q35,accel=tcg",
        "-cpu",
        "max",
        "-m",
        "512M",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={code_path}",
        "-drive",
        f"if=pflash,format=raw,file={variables_path}",
        "-drive",
        disk_options,
        "-device",
        "nvme,drive=zi_storage,serial=ZIZIUMSEED",
    ]
    if boot_image_path is not None:
        boot_disk_options = "if=ide,index=0,media=disk,format=raw"
        if disk_snapshot:
            boot_disk_options += ",snapshot=on"
        boot_disk_options += f",file={boot_image_path}"
        command.extend(["-drive", boot_disk_options])
    command.extend(
        [
            "-boot",
            "c",
            "-no-reboot",
            "-no-shutdown",
            "-net",
            "none",
            "-monitor",
            "none",
            "-name",
            f"Zizium Seed ({build_root.name})",
        ]
    )
    return command


def prepare_qemu(root: Path, configuration: str) -> tuple[Path, Path, Path]:
    build_root = host_build(root, configuration)
    kernel_path = kernel_build(root, configuration, build_root)
    native_outputs = native_artifacts_build(root, configuration, build_root)
    run(
        [
            str(build_root / "host" / "pecheck.exe"),
            "--kind",
            "kernel",
            str(kernel_path),
        ],
        root=root,
    )
    image_path = image_build(
        root, configuration, build_root, kernel_path, native_outputs=native_outputs
    )
    _, variables_template = locate_firmware()
    firmware_directory = build_root / "firmware"
    firmware_directory.mkdir(parents=True, exist_ok=True)
    variables_path = firmware_directory / "edk2-vars.fd"
    shutil.copyfile(variables_template, variables_path)
    return build_root, image_path, variables_path


def qemu_run(root: Path, configuration: str) -> None:
    build_root, image_path, variables_path = prepare_qemu(root, configuration)
    command = qemu_base_command(root, build_root, image_path, variables_path)
    command.extend(["-serial", "stdio"])
    run(command, root=root)


def run_headless_qemu(
    root: Path,
    command: list[str],
    serial_path: Path,
    stop_markers: tuple[str, ...],
    *,
    timeout_seconds: float = 20.0,
) -> str:
    if serial_path.exists():
        serial_path.unlink()
    print("+ " + subprocess.list2cmdline(command), flush=True)
    process = subprocess.Popen(command, cwd=root)
    deadline = time.monotonic() + timeout_seconds
    serial_output = ""
    try:
        while time.monotonic() < deadline:
            if serial_path.is_file():
                try:
                    serial_output = serial_path.read_text(
                        encoding="utf-8", errors="replace"
                    )
                except OSError:
                    serial_output = ""
                if all(marker in serial_output for marker in stop_markers):
                    break
            if process.poll() is not None:
                break
            time.sleep(0.05)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    if not serial_path.is_file():
        raise BuildFailure("QEMU did not create the serial smoke-test log.")
    return serial_path.read_text(encoding="utf-8", errors="replace")


def boot_test(root: Path, configuration: str) -> None:
    build_root, image_path, _ = prepare_qemu(root, configuration)
    _, variables_template = locate_firmware()
    variables_path = build_root / "firmware" / "edk2-vars-smoke.fd"
    shutil.copyfile(variables_template, variables_path)
    serial_path = build_root / "boot-smoke-serial.log"
    command = qemu_base_command(
        root, build_root, image_path, variables_path, disk_snapshot=True
    )
    command.extend(
        [
            "-display",
            "none",
            "-chardev",
            f"file,id=zi_serial,path={serial_path},append=off",
            "-serial",
            "chardev:zi_serial",
        ]
    )
    serial_output = run_headless_qemu(
        root, command, serial_path, ("[ZI:BOOT:USER_SESSION]",)
    )
    print("--- QEMU serial smoke-test output ---")
    print(serial_output, end="" if serial_output.endswith("\n") else "\n")
    required_markers = [
        "[ZI:BOOT:ENTRY]",
        "[ZI:BOOT:SERIAL]",
        "[ZI:BOOT:CPU_TABLES]",
        "[ZI:BOOT:EXCEPTION_READY]",
        "[ZI:BOOT:BOOT_CONTEXT]",
        "[ZI:BOOT:MEMORY_INVENTORY]",
        "[ZI:BOOT:PMM_READY]",
        "[ZI:BOOT:VMM_READY]",
        "[ZI:BOOT:TEMPORARY_MAPPING]",
        "[ZI:BOOT:HEAP_READY]",
        "[ZI:BOOT:GUARDED_STACKS]",
        "[ZI:BOOT:MEMORY_STRESS]",
        "[ZI:BOOT:IO_MANAGER]",
        "[ZI:BOOT:DMA_READY]",
        "[ZI:BOOT:ACPI_READY]",
        "[ZI:BOOT:PCIE_ENUMERATED]",
        "[ZI:BOOT:PCI_DEVICES]",
        "[ZI:BOOT:NVME_READY]",
        "[ZI:BOOT:GPT_ZIFS]",
        "[ZI:BOOT:ZIFS_PARTITION]",
        "[ZI:BOOT:STORAGE_READ_STRESS]",
        "[ZI:BOOT:ZIFS_DIRECT]",
        "[ZI:BOOT:ZIFS_MOUNT]",
        "[ZI:BOOT:ZIFS_SECURITY]",
        "[ZI:BOOT:ZIFS_FILE_READ]",
        "[ZI:BOOT:CASE_SENSITIVE]",
        "[ZI:BOOT:SERVICE_MANIFESTS]",
        "[ZI:BOOT:SERVICE_DEPENDENCIES]",
        "[ZI:BOOT:FILESYSTEM_PE_SOURCE]",
        "[ZI:BOOT:USER_ADDRESS_SPACE]",
        "[ZI:BOOT:USER_PE_LOADED]",
        "[ZI:BOOT:USER_PE_RELOCATED]",
        "[ZI:BOOT:USER_IMPORTS_RESOLVED]",
        "[ZI:BOOT:USER_PARAMETERS]",
        "[ZI:BOOT:USER_TOKEN_BOUND]",
        "[ZI:BOOT:USER_PROCESS_SET]",
        "[ZI:BOOT:OBJECT_NAMESPACE]",
        "[ZI:BOOT:HANDLE_ACCESS]",
        "[ZI:BOOT:WAIT_OBJECTS]",
        "[ZI:BOOT:IPC_EXCHANGE]",
        "[ZI:BOOT:IPC_HANDLE_TRANSFER]",
        "[ZI:BOOT:SYSCALL_READY]",
        "[ZI:BOOT:RING3_ENTER]",
        "[ZI:BOOT:SYSCALL_ENTRY]",
        "[ZI:BOOT:USER_PROCESS_EXIT]",
        "[ZI:BOOT:USER_PROCESS_CLEAN]",
        "[ZI:BOOT:USER_PROCESS_SET_CLEAN]",
        "[ZI:BOOT:IPC_PROCESS_CLEAN]",
        "[ZI:BOOT:STANDARD_C_MAIN]",
        "[ZI:BOOT:STANDARD_C_ARGUMENTS]",
        "[ZI:BOOT:ZIA_LIBRARY]",
        "[ZI:BOOT:APIC_TIMER]",
        "[ZI:BOOT:SCHEDULER_TICKS]",
        "[ZI:BOOT:PREEMPTION]",
        "[ZI:BOOT:SERVICE_HOST]",
        "[ZI:BOOT:SERVICE_FAILURE_DETECTED]",
        "[ZI:BOOT:SERVICE_RESTART_LIMIT]",
        "[ZI:BOOT:SECURITY_HOST]",
        "[ZI:BOOT:LOG_HOST]",
        "[ZI:BOOT:MOUNT_HOST]",
        "[ZI:BOOT:SESSION_CHANNEL]",
        "[ZI:BOOT:SESSION_HOST]",
        "[ZI:BOOT:USER_CREATE_PROCESS]",
        "[ZI:BOOT:USER_WAIT_PROCESS]",
        "[ZI:BOOT:LUMA_CHILD_PROCESS]",
        "[ZI:BOOT:USER_LUMA]",
        "[ZI:BOOT:USER_LUMA_READY]",
        "[ZI:BOOT:USER_SESSION]",
    ]
    missing = [marker for marker in required_markers if marker not in serial_output]
    framebuffer_marked = (
        "[ZI:BOOT:FRAMEBUFFER]" in serial_output
        or "[ZI:BOOT:FRAMEBUFFER_FALLBACK]" in serial_output
    )
    if "[ZI:BOOT:PANIC]" in serial_output:
        raise BuildFailure("The kernel reported a panic during the QEMU smoke test.")
    if "[ZI:BOOT:STORAGE_MODULE_FALLBACK]" in serial_output:
        raise BuildFailure("The normal QEMU boot used the recovery ZiFS module path.")
    expected_messages = (
        "Hello from standard C on Zizium.",
        "Arguments and environment reached standard C.",
        "Hello through the optional ZIA library.",
        "ServiceHost completed its Phase 6 bootstrap hand-off.",
        "SessionHost published the bounded Luma bootstrap contract.",
        "Luma parsed a quoted path and completed a child process.",
    )
    missing_messages = [
        message for message in expected_messages if message not in serial_output
    ]
    if missing_messages:
        raise BuildFailure(
            "Ring-3 programmes did not write the expected messages: "
            + ", ".join(missing_messages)
        )
    if missing or not framebuffer_marked:
        details = ", ".join(missing) if missing else "framebuffer discovery/fallback"
        raise BuildFailure(f"QEMU boot did not reach required markers: {details}.")
    print("QEMU boot smoke test passed all required serial markers.")


def corrupt_gpt_header_checksums(image_path: Path) -> None:
    sector_size = 512
    image_size = image_path.stat().st_size
    if image_size < sector_size * 3 or image_size % sector_size != 0:
        raise BuildFailure(
            "The corrupt-GPT fixture is not a sector-aligned disk image."
        )
    header_offsets = (sector_size, image_size - sector_size)
    with image_path.open("r+b") as image:
        for header_offset in header_offsets:
            image.seek(header_offset)
            if image.read(8) != b"EFI PART":
                raise BuildFailure(
                    "The corrupt-GPT fixture does not contain both GPT headers."
                )
            image.seek(header_offset + 16)
            checksum = image.read(4)
            if len(checksum) != 4:
                raise BuildFailure("The corrupt-GPT fixture header is truncated.")
            corrupted = int.from_bytes(checksum, "little") ^ 0xFFFFFFFF
            image.seek(header_offset + 16)
            image.write(corrupted.to_bytes(4, "little"))


def storage_test(root: Path, configuration: str) -> None:
    build_root = host_build(root, configuration)
    kernel_path = kernel_build(root, configuration, build_root)
    native_outputs = native_artifacts_build(root, configuration, build_root)
    pecheck = build_root / "host" / "pecheck.exe"
    run([str(pecheck), "--kind", "kernel", str(kernel_path)], root=root)

    source_configuration = root / "boot" / "limine" / "limine.conf"
    configuration_text = source_configuration.read_text(encoding="utf-8")
    command_line = "    cmdline: release=Seed root=C:"
    if command_line not in configuration_text:
        raise BuildFailure(
            "The Limine command line could not be extended for storage testing."
        )
    generated_directory = build_root / "generated"
    generated_directory.mkdir(parents=True, exist_ok=True)
    firmware_directory = build_root / "firmware"
    firmware_directory.mkdir(parents=True, exist_ok=True)
    _, variables_template = locate_firmware()

    def build_case_image(case_name: str, test_token: str) -> Path:
        generated_configuration = (
            generated_directory / f"limine-storage-{case_name}.conf"
        )
        generated_configuration.write_text(
            configuration_text.replace(command_line, f"{command_line} {test_token}", 1),
            encoding="utf-8",
            newline="\n",
        )
        return image_build(
            root,
            configuration,
            build_root,
            kernel_path,
            limine_configuration=generated_configuration,
            image_name=f"zizium-storage-{case_name}.img",
            native_outputs=native_outputs,
        )

    def run_case(
        case_name: str,
        storage_image: Path,
        required_markers: tuple[str, ...],
        forbidden_markers: tuple[str, ...],
        *,
        boot_image: Path | None = None,
    ) -> None:
        variables_path = firmware_directory / f"edk2-vars-storage-{case_name}.fd"
        shutil.copyfile(variables_template, variables_path)
        serial_path = build_root / f"storage-{case_name}-serial.log"
        command = qemu_base_command(
            root,
            build_root,
            storage_image,
            variables_path,
            disk_snapshot=True,
            boot_image_path=boot_image,
        )
        command.extend(
            [
                "-display",
                "none",
                "-chardev",
                f"file,id=zi_serial,path={serial_path},append=off",
                "-serial",
                "chardev:zi_serial",
            ]
        )
        serial_output = run_headless_qemu(
            root,
            command,
            serial_path,
            ("[ZI:BOOT:LUMA_READY]",),
            timeout_seconds=30.0,
        )
        print(f"--- QEMU {case_name} storage-test output ---")
        print(serial_output, end="" if serial_output.endswith("\n") else "\n")
        missing = [marker for marker in required_markers if marker not in serial_output]
        present = [marker for marker in forbidden_markers if marker in serial_output]
        if missing:
            raise BuildFailure(
                f"The {case_name} storage test missed markers: {', '.join(missing)}."
            )
        if present:
            raise BuildFailure(
                f"The {case_name} storage test reached forbidden markers: {', '.join(present)}."
            )
        if "[ZI:BOOT:PANIC]" in serial_output:
            raise BuildFailure(
                f"The {case_name} storage test reached the kernel panic path."
            )
        print(f"QEMU {case_name} storage test passed.")

    timeout_image = build_case_image("timeout", "zi.test=storage-timeout")
    run_case(
        "timeout",
        timeout_image,
        (
            "[ZI:BOOT:IO_MANAGER]",
            "[ZI:BOOT:DMA_READY]",
            "[ZI:BOOT:ACPI_READY]",
            "[ZI:BOOT:PCIE_ENUMERATED]",
            "[ZI:BOOT:PCI_DEVICES]",
            "[ZI:BOOT:STORAGE_TIMEOUT_SAFE]",
            "[ZI:BOOT:STORAGE_MODULE_FALLBACK]",
            "[ZI:BOOT:ZIFS_MOUNT]",
            "[ZI:BOOT:CASE_SENSITIVE]",
            "[ZI:BOOT:LUMA_READY]",
        ),
        ("[ZI:BOOT:NVME_READY]", "[ZI:BOOT:ZIFS_DIRECT]"),
    )

    corrupt_boot_image = build_case_image(
        "corrupt-gpt-boot", "zi.test=storage-corrupt-gpt"
    )
    corrupt_storage_image = build_root / "images" / "zizium-storage-corrupt-gpt.img"
    shutil.copyfile(corrupt_boot_image, corrupt_storage_image)
    corrupt_gpt_header_checksums(corrupt_storage_image)
    run_case(
        "corrupt-gpt",
        corrupt_storage_image,
        (
            "[ZI:BOOT:IO_MANAGER]",
            "[ZI:BOOT:DMA_READY]",
            "[ZI:BOOT:ACPI_READY]",
            "[ZI:BOOT:PCIE_ENUMERATED]",
            "[ZI:BOOT:PCI_DEVICES]",
            "[ZI:BOOT:NVME_READY]",
            "[ZI:BOOT:GPT_CORRUPTION_SAFE]",
            "[ZI:BOOT:STORAGE_MODULE_FALLBACK]",
            "[ZI:BOOT:ZIFS_MOUNT]",
            "[ZI:BOOT:CASE_SENSITIVE]",
            "[ZI:BOOT:LUMA_READY]",
        ),
        ("[ZI:BOOT:GPT_ZIFS]", "[ZI:BOOT:ZIFS_DIRECT]"),
        boot_image=corrupt_boot_image,
    )


def copy_efi_system_partition(source_image: Path, destination_image: Path) -> None:
    sector_size = 512
    partition_offset = 2048 * sector_size
    partition_size = 64 * 1024 * 1024
    if (
        source_image.stat().st_size != destination_image.stat().st_size
        or source_image.stat().st_size < partition_offset + partition_size
    ):
        raise BuildFailure("The ZiFS reboot fixture has an incompatible disk layout.")
    with source_image.open("rb") as source, destination_image.open(
        "r+b"
    ) as destination:
        source.seek(partition_offset)
        destination.seek(partition_offset)
        remaining = partition_size
        while remaining != 0:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                raise BuildFailure("The source EFI System Partition is truncated.")
            destination.write(chunk)
            remaining -= len(chunk)
        destination.flush()
        os.fsync(destination.fileno())


def corrupt_zifs_security_table(image_path: Path) -> None:
    sector_size = 512
    gpt_entry_offset = 2 * sector_size + 128
    with image_path.open("r+b") as image:
        image.seek(gpt_entry_offset)
        entry = image.read(128)
        if len(entry) != 128:
            raise BuildFailure("The security-corruption fixture has a truncated GPT.")
        first_lba = int.from_bytes(entry[32:40], "little")
        final_lba = int.from_bytes(entry[40:48], "little")
        if first_lba == 0 or final_lba < first_lba:
            raise BuildFailure("The ZiFS GPT entry is invalid in the corruption fixture.")
        partition_offset = first_lba * sector_size
        image.seek(partition_offset)
        superblock = image.read(256)
        if len(superblock) != 256 or superblock[:8] != b"ZiFS\r\n\x1a\n":
            raise BuildFailure("The corruption fixture has no valid ZiFS superblock.")
        security_start = int.from_bytes(superblock[144:152], "little")
        security_blocks = int.from_bytes(superblock[152:160], "little")
        if security_blocks == 0:
            raise BuildFailure("The corruption fixture has no security table.")
        record_access_byte = (
            partition_offset + security_start * 4096 + 256 + 48 + 4
        )
        partition_end = (final_lba + 1) * sector_size
        if record_access_byte >= partition_end:
            raise BuildFailure("The ZiFS security record lies outside its partition.")
        image.seek(record_access_byte)
        original = image.read(1)
        if len(original) != 1:
            raise BuildFailure("The ZiFS security record is truncated.")
        image.seek(record_access_byte)
        image.write(bytes([original[0] ^ 0x80]))
        image.flush()
        os.fsync(image.fileno())


def zifs_write_test(root: Path, configuration: str) -> None:
    build_root = host_build(root, configuration)
    kernel_path = kernel_build(root, configuration, build_root)
    native_outputs = native_artifacts_build(root, configuration, build_root)
    pecheck = build_root / "host" / "pecheck.exe"
    run([str(pecheck), "--kind", "kernel", str(kernel_path)], root=root)

    source_configuration = root / "boot" / "limine" / "limine.conf"
    configuration_text = source_configuration.read_text(encoding="utf-8")
    command_line = "    cmdline: release=Seed root=C:"
    if command_line not in configuration_text:
        raise BuildFailure(
            "The Limine command line could not be extended for ZiFS testing."
        )
    generated_directory = build_root / "generated"
    generated_directory.mkdir(parents=True, exist_ok=True)
    truncate_fixture = generated_directory / "zifs-truncate-seed.bin"
    truncate_fixture.write_bytes(b"MZ" + bytes([0x21]) * ((3 * 4096) - 2))
    zifs_test_inputs = {"Temp/Truncate Seed.bin": truncate_fixture}
    image_directory = build_root / "images"
    image_directory.mkdir(parents=True, exist_ok=True)
    firmware_directory = build_root / "firmware"
    firmware_directory.mkdir(parents=True, exist_ok=True)
    _, variables_template = locate_firmware()

    case_tokens = {
        "create": "zi.test=zifs-create",
        "crash-rollback": "zi.test=zifs-crash-rollback",
        "crash-replay": "zi.test=zifs-crash-replay",
        "verify-present": "zi.test=zifs-verify-present",
        "verify-absent": "zi.test=zifs-verify-absent",
        "wrap-create": "zi.test=zifs-wrap-create",
        "wrap-verify": "zi.test=zifs-wrap-verify",
        "rename-move": "zi.test=zifs-rename-move",
        "rename-move-verify": "zi.test=zifs-rename-move-verify",
        "move-crash-rollback": "zi.test=zifs-move-crash-rollback",
        "move-crash-replay": "zi.test=zifs-move-crash-replay",
        "move-verify-old": "zi.test=zifs-move-verify-old",
        "move-verify-new": "zi.test=zifs-move-verify-new",
        "truncate-delete": "zi.test=zifs-truncate-delete",
        "truncate-delete-verify": "zi.test=zifs-truncate-delete-verify",
        "truncate-crash-rollback": "zi.test=zifs-truncate-crash-rollback",
        "truncate-crash-replay": "zi.test=zifs-truncate-crash-replay",
        "truncate-verify-old": "zi.test=zifs-truncate-verify-old",
        "truncate-verify-new": "zi.test=zifs-truncate-verify-new",
        "delete-crash-rollback": "zi.test=zifs-delete-crash-rollback",
        "delete-crash-replay": "zi.test=zifs-delete-crash-replay",
        "delete-verify-old": "zi.test=zifs-delete-verify-old",
        "delete-verify-new": "zi.test=zifs-delete-verify-new",
        "security-corrupt": "zi.test=zifs-security-corrupt",
    }
    case_images: dict[str, Path] = {}
    for case_name, token in case_tokens.items():
        generated_configuration = generated_directory / f"limine-zifs-{case_name}.conf"
        generated_configuration.write_text(
            configuration_text.replace(command_line, f"{command_line} {token}", 1),
            encoding="utf-8",
            newline="\n",
        )
        case_images[case_name] = image_build(
            root,
            configuration,
            build_root,
            kernel_path,
            limine_configuration=generated_configuration,
            image_name=f"zizium-zifs-{case_name}.img",
            native_outputs=native_outputs,
            additional_zifs_inputs=zifs_test_inputs,
        )

    def run_case(
        case_name: str,
        image_path: Path,
        required_markers: tuple[str, ...],
        forbidden_markers: tuple[str, ...] = (),
        allow_module_fallback: bool = False,
    ) -> None:
        variables_path = firmware_directory / f"edk2-vars-zifs-{case_name}.fd"
        shutil.copyfile(variables_template, variables_path)
        serial_path = build_root / f"zifs-{case_name}-serial.log"
        command = qemu_base_command(root, build_root, image_path, variables_path)
        command.extend(
            [
                "-display",
                "none",
                "-chardev",
                f"file,id=zi_serial,path={serial_path},append=off",
                "-serial",
                "chardev:zi_serial",
            ]
        )
        serial_output = run_headless_qemu(
            root,
            command,
            serial_path,
            (required_markers[-1],),
            timeout_seconds=30.0,
        )
        print(f"--- QEMU {case_name} ZiFS-test output ---")
        print(serial_output, end="" if serial_output.endswith("\n") else "\n")
        missing = [marker for marker in required_markers if marker not in serial_output]
        present = [marker for marker in forbidden_markers if marker in serial_output]
        if missing:
            raise BuildFailure(
                f"The {case_name} ZiFS test missed markers: {', '.join(missing)}."
            )
        if present:
            raise BuildFailure(
                f"The {case_name} ZiFS test reached forbidden markers: {', '.join(present)}."
            )
        if "[ZI:BOOT:PANIC]" in serial_output:
            raise BuildFailure(
                f"The {case_name} ZiFS test reached the kernel panic path."
            )
        if (
            "[ZI:BOOT:STORAGE_MODULE_FALLBACK]" in serial_output
            and not allow_module_fallback
        ):
            raise BuildFailure(
                f"The {case_name} ZiFS test bypassed the native partition."
            )
        print(f"QEMU {case_name} ZiFS test passed.")

    common_markers = (
        "[ZI:BOOT:NVME_READY]",
        "[ZI:BOOT:GPT_ZIFS]",
        "[ZI:BOOT:ZIFS_PARTITION]",
        "[ZI:BOOT:ZIFS_DIRECT]",
        "[ZI:BOOT:ZIFS_MOUNT]",
        "[ZI:BOOT:ZIFS_SECURITY]",
    )
    recovery_markers = (
        "[ZI:BOOT:ZIFS_RECOVERY_REPAIR]",
        "[ZI:BOOT:ZIFS_RECOVERY_ROLLBACK]",
        "[ZI:BOOT:ZIFS_RECOVERY_REPLAY]",
    )

    clean_storage = image_directory / "zizium-zifs-clean-reboot.img"
    shutil.copyfile(case_images["create"], clean_storage)
    run_case(
        "clean-create",
        clean_storage,
        (*common_markers, "[ZI:BOOT:ZIFS_WRITE_COMMIT]"),
        recovery_markers,
    )
    copy_efi_system_partition(case_images["verify-present"], clean_storage)
    run_case(
        "clean-reboot",
        clean_storage,
        (*common_markers, "[ZI:BOOT:ZIFS_WRITE_PERSISTED]"),
        recovery_markers,
    )

    rollback_storage = image_directory / "zizium-zifs-rollback-reboot.img"
    shutil.copyfile(case_images["crash-rollback"], rollback_storage)
    run_case(
        "crash-rollback",
        rollback_storage,
        (*common_markers, "[ZI:BOOT:ZIFS_CRASH_ROLLBACK_BOUNDARY]"),
        recovery_markers,
    )
    copy_efi_system_partition(case_images["verify-absent"], rollback_storage)
    run_case(
        "rollback-recovery",
        rollback_storage,
        (
            *common_markers,
            "[ZI:BOOT:ZIFS_RECOVERY_ROLLBACK]",
            "[ZI:BOOT:ZIFS_WRITE_ABSENT]",
        ),
        (
            "[ZI:BOOT:ZIFS_RECOVERY_REPAIR]",
            "[ZI:BOOT:ZIFS_RECOVERY_REPLAY]",
        ),
    )

    replay_storage = image_directory / "zizium-zifs-replay-reboot.img"
    shutil.copyfile(case_images["crash-replay"], replay_storage)
    run_case(
        "crash-replay",
        replay_storage,
        (*common_markers, "[ZI:BOOT:ZIFS_CRASH_REPLAY_BOUNDARY]"),
        recovery_markers,
    )
    copy_efi_system_partition(case_images["verify-present"], replay_storage)
    run_case(
        "replay-recovery",
        replay_storage,
        (
            *common_markers,
            "[ZI:BOOT:ZIFS_RECOVERY_REPLAY]",
            "[ZI:BOOT:ZIFS_WRITE_PERSISTED]",
        ),
        (
            "[ZI:BOOT:ZIFS_RECOVERY_REPAIR]",
            "[ZI:BOOT:ZIFS_RECOVERY_ROLLBACK]",
        ),
    )

    wrap_storage = image_directory / "zizium-zifs-wrap-reboot.img"
    shutil.copyfile(case_images["wrap-create"], wrap_storage)
    run_case(
        "wrap-create",
        wrap_storage,
        (*common_markers, "[ZI:BOOT:ZIFS_JOURNAL_WRAPPED]"),
        recovery_markers,
    )
    copy_efi_system_partition(case_images["wrap-verify"], wrap_storage)
    run_case(
        "wrap-reboot",
        wrap_storage,
        (*common_markers, "[ZI:BOOT:ZIFS_WRAP_PERSISTED]"),
        recovery_markers,
    )

    rename_storage = image_directory / "zizium-zifs-rename-move-reboot.img"
    shutil.copyfile(case_images["rename-move"], rename_storage)
    run_case(
        "rename-move",
        rename_storage,
        (*common_markers, "[ZI:BOOT:ZIFS_RENAME_MOVE_COMMIT]"),
        recovery_markers,
    )
    copy_efi_system_partition(case_images["rename-move-verify"], rename_storage)
    run_case(
        "rename-move-reboot",
        rename_storage,
        (*common_markers, "[ZI:BOOT:ZIFS_RENAME_MOVE_PERSISTED]"),
        recovery_markers,
    )

    move_rollback_storage = image_directory / "zizium-zifs-move-rollback-reboot.img"
    shutil.copyfile(case_images["move-crash-rollback"], move_rollback_storage)
    run_case(
        "move-crash-rollback",
        move_rollback_storage,
        (*common_markers, "[ZI:BOOT:ZIFS_MOVE_CRASH_ROLLBACK_BOUNDARY]"),
        recovery_markers,
    )
    copy_efi_system_partition(case_images["move-verify-old"], move_rollback_storage)
    run_case(
        "move-rollback-recovery",
        move_rollback_storage,
        (
            *common_markers,
            "[ZI:BOOT:ZIFS_RECOVERY_ROLLBACK]",
            "[ZI:BOOT:ZIFS_MOVE_OLD_STATE]",
        ),
        (
            "[ZI:BOOT:ZIFS_RECOVERY_REPAIR]",
            "[ZI:BOOT:ZIFS_RECOVERY_REPLAY]",
        ),
    )

    move_replay_storage = image_directory / "zizium-zifs-move-replay-reboot.img"
    shutil.copyfile(case_images["move-crash-replay"], move_replay_storage)
    run_case(
        "move-crash-replay",
        move_replay_storage,
        (*common_markers, "[ZI:BOOT:ZIFS_MOVE_CRASH_REPLAY_BOUNDARY]"),
        recovery_markers,
    )
    copy_efi_system_partition(case_images["move-verify-new"], move_replay_storage)
    run_case(
        "move-replay-recovery",
        move_replay_storage,
        (
            *common_markers,
            "[ZI:BOOT:ZIFS_RECOVERY_REPLAY]",
            "[ZI:BOOT:ZIFS_MOVE_PERSISTED]",
        ),
        (
            "[ZI:BOOT:ZIFS_RECOVERY_REPAIR]",
            "[ZI:BOOT:ZIFS_RECOVERY_ROLLBACK]",
        ),
    )

    truncate_delete_storage = image_directory / "zizium-zifs-truncate-delete-reboot.img"
    shutil.copyfile(case_images["truncate-delete"], truncate_delete_storage)
    run_case(
        "truncate-delete",
        truncate_delete_storage,
        (*common_markers, "[ZI:BOOT:ZIFS_RECLAIM_AFTER_CHECKPOINT]"),
        recovery_markers,
    )
    copy_efi_system_partition(
        case_images["truncate-delete-verify"], truncate_delete_storage
    )
    run_case(
        "truncate-delete-reboot",
        truncate_delete_storage,
        (*common_markers, "[ZI:BOOT:ZIFS_TRUNCATE_DELETE_PERSISTED]"),
        recovery_markers,
    )

    truncate_rollback_storage = (
        image_directory / "zizium-zifs-truncate-rollback-reboot.img"
    )
    shutil.copyfile(
        case_images["truncate-crash-rollback"], truncate_rollback_storage
    )
    run_case(
        "truncate-crash-rollback",
        truncate_rollback_storage,
        (*common_markers, "[ZI:BOOT:ZIFS_TRUNCATE_CRASH_ROLLBACK_BOUNDARY]"),
        recovery_markers,
    )
    copy_efi_system_partition(
        case_images["truncate-verify-old"], truncate_rollback_storage
    )
    run_case(
        "truncate-rollback-recovery",
        truncate_rollback_storage,
        (
            *common_markers,
            "[ZI:BOOT:ZIFS_RECOVERY_ROLLBACK]",
            "[ZI:BOOT:ZIFS_TRUNCATE_OLD_STATE]",
        ),
        (
            "[ZI:BOOT:ZIFS_RECOVERY_REPAIR]",
            "[ZI:BOOT:ZIFS_RECOVERY_REPLAY]",
        ),
    )

    truncate_replay_storage = (
        image_directory / "zizium-zifs-truncate-replay-reboot.img"
    )
    shutil.copyfile(case_images["truncate-crash-replay"], truncate_replay_storage)
    run_case(
        "truncate-crash-replay",
        truncate_replay_storage,
        (*common_markers, "[ZI:BOOT:ZIFS_TRUNCATE_CRASH_REPLAY_BOUNDARY]"),
        recovery_markers,
    )
    copy_efi_system_partition(
        case_images["truncate-verify-new"], truncate_replay_storage
    )
    run_case(
        "truncate-replay-recovery",
        truncate_replay_storage,
        (
            *common_markers,
            "[ZI:BOOT:ZIFS_RECOVERY_REPLAY]",
            "[ZI:BOOT:ZIFS_TRUNCATE_NEW_STATE]",
        ),
        (
            "[ZI:BOOT:ZIFS_RECOVERY_REPAIR]",
            "[ZI:BOOT:ZIFS_RECOVERY_ROLLBACK]",
        ),
    )

    delete_rollback_storage = image_directory / "zizium-zifs-delete-rollback-reboot.img"
    shutil.copyfile(case_images["delete-crash-rollback"], delete_rollback_storage)
    run_case(
        "delete-crash-rollback",
        delete_rollback_storage,
        (*common_markers, "[ZI:BOOT:ZIFS_DELETE_CRASH_ROLLBACK_BOUNDARY]"),
        recovery_markers,
    )
    copy_efi_system_partition(
        case_images["delete-verify-old"], delete_rollback_storage
    )
    run_case(
        "delete-rollback-recovery",
        delete_rollback_storage,
        (
            *common_markers,
            "[ZI:BOOT:ZIFS_RECOVERY_ROLLBACK]",
            "[ZI:BOOT:ZIFS_DELETE_OLD_STATE]",
        ),
        (
            "[ZI:BOOT:ZIFS_RECOVERY_REPAIR]",
            "[ZI:BOOT:ZIFS_RECOVERY_REPLAY]",
        ),
    )

    delete_replay_storage = image_directory / "zizium-zifs-delete-replay-reboot.img"
    shutil.copyfile(case_images["delete-crash-replay"], delete_replay_storage)
    run_case(
        "delete-crash-replay",
        delete_replay_storage,
        (*common_markers, "[ZI:BOOT:ZIFS_DELETE_CRASH_REPLAY_BOUNDARY]"),
        recovery_markers,
    )
    copy_efi_system_partition(case_images["delete-verify-new"], delete_replay_storage)
    run_case(
        "delete-replay-recovery",
        delete_replay_storage,
        (
            *common_markers,
            "[ZI:BOOT:ZIFS_RECOVERY_REPLAY]",
            "[ZI:BOOT:ZIFS_DELETE_NEW_STATE]",
        ),
        (
            "[ZI:BOOT:ZIFS_RECOVERY_REPAIR]",
            "[ZI:BOOT:ZIFS_RECOVERY_ROLLBACK]",
        ),
    )

    security_corrupt_storage = (
        image_directory / "zizium-zifs-security-corrupt-storage.img"
    )
    shutil.copyfile(case_images["security-corrupt"], security_corrupt_storage)
    corrupt_zifs_security_table(security_corrupt_storage)
    run_case(
        "security-corrupt",
        security_corrupt_storage,
        (
            "[ZI:BOOT:NVME_READY]",
            "[ZI:BOOT:GPT_ZIFS]",
            "[ZI:BOOT:ZIFS_PARTITION]",
            "[ZI:BOOT:ZIFS_SECURITY_CORRUPTION_SAFE]",
            "[ZI:BOOT:STORAGE_MODULE_FALLBACK]",
            "[ZI:BOOT:ZIFS_MOUNT]",
            "[ZI:BOOT:ZIFS_SECURITY]",
            "[ZI:BOOT:USER_SESSION]",
        ),
        ("[ZI:BOOT:ZIFS_DIRECT]",),
        allow_module_fallback=True,
    )
    print(
        "QEMU ZiFS create, wrap, rename, move, truncate, delete, reclamation, "
        "security-corruption, rollback, and replay tests passed across twenty-five boots."
    )


def fault_test(root: Path, configuration: str) -> None:
    build_root = host_build(root, configuration)
    kernel_path = kernel_build(root, configuration, build_root)
    native_outputs = native_artifacts_build(root, configuration, build_root)
    pecheck = build_root / "host" / "pecheck.exe"
    run([str(pecheck), "--kind", "kernel", str(kernel_path)], root=root)

    source_configuration = root / "boot" / "limine" / "limine.conf"
    configuration_text = source_configuration.read_text(encoding="utf-8")
    command_line = "    cmdline: release=Seed root=C:"
    if command_line not in configuration_text:
        raise BuildFailure(
            "The Limine command line could not be extended for fault testing."
        )

    _, variables_template = locate_firmware()
    generated_directory = build_root / "generated"
    generated_directory.mkdir(parents=True, exist_ok=True)
    firmware_directory = build_root / "firmware"
    firmware_directory.mkdir(parents=True, exist_ok=True)
    cases = (
        (
            "invalid-opcode",
            "zi.test=exception-ud",
            "[ZI:BOOT:FAULT_TEST_INVALID_OPCODE]",
            "[ZI:BOOT:EXCEPTION_INVALID_OPCODE]",
            None,
            "Invalid opcode",
        ),
        (
            "page-fault",
            "zi.test=exception-pf",
            "[ZI:BOOT:FAULT_TEST_PAGE_FAULT]",
            "[ZI:BOOT:EXCEPTION_PAGE_FAULT]",
            None,
            "CR2=0x0000400000000000",
        ),
        (
            "memory-guard",
            "zi.test=memory-guard",
            "[ZI:BOOT:FAULT_TEST_MEMORY_GUARD]",
            "[ZI:BOOT:EXCEPTION_PAGE_FAULT]",
            "[ZI:BOOT:MEMORY_GUARD_FAULT]",
            "A kernel stack crossed its unmapped guard page.",
        ),
    )
    for (
        case_name,
        command_token,
        trigger_marker,
        exception_marker,
        classification_marker,
        diagnostic,
    ) in cases:
        generated_configuration = generated_directory / f"limine-{case_name}.conf"
        generated_configuration.write_text(
            configuration_text.replace(
                command_line, f"{command_line} {command_token}", 1
            ),
            encoding="utf-8",
            newline="\n",
        )
        image_path = image_build(
            root,
            configuration,
            build_root,
            kernel_path,
            limine_configuration=generated_configuration,
            image_name=f"zizium-{case_name}.img",
            native_outputs=native_outputs,
        )
        variables_path = firmware_directory / f"edk2-vars-{case_name}.fd"
        shutil.copyfile(variables_template, variables_path)
        serial_path = build_root / f"fault-{case_name}-serial.log"
        command = qemu_base_command(
            root, build_root, image_path, variables_path, disk_snapshot=True
        )
        command.extend(
            [
                "-display",
                "none",
                "-chardev",
                f"file,id=zi_serial,path={serial_path},append=off",
                "-serial",
                "chardev:zi_serial",
            ]
        )
        serial_output = run_headless_qemu(
            root, command, serial_path, ("[ZI:BOOT:PANIC]",)
        )
        print(f"--- QEMU {case_name} fault-test output ---")
        print(serial_output, end="" if serial_output.endswith("\n") else "\n")
        required_markers = (
            "[ZI:BOOT:ENTRY]",
            "[ZI:BOOT:CPU_TABLES]",
            "[ZI:BOOT:EXCEPTION_READY]",
            trigger_marker,
            "[ZI:BOOT:EXCEPTION_DIAGNOSTIC]",
            exception_marker,
            "[ZI:BOOT:PANIC]",
        )
        if classification_marker is not None:
            required_markers += (classification_marker,)
        missing = [marker for marker in required_markers if marker not in serial_output]
        if missing:
            raise BuildFailure(
                f"The {case_name} fault test missed markers: {', '.join(missing)}."
            )
        if diagnostic not in serial_output:
            raise BuildFailure(
                f"The {case_name} fault test did not emit its required diagnostic."
            )
        if "[ZI:BOOT:EXCEPTION_RECURSIVE]" in serial_output:
            raise BuildFailure(
                f"The {case_name} fault test recursed in the exception path."
            )
        if "[ZI:BOOT:LUMA_READY]" in serial_output:
            raise BuildFailure(
                f"The {case_name} fault test continued after a fatal exception."
            )
        print(f"QEMU {case_name} fault test passed.")

    case_name = "user-fault"
    generated_configuration = generated_directory / f"limine-{case_name}.conf"
    generated_configuration.write_text(
        configuration_text.replace(
            command_line, f"{command_line} zi.test=user-fault", 1
        ),
        encoding="utf-8",
        newline="\n",
    )
    image_path = image_build(
        root,
        configuration,
        build_root,
        kernel_path,
        limine_configuration=generated_configuration,
        image_name=f"zizium-{case_name}.img",
        native_outputs=native_outputs,
    )
    variables_path = firmware_directory / f"edk2-vars-{case_name}.fd"
    shutil.copyfile(variables_template, variables_path)
    serial_path = build_root / f"fault-{case_name}-serial.log"
    command = qemu_base_command(
        root, build_root, image_path, variables_path, disk_snapshot=True
    )
    command.extend(
        [
            "-display",
            "none",
            "-chardev",
            f"file,id=zi_serial,path={serial_path},append=off",
            "-serial",
            "chardev:zi_serial",
        ]
    )
    serial_output = run_headless_qemu(
        root, command, serial_path, ("[ZI:BOOT:USER_SESSION]",)
    )
    print("--- QEMU user-fault containment output ---")
    print(serial_output, end="" if serial_output.endswith("\n") else "\n")
    required_markers = (
        "[ZI:BOOT:USER_ADDRESS_SPACE]",
        "[ZI:BOOT:USER_PE_LOADED]",
        "[ZI:BOOT:USER_PE_RELOCATED]",
        "[ZI:BOOT:USER_IMPORTS_RESOLVED]",
        "[ZI:BOOT:USER_PARAMETERS]",
        "[ZI:BOOT:USER_TOKEN_BOUND]",
        "[ZI:BOOT:USER_PROCESS_SET]",
        "[ZI:BOOT:SYSCALL_READY]",
        "[ZI:BOOT:RING3_ENTER]",
        "[ZI:BOOT:USER_FAULT_CONTAINED]",
        "[ZI:BOOT:USER_PROCESS_CLEAN]",
        "[ZI:BOOT:USER_PROCESS_SET_CLEAN]",
        "[ZI:BOOT:APIC_TIMER]",
        "[ZI:BOOT:PREEMPTION]",
        "[ZI:BOOT:USER_LUMA_READY]",
    )
    missing = [marker for marker in required_markers if marker not in serial_output]
    if missing:
        raise BuildFailure(f"The user-fault test missed markers: {', '.join(missing)}.")
    if (
        "[ZI:BOOT:PANIC]" in serial_output
        or "[ZI:BOOT:EXCEPTION_DIAGNOSTIC]" in serial_output
    ):
        raise BuildFailure(
            "A contained Ring-3 fault entered the fatal kernel exception path."
        )
    fault_prefix = serial_output.split("[ZI:BOOT:USER_FAULT_CONTAINED]", 1)[0]
    if "[ZI:BOOT:SYSCALL_ENTRY]" in fault_prefix:
        raise BuildFailure(
            "The forced user fault unexpectedly crossed the syscall boundary."
        )
    print("QEMU user-fault containment test passed.")


def format_check(root: Path) -> None:
    formatter = require_tool(
        "clang-format", "Install LLVM 22 or later and add its bin directory to PATH."
    )
    source_files = sorted(
        path
        for directory in (
            "boot",
            "drivers",
            "kernel",
            "sdk",
            "tests",
            "tools",
            "userland",
        )
        for path in (root / directory).rglob("*")
        if path.suffix in {".c", ".h"}
    )
    if source_files:
        run([formatter, "--dry-run", "--Werror", *map(str, source_files)], root=root)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def mutate_zifs_inspection_fixture(path: Path, mutation: str) -> None:
    with path.open("r+b") as file:
        superblock = file.read(256)
        if len(superblock) != 256:
            raise BuildFailure("The ZiFS inspection fixture has a truncated superblock.")
        record_start = int.from_bytes(superblock[80:88], "little")
        directory_start = int.from_bytes(superblock[96:104], "little")
        bitmap_start = int.from_bytes(superblock[112:120], "little")
        journal_start = int.from_bytes(superblock[128:136], "little")
        security_start = int.from_bytes(superblock[144:152], "little")
        offsets: list[int]
        if mutation == "primary-superblock":
            offsets = [252]
        elif mutation == "security-record":
            offsets = [(security_start * 4096) + 256 + 48 + 4]
        elif mutation == "journal-headers":
            offsets = [
                (journal_start * 4096) + 8,
                ((journal_start + 1) * 4096) + 8,
            ]
        elif mutation == "directory":
            offsets = [(directory_start * 4096) + 64 + 24]
        elif mutation == "file-record":
            offsets = [(record_start * 4096) + 256 + 8]
        elif mutation == "allocation":
            offsets = [bitmap_start * 4096]
        else:
            raise BuildFailure(f"Unknown ZiFS inspection mutation '{mutation}'.")
        for offset in offsets:
            file.seek(offset)
            encoded = file.read(1)
            if len(encoded) != 1:
                raise BuildFailure(
                    f"ZiFS inspection mutation '{mutation}' is outside the fixture."
                )
            value = encoded[0]
            if mutation == "allocation":
                value &= 0xFE
            else:
                value ^= 0x21
            file.seek(offset)
            file.write(bytes((value,)))
        file.flush()
        os.fsync(file.fileno())


def run_zifs_inspector_case(
    root: Path,
    inspector: Path,
    fixture: Path,
    expected_exit: int,
    required_text: tuple[str, ...],
    environment: dict[str, str] | None,
) -> None:
    command = [str(inspector), "--raw", str(fixture)]
    print("+ " + subprocess.list2cmdline(command), flush=True)
    before_hash = file_sha256(fixture)
    result = subprocess.run(
        command,
        cwd=root,
        check=False,
        text=True,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    print(result.stdout, end="")
    after_hash = file_sha256(fixture)
    if result.returncode != expected_exit:
        raise BuildFailure(
            f"zifsinspect returned {result.returncode}; expected {expected_exit} "
            f"for '{fixture.name}'."
        )
    if before_hash != after_hash:
        raise BuildFailure(f"zifsinspect modified its read-only fixture '{fixture.name}'.")
    for expected in required_text:
        if expected not in result.stdout:
            raise BuildFailure(
                f"zifsinspect output for '{fixture.name}' omitted '{expected}'."
            )


def zifs_inspector_tests(
    root: Path,
    build_root: Path,
    source_image: Path,
    environment: dict[str, str] | None,
) -> None:
    inspector = build_root / "host" / "zifsinspect.exe"
    fixture_directory = build_root / "tests" / "zifsinspect"
    fixture_directory.mkdir(parents=True, exist_ok=True)
    valid_fixture = fixture_directory / "valid.zifs"
    shutil.copyfile(source_image, valid_fixture)
    run_zifs_inspector_case(
        root,
        inspector,
        valid_fixture,
        0,
        (
            "Access: read-only; recovery and repair are disabled",
            "Security: 1 descriptors, 4 ACEs",
            "Namespace: 75 live records",
            "Result: valid ZiFS metadata",
        ),
        environment,
    )
    cases = (
        (
            "primary-superblock",
            ("Selected superblock: backup", "requires recovery or repair"),
        ),
        ("security-record", ("security=checksum mismatch", "Result: invalid")),
        ("journal-headers", ("journal=checksum mismatch", "Result: invalid")),
        ("directory", ("namespace=checksum mismatch", "Result: invalid")),
        ("file-record", ("namespace=checksum mismatch", "Result: invalid")),
        ("allocation", ("allocation=corrupt filesystem", "Result: invalid")),
    )
    for mutation, required_text in cases:
        fixture = fixture_directory / f"corrupt-{mutation}.zifs"
        shutil.copyfile(source_image, fixture)
        mutate_zifs_inspection_fixture(fixture, mutation)
        run_zifs_inspector_case(
            root,
            inspector,
            fixture,
            1,
            required_text,
            environment,
        )
    print("ZiFS read-only inspector acceptance tests passed across seven fixtures.")


def run_tests(root: Path, configuration: str, *, sanitised: bool = False) -> None:
    sanitised = sanitised or configuration == "sanitised"
    spelling_check(root)
    header_check(root, configuration)
    build_root = host_build(root, configuration, sanitised=sanitised)
    test_binary = build_root / "tests" / "zizium_host_tests.exe"
    if not test_binary.exists():
        raise BuildFailure("The host test source is missing; no tests were executed.")
    test_environment = None
    if sanitised:
        compiler = require_tool(
            "clang-cl", "Install LLVM 22 or later and add its bin directory to PATH."
        )
        resource_root = Path(
            run([compiler, "--print-resource-dir"], root=root, capture=True).strip()
        )
        runtime_root = resource_root / "lib" / "windows"
        runtime_dll = runtime_root / "clang_rt.asan_dynamic-x86_64.dll"
        if not runtime_dll.is_file():
            raise BuildFailure(
                f"The matching AddressSanitizer runtime was not found at '{runtime_dll}'."
            )
        test_environment = os.environ.copy()
        test_environment["PATH"] = (
            str(runtime_root) + os.pathsep + test_environment["PATH"]
        )
    run([str(test_binary)], root=root, environment=test_environment)

    image_path = build_root / "images" / "zizium-root.zifs"
    image_path.parent.mkdir(parents=True, exist_ok=True)
    run(
        [str(build_root / "host" / "mkzifs.exe"), str(image_path), "32"],
        root=root,
        environment=test_environment,
    )
    zifs_inspector_tests(root, build_root, image_path, test_environment)
    manifests = sorted((root / "userland" / "services" / "manifests").glob("*.zsvc"))
    run(
        [str(build_root / "host" / "zsvccheck.exe"), *map(str, manifests)],
        root=root,
        environment=test_environment,
    )


def analyse(root: Path, configuration: str) -> None:
    tidy = require_tool(
        "clang-tidy", "Install LLVM 22 or later and add its bin directory to PATH."
    )
    compiler = require_tool(
        "clang-cl", "Install LLVM 22 or later and add its bin directory to PATH."
    )
    format_check(root)
    source_files = sorted(
        path
        for directory in (
            "boot",
            "drivers",
            "kernel",
            "sdk",
            "tests",
            "tools",
            "userland",
        )
        for path in (root / directory).rglob("*.c")
    )
    for source in source_files:
        run(
            [
                tidy,
                str(source),
                "--exclude-header-filter=.*external[/\\\\]deps.*",
                "--warnings-as-errors=*",
                "--",
                "-std=c17",
                f"-I{root / 'sdk' / 'include'}",
                f"-I{root / 'kernel' / 'include'}",
                f"-I{root / 'external' / 'deps' / 'limine-protocol'}",
            ],
            root=root,
        )
    run([compiler, "--version"], root=root)
    host_build(root, configuration)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build Zizium from the shared build graph."
    )
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument(
        "--configuration", choices=("debug", "release", "sanitised"), default="debug"
    )
    parser.add_argument(
        "--target",
        choices=(
            "all",
            "host",
            "kernel",
            "image",
            "analyse",
            "intel",
            "test",
            "boot-test",
            "fault-test",
            "storage-test",
            "zifs-test",
            "run",
        ),
        default="all",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    root = arguments.root.resolve()
    if not (root / "c_style.md").is_file():
        print(f"error: '{root}' is not a Zizium repository", file=sys.stderr)
        return 2
    try:
        if arguments.target == "analyse":
            analyse(root, arguments.configuration)
        elif arguments.target == "test":
            run_tests(root, arguments.configuration)
        elif arguments.target == "boot-test":
            boot_test(root, arguments.configuration)
        elif arguments.target == "fault-test":
            fault_test(root, arguments.configuration)
        elif arguments.target == "storage-test":
            storage_test(root, arguments.configuration)
        elif arguments.target == "zifs-test":
            zifs_write_test(root, arguments.configuration)
        elif arguments.target == "run":
            qemu_run(root, arguments.configuration)
        elif arguments.target in {"kernel", "image", "all"}:
            build_root = host_build(root, arguments.configuration)
            kernel_path = kernel_build(root, arguments.configuration, build_root)
            native_outputs = native_artifacts_build(
                root, arguments.configuration, build_root
            )
            pecheck = build_root / "host" / "pecheck.exe"
            run([str(pecheck), "--kind", "kernel", str(kernel_path)], root=root)
            for native_output in native_outputs:
                if native_output.suffix.lower() == ".sys":
                    image_kind = "driver"
                elif native_output.suffix.lower() == ".dll":
                    image_kind = "library"
                else:
                    image_kind = "programme"
                run([str(pecheck), "--kind", image_kind, str(native_output)], root=root)
            if arguments.target in {"image", "all"}:
                image_build(
                    root,
                    arguments.configuration,
                    build_root,
                    kernel_path,
                    native_outputs=native_outputs,
                )
        elif arguments.target == "intel":
            intel_validation(root, arguments.configuration)
        else:
            host_build(root, arguments.configuration)
    except BuildFailure as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
