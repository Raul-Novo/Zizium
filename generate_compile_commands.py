from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT = ROOT / "compile_commands.json"

SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".m", ".mm"}
HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".inc"}

# Project-generated or irrelevant trees. "external" is intentionally NOT here:
# project sources are excluded from it separately, while its headers can still
# be discovered when the project includes them (for example limine.h).
PRUNE_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vs",
    ".vscode",
    ".cache",
    "__pycache__",
    "build",
    "out",
    "bin",
    "obj",
    "dist",
    "coverage",
    "downloads",
}

INCLUDE_RE = re.compile(
    r'^\s*#\s*include\s*[<"]([^">]+)[">]',
    re.MULTILINE,
)


def is_pruned(path: Path) -> bool:
    return any(part.casefold() in PRUNE_DIR_NAMES for part in path.parts)


def walk_files(root: Path, suffixes: set[str], *, allow_external: bool) -> list[Path]:
    result: list[Path] = []

    for current, dirs, files in os.walk(root):
        current_path = Path(current)

        dirs[:] = [
            directory
            for directory in dirs
            if directory.casefold() not in PRUNE_DIR_NAMES
        ]

        if not allow_external:
            try:
                relative = current_path.relative_to(root)
            except ValueError:
                relative = current_path

            if relative.parts and relative.parts[0].casefold() == "external":
                dirs[:] = []
                continue

        for name in files:
            path = current_path / name
            if path.suffix.casefold() in suffixes and not is_pruned(path):
                result.append(path.resolve())

    return sorted(set(result), key=lambda p: p.as_posix().casefold())


def discover_sources() -> list[Path]:
    # Zizium-owned translation units only. Vendored .c files under external/
    # should not become part of the project's clangd database.
    return walk_files(ROOT, SOURCE_SUFFIXES, allow_external=False)


def discover_headers() -> list[Path]:
    # External headers are allowed because project code may include them.
    return walk_files(ROOT, HEADER_SUFFIXES, allow_external=True)


def discover_conventional_include_roots() -> set[Path]:
    roots: set[Path] = set()

    for current, dirs, _files in os.walk(ROOT):
        current_path = Path(current)

        dirs[:] = [
            directory
            for directory in dirs
            if directory.casefold() not in PRUNE_DIR_NAMES
        ]

        for directory in dirs:
            if directory.casefold() in {"include", "includes", "inc"}:
                roots.add((current_path / directory).resolve())

    return roots


def read_include_tokens(paths: list[Path]) -> set[str]:
    tokens: set[str] = set()

    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for match in INCLUDE_RE.finditer(text):
            token = match.group(1).strip().replace("\\", "/")
            if token and not token.startswith("/"):
                tokens.add(token)

    return tokens


def infer_root_for_match(header: Path, include_token: str) -> Path:
    parts = [part for part in include_token.replace("\\", "/").split("/") if part]
    root = header

    # The token includes the filename itself:
    #   .../kernel/include/zi/foo.h + "zi/foo.h" -> .../kernel/include
    for _ in parts:
        root = root.parent

    return root.resolve()


def discover_inferred_include_roots(
    headers: list[Path],
    include_tokens: set[str],
) -> set[Path]:
    roots: set[Path] = set()

    by_basename: dict[str, list[Path]] = {}
    for header in headers:
        by_basename.setdefault(header.name.casefold(), []).append(header)

    for token in sorted(include_tokens, key=str.casefold):
        token_path = Path(token)
        basename = token_path.name.casefold()
        candidates = by_basename.get(basename, [])
        wanted = token.replace("\\", "/").casefold()

        for header in candidates:
            try:
                relative = header.relative_to(ROOT).as_posix().casefold()
            except ValueError:
                relative = header.as_posix().casefold()

            if relative == wanted or relative.endswith("/" + wanted):
                roots.add(infer_root_for_match(header, token))

    return roots


def discover_include_roots(
    sources: list[Path],
    headers: list[Path],
) -> list[Path]:
    roots = discover_conventional_include_roots()

    # Parse only Zizium-owned source/header files. Vendored headers are indexed
    # as possible include targets but do not influence discovery themselves.
    owned_headers = [
        header
        for header in headers
        if "external"
        not in {part.casefold() for part in header.relative_to(ROOT).parts}
    ]

    tokens = read_include_tokens([*sources, *owned_headers])
    roots.update(discover_inferred_include_roots(headers, tokens))

    # The project root itself is useful for explicit project-relative includes,
    # and costs very little compared with adding every directory recursively.
    roots.add(ROOT)

    return sorted(roots, key=lambda p: p.as_posix().casefold())


def find_compiler(override: str | None) -> str:
    if override:
        return str(Path(override).expanduser())

    found = shutil.which("clang-cl")
    if found:
        return found

    if os.name == "nt":
        program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        candidate = program_files / "LLVM" / "bin" / "clang-cl.exe"
        if candidate.is_file():
            return str(candidate)

    # clangd can still understand the driver name from compile_commands.json
    # even if this script cannot currently resolve the executable.
    return "clang-cl"


def relative_parts(path: Path) -> tuple[str, ...]:
    try:
        return tuple(part.casefold() for part in path.relative_to(ROOT).parts)
    except ValueError:
        return tuple(part.casefold() for part in path.parts)


def is_host_translation_unit(source: Path) -> bool:
    parts = relative_parts(source)

    if not parts:
        return False

    # These are built as ordinary Windows-hosted programs/tests in Zizium.
    if parts[0] == "tools":
        return True

    if len(parts) >= 2 and parts[0] == "tests" and parts[1] == "host":
        return True

    return False


def language_flags(source: Path) -> list[str]:
    suffix = source.suffix.casefold()

    if suffix == ".c":
        return ["/std:c17"]

    if suffix in {".cc", ".cpp", ".cxx"}:
        return ["/std:c++20", "/EHsc"]

    if suffix == ".m":
        return ["/clang:-x", "/clang:objective-c", "/std:c17"]

    if suffix == ".mm":
        return ["/clang:-x", "/clang:objective-c++", "/std:c++20"]

    return []


def compile_arguments(
    compiler: str,
    source: Path,
    include_roots: list[Path],
    configuration: str,
) -> list[str]:
    arguments = [
        compiler,
        "/nologo",
        "/c",
        *language_flags(source),
        "/utf-8",
        "/W4",
        "/Brepro",
    ]

    if is_host_translation_unit(source):
        if configuration == "release":
            arguments.extend(["/O2", "/DNDEBUG"])
        else:
            arguments.extend(["/Od", "/Zi", "/DZI_DEBUG=1"])
    else:
        # Mirrors the freestanding/native side of Zizium closely enough for
        # clangd diagnostics, completion, navigation and macro evaluation.
        arguments.extend(
            [
                "/GS-",
                "/Zl",
                "/DZI_KERNEL=1",
                "/clang:-ffreestanding",
                "/clang:-fno-builtin",
            ]
        )

        if configuration == "release":
            arguments.extend(["/O2", "/DNDEBUG"])
        else:
            arguments.extend(["/O1", "/Zi", "/DZI_DEBUG=1"])

    arguments.extend(f"/I{include_root}" for include_root in include_roots)
    arguments.append(str(source))

    return arguments


def build_database(
    compiler: str,
    configuration: str,
) -> tuple[list[dict[str, object]], list[Path], list[Path]]:
    sources = discover_sources()
    headers = discover_headers()
    include_roots = discover_include_roots(sources, headers)

    database: list[dict[str, object]] = []

    for source in sources:
        database.append(
            {
                "directory": str(ROOT),
                "file": str(source),
                "arguments": compile_arguments(
                    compiler,
                    source,
                    include_roots,
                    configuration,
                ),
            }
        )

    return database, sources, include_roots


def write_database(
    output: Path,
    compiler: str,
    configuration: str,
    *,
    quiet: bool = False,
) -> None:
    database, sources, include_roots = build_database(compiler, configuration)

    output.write_text(
        json.dumps(database, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    if quiet:
        return

    print(f"Wrote: {output}")
    print(f"Sources: {len(sources)}")
    print(f"Include roots: {len(include_roots)}")

    for include_root in include_roots:
        try:
            shown = include_root.relative_to(ROOT)
        except ValueError:
            shown = include_root
        print(f"  + {shown}")


def project_fingerprint() -> tuple[tuple[str, int, int], ...]:
    watched_suffixes = SOURCE_SUFFIXES | HEADER_SUFFIXES
    entries: list[tuple[str, int, int]] = []

    for current, dirs, files in os.walk(ROOT):
        current_path = Path(current)
        dirs[:] = [
            directory
            for directory in dirs
            if directory.casefold() not in PRUNE_DIR_NAMES
        ]

        for name in files:
            path = current_path / name
            if path.suffix.casefold() not in watched_suffixes:
                continue

            try:
                stat = path.stat()
                relative = path.relative_to(ROOT).as_posix()
            except (OSError, ValueError):
                continue

            entries.append((relative, stat.st_mtime_ns, stat.st_size))

    return tuple(sorted(entries, key=lambda item: item[0].casefold()))


def watch(
    output: Path,
    compiler: str,
    configuration: str,
    interval: float,
) -> None:
    write_database(output, compiler, configuration)
    previous = project_fingerprint()

    print(f"Watching Zizium every {interval:g}s. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(interval)
            current = project_fingerprint()

            if current == previous:
                continue

            write_database(
                output,
                compiler,
                configuration,
                quiet=True,
            )
            previous = current
            print("compile_commands.json regenerated.")
    except KeyboardInterrupt:
        print("\nStopped.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Discover Zizium translation units and include roots, then generate "
            "compile_commands.json for clangd."
        )
    )
    parser.add_argument(
        "--compiler",
        help="clang-cl executable to record in compile_commands.json.",
    )
    parser.add_argument(
        "--configuration",
        choices=("debug", "release"),
        default="debug",
        help="Semantic configuration recorded for clangd (default: debug).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output path (default: ./compile_commands.json).",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Regenerate automatically when C/C++/header files change.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Polling interval for --watch in seconds (default: 1.0).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    compiler = find_compiler(args.compiler)
    output = args.output.resolve()

    if args.watch:
        watch(
            output,
            compiler,
            args.configuration,
            max(args.interval, 0.2),
        )
    else:
        write_database(
            output,
            compiler,
            args.configuration,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
