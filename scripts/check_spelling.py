# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject project-owned American spellings for words with mandated forms."""

from __future__ import annotations

from pathlib import Path
import re
import sys


FORBIDDEN = re.compile(
    r"\b(?:color|colors|behavior|behaviors|initialize|initialized|initializing|"
    r"initialization|serialize|serialized|serialization|normalize|normalized|"
    r"normalization|synchronize|synchronized|synchronization|center|centered|"
    r"favor|favored|favorite|neighbor|neighbors|catalog|catalogs)\b",
    re.IGNORECASE,
)
TEXT_SUFFIXES = {".c", ".h", ".md", ".ps1", ".py", ".asm", ".conf", ".json", ".zsvc"}
EXCLUDED_FILES = {"LICENSE", "c_style.md", "check_spelling.py"}
EXCLUDED_DIRECTORIES = {"build", ".git"}
EXTERNAL_API_MARKERS = (
    "SPDX-License-Identifier",
    "Program Files",
    "Program Data",
    "https://",
    "http://",
)


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    failures: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name in EXCLUDED_FILES:
            continue
        relative = path.relative_to(root)
        if any(part in EXCLUDED_DIRECTORIES for part in relative.parts):
            continue
        if relative.parts[:2] == ("external", "deps"):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {
            ".clangd",
            ".clang-format",
            ".clang-tidy",
            ".editorconfig",
            "Makefile",
        }:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(lines, start=1):
            if any(marker in line for marker in EXTERNAL_API_MARKERS):
                continue
            match = FORBIDDEN.search(line)
            if match is not None:
                failures.append(f"{relative}:{line_number}: forbidden spelling '{match.group(0)}'")
    if failures:
        print("British-English spelling check failed:")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print("British-English spelling check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
