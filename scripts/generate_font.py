# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate the early Zizium 8x16 bitmap table from the pinned Spleen BDF."""

from __future__ import annotations

import argparse
from pathlib import Path


def read_glyphs(path: Path) -> dict[int, list[int]]:
    glyphs: dict[int, list[int]] = {}
    encoding: int | None = None
    bitmap: list[int] | None = None
    for raw_line in path.read_text(encoding="ascii").splitlines():
        line = raw_line.strip()
        if line.startswith("ENCODING "):
            encoding = int(line.split()[1])
        elif line == "BITMAP":
            bitmap = []
        elif line == "ENDCHAR":
            if encoding is not None and bitmap is not None and len(bitmap) == 16:
                glyphs[encoding] = bitmap
            encoding = None
            bitmap = None
        elif bitmap is not None:
            bitmap.append(int(line, 16))
    return glyphs


def generate(input_path: Path, output_path: Path) -> None:
    glyphs = read_glyphs(input_path)
    missing = [codepoint for codepoint in range(32, 127) if codepoint not in glyphs]
    if missing:
        raise ValueError(f"Spleen BDF is missing required glyphs: {missing}")
    replacement = [0x7E, 0x42, 0x5A, 0x5A, 0x66, 0x66, 0x5A, 0x5A,
                   0x42, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    rows: list[list[int]] = []
    for codepoint in range(128):
        if codepoint < 32:
            rows.append([0] * 16)
        elif codepoint == 127:
            rows.append(replacement)
        else:
            rows.append(glyphs[codepoint])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "// Generated from Spleen 8x16 2.2.0; do not edit.",
        "// SPDX-License-Identifier: BSD-2-Clause",
        "",
        "#include <stdint.h>",
        "",
        "const uint8_t k_zi_font_spleen_8x16[128][16] = {",
    ]
    for codepoint, row in enumerate(rows):
        values = ", ".join(f"0x{value:02x}" for value in row)
        lines.append(f"    /* U+{codepoint:04X} */ {{{values}}},")
    lines.extend(["};", ""])
    output_path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    generate(arguments.input, arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
