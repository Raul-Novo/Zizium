# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent formatter-wire assertions; runtime ACL decisions are boot-tested."""

from pathlib import Path


def check_private_storage(image_path: Path) -> None:
    """Inspect a small, inspector-validated fixture without modifying it."""
    data = image_path.read_bytes()

    def integer(offset: int, size: int) -> int:
        if offset < 0 or offset + size > len(data):
            raise ValueError("Private-storage fixture field is outside the image.")
        return int.from_bytes(data[offset:offset + size], "little")

    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(f"Private-storage fixture: {message}")

    record_start = integer(80, 8) * 4096
    security_start = integer(144, 8) * 4096
    require(integer(security_start + 16, 4) == 2, "expected two descriptors")
    private = security_start + 512
    require(data[private:private + 4] == b"ZISE", "missing private descriptor")
    require(integer(private + 8, 8) == 2, "private ID differs")
    require(integer(private + 16, 4) == 1, "DACL must be present")
    require(integer(private + 20, 4) == 0, "unexpected descriptor controls")
    require(integer(private + 24, 4) == 1, "owner must be SYSTEM authority")
    require(integer(private + 28, 4) == 1, "owner must be SYSTEM:1")
    require(integer(private + 32, 4) == 2, "primary group authority differs")
    require(integer(private + 36, 4) == 1, "primary group must be Administrators")
    require(integer(private + 40, 2) == 1, "private DACL must have exactly one ACE")
    require(integer(private + 48, 1) == 1, "private ACE must allow")
    require(integer(private + 49, 3) == 0, "no ACE inheritance or reserved flags")
    require(integer(private + 52, 4) == 255, "SYSTEM requires explicit FullControl")
    require(integer(private + 56, 4) == 1, "trustee must be SYSTEM authority")
    require(integer(private + 60, 4) == 1, "trustee must be SYSTEM:1")
    require(not any(data[private + 64:private + 252]), "unexpected trailing policy")

    def record_for(components: tuple[bytes, ...]) -> int:
        record = record_start + integer(72, 8) * 256
        for component in components:
            directory = integer(record + 224, 8) * 4096
            count = integer(directory + 16, 4)
            cursor = directory + 64
            matches = []
            for _ in range(count):
                entry_size = integer(cursor, 2)
                name_size = integer(cursor + 2, 2)
                require(entry_size >= 24 + name_size, "invalid directory entry")
                require(cursor + entry_size <= directory + 4096, "entry crosses block")
                if data[cursor + 24:cursor + 24 + name_size] == component:
                    matches.append(integer(cursor + 16, 8))
                cursor += entry_size
            require(len(matches) == 1, f"exact path component missing or duplicate: {component!r}")
            record = record_start + matches[0] * 256
        return record

    paths = (
        ((b"Zizium", b"Security"), 2),
        ((b"Zizium", b"Security", b"Private Fixture"), 2),
        ((b"Zizium", b"Security", b"private fixture"), 2),
        ((b"Zizium", b"SecurityOther"), 1),
        ((b"Zizium", b"security"), 1),
        ((b"Temp", b"Security"), 1),
        ((b"Temp",), 1),
        ((b"Zizium",), 1),
    )
    seen = set()
    for path, expected in paths:
        record = record_for(path)
        require(record not in seen, "distinct exact-case paths alias one record")
        seen.add(record)
        require(integer(record + 48, 8) == expected, f"wrong security ID for {path!r}")
