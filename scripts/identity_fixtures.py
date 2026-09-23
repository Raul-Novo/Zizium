# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent byte fixtures for explicitly requested identity acceptance images."""

from collections.abc import Callable
from pathlib import Path

VOLUME = bytes.fromhex("215a69465300400180006496e6d1ecfc")
ISSUER = bytes.fromhex("51192026") + bytes(12)
DATABASE = bytes.fromhex("62192026") + bytes(12)
DESTINATION = "Zizium/Security/Identity Fixture.db"


def database_fixture(generation: int, checksum: Callable[[bytes], int]) -> bytes:
    """Encode four fixed expected snapshots, never production provisioning."""
    if generation not in (1, 2, 3, 4):
        raise ValueError("Unsupported identity fixture generation.")
    data = bytearray(36864)

    def put(offset: int, size: int, value: int) -> None:
        data[offset:offset + size] = value.to_bytes(size, "little")

    count = (0, 0, 1, 1, 2)[generation]
    data[:4] = b"ZIDB"
    for offset, size, value in (
        (4, 2, 1), (6, 2, 4096), (8, 4, len(data)), (12, 2, 512),
        (14, 2, 64), (16, 4, count), (24, 8, generation),
        (80, 4, 255), (84, 4, 255 + count), (88, 4, 255),
    ):
        put(offset, size, value)
    data[32:48], data[48:64], data[64:80] = ISSUER, VOLUME, DATABASE
    for index in range(count):
        start = 4096 + index * 512
        tombstone = index == 0 and generation >= 3
        data[start:start + 4] = b"ZIAR"
        for offset, size, value in (
            (4, 2, 1), (6, 2, 512), (8, 4, 2 if tombstone else 1),
            (20, 2, 1), (22, 2, 32), (40, 4, 3), (44, 4, 256 + index),
            (48, 2, 9), (56, 8, 3 if tombstone else 2 + index * 2),
        ):
            put(start + offset, size, value)
        data[start + 16:start + 20] = b"ZNID"
        data[start + 24:start + 40] = ISSUER
        data[start + 64:start + 73] = b"Seed User"
        put(start + 508, 4, checksum(bytes(data[start:start + 508])))
    put(4092, 4, checksum(bytes(data)))
    return bytes(data)


def integer(data: bytes, offset: int, size: int) -> int:
    if offset < 0 or offset + size > len(data):
        raise ValueError("Identity fixture field is outside its image.")
    return int.from_bytes(data[offset:offset + size], "little")


def file_record(data: bytes, index: int) -> int:
    if index >= integer(data, 88, 8) * 16:
        raise ValueError("Identity fixture record index exceeds the table.")
    return integer(data, 80, 8) * 4096 + index * 256


def binding(raw_path: Path) -> tuple[int, int]:
    """Inspect trusted formatter output before boot, not guest identity contents."""
    data = raw_path.read_bytes()
    if data[40:56] != VOLUME:
        raise ValueError("Formatter volume differs from the independent fixture UUID.")
    index = integer(data, 72, 8)
    for name in DESTINATION.split("/"):
        record = file_record(data, index)
        directory = integer(data, record + 224, 8) * 4096
        cursor = directory + 64
        entries = integer(data, directory + 16, 4)
        if entries > 168:
            raise ValueError("Identity fixture directory entry count exceeds its block.")
        matches = []
        for _ in range(entries):
            size = integer(data, cursor, 2)
            name_size = integer(data, cursor + 2, 2)
            if size < 24 + name_size or cursor + size > directory + 4096:
                raise ValueError("Identity fixture directory entry is malformed.")
            if data[cursor + 24:cursor + 24 + name_size] == name.encode("utf-8"):
                matches.append(integer(data, cursor + 16, 8))
            cursor += size
        if len(matches) != 1:
            raise ValueError("Identity fixture path must resolve exactly once.")
        index = matches[0]
    record = file_record(data, index)
    if integer(data, record + 48, 8) != 2:
        raise ValueError("Identity fixture did not receive the private initial descriptor.")
    return index, integer(data, record + 8, 8)


def check_snapshot(image_path: Path, expected_binding: tuple[int, int], expected: bytes) -> None:
    """Read an inspector-validated GPT image and compare every database byte."""
    with image_path.open("rb") as image:
        image.seek(1024 + 128)
        entry = image.read(128)
        first = integer(entry, 32, 8)
        last = integer(entry, 40, 8)
        if last < first or (last - first + 1) * 512 != 32 * 1024 * 1024:
            raise ValueError("Identity fixture partition geometry differs.")
        image.seek(first * 512)
        data = image.read(32 * 1024 * 1024)
    if len(data) != 32 * 1024 * 1024 or data[40:56] != VOLUME:
        raise ValueError("Identity fixture partition is truncated or unbound.")
    record = file_record(data, expected_binding[0])
    if (integer(data, record + 8, 8) != expected_binding[1]
            or integer(data, record + 32, 8) != len(expected)
            or integer(data, record + 56, 4) != 1
            or integer(data, record + 64, 8) != 0
            or integer(data, record + 80, 8) != 9):
        raise ValueError("Identity fixture file identity or extent shape changed.")
    start = integer(data, record + 72, 8) * 4096
    if data[start:start + len(expected)] != expected:
        raise ValueError("Persisted identity database differs from its complete expected snapshot.")
