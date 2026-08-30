# SPDX-License-Identifier: GPL-3.0-or-later
"""Create Zizium's deterministic GPT, FAT32 ESP, and ZiFS disk image."""

from __future__ import annotations

import argparse
import binascii
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import struct
import uuid


SECTOR_SIZE = 512
IMAGE_SIZE_MIB = 128
TOTAL_SECTORS = IMAGE_SIZE_MIB * 1024 * 1024 // SECTOR_SIZE
ESP_START = 2048
ESP_SECTORS = 64 * 1024 * 1024 // SECTOR_SIZE
ZIFS_START = ESP_START + ESP_SECTORS
ZIFS_SECTORS = 32 * 1024 * 1024 // SECTOR_SIZE
GPT_ENTRY_COUNT = 128
GPT_ENTRY_SIZE = 128
GPT_ENTRY_SECTORS = GPT_ENTRY_COUNT * GPT_ENTRY_SIZE // SECTOR_SIZE

ESP_TYPE = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
ZIFS_TYPE = uuid.UUID("9ef9e22a-3719-44d4-89af-de9cc7b6b255")
DISK_GUID = uuid.UUID("215a495a-0001-4000-8021-6496e6d1ecfc")
ESP_GUID = uuid.UUID("215a495a-1001-4000-8021-6496e6d1ecfc")
ZIFS_GUID = uuid.UUID("215a495a-1002-4000-8021-6496e6d1ecfc")


@dataclass
class FatNode:
    name: str
    is_directory: bool
    source: Path | None = None
    children: list["FatNode"] = field(default_factory=list)
    parent: "FatNode | None" = None
    first_cluster: int = 0
    clusters: list[int] = field(default_factory=list)

    @property
    def size(self) -> int:
        if self.is_directory:
            return 0
        if self.source is None:
            raise ValueError(f"file node {self.name!r} has no source")
        return self.source.stat().st_size

    def add(self, child: "FatNode") -> "FatNode":
        child.parent = self
        self.children.append(child)
        return child


class Fat32Volume:
    def __init__(self, image, partition_start: int, total_sectors: int) -> None:
        self.image = image
        self.partition_start = partition_start
        self.total_sectors = total_sectors
        self.sectors_per_cluster = 1
        self.reserved_sectors = 32
        self.fat_count = 2
        self.fat_sectors = 1
        while True:
            data_sectors = (
                self.total_sectors
                - self.reserved_sectors
                - self.fat_count * self.fat_sectors
            )
            cluster_count = data_sectors // self.sectors_per_cluster
            required = (cluster_count + 2) * 4
            calculated = (required + SECTOR_SIZE - 1) // SECTOR_SIZE
            if calculated <= self.fat_sectors:
                break
            self.fat_sectors = calculated
        self.data_start = self.reserved_sectors + self.fat_count * self.fat_sectors
        self.cluster_count = (
            self.total_sectors - self.data_start
        ) // self.sectors_per_cluster
        if self.cluster_count < 65525:
            raise ValueError("the ESP is too small to be a conforming FAT32 volume")
        self.fat = [0] * (self.cluster_count + 2)
        self.fat[0] = 0x0FFFFFF8
        self.fat[1] = 0x0FFFFFFF
        self.next_cluster = 2

    @property
    def cluster_size(self) -> int:
        return self.sectors_per_cluster * SECTOR_SIZE

    def allocate(self, count: int) -> list[int]:
        if count <= 0:
            return []
        if self.next_cluster + count > len(self.fat):
            raise ValueError("the ESP does not have enough free clusters")
        result = list(range(self.next_cluster, self.next_cluster + count))
        self.next_cluster += count
        for index, cluster in enumerate(result):
            self.fat[cluster] = (
                result[index + 1] if index + 1 < len(result) else 0x0FFFFFFF
            )
        return result

    def cluster_offset(self, cluster: int) -> int:
        relative_sector = self.data_start + (cluster - 2) * self.sectors_per_cluster
        return (self.partition_start + relative_sector) * SECTOR_SIZE

    def write(self, root: FatNode) -> None:
        directories = list(walk_directories(root))
        files = list(walk_files(root))
        for directory in directories:
            directory.clusters = self.allocate(1)
            directory.first_cluster = directory.clusters[0]
        for node in files:
            cluster_count = max(1, (node.size + self.cluster_size - 1) // self.cluster_size)
            node.clusters = self.allocate(cluster_count)
            node.first_cluster = node.clusters[0]

        self.write_boot_regions(root.first_cluster)
        for directory in directories:
            data = encode_directory(directory, root.first_cluster, self.cluster_size)
            self.write_cluster(directory.first_cluster, data)
        for node in files:
            self.write_file(node)
        self.write_fats()
        self.write_fsinfo()

    def write_boot_regions(self, root_cluster: int) -> None:
        boot = bytearray(SECTOR_SIZE)
        boot[0:3] = b"\xeb\x58\x90"
        boot[3:11] = b"ZIZIUM  "
        struct.pack_into("<H", boot, 11, SECTOR_SIZE)
        boot[13] = self.sectors_per_cluster
        struct.pack_into("<H", boot, 14, self.reserved_sectors)
        boot[16] = self.fat_count
        struct.pack_into("<H", boot, 17, 0)
        struct.pack_into("<H", boot, 19, 0)
        boot[21] = 0xF8
        struct.pack_into("<H", boot, 22, 0)
        struct.pack_into("<H", boot, 24, 63)
        struct.pack_into("<H", boot, 26, 255)
        struct.pack_into("<I", boot, 28, self.partition_start)
        struct.pack_into("<I", boot, 32, self.total_sectors)
        struct.pack_into("<I", boot, 36, self.fat_sectors)
        struct.pack_into("<H", boot, 40, 0)
        struct.pack_into("<H", boot, 42, 0)
        struct.pack_into("<I", boot, 44, root_cluster)
        struct.pack_into("<H", boot, 48, 1)
        struct.pack_into("<H", boot, 50, 6)
        boot[64] = 0x80
        boot[66] = 0x29
        struct.pack_into("<I", boot, 67, 0x215A495A)
        boot[71:82] = b"ZIZIUM ESP "
        boot[82:90] = b"FAT32   "
        boot[510:512] = b"\x55\xaa"
        self.write_sector(0, boot)
        self.write_sector(6, boot)

    def write_fsinfo(self) -> None:
        info = bytearray(SECTOR_SIZE)
        struct.pack_into("<I", info, 0, 0x41615252)
        struct.pack_into("<I", info, 484, 0x61417272)
        free_clusters = self.cluster_count - (self.next_cluster - 2)
        struct.pack_into("<I", info, 488, free_clusters)
        struct.pack_into("<I", info, 492, self.next_cluster)
        struct.pack_into("<I", info, 508, 0xAA550000)
        self.write_sector(1, info)
        self.write_sector(7, info)

    def write_fats(self) -> None:
        data = bytearray(self.fat_sectors * SECTOR_SIZE)
        for index, value in enumerate(self.fat):
            struct.pack_into("<I", data, index * 4, value)
        for copy_index in range(self.fat_count):
            relative_sector = self.reserved_sectors + copy_index * self.fat_sectors
            self.image.seek((self.partition_start + relative_sector) * SECTOR_SIZE)
            self.image.write(data)

    def write_file(self, node: FatNode) -> None:
        if node.source is None:
            raise ValueError(f"file node {node.name!r} has no source")
        self.image.seek(self.cluster_offset(node.first_cluster))
        with node.source.open("rb") as source:
            copied = 0
            while data := source.read(1024 * 1024):
                self.image.write(data)
                copied += len(data)
        allocated_size = len(node.clusters) * self.cluster_size
        if copied > allocated_size:
            raise ValueError(f"file {node.source} changed while the image was built")
        if copied < allocated_size:
            self.image.write(bytes(allocated_size - copied))

    def write_cluster(self, cluster: int, data: bytes) -> None:
        if len(data) != self.cluster_size:
            raise ValueError("cluster writes must have exactly one cluster of data")
        self.image.seek(self.cluster_offset(cluster))
        self.image.write(data)

    def write_sector(self, relative_sector: int, data: bytes) -> None:
        if len(data) != SECTOR_SIZE:
            raise ValueError("sector writes must contain exactly 512 bytes")
        self.image.seek((self.partition_start + relative_sector) * SECTOR_SIZE)
        self.image.write(data)


def walk_directories(root: FatNode):
    yield root
    for child in root.children:
        if child.is_directory:
            yield from walk_directories(child)


def walk_files(root: FatNode):
    for child in root.children:
        if child.is_directory:
            yield from walk_files(child)
        else:
            yield child


def short_name(name: str) -> tuple[bytes, bool]:
    parts = name.rsplit(".", 1)
    base = parts[0]
    extension = parts[1] if len(parts) == 2 else ""
    valid = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$%'-@~`!(){}^#&")
    upper_base = base.upper()
    upper_extension = extension.upper()
    fits = (
        1 <= len(upper_base) <= 8
        and len(upper_extension) <= 3
        and all(character in valid for character in upper_base + upper_extension)
    )
    if fits:
        return (upper_base.ljust(8) + upper_extension.ljust(3)).encode("ascii"), False
    clean_base = "".join(character for character in upper_base if character in valid)
    clean_extension = "".join(
        character for character in upper_extension if character in valid
    )
    alias = (clean_base[:6] + "~1").ljust(8) + clean_extension[:3].ljust(3)
    return alias.encode("ascii"), True


def lfn_checksum(short: bytes) -> int:
    value = 0
    for byte in short:
        value = ((value & 1) << 7) + (value >> 1) + byte
        value &= 0xFF
    return value


def encode_lfn_entries(name: str, short: bytes) -> list[bytes]:
    encoded = name.encode("utf-16le")
    units = list(struct.unpack(f"<{len(encoded) // 2}H", encoded))
    units.append(0)
    while len(units) % 13:
        units.append(0xFFFF)
    chunks = [units[index : index + 13] for index in range(0, len(units), 13)]
    result: list[bytes] = []
    checksum = lfn_checksum(short)
    for sequence in range(len(chunks), 0, -1):
        entry = bytearray(32)
        entry[0] = sequence | (0x40 if sequence == len(chunks) else 0)
        entry[11] = 0x0F
        entry[12] = 0
        entry[13] = checksum
        struct.pack_into("<H", entry, 26, 0)
        chunk = chunks[sequence - 1]
        positions = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
        for position, unit in zip(positions, chunk, strict=True):
            struct.pack_into("<H", entry, position, unit)
        result.append(bytes(entry))
    return result


def encode_short_entry(node: FatNode, short: bytes) -> bytes:
    entry = bytearray(32)
    entry[0:11] = short
    entry[11] = 0x10 if node.is_directory else 0x20
    dos_time = (11 << 11) | (45 << 5)
    dos_date = ((2026 - 1980) << 9) | (8 << 5) | 8
    struct.pack_into("<H", entry, 14, dos_time)
    struct.pack_into("<H", entry, 16, dos_date)
    struct.pack_into("<H", entry, 18, dos_date)
    struct.pack_into("<H", entry, 22, dos_time)
    struct.pack_into("<H", entry, 24, dos_date)
    struct.pack_into("<H", entry, 20, node.first_cluster >> 16)
    struct.pack_into("<H", entry, 26, node.first_cluster & 0xFFFF)
    struct.pack_into("<I", entry, 28, node.size)
    return bytes(entry)


def encode_dot_entry(name: bytes, cluster: int) -> bytes:
    entry = bytearray(32)
    entry[0:11] = name.ljust(11, b" ")
    entry[11] = 0x10
    struct.pack_into("<H", entry, 20, cluster >> 16)
    struct.pack_into("<H", entry, 26, cluster & 0xFFFF)
    return bytes(entry)


def encode_directory(directory: FatNode, root_cluster: int, cluster_size: int) -> bytes:
    entries: list[bytes] = []
    if directory.parent is not None:
        entries.append(encode_dot_entry(b".", directory.first_cluster))
        parent_cluster = (
            directory.parent.first_cluster
            if directory.parent.parent is not None
            else root_cluster
        )
        entries.append(encode_dot_entry(b"..", parent_cluster))
    for node in directory.children:
        short, needs_lfn = short_name(node.name)
        if needs_lfn:
            entries.extend(encode_lfn_entries(node.name, short))
        entries.append(encode_short_entry(node, short))
    data = b"".join(entries)
    if len(data) > cluster_size:
        raise ValueError(f"directory {directory.name!r} exceeds one early FAT cluster")
    return data + bytes(cluster_size - len(data))


def create_tree(
    limine_efi: Path,
    configuration: Path,
    kernel: Path,
    zifs: Path,
    modules: list[tuple[str, Path]],
) -> FatNode:
    root = FatNode("", True)
    efi = root.add(FatNode("EFI", True))
    efi_boot = efi.add(FatNode("BOOT", True))
    efi_boot.add(FatNode("BOOTX64.EFI", False, limine_efi))
    efi_boot.add(FatNode("limine.conf", False, configuration))
    root.add(FatNode("limine.conf", False, configuration))
    zizium = root.add(FatNode("Zizium", True))
    zizium_boot = zizium.add(FatNode("Boot", True))
    zizium_boot.add(FatNode("zizium.efi", False, kernel))
    zizium_boot.add(FatNode("zizium-root.zifs", False, zifs))
    for destination, source in modules:
        components = destination.replace("\\", "/").split("/")
        if not components or any(not component or component in {".", ".."} for component in components):
            raise ValueError(f"invalid Zizium module destination {destination!r}")
        parent = zizium
        for component in components[:-1]:
            child = next(
                (node for node in parent.children if node.name == component and node.is_directory),
                None,
            )
            if child is None:
                child = parent.add(FatNode(component, True))
            parent = child
        if any(node.name == components[-1] for node in parent.children):
            raise ValueError(f"duplicate Zizium module destination {destination!r}")
        parent.add(FatNode(components[-1], False, source))
    return root


def encode_partition_entry(
    type_guid: uuid.UUID,
    unique_guid: uuid.UUID,
    first_lba: int,
    last_lba: int,
    name: str,
) -> bytes:
    entry = bytearray(GPT_ENTRY_SIZE)
    entry[0:16] = type_guid.bytes_le
    entry[16:32] = unique_guid.bytes_le
    struct.pack_into("<Q", entry, 32, first_lba)
    struct.pack_into("<Q", entry, 40, last_lba)
    struct.pack_into("<Q", entry, 48, 0)
    encoded_name = name.encode("utf-16le")
    entry[56 : 56 + min(len(encoded_name), 72)] = encoded_name[:72]
    return bytes(entry)


def encode_gpt_header(
    current_lba: int,
    backup_lba: int,
    entries_lba: int,
    entries_crc: int,
) -> bytes:
    header = bytearray(SECTOR_SIZE)
    header[0:8] = b"EFI PART"
    struct.pack_into("<I", header, 8, 0x00010000)
    struct.pack_into("<I", header, 12, 92)
    struct.pack_into("<I", header, 16, 0)
    struct.pack_into("<Q", header, 24, current_lba)
    struct.pack_into("<Q", header, 32, backup_lba)
    struct.pack_into("<Q", header, 40, 34)
    struct.pack_into("<Q", header, 48, TOTAL_SECTORS - GPT_ENTRY_SECTORS - 2)
    header[56:72] = DISK_GUID.bytes_le
    struct.pack_into("<Q", header, 72, entries_lba)
    struct.pack_into("<I", header, 80, GPT_ENTRY_COUNT)
    struct.pack_into("<I", header, 84, GPT_ENTRY_SIZE)
    struct.pack_into("<I", header, 88, entries_crc)
    checksum = binascii.crc32(header[:92]) & 0xFFFFFFFF
    struct.pack_into("<I", header, 16, checksum)
    return bytes(header)


def write_gpt(image) -> None:
    mbr = bytearray(SECTOR_SIZE)
    mbr[446 + 4] = 0xEE
    struct.pack_into("<I", mbr, 446 + 8, 1)
    struct.pack_into("<I", mbr, 446 + 12, TOTAL_SECTORS - 1)
    mbr[510:512] = b"\x55\xaa"
    image.seek(0)
    image.write(mbr)

    entries = bytearray(GPT_ENTRY_COUNT * GPT_ENTRY_SIZE)
    entries[0:GPT_ENTRY_SIZE] = encode_partition_entry(
        ESP_TYPE,
        ESP_GUID,
        ESP_START,
        ESP_START + ESP_SECTORS - 1,
        "EFI System Partition",
    )
    entries[GPT_ENTRY_SIZE : 2 * GPT_ENTRY_SIZE] = encode_partition_entry(
        ZIFS_TYPE,
        ZIFS_GUID,
        ZIFS_START,
        ZIFS_START + ZIFS_SECTORS - 1,
        "Zizium ZiFS",
    )
    entries_crc = binascii.crc32(entries) & 0xFFFFFFFF
    primary_header = encode_gpt_header(1, TOTAL_SECTORS - 1, 2, entries_crc)
    backup_entries_lba = TOTAL_SECTORS - GPT_ENTRY_SECTORS - 1
    backup_header = encode_gpt_header(
        TOTAL_SECTORS - 1, 1, backup_entries_lba, entries_crc
    )
    image.seek(SECTOR_SIZE)
    image.write(primary_header)
    image.seek(2 * SECTOR_SIZE)
    image.write(entries)
    image.seek(backup_entries_lba * SECTOR_SIZE)
    image.write(entries)
    image.seek((TOTAL_SECTORS - 1) * SECTOR_SIZE)
    image.write(backup_header)


def copy_zifs_partition(image, zifs_path: Path) -> None:
    if zifs_path.stat().st_size != ZIFS_SECTORS * SECTOR_SIZE:
        raise ValueError("the ZiFS partition image must be exactly 32 MiB")
    image.seek(ZIFS_START * SECTOR_SIZE)
    with zifs_path.open("rb") as source:
        while data := source.read(1024 * 1024):
            image.write(data)


def build_image(arguments: argparse.Namespace) -> str:
    for path in (
        arguments.limine,
        arguments.configuration,
        arguments.kernel,
        arguments.zifs,
    ):
        if not path.is_file():
            raise FileNotFoundError(path)
    modules = [(destination, Path(source)) for destination, source in arguments.module]
    for _, source in modules:
        if not source.is_file():
            raise FileNotFoundError(source)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    with arguments.output.open("w+b") as image:
        image.truncate(TOTAL_SECTORS * SECTOR_SIZE)
        write_gpt(image)
        tree = create_tree(
            arguments.limine,
            arguments.configuration,
            arguments.kernel,
            arguments.zifs,
            modules,
        )
        Fat32Volume(image, ESP_START, ESP_SECTORS).write(tree)
        copy_zifs_partition(image, arguments.zifs)
        image.flush()
    digest = hashlib.sha256()
    with arguments.output.open("rb") as image:
        while data := image.read(1024 * 1024):
            digest.update(data)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--limine", required=True, type=Path)
    parser.add_argument("--configuration", required=True, type=Path)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--zifs", required=True, type=Path)
    parser.add_argument(
        "--module",
        action="append",
        nargs=2,
        default=[],
        metavar=("DESTINATION", "SOURCE"),
        help="optionally add a recovery/debug PE module beneath C:\\Zizium in the ESP",
    )
    arguments = parser.parse_args()
    digest = build_image(arguments)
    print(f"Created deterministic {IMAGE_SIZE_MIB} MiB Zizium GPT image: {arguments.output}")
    print(f"SHA-256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
