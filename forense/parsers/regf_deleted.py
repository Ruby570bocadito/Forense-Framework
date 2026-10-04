"""Recovery of deleted keys and values from the unallocated space of a registry hive.

When a key or value is deleted, Windows marks its cells as free (positive cell
size) but does not wipe them: the key node (``nk``) keeps its name, last
written time, parent offset and value list, and value records (``vk``) keep
their name, type and a pointer to their data until the space is reused.

Free cells (and adjacent free cells merged into one) are scanned at 8-byte
boundaries for ``nk``/``vk`` records; allocated key and value cells that are
no longer linked to the tree (left behind by an interrupted or "healed"
write) are recovered too. The path of a deleted key is rebuilt by
following parent offsets through allocated and deleted keys; when the chain is
broken the path is *partial* (starts at the first key that could be resolved).
Data is recovered on a best-effort basis: a data cell that was reused since the
deletion yields whatever it holds now, so recovered values are leads to be
corroborated, as with any carved data.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from forense.core.utils import filetime_to_dt
from forense.parsers.regf import (
    BASE_BLOCK_SIZE,
    KEY_COMP_NAME,
    TYPE_NAMES,
    VALUE_COMP_NAME,
    RegistryError,
    RegistryHive,
    RegistryValue,
    _decode_name,
)

_HBIN_HEADER = 32
_NK_MIN, _VK_MIN = 76, 20  # fixed part of the records (after the cell size)
_MAX_VALUES = 4096
_MAX_DEPTH = 512


@dataclass
class DeletedValue:
    offset: int
    name: str
    type: int
    data: object  # str, list[str], int or bytes; None when the data cell is gone
    key_path: str = ""  # owner, when a deleted key references it
    data_size: int = 0

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.type, f"0x{self.type:x}")


@dataclass
class DeletedKey:
    offset: int
    name: str
    path: str
    partial: bool  # the parent chain is broken: the path starts at the first resolvable key
    last_written: Optional[datetime]
    parent_offset: int
    still_present: bool = False  # a live key with the same path exists (older copy of a key)
    values: list[DeletedValue] = field(default_factory=list)


@dataclass
class _Node:
    offset: int
    name: str
    parent: int
    last_written: Optional[datetime]
    value_count: int
    values_offset: int


def cells(hive: RegistryHive) -> list[tuple[int, int, bool]]:
    """``(start, end, free)`` file offsets of every cell in the hive bins."""
    data = hive.data
    end_of_bins = min(len(data), BASE_BLOCK_SIZE + hive.hbins_size) if hive.hbins_size > 0 else len(data)
    found = []
    pos = BASE_BLOCK_SIZE
    while pos + _HBIN_HEADER <= end_of_bins:
        if data[pos:pos + 4] != b"hbin":
            pos += 4096  # damaged bin: look for the next one on a page boundary
            continue
        size = struct.unpack_from("<I", data, pos + 8)[0]
        if size < 4096 or size % 4096 or pos + size > len(data):
            size = 4096
        cell, bin_end = pos + _HBIN_HEADER, pos + size
        while cell + 4 <= bin_end:
            raw = struct.unpack_from("<i", data, cell)[0]
            length = abs(raw)
            if length < 8 or length % 8 or cell + length > bin_end:
                break  # damaged cell chain: the rest of the bin cannot be walked reliably
            found.append((cell, cell + length, raw > 0))
            cell += length
        pos = bin_end
    return found


def free_regions(hive: RegistryHive) -> list[tuple[int, int]]:
    return [(start, end) for start, end, free in cells(hive) if free]


def _signatures(data, start: int, end: int, signature: bytes):
    """Offsets of record headers (cell size field) whose signature lies in ``[start, end)``."""
    find = data.find
    pos = find(signature, start + 4, end)
    while pos != -1:
        header = pos - 4
        if header % 8 == 0:
            yield header
        pos = find(signature, pos + 1, end)


def _node(data, header: int, region_end: int) -> Optional[_Node]:
    raw = struct.unpack_from("<i", data, header)[0]
    length = min(abs(raw), region_end - header) if raw else region_end - header
    if length < 4 + _NK_MIN:
        return None
    body = bytes(data[header + 4:header + length])
    flags = struct.unpack_from("<H", body, 2)[0]
    last_written = filetime_to_dt(struct.unpack_from("<Q", body, 4)[0])
    if last_written is None or not 1980 <= last_written.year <= 2200:
        return None
    parent = struct.unpack_from("<I", body, 16)[0]
    value_count, values_offset = struct.unpack_from("<II", body, 36)
    name_length = struct.unpack_from("<H", body, 72)[0]
    if not 0 < name_length <= len(body) - _NK_MIN or name_length > 512:
        return None
    name = _decode_name(body[76:76 + name_length], bool(flags & KEY_COMP_NAME))
    if not name or any(ord(c) < 32 for c in name):
        return None
    return _Node(header - BASE_BLOCK_SIZE, name, parent, last_written, value_count, values_offset)


def _plausible_value(data, header: int, region_end: int) -> bool:
    raw = struct.unpack_from("<i", data, header)[0]
    length = min(abs(raw), region_end - header) if raw else region_end - header
    if length < 4 + _VK_MIN:
        return False
    name_length, data_size, _offset, value_type, flags = struct.unpack_from("<HIIIH", data, header + 6)
    if name_length > length - 4 - _VK_MIN or name_length > 16383:
        return False
    if value_type > 0xFFFF and value_type not in (0xFFFF0000,):
        return False
    if not data_size & 0x80000000 and data_size > 64 * 1024 * 1024:
        return False
    if name_length:
        name = _decode_name(bytes(data[header + 24:header + 24 + name_length]), bool(flags & VALUE_COMP_NAME))
        if any(ord(c) < 32 for c in name):
            return False
    return True


def _value(hive: RegistryHive, offset: int, owner: str = "") -> Optional[DeletedValue]:
    try:
        value = RegistryValue(hive, offset)
    except (RegistryError, struct.error, IndexError):
        return None
    try:
        data = value.data
    except (RegistryError, struct.error, IndexError):
        data = None
    return DeletedValue(offset, value.name, value.type, data, owner, value._size & 0x7FFFFFFF)


def recover_deleted(hive: RegistryHive) -> tuple[list[DeletedKey], list[DeletedValue]]:
    """Deleted keys (with the values they still reference) and deleted values found in free cells."""
    data = hive.data
    live: dict[int, str] = {}
    referenced: set[int] = set()  # value records used by live keys
    for key in hive.walk():
        live[key.offset] = key.path
        if key._value_count and key._values_offset != 0xFFFFFFFF:
            try:
                listing = hive.cell(key._values_offset)
            except RegistryError:
                continue
            count = min(key._value_count, len(listing) // 4)
            referenced.update(struct.unpack_from(f"<{count}I", listing))
    live_paths = {path.lower() for path in live.values()}

    nodes: dict[int, _Node] = {}
    value_offsets: list[int] = []

    def add_node(header: int, end: int) -> None:
        try:
            node = _node(data, header, end)
        except struct.error:
            node = None
        if node is not None and node.offset not in live:
            nodes[node.offset] = node

    def add_value(header: int, end: int) -> None:
        try:
            if header - BASE_BLOCK_SIZE not in referenced and _plausible_value(data, header, end):
                value_offsets.append(header - BASE_BLOCK_SIZE)
        except struct.error:
            pass

    for start, end, free in cells(hive):
        if free:  # freed records, possibly several merged into one free cell
            for header in _signatures(data, start, end, b"nk"):
                add_node(header, end)
            for header in _signatures(data, start, end, b"vk"):
                add_value(header, end)
        elif data[start + 4:start + 6] == b"nk":  # allocated but no longer linked to the tree
            add_node(start, end)
        elif data[start + 4:start + 6] == b"vk":
            add_value(start, end)

    paths: dict[int, tuple[str, bool]] = {}

    def resolve(offset: int, depth: int = 0) -> Optional[tuple[str, bool]]:
        """(path, partial) of a key, or None when ``offset`` is not a key we know."""
        if offset in live:
            return live[offset], False
        if offset in paths:
            return paths[offset]
        node = nodes.get(offset)
        if node is None or depth > _MAX_DEPTH:
            return None
        paths[offset] = (node.name, True)  # provisional: breaks cycles between deleted keys
        parent = resolve(node.parent, depth + 1) if node.parent != offset else None
        if parent is None:
            result = (node.name, True)
        else:
            result = (f"{parent[0]}\\{node.name}" if parent[0] else node.name, parent[1])
        paths[offset] = result
        return result

    keys: list[DeletedKey] = []
    owned: dict[int, str] = {}
    for offset in sorted(nodes):
        node = nodes[offset]
        path, partial = resolve(offset) or (node.name, True)
        key = DeletedKey(offset, node.name, path, partial, node.last_written, node.parent,
                         still_present=not partial and path.lower() in live_paths)
        if node.value_count and node.values_offset != 0xFFFFFFFF:
            try:
                listing = hive.cell(node.values_offset)
            except RegistryError:
                listing = b""
            for i in range(min(node.value_count, len(listing) // 4, _MAX_VALUES)):
                value_offset = struct.unpack_from("<I", listing, i * 4)[0]
                value = _value(hive, value_offset, path)
                if value is not None:
                    key.values.append(value)
                    owned[value_offset] = path
        keys.append(key)

    values: list[DeletedValue] = []
    seen: set[int] = set()
    for offset in value_offsets:
        if offset in seen:
            continue
        seen.add(offset)
        value = _value(hive, offset, owned.get(offset, ""))
        if value is not None:
            values.append(value)
    return keys, values
