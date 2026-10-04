"""Parser of the NTFS Master File Table ($MFT) extracted as a file.

For each FILE record it extracts the $STANDARD_INFORMATION and $FILE_NAME
timestamps, the logical size, alternate data streams (including the content of
``Zone.Identifier``, which records where a file was downloaded from) and the
full path rebuilt from parent references. Records are fixed up with the update
sequence array before parsing.

Limitations: attributes stored in extension records ($ATTRIBUTE_LIST) of very
fragmented files are not merged into their base record.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Iterator, Optional

from forense.core.utils import filetime_to_dt

ROOT_RECORD = 5
SI, ATTR_LIST, FILE_NAME, DATA, END = 0x10, 0x20, 0x30, 0x80, 0xFFFFFFFF
NAMESPACE_DOS = 2
SECTOR = 512


class MftError(ValueError):
    pass


@dataclass
class Timestamps:
    created: int
    modified: int
    mft_modified: int
    accessed: int

    def as_datetimes(self) -> dict[str, Optional[datetime]]:
        return {"created": filetime_to_dt(self.created), "modified": filetime_to_dt(self.modified),
                "mft_modified": filetime_to_dt(self.mft_modified), "accessed": filetime_to_dt(self.accessed)}


@dataclass
class MftEntry:
    record: int
    sequence: int
    in_use: bool
    is_directory: bool
    base_record: int
    si: Optional[Timestamps] = None
    fn: Optional[Timestamps] = None
    name: str = ""
    parent_record: int = 0
    parent_sequence: int = 0
    size: int = 0
    ads: list[str] = field(default_factory=list)
    zone_identifier: str = ""
    fixup_ok: bool = True

    @property
    def timestomp_indicators(self) -> list[str]:
        """Heuristic signs that $STANDARD_INFORMATION timestamps were manipulated."""
        if not self.si or not self.fn or not self.si.created or not self.fn.created:
            return []
        indicators = []
        if self.si.created < self.fn.created - 10_000_000:  # earlier by more than 1 s
            indicators.append("si_created_before_fn")
        if self.si.created % 10_000_000 == 0 and self.fn.created % 10_000_000 != 0:
            indicators.append("si_no_subseconds")
        return indicators


def _apply_fixups(buf: bytearray) -> bool:
    usa_offset, usa_count = struct.unpack_from("<HH", buf, 4)
    if usa_count < 2 or usa_offset + usa_count * 2 > len(buf):
        return False
    usn = bytes(buf[usa_offset:usa_offset + 2])
    ok = True
    for i in range(1, usa_count):
        end = i * SECTOR - 2
        if end + 2 > len(buf):
            break
        if buf[end:end + 2] != usn:
            ok = False
        buf[end:end + 2] = buf[usa_offset + i * 2:usa_offset + i * 2 + 2]
    return ok


def parse_record(raw: bytes, record_number: int) -> Optional[MftEntry]:
    """Parse one FILE record; returns None for empty or non-FILE (e.g. ``BAAD``) records."""
    if raw[:4] != b"FILE":
        return None
    buf = bytearray(raw)
    fixup_ok = _apply_fixups(buf)
    sequence, _links, first_attr, flags = struct.unpack_from("<HHHH", buf, 16)
    base_ref = struct.unpack_from("<Q", buf, 32)[0] & 0xFFFFFFFFFFFF
    entry = MftEntry(record_number, sequence, bool(flags & 0x1), bool(flags & 0x2), base_ref, fixup_ok=fixup_ok)

    best_ns = None
    off = first_attr
    while off + 16 <= len(buf):
        attr_type, length = struct.unpack_from("<II", buf, off)
        if attr_type == END or length < 16 or off + length > len(buf):
            break
        non_resident, name_len, name_off = struct.unpack_from("<BBH", buf, off + 8)
        attr_name = bytes(buf[off + name_off:off + name_off + name_len * 2]).decode("utf-16-le", errors="replace")
        content = b""
        if not non_resident:
            size, content_off = struct.unpack_from("<IH", buf, off + 16)
            content = bytes(buf[off + content_off:off + content_off + size])

        if attr_type == SI and len(content) >= 32:
            entry.si = Timestamps(*struct.unpack_from("<QQQQ", content, 0))
        elif attr_type == FILE_NAME and len(content) >= 66:
            namespace = content[65]
            # Prefer Win32 / POSIX names over 8.3 DOS names.
            if best_ns is None or (best_ns == NAMESPACE_DOS and namespace != NAMESPACE_DOS):
                parent = struct.unpack_from("<Q", content, 0)[0]
                entry.parent_record = parent & 0xFFFFFFFFFFFF
                entry.parent_sequence = parent >> 48
                entry.fn = Timestamps(*struct.unpack_from("<QQQQ", content, 8))
                name_chars = content[64]
                entry.name = content[66:66 + name_chars * 2].decode("utf-16-le", errors="replace")
                if not entry.size:
                    entry.size = struct.unpack_from("<Q", content, 48)[0]
                best_ns = namespace
        elif attr_type == DATA:
            if attr_name:
                entry.ads.append(attr_name)
                if attr_name == "Zone.Identifier" and content:
                    entry.zone_identifier = content.decode("utf-8", errors="replace")
            else:
                entry.size = len(content) if not non_resident else struct.unpack_from("<Q", buf, off + 48)[0]
        off += length
    return entry


class MftReader:
    """Iterate the records of an extracted $MFT file."""

    def __init__(self, fh: BinaryIO) -> None:
        self.fh = fh
        first = fh.read(1024)
        fh.seek(0)
        if first[:4] != b"FILE":
            raise MftError("first record is not a FILE record")
        allocated = struct.unpack_from("<I", first, 28)[0]
        self.record_size = allocated if allocated in (1024, 2048, 4096) else 1024

    @classmethod
    def open(cls, path: Path) -> "MftReader":
        return cls(open(path, "rb"))

    def close(self) -> None:
        self.fh.close()

    def __enter__(self) -> "MftReader":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __iter__(self) -> Iterator[MftEntry]:
        self.fh.seek(0)
        number = 0
        while True:
            raw = self.fh.read(self.record_size)
            if len(raw) < self.record_size:
                return
            try:
                entry = parse_record(raw, number)
            except struct.error:
                entry = None
            if entry is not None:
                yield entry
            number += 1


class PathResolver:
    """Rebuild full paths from (name, parent) pairs collected in a first pass."""

    def __init__(self) -> None:
        self._nodes: dict[int, tuple[str, int, int, int]] = {}  # record -> (name, parent, parent_seq, seq)
        self._cache: dict[int, str] = {}

    def add(self, entry: MftEntry) -> None:
        if entry.base_record or not entry.name:
            return
        self._nodes[entry.record] = (entry.name, entry.parent_record, entry.parent_sequence, entry.sequence)

    def path(self, record: int) -> str:
        if record in self._cache:
            return self._cache[record]
        parts: list[str] = []
        current, seen = record, set()
        prefix = ""
        while current != ROOT_RECORD:
            node = self._nodes.get(current)
            if node is None or current in seen or len(parts) > 255:
                prefix = "\\$OrphanFiles"
                break
            seen.add(current)
            name, parent, parent_seq, _seq = node
            parts.append(name)
            parent_node = self._nodes.get(parent)
            if parent != ROOT_RECORD and parent_node is not None and parent_seq and parent_node[3] != parent_seq:
                prefix = "\\$OrphanFiles"  # parent record was reused: original location unknown
                break
            current = parent
        result = prefix + "\\" + "\\".join(reversed(parts))
        self._cache[record] = result
        return result


def parse_zone_identifier(text: str) -> dict[str, str]:
    """Parse the INI-style content of a Zone.Identifier stream."""
    values = {}
    for line in text.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values
