"""NTFS change journal ($Extend\\$UsnJrnl:$J): USN_RECORD_V2/V3 parser.

The $J stream is sparse: old records are released by zeroing the beginning of
the stream, so the parser skips zero runs and resynchronises on 8-byte
boundaries. It works on a memory map, so multi-GB journals are not loaded.
"""

from __future__ import annotations

import mmap
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Optional

REASONS = (
    (0x00000001, "DATA_OVERWRITE"), (0x00000002, "DATA_EXTEND"), (0x00000004, "DATA_TRUNCATION"),
    (0x00000010, "NAMED_DATA_OVERWRITE"), (0x00000020, "NAMED_DATA_EXTEND"), (0x00000040, "NAMED_DATA_TRUNCATION"),
    (0x00000100, "FILE_CREATE"), (0x00000200, "FILE_DELETE"), (0x00000400, "EA_CHANGE"),
    (0x00000800, "SECURITY_CHANGE"), (0x00001000, "RENAME_OLD_NAME"), (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"), (0x00008000, "BASIC_INFO_CHANGE"), (0x00010000, "HARD_LINK_CHANGE"),
    (0x00020000, "COMPRESSION_CHANGE"), (0x00040000, "ENCRYPTION_CHANGE"), (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"), (0x00200000, "STREAM_CHANGE"), (0x00400000, "TRANSACTED_CHANGE"),
    (0x00800000, "INTEGRITY_CHANGE"), (0x80000000, "CLOSE"),
)
FILE_CREATE, FILE_DELETE, RENAME_OLD, RENAME_NEW, CLOSE = 0x100, 0x200, 0x1000, 0x2000, 0x80000000
ATTR_DIRECTORY = 0x10
_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_NONZERO = re.compile(rb"[^\x00]")
_MIN_TS, _MAX_TS = 119600064000000000, 159545856000000000  # 1980 .. 2106


@dataclass
class UsnRecord:
    usn: int
    timestamp: datetime
    entry: int
    sequence: int
    parent_entry: int
    parent_sequence: int
    name: str
    reason: int
    attributes: int
    offset: int

    @property
    def reasons(self) -> list[str]:
        return [name for flag, name in REASONS if self.reason & flag]

    @property
    def is_directory(self) -> bool:
        return bool(self.attributes & ATTR_DIRECTORY)


def reason_names(reason: int) -> str:
    return "|".join(name for flag, name in REASONS if reason & flag)


def _parse(data, pos: int) -> Optional[tuple[UsnRecord, int]]:
    try:
        length, major, minor = struct.unpack_from("<IHH", data, pos)
    except struct.error:
        return None
    if length < 60 or length > 4096 or length % 8 or major not in (2, 3) or pos + length > len(data):
        return None
    if major == 2:
        frn, parent, usn, ts, reason, _source, _sec, attrs, name_len, name_off = struct.unpack_from(
            "<QQqQIIIIHH", data, pos + 8)
        entry, seq = frn & 0xFFFFFFFFFFFF, frn >> 48
        parent_entry, parent_seq = parent & 0xFFFFFFFFFFFF, parent >> 48
        expected_offset = 60
    else:
        frn_lo, frn_hi, par_lo, par_hi, usn, ts, reason, _source, _sec, attrs, name_len, name_off = \
            struct.unpack_from("<QQQQqQIIIIHH", data, pos + 8)
        entry, seq = frn_lo & 0xFFFFFFFFFFFF, (frn_lo >> 48) & 0xFFFF
        parent_entry, parent_seq = par_lo & 0xFFFFFFFFFFFF, (par_lo >> 48) & 0xFFFF
        expected_offset = 76
    if name_off != expected_offset or name_off + name_len > length or name_len % 2 or not _MIN_TS <= ts <= _MAX_TS:
        return None
    name = bytes(data[pos + name_off:pos + name_off + name_len]).decode("utf-16-le", errors="replace")
    timestamp = _EPOCH + timedelta(microseconds=ts // 10)
    return UsnRecord(usn, timestamp, entry, seq, parent_entry, parent_seq, name, reason, attrs, pos), length


def iter_records(data) -> Iterator[UsnRecord]:
    """Records of a $J buffer (bytes or mmap)."""
    pos, size = 0, len(data)
    while pos + 60 <= size:
        if data[pos:pos + 8] == b"\x00" * 8:
            match = _NONZERO.search(data, pos)
            if not match:
                return
            pos = match.start() & ~7
            continue
        parsed = _parse(data, pos)
        if parsed is None:
            pos += 8
            continue
        record, length = parsed
        yield record
        pos += length


def open_journal(path: Path):
    """Context manager returning a read-only memory map of the journal (``b''`` for an empty file)."""
    class _Journal:
        def __enter__(self):
            self.fh = open(path, "rb")
            size = Path(path).stat().st_size
            self.map = mmap.mmap(self.fh.fileno(), 0, access=mmap.ACCESS_READ) if size else None
            return self.map if self.map is not None else b""

        def __exit__(self, *exc):
            if self.map is not None:
                self.map.close()
            self.fh.close()

    return _Journal()


def build_record(name: str, entry: int, parent: int, reason: int, when: datetime, usn: int, sequence: int = 1,
                 parent_sequence: int = 1, attributes: int = 0x20) -> bytes:
    """USN_RECORD_V2 bytes (used by the demo and the tests)."""
    encoded = name.encode("utf-16-le")
    length = (60 + len(encoded) + 7) & ~7
    ts = int((when - _EPOCH).total_seconds() * 10_000_000)
    header = struct.pack("<IHHQQqQIIIIHH", length, 2, 0, entry | (sequence << 48), parent | (parent_sequence << 48),
                         usn, ts, reason, 0, 0, attributes, len(encoded), 60)
    return (header + encoded).ljust(length, b"\x00")
