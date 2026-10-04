"""Parser of the AppCompatCache (ShimCache) registry value.

Supported layouts: Windows 10/11 (``10ts`` entries after a 0x30/0x34 header)
and Windows 7 / Server 2008 R2 (``0xBADC0FEE`` header, 32 and 64-bit).
Entry order reflects recency (first = most recently inserted). The timestamp
is the file's last modification time, *not* an execution time.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from forense.core.utils import filetime_to_dt

WIN7_MAGIC = 0xBADC0FEE


@dataclass
class ShimEntry:
    position: int
    path: str
    last_modified: Optional[datetime]
    executed: Optional[bool] = None  # only recorded by Windows 7


class ShimCacheError(ValueError):
    pass


def parse_appcompatcache(data: bytes) -> tuple[str, list[ShimEntry]]:
    """Return ``(format, entries)``."""
    if len(data) < 8:
        raise ShimCacheError("value too short")
    first = struct.unpack_from("<I", data, 0)[0]
    if first in (0x30, 0x34) and data[first:first + 4] == b"10ts":
        return "windows10", _parse_win10(data, first)
    if first == WIN7_MAGIC:
        return "windows7", _parse_win7(data)
    raise ShimCacheError(f"unsupported AppCompatCache format (header 0x{first:x})")


def _parse_win10(data: bytes, offset: int) -> list[ShimEntry]:
    entries = []
    while offset + 14 <= len(data) and data[offset:offset + 4] == b"10ts":
        entry_size = struct.unpack_from("<I", data, offset + 8)[0]
        body = offset + 12
        path_size = struct.unpack_from("<H", data, body)[0]
        path = data[body + 2:body + 2 + path_size].decode("utf-16-le", errors="replace")
        ts_off = body + 2 + path_size
        modified = struct.unpack_from("<Q", data, ts_off)[0] if ts_off + 8 <= len(data) else 0
        entries.append(ShimEntry(len(entries) + 1, path, filetime_to_dt(modified)))
        offset = body + entry_size
    return entries


def _parse_win7(data: bytes) -> list[ShimEntry]:
    count = struct.unpack_from("<I", data, 4)[0]
    entries = []
    # 64-bit entries have 4 bytes of zero padding after the two length fields.
    is_64 = len(data) >= 0x80 + 48 and struct.unpack_from("<I", data, 0x80 + 4)[0] == 0
    size = 48 if is_64 else 32
    for i in range(count):
        pos = 0x80 + i * size
        if pos + size > len(data):
            break
        if is_64:
            length, _max, _pad, path_off, modified, flags = struct.unpack_from("<HHIQQI", data, pos)
        else:
            length, _max, path_off, modified, flags = struct.unpack_from("<HHIQI", data, pos)
        path = data[path_off:path_off + length].decode("utf-16-le", errors="replace")
        entries.append(ShimEntry(i + 1, path, filetime_to_dt(modified), bool(flags & 0x2)))
    return entries
