"""Parser of Windows Recycle Bin ``$I`` metadata files (Windows Vista and later).

Version 1 (Vista - 8.1): fixed 520-byte path. Version 2 (Windows 10+):
length-prefixed path.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sabueso.core.utils import filetime_to_dt


class RecycleBinError(ValueError):
    pass


@dataclass
class DeletedItem:
    version: int
    original_size: int
    deleted: Optional[datetime]
    original_path: str


def parse_i_file(data: bytes) -> DeletedItem:
    if len(data) < 24:
        raise RecycleBinError("too short")
    version, size, deleted = struct.unpack_from("<QqQ", data, 0)
    if version == 1:
        raw = data[24:24 + 520]
    elif version == 2:
        if len(data) < 28:
            raise RecycleBinError("too short")
        chars = struct.unpack_from("<I", data, 24)[0]
        raw = data[28:28 + chars * 2]
    else:
        raise RecycleBinError(f"unknown $I version {version}")
    path = raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
    return DeletedItem(version, size, filetime_to_dt(deleted), path)


@dataclass
class Info2Item:
    index: int  # the deleted file is stored as D<drive letter><index><original extension>
    drive: str
    deleted: Optional[datetime]
    size: int  # allocated size on disk
    original_path: str


def parse_info2(data: bytes) -> list[Info2Item]:
    """Records of a Windows 95 to Server 2003 ``INFO2`` file (``RECYCLER/<SID>/INFO2``).

    Header: version, three counters and the record size (280 bytes up to ME with an ANSI path only,
    800 bytes on NT with an ANSI and a UTF-16 path). Each record: ANSI path (260), index (4), drive (4),
    deletion FILETIME (8), size (4) and, in 800-byte records, the UTF-16 path (520). Truncated or garbled
    files yield the complete records they hold."""
    if len(data) < 20:
        raise RecycleBinError("too short")
    size = struct.unpack_from("<I", data, 12)[0]
    if size not in (280, 800):
        raise RecycleBinError(f"unknown INFO2 record size {size}")
    items = []
    for offset in range(20, len(data) - size + 1, size):
        ansi, index, drive, deleted, allocated = struct.unpack_from("<260sIIQI", data, offset)
        path = ansi.split(b"\x00", 1)[0].decode("cp1252", errors="replace")
        if size == 800:
            wide = data[offset + 280:offset + 800].decode("utf-16-le", errors="replace").split("\x00", 1)[0]
            path = wide or path
        if not path and not deleted:
            continue  # empty slot
        letter = chr(ord("a") + drive) if drive < 26 else "?"
        items.append(Info2Item(index, letter, filetime_to_dt(deleted), allocated, path))
    return items
