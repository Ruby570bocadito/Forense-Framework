"""Parser of Windows Recycle Bin ``$I`` metadata files (Windows Vista and later).

Version 1 (Vista - 8.1): fixed 520-byte path. Version 2 (Windows 10+):
length-prefixed path.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from forense.core.utils import filetime_to_dt


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
