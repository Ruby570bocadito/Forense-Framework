"""Jump lists: ``*.automaticDestinations-ms`` (OLE compound file with numbered LNK streams and a
DestList stream) and ``*.customDestinations-ms`` (concatenated LNK structures).

DestList layout per libyal dtformats ("Jump lists format").
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from forense.core.utils import filetime_to_dt
from forense.parsers.lnk import LnkError, LnkFile, find_embedded_lnks, parse_lnk

# Application identifiers (CRC-64 of the AppUserModelID / executable path) of commonly seen programs.
APP_IDS = {
    "1b4dd67f29cb1962": "Windows Explorer (7)",
    "f01b4d95cf55d32a": "Windows Explorer (8.1/10)",
    "5f7b5f1e01b83767": "Quick Access",
    "9b9cdc69c1c24e2b": "Notepad (64-bit)",
    "918e0ecb43d17e23": "Notepad (32-bit)",
    "12dc1ea8e34b5a6": "Paint",
    "1bc392b8e104a00e": "Remote Desktop Connection",
    "6728dd69a3088f97": "Command Prompt",
    "7e4dca80246863e3": "Control Panel",
    "5d696d521de238c3": "Google Chrome",
    "28c8b86deab549a1": "Internet Explorer",
    "3dc02b55e44d6697": "7-Zip",
    "290532160612e071": "WinRAR",
}
RDP_APP_ID = "1bc392b8e104a00e"


@dataclass
class DestListEntry:
    entry_number: int
    hostname: str
    last_modified: Optional[datetime]
    pinned: bool
    access_count: Optional[int]
    path: str
    droid_volume: str = ""
    droid_file: str = ""


@dataclass
class JumpListEntry:
    stream: str
    lnk: Optional[LnkFile]
    dest: Optional[DestListEntry] = None


@dataclass
class JumpList:
    app_id: str
    kind: str  # automatic | custom
    entries: list[JumpListEntry] = field(default_factory=list)
    destlist_version: Optional[int] = None

    @property
    def application(self) -> str:
        return APP_IDS.get(self.app_id, "")


def _guid(raw: bytes) -> str:
    try:
        return str(uuid.UUID(bytes_le=raw))
    except ValueError:
        return ""


def parse_destlist(data: bytes) -> tuple[int, list[DestListEntry]]:
    if len(data) < 32:
        return 0, []
    version, count = struct.unpack_from("<II", data, 0)
    entries = []
    pos = 32
    for _ in range(count):
        fixed = 130 if version >= 2 else 114
        if pos + fixed > len(data):
            break
        hostname = data[pos + 72:pos + 88].split(b"\x00", 1)[0].decode("cp1252", errors="replace")
        number = struct.unpack_from("<I", data, pos + 88)[0]
        modified = filetime_to_dt(struct.unpack_from("<Q", data, pos + 100)[0])
        pin = struct.unpack_from("<i", data, pos + 108)[0]
        access_count = struct.unpack_from("<I", data, pos + 116)[0] if version >= 2 else None
        size_off = 128 if version >= 2 else 112
        chars = struct.unpack_from("<H", data, pos + size_off)[0]
        start = pos + size_off + 2
        path = data[start:start + chars * 2].decode("utf-16-le", errors="replace")
        entries.append(DestListEntry(number, hostname, modified, pin >= 0, access_count, path,
                                     _guid(data[pos + 8:pos + 24]), _guid(data[pos + 24:pos + 40])))
        pos = start + chars * 2 + (4 if version >= 2 else 0)
    return version, entries


def parse_automatic(path: Path) -> JumpList:
    import olefile

    jump = JumpList(Path(path).name.split(".")[0].lower(), "automatic")
    with olefile.OleFileIO(str(path)) as ole:
        streams = ["/".join(s) for s in ole.listdir()]
        dest: dict[int, DestListEntry] = {}
        if "DestList" in streams:
            jump.destlist_version, entries = parse_destlist(ole.openstream("DestList").read())
            dest = {e.entry_number: e for e in entries}
        for name in streams:
            if name == "DestList":
                continue
            try:
                number = int(name, 16)
            except ValueError:
                continue
            try:
                lnk = parse_lnk(ole.openstream(name).read())
            except (LnkError, struct.error):
                lnk = None
            jump.entries.append(JumpListEntry(name, lnk, dest.get(number)))
    jump.entries.sort(key=lambda e: (e.dest.last_modified.timestamp() if e.dest and e.dest.last_modified else 0),
                      reverse=True)
    return jump


def parse_custom(path: Path) -> JumpList:
    jump = JumpList(Path(path).name.split(".")[0].lower(), "custom")
    data = Path(path).read_bytes()
    for offset, lnk in find_embedded_lnks(data):
        jump.entries.append(JumpListEntry(f"@{offset}", lnk))
    return jump
