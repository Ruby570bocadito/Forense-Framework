"""Windows Shell Items (as stored in ShellBags, LNK target ID lists and jump lists).

Implements the common item types documented by libfwsi: root folders (by
GUID), volumes, file entries (with the 0xBEEF0004 extension holding the long
name, FAT creation/access times and the NTFS file reference), network
locations, URIs, control panel items and users property views (known
folders). Unknown items are kept with a descriptive placeholder name so that
paths stay complete.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

KNOWN_FOLDERS = {
    "20d04fe0-3aea-1069-a2d8-08002b30309d": "This PC",
    "59031a47-3f72-44a7-89c5-5595fe6b30ee": "Users",
    "5e6c858f-0e22-4760-9afe-ea3317b67173": "%UserProfile%",
    "031e4825-7b94-4dc3-b131-e946b44c8dd5": "Libraries",
    "208d2c60-3aea-1069-a2d7-08002b30309d": "Network",
    "f02c1a0d-be21-4350-88b0-7367fc96ef3c": "Network",
    "645ff040-5081-101b-9f08-00aa002f954e": "Recycle Bin",
    "26ee0668-a00a-44d7-9371-beb064c98683": "Control Panel",
    "21ec2020-3aea-1069-a2dd-08002b30309d": "Control Panel",
    "5399e694-6ce5-4d6c-8fce-1d8870fdcba0": "Control Panel",
    "450d8fba-ad25-11d0-98a8-0800361b1103": "My Documents",
    "871c5380-42a0-1069-a2ea-08002b30309d": "Internet Explorer",
    "679f85cb-0220-4080-b29b-5540cc05aab6": "Quick access",
    "f874310e-b6b7-47dc-bc84-b9e6b38f5903": "Home",
    "4234d49b-0245-4df3-b780-3893943456e1": "Applications",
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
    "fdd39ad0-238f-46af-adb4-6c85480369c7": "Documents",
    "d3162b92-9365-467a-956b-92703aca08af": "Documents",
    "374de290-123f-4565-9164-39c4925e467b": "Downloads",
    "088e3905-0323-4b02-9826-5d99428e115f": "Downloads",
    "4bd8d571-6d19-48d3-be97-422220080e43": "Music",
    "3dfdf296-dbec-4fb4-81d1-6a3438bcf4de": "Music",
    "33e28130-4e1e-4676-835a-98395c3bc3bb": "Pictures",
    "24ad3ad4-a569-4530-98e1-ab02f9417aa8": "Pictures",
    "18989b1d-99b5-455b-841c-ab7c74e4ddfc": "Videos",
    "f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a": "Videos",
    "018d5c66-4533-4307-9b53-224de2ed1fe6": "OneDrive",
    "1cf1260c-4dd0-4ebb-811f-33c572699fde": "Music",
    "3add1653-eb32-4cb0-bbd7-dfa0abb5acca": "Pictures",
    "a0953c92-50dc-43bf-be83-3742fed03c9c": "Videos",
    "a8cdff1c-4878-43be-b5fd-f8091c1c60d0": "Documents",
    "1fa9085f-25a2-489b-85d4-86326eedcd87": "Manage Wireless Networks",
    "9e3995ab-1f9c-4f13-b827-48b24b6c7174": "User Pinned",
}


@dataclass
class ShellItem:
    kind: str  # root, volume, directory, file, network, uri, control_panel, known_folder, unknown
    name: str
    modified: Optional[datetime] = None
    created: Optional[datetime] = None
    accessed: Optional[datetime] = None
    mft_entry: Optional[int] = None
    mft_sequence: Optional[int] = None


def fat_datetime(raw: bytes) -> Optional[datetime]:
    """FAT date (low word) and time (high word) as stored in shell items (UTC, 2 s resolution)."""
    if len(raw) < 4:
        return None
    date, time = struct.unpack_from("<HH", raw)
    if not date:
        return None
    try:
        return datetime(1980 + (date >> 9), (date >> 5) & 0x0F, date & 0x1F, time >> 11, (time >> 5) & 0x3F,
                        (time & 0x1F) * 2, tzinfo=timezone.utc)
    except ValueError:
        return None


def _guid(raw: bytes) -> str:
    try:
        return str(uuid.UUID(bytes_le=bytes(raw[:16])))
    except ValueError:
        return raw[:16].hex()


def _folder_name(guid: str) -> str:
    return KNOWN_FOLDERS.get(guid.lower(), "{" + guid + "}")


def _ascii(data: bytes, offset: int) -> tuple[str, int]:
    end = data.find(b"\x00", offset)
    end = len(data) if end < 0 else end
    return data[offset:end].decode("cp1252", errors="replace"), end + 1


def _utf16(data: bytes, offset: int) -> tuple[str, int]:
    end = offset
    while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
        end += 2
    return data[offset:end].decode("utf-16-le", errors="replace"), end + 2


def _beef0004(data: bytes, item: ShellItem) -> None:
    """Find and decode the file entry extension block inside a file entry item."""
    pos = data.find(b"\x04\x00\xef\xbe")
    if pos < 4:
        return
    block = data[pos - 4:]
    size, version = struct.unpack_from("<HH", block)
    if size < 20 or size > len(block):
        return
    item.created = fat_datetime(block[8:12])
    item.accessed = fat_datetime(block[12:16])
    offset = 18
    if version >= 7 and len(block) >= 36:
        ref = struct.unpack_from("<Q", block, 20)[0]
        item.mft_entry, item.mft_sequence = ref & 0xFFFFFFFFFFFF, ref >> 48
        offset = 36
    if version >= 3:
        offset += 2
    if version >= 9:
        offset += 4
    if version >= 8:
        offset += 4
    if offset < size:
        long_name, _ = _utf16(block[:size], offset)
        if long_name:
            item.name = long_name


def parse_shell_item(data: bytes) -> ShellItem:
    """Parse the first shell item of ``data`` (a shell item or item list)."""
    if len(data) < 3:
        return ShellItem("unknown", "[empty]")
    size = struct.unpack_from("<H", data)[0]
    data = data[:size] if 3 <= size <= len(data) else data
    kind = data[2]
    try:
        if kind == 0x1F and len(data) >= 20:
            return ShellItem("root", _folder_name(_guid(data[4:20])))
        if kind & 0x70 == 0x20:
            if kind & 0x01:
                name, _ = _ascii(data, 3)
                return ShellItem("volume", name.rstrip("\\") or "[volume]")
            if len(data) >= 20:
                return ShellItem("root", _folder_name(_guid(data[4:20])))
            return ShellItem("volume", "[volume]")
        if kind & 0x70 == 0x30:
            return _file_entry(data, kind)
        if kind & 0x70 == 0x40:
            flags = data[4] if len(data) > 4 else 0
            location, pos = _ascii(data, 5)
            if flags & 0x80:
                _description, pos = _ascii(data, pos)
            return ShellItem("network", location)
        if kind == 0x61:
            return _uri(data)
        if kind in (0x71, 0x01):
            guid = _guid(data[14:30]) if kind == 0x71 and len(data) >= 30 else ""
            return ShellItem("control_panel", _folder_name(guid) if guid else "[Control Panel]")
        if kind == 0x00 and len(data) > 10:
            return _users_property_view(data)
    except (struct.error, IndexError, ValueError):
        pass
    return ShellItem("unknown", f"[0x{kind:02X}]")


def _file_entry(data: bytes, kind: int) -> ShellItem:
    modified = fat_datetime(data[8:12])
    unicode = bool(kind & 0x04)
    name, _ = (_utf16 if unicode else _ascii)(data, 14)
    item = ShellItem("directory" if kind & 0x01 else "file", name, modified=modified)
    _beef0004(data, item)
    return item


def _uri(data: bytes) -> ShellItem:
    flags = data[3]
    if len(data) > 8:
        size = struct.unpack_from("<H", data, 4)[0]
        if size and len(data) >= 6 + size:
            text = data[6:6 + size]
            for offset in range(len(text)):
                if text[offset:offset + 4] in (b"http", b"ftp:", b"file"):
                    uri, _ = _ascii(text, offset)
                    return ShellItem("uri", uri)
    rest = data[6:] if flags & 0x80 else data[6:]
    for candidate in (_utf16(rest, 0)[0], _ascii(rest, 0)[0]):
        if "://" in candidate:
            return ShellItem("uri", candidate)
    return ShellItem("uri", "[URI]")


def _users_property_view(data: bytes) -> ShellItem:
    marker = data.find(struct.pack("<I", 0x23FEBBEE))
    if marker >= 0 and len(data) >= marker + 4 + 16 + 4:
        # signature, property store size (2), identifier size (2), identifier (GUID)
        guid = _guid(data[marker + 8:marker + 24])
        return ShellItem("known_folder", _folder_name(guid))
    if b"\x04\x00\xef\xbe" in data:  # delegate items wrapping a file entry
        item = ShellItem("directory", "[delegate]")
        _beef0004(data, item)
        return item
    return ShellItem("unknown", "[0x00]")


def join_path(parent: str, item: ShellItem) -> str:
    """Full path of ``item`` below ``parent``. Volumes and UNC locations start a new path (``C:``, ``\\\\srv``)."""
    if not parent or item.kind == "volume" or (item.kind == "network" and item.name.startswith("\\\\")):
        return item.name
    separator = "" if parent.endswith("\\") else "\\"
    return f"{parent}{separator}{item.name}"
