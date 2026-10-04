"""Parser of Windows Shell Link (.lnk) files, as specified in [MS-SHLLINK].

Extracts what matters forensically: target path (local or network), target
MAC timestamps and size, volume serial/label/type, command-line arguments,
and the TrackerDataBlock (NetBIOS machine name, droid GUIDs and the MAC
address embedded in version-1 object GUIDs).
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from forense.core.utils import filetime_to_dt

LNK_HEADER = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

HAS_TARGET_ID_LIST = 0x1
HAS_LINK_INFO = 0x2
HAS_NAME = 0x4
HAS_RELATIVE_PATH = 0x8
HAS_WORKING_DIR = 0x10
HAS_ARGUMENTS = 0x20
HAS_ICON_LOCATION = 0x40
IS_UNICODE = 0x80

DRIVE_TYPES = {0: "unknown", 1: "no_root_dir", 2: "removable", 3: "fixed", 4: "remote", 5: "cdrom", 6: "ramdisk"}
TRACKER_SIGNATURE = 0xA0000003


class LnkError(ValueError):
    pass


@dataclass
class LnkFile:
    flags: int
    attributes: int
    target_created: Optional[datetime]
    target_accessed: Optional[datetime]
    target_modified: Optional[datetime]
    target_size: int
    local_path: str = ""
    network_path: str = ""
    common_suffix: str = ""
    drive_type: str = ""
    volume_serial: str = ""
    volume_label: str = ""
    name: str = ""
    relative_path: str = ""
    working_dir: str = ""
    arguments: str = ""
    icon_location: str = ""
    machine_id: str = ""
    droid_volume: str = ""
    droid_file: str = ""
    mac_address: str = ""
    extra_blocks: list = field(default_factory=list)

    @property
    def target_path(self) -> str:
        if self.local_path:
            base = self.local_path
        elif self.network_path:
            base = self.network_path
        else:
            return self.relative_path
        if self.common_suffix:
            return base.rstrip("\\") + "\\" + self.common_suffix if base else self.common_suffix
        return base


def _cstring(data: bytes, offset: int, unicode: bool = False) -> str:
    if offset <= 0 or offset >= len(data):
        return ""
    if unicode:
        end = offset
        while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
            end += 2
        return data[offset:end].decode("utf-16-le", errors="replace")
    end = data.find(b"\x00", offset)
    end = len(data) if end < 0 else end
    return data[offset:end].decode("cp1252", errors="replace")


def _mac_from_guid(raw: bytes) -> str:
    """MAC address (node) of a version-1 GUID, as used in object IDs created by Windows."""
    try:
        value = uuid.UUID(bytes_le=raw)
    except ValueError:
        return ""
    if value.version != 1:
        return ""
    return ":".join(f"{b:02x}" for b in value.node.to_bytes(6, "big"))


def _guid(raw: bytes) -> str:
    try:
        return str(uuid.UUID(bytes_le=raw))
    except ValueError:
        return ""


def parse_lnk(data: bytes) -> LnkFile:
    if len(data) < 76 or data[:20] != LNK_HEADER:
        raise LnkError("not a shell link")
    flags, attributes, created, accessed, written, size = struct.unpack_from("<IIQQQI", data, 20)
    lnk = LnkFile(flags, attributes, filetime_to_dt(created), filetime_to_dt(accessed),
                  filetime_to_dt(written), size)
    pos = 76
    if flags & HAS_TARGET_ID_LIST:
        if pos + 2 > len(data):
            raise LnkError("truncated IDList")
        pos += 2 + struct.unpack_from("<H", data, pos)[0]

    if flags & HAS_LINK_INFO:
        if pos + 28 > len(data):
            raise LnkError("truncated LinkInfo")
        info_size, header_size, info_flags, volume_off, base_off, net_off, suffix_off = \
            struct.unpack_from("<IIIIIII", data, pos)
        info = data[pos:pos + info_size]
        base_off_u = suffix_off_u = 0
        if header_size >= 0x24 and len(info) >= 0x24:
            base_off_u, suffix_off_u = struct.unpack_from("<II", info, 28)
        if info_flags & 0x1 and volume_off:
            _parse_volume(lnk, info, volume_off)
            lnk.local_path = (_cstring(info, base_off_u, True) if base_off_u else "") or _cstring(info, base_off)
        if info_flags & 0x2 and net_off:
            lnk.network_path = _parse_network(info, net_off)
        lnk.common_suffix = (_cstring(info, suffix_off_u, True) if suffix_off_u else "") or _cstring(info, suffix_off)
        pos += info_size

    unicode = bool(flags & IS_UNICODE)
    for flag, attr in ((HAS_NAME, "name"), (HAS_RELATIVE_PATH, "relative_path"),
                       (HAS_WORKING_DIR, "working_dir"), (HAS_ARGUMENTS, "arguments"),
                       (HAS_ICON_LOCATION, "icon_location")):
        if flags & flag:
            if pos + 2 > len(data):
                raise LnkError("truncated StringData")
            count = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            length = count * 2 if unicode else count
            raw = data[pos:pos + length]
            setattr(lnk, attr, raw.decode("utf-16-le" if unicode else "cp1252", errors="replace"))
            pos += length

    _parse_extra_data(lnk, data, pos)
    return lnk


def _parse_volume(lnk: LnkFile, info: bytes, offset: int) -> None:
    if offset + 16 > len(info):
        return
    _size, drive_type, serial, label_off = struct.unpack_from("<IIII", info, offset)
    lnk.drive_type = DRIVE_TYPES.get(drive_type, str(drive_type))
    lnk.volume_serial = f"{serial >> 16:04X}-{serial & 0xFFFF:04X}"
    if label_off == 0x14 and offset + 20 <= len(info):
        label_off_u = struct.unpack_from("<I", info, offset + 16)[0]
        lnk.volume_label = _cstring(info, offset + label_off_u, True)
    else:
        lnk.volume_label = _cstring(info, offset + label_off)


def _parse_network(info: bytes, offset: int) -> str:
    if offset + 20 > len(info):
        return ""
    _size, _flags, net_name_off, _device_off, _provider = struct.unpack_from("<IIIII", info, offset)
    if net_name_off > 0x14 and offset + 28 <= len(info):
        net_name_off_u = struct.unpack_from("<I", info, offset + 20)[0]
        return _cstring(info, offset + net_name_off_u, True)
    return _cstring(info, offset + net_name_off)


def _parse_extra_data(lnk: LnkFile, data: bytes, pos: int) -> None:
    while pos + 8 <= len(data):
        size, signature = struct.unpack_from("<II", data, pos)
        if size < 8 or pos + size > len(data):
            break
        lnk.extra_blocks.append(f"0x{signature:08X}")
        if signature == TRACKER_SIGNATURE and size >= 0x60:
            block = data[pos:pos + size]
            lnk.machine_id = block[16:32].split(b"\x00", 1)[0].decode("cp1252", errors="replace")
            lnk.droid_volume = _guid(block[32:48])
            lnk.droid_file = _guid(block[48:64])
            lnk.mac_address = _mac_from_guid(block[48:64])
        pos += size


def find_embedded_lnks(data: bytes) -> list[tuple[int, LnkFile]]:
    """Shell links concatenated in a blob (e.g. ``*.customDestinations-ms`` jump lists)."""
    found = []
    pos = data.find(LNK_HEADER)
    while pos != -1:
        try:
            found.append((pos, parse_lnk(data[pos:])))
        except (LnkError, struct.error):
            pass
        pos = data.find(LNK_HEADER, pos + 1)
    return found
