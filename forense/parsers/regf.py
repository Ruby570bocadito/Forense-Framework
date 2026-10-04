"""Read-only parser of Windows registry hive files (regf format).

Supports hive format 1.3 - 1.6 (Windows XP to 11): keys (``nk``), values
(``vk``), every subkey list type (``lf``, ``lh``, ``li``, ``ri``) and big data
values (``db``). A *dirty* hive (sequence numbers differ: recent changes only
exist in the transaction logs) is recovered in memory with the ``.LOG``,
``.LOG1`` and ``.LOG2`` files found next to it (see :mod:`forense.parsers.regf_log`).

Reference: https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md
"""

from __future__ import annotations

import mmap
import struct
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional, Union

from forense.core.utils import filetime_to_dt

REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_DWORD_BE = 0, 1, 2, 3, 4, 5
REG_LINK, REG_MULTI_SZ, REG_QWORD = 6, 7, 11
TYPE_NAMES = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR", 10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD",
}

BASE_BLOCK_SIZE = 4096
KEY_COMP_NAME = 0x0020
VALUE_COMP_NAME = 0x0001
BIG_DATA_THRESHOLD = 16344
_MAX_DEPTH = 512


class RegistryError(ValueError):
    pass


def _decode_name(raw: bytes, compressed: bool) -> str:
    if compressed:
        return raw.decode("latin-1")
    return raw.decode("utf-16-le", errors="replace")


def decode_utf16_string(raw: bytes) -> str:
    """Decode a (possibly NUL-terminated or odd-sized) UTF-16LE string."""
    if len(raw) % 2:
        raw = raw[:-1]
    text = raw.decode("utf-16-le", errors="replace")
    end = text.find("\x00")
    return text if end < 0 else text[:end]


class RegistryHive:
    """An open hive. Use as a context manager or call :meth:`close`."""

    def __init__(self, source: Union[str, Path, bytes], recover_logs: bool = True) -> None:
        self._fh = None
        self._mm = None
        self.recovery = None  # forense.parsers.regf_log.Recovery when transaction logs were applied
        if isinstance(source, (bytes, bytearray)):
            self.data = bytes(source)
        else:
            self._fh = open(source, "rb")
            size = self._fh.seek(0, 2)
            if size < BASE_BLOCK_SIZE:
                self._fh.close()
                raise RegistryError("file too small to be a registry hive")
            self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
            self.data = self._mm
        self._parse_base_block()
        self.was_dirty = self.dirty
        if self.dirty and recover_logs and not isinstance(source, (bytes, bytearray)):
            self._recover(Path(source))

    def _recover(self, path: Path) -> None:
        from forense.parsers.regf_log import log_files, parse_log, recover

        logs = []
        for log_path in log_files(path):
            try:
                log = parse_log(log_path.read_bytes(), log_path.name)
            except (OSError, struct.error):
                log = None
            if log is not None:
                logs.append(log)
        recovery = recover(bytes(self.data), logs) if logs else None
        if recovery is None:
            return
        self.close()
        self.data = bytes(recovery.data)
        self.recovery = recovery
        self._parse_base_block()

    def close(self) -> None:
        if self._mm is not None:
            self._mm.close()
            self._mm = None
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> "RegistryHive":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- base block ---------------------------------------------------------
    def _parse_base_block(self) -> None:
        data = self.data
        if len(data) < BASE_BLOCK_SIZE or data[0:4] != b"regf":
            raise RegistryError("missing 'regf' signature")
        (self.primary_seq, self.secondary_seq, timestamp, self.major, self.minor,
         self.file_type, _fmt, self.root_offset, self.hbins_size) = struct.unpack_from("<IIQIIIIII", data, 4)
        self.last_written: Optional[datetime] = filetime_to_dt(timestamp)
        self.embedded_name = decode_utf16_string(bytes(data[48:48 + 64]))
        checksum = 0
        for (dword,) in struct.iter_unpack("<I", bytes(data[0:508])):
            checksum ^= dword
        stored = struct.unpack_from("<I", data, 508)[0]
        self.checksum_ok = checksum == stored or (checksum in (0, 0xFFFFFFFF) and stored in (1, 0xFFFFFFFE))
        self.dirty = self.primary_seq != self.secondary_seq

    # -- cells ----------------------------------------------------------------
    def cell(self, offset: int) -> bytes:
        """Return the data of the cell at hive-bins ``offset`` (without its size field)."""
        pos = BASE_BLOCK_SIZE + offset
        if offset < 0 or pos + 4 > len(self.data):
            raise RegistryError(f"cell offset out of range: {offset:#x}")
        size = struct.unpack_from("<i", self.data, pos)[0]
        size = -size if size < 0 else size
        if size < 4 or pos + size > len(self.data):
            raise RegistryError(f"invalid cell size at {offset:#x}")
        return bytes(self.data[pos + 4:pos + size])

    def root(self) -> "RegistryKey":
        return RegistryKey(self, self.root_offset, "", is_root=True)

    def open(self, path: str) -> Optional["RegistryKey"]:
        """Open a key by backslash-separated path relative to the root (case-insensitive)."""
        root = self.root()
        return root.subkey(path) if path.strip("\\") else root

    def walk(self, key: Optional["RegistryKey"] = None) -> Iterator["RegistryKey"]:
        stack = [(key or self.root(), 0)]
        while stack:
            current, depth = stack.pop()
            yield current
            if depth < _MAX_DEPTH:
                stack.extend((child, depth + 1) for child in reversed(current.subkeys()))


class RegistryKey:
    """A key. ``path`` is relative to the hive root (the root key itself has an empty path)."""

    def __init__(self, hive: RegistryHive, offset: int, parent_path: str, is_root: bool = False) -> None:
        self.hive = hive
        self.offset = offset
        data = hive.cell(offset)
        if data[0:2] != b"nk":
            raise RegistryError(f"expected key node at {offset:#x}")
        self._data = data
        self.flags = struct.unpack_from("<H", data, 2)[0]
        self.last_written: Optional[datetime] = filetime_to_dt(struct.unpack_from("<Q", data, 4)[0])
        (self._subkey_count, _volatile, self._subkeys_offset, _vol_list, self._value_count,
         self._values_offset, _security, self._class_offset) = struct.unpack_from("<IIIIIIII", data, 20)
        name_len, self._class_len = struct.unpack_from("<HH", data, 72)
        self.name = _decode_name(data[76:76 + name_len], bool(self.flags & KEY_COMP_NAME))
        if is_root:
            self.path = ""
        else:
            self.path = f"{parent_path}\\{self.name}" if parent_path else self.name

    def __repr__(self) -> str:
        return f"RegistryKey({self.path!r})"

    @property
    def class_name(self) -> str:
        if self._class_offset == 0xFFFFFFFF or not self._class_len:
            return ""
        try:
            return decode_utf16_string(self.hive.cell(self._class_offset)[:self._class_len])
        except RegistryError:
            return ""

    def _subkey_offsets(self, list_offset: int, depth: int = 0) -> list[int]:
        if list_offset == 0xFFFFFFFF or depth > 4:
            return []
        data = self.hive.cell(list_offset)
        sig, count = data[0:2], struct.unpack_from("<H", data, 2)[0]
        if sig in (b"lf", b"lh"):
            return [struct.unpack_from("<I", data, 4 + i * 8)[0] for i in range(count)]
        if sig == b"li":
            return [struct.unpack_from("<I", data, 4 + i * 4)[0] for i in range(count)]
        if sig == b"ri":
            offsets: list[int] = []
            for i in range(count):
                offsets.extend(self._subkey_offsets(struct.unpack_from("<I", data, 4 + i * 4)[0], depth + 1))
            return offsets
        raise RegistryError(f"unknown subkey list {sig!r} at {list_offset:#x}")

    def subkeys(self) -> list["RegistryKey"]:
        if not self._subkey_count:
            return []
        keys = []
        for offset in self._subkey_offsets(self._subkeys_offset):
            try:
                keys.append(RegistryKey(self.hive, offset, self.path))
            except RegistryError:
                continue
        return keys

    def subkey(self, name: str) -> Optional["RegistryKey"]:
        """Direct or nested (backslash-separated) subkey, case-insensitive."""
        key: Optional[RegistryKey] = self
        for part in [p for p in name.split("\\") if p]:
            wanted = part.lower()
            key = next((k for k in key.subkeys() if k.name.lower() == wanted), None) if key else None
        return key if key is not self else None

    def values(self) -> list["RegistryValue"]:
        if not self._value_count or self._values_offset == 0xFFFFFFFF:
            return []
        data = self.hive.cell(self._values_offset)
        count = min(self._value_count, len(data) // 4)
        values = []
        for i in range(count):
            try:
                values.append(RegistryValue(self.hive, struct.unpack_from("<I", data, i * 4)[0]))
            except RegistryError:
                continue
        return values

    def value(self, name: str) -> Optional["RegistryValue"]:
        wanted = name.lower()
        for value in self.values():
            if value.name.lower() == wanted:
                return value
        return None

    def get(self, name: str, default: object = None) -> object:
        value = self.value(name)
        return value.data if value is not None else default


class RegistryValue:
    def __init__(self, hive: RegistryHive, offset: int) -> None:
        self.hive = hive
        data = hive.cell(offset)
        if data[0:2] != b"vk":
            raise RegistryError(f"expected value at {offset:#x}")
        name_len, self._size, self._data_offset, self.type, flags = struct.unpack_from("<HIIIH", data, 2)
        self.name = _decode_name(data[20:20 + name_len], bool(flags & VALUE_COMP_NAME)) if name_len else ""

    def __repr__(self) -> str:
        return f"RegistryValue({self.name!r}, {TYPE_NAMES.get(self.type, self.type)})"

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.type, f"0x{self.type:x}")

    @property
    def raw(self) -> bytes:
        size = self._size
        if size & 0x80000000:  # data stored inline in the offset field
            return struct.pack("<I", self._data_offset)[:size & 0x7FFFFFFF]
        if size == 0:
            return b""
        cell = self.hive.cell(self._data_offset)
        if size > BIG_DATA_THRESHOLD and cell[0:2] == b"db" and self.hive.minor > 3:
            count, list_offset = struct.unpack_from("<HI", cell, 2)
            segments = self.hive.cell(list_offset)
            chunks = []
            for i in range(count):
                segment = self.hive.cell(struct.unpack_from("<I", segments, i * 4)[0])
                chunks.append(segment[:BIG_DATA_THRESHOLD])
            return b"".join(chunks)[:size]
        return cell[:size]

    @property
    def data(self) -> object:
        """Decoded data: str, list[str], int or bytes depending on the type."""
        raw = self.raw
        kind = self.type
        try:
            if kind in (REG_SZ, REG_EXPAND_SZ, REG_LINK):
                return decode_utf16_string(raw)
            if kind == REG_MULTI_SZ:
                if len(raw) % 2:
                    raw = raw[:-1]
                return [s for s in raw.decode("utf-16-le", errors="replace").split("\x00") if s]
            if kind == REG_DWORD and len(raw) >= 4:
                return struct.unpack_from("<I", raw)[0]
            if kind == REG_DWORD_BE and len(raw) >= 4:
                return struct.unpack_from(">I", raw)[0]
            if kind == REG_QWORD and len(raw) >= 8:
                return struct.unpack_from("<Q", raw)[0]
        except UnicodeDecodeError:
            pass
        return raw


@dataclass
class HiveInfo:
    kind: str  # system, software, sam, security, ntuser, usrclass, amcache, unknown
    dirty: bool
    last_written: Optional[datetime]
    embedded_name: str


def identify(hive: RegistryHive, filename: str = "") -> str:
    """Best-effort hive type from its content (falls back to the file name)."""
    root = hive.root()
    names = {k.name.lower() for k in root.subkeys()}
    if "select" in names and any(n.startswith("controlset") for n in names):
        return "system"
    if hive.open("Microsoft\\Windows NT\\CurrentVersion") is not None:
        return "software"
    if hive.open("SAM\\Domains\\Account") is not None:
        return "sam"
    if "policy" in names:
        return "security"
    if hive.open("Root\\InventoryApplicationFile") is not None or hive.open("Root\\File") is not None:
        return "amcache"
    if hive.open("Local Settings\\Software\\Microsoft\\Windows") is not None:
        return "usrclass"
    if "software" in names and ("control panel" in names or "environment" in names):
        return "ntuser"
    low = Path(filename).name.lower()
    for kind, candidates in (("ntuser", ("ntuser.dat",)), ("usrclass", ("usrclass.dat",)),
                             ("amcache", ("amcache.hve",)), ("system", ("system",)),
                             ("software", ("software",)), ("sam", ("sam",)), ("security", ("security",))):
        if low in candidates:
            return kind
    return "unknown"
