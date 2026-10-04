"""Builders of synthetic Windows artifacts, used by the demo case and the test-suite.

They write structurally valid files (registry hives, shell links, Recycle Bin
``$I`` files, $MFT records, browser databases, images...) so every parser can
be exercised without shipping real, potentially personal, evidence.
"""

from __future__ import annotations

import io
import sqlite3
import struct
import uuid
import zipfile
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def to_filetime(dt: Optional[datetime]) -> int:
    if dt is None:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - FILETIME_EPOCH
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def to_webkit(dt: datetime) -> int:
    return to_filetime(dt) // 10


def to_unix_us(dt: datetime) -> int:
    return int(dt.timestamp() * 1_000_000)


# --------------------------------------------------------------------------
# Registry hives
# --------------------------------------------------------------------------
REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD = 1, 2, 3, 4, 7, 11


@dataclass
class _Value:
    name: str
    type: int
    data: bytes


@dataclass
class _Key:
    name: str
    last_written: Optional[datetime] = None
    subkeys: dict = field(default_factory=dict)
    values: list = field(default_factory=list)
    deleted: bool = False  # written in free cells and not linked from its parent
    deleted_values: list = field(default_factory=list)


def encode_value(type_: int, data: Union[str, int, bytes, list]) -> bytes:
    if isinstance(data, bytes):
        return data
    if type_ in (REG_SZ, REG_EXPAND_SZ):
        return (str(data) + "\x00").encode("utf-16-le")
    if type_ == REG_MULTI_SZ:
        return ("\x00".join(data) + "\x00\x00").encode("utf-16-le")
    if type_ == REG_DWORD:
        return struct.pack("<I", data)
    if type_ == REG_QWORD:
        return struct.pack("<Q", data)
    raise ValueError(f"cannot encode {data!r} as type {type_}")


class HiveBuilder:
    """Build a registry hive (regf 1.5) in memory."""

    def __init__(self, root_name: str = "ROOT", default_time: Optional[datetime] = None,
                 embedded_name: str = "") -> None:
        self.default_time = default_time or datetime(2024, 1, 1, tzinfo=timezone.utc)
        self.root = _Key(root_name, self.default_time)
        self.embedded_name = embedded_name
        self.dirty = False

    def key(self, path: str, last_written: Optional[datetime] = None, deleted: bool = False) -> _Key:
        node = self.root
        for part in [p for p in path.split("\\") if p]:
            child = node.subkeys.get(part.lower())
            if child is None:
                child = _Key(part, self.default_time)
                node.subkeys[part.lower()] = child
            node = child
        if last_written is not None:
            node.last_written = last_written
        if deleted:
            node.deleted = True
        return node

    def value(self, path: str, name: str, type_: int, data: Union[str, int, bytes, list]) -> "HiveBuilder":
        self.key(path).values.append(_Value(name, type_, encode_value(type_, data)))
        return self

    def deleted_value(self, path: str, name: str, type_: int, data: Union[str, int, bytes, list]) -> "HiveBuilder":
        """A value removed from ``path``: its record stays in a free cell, no longer in the key's value list."""
        self.key(path).deleted_values.append(_Value(name, type_, encode_value(type_, data)))
        return self

    # -- serialisation --------------------------------------------------------
    def build(self) -> bytes:
        self._bins = bytearray(b"\x00" * 32)  # hbin header, filled at the end
        root_offset = self._emit_key(self.root, 0xFFFFFFFF, is_root=True)
        free = (-(len(self._bins) + 8) % 4096) + 8
        self._bins += struct.pack("<i", free) + b"\x00" * (free - 4)
        bins = self._bins
        bins[0:32] = struct.pack("<4sIIQQI", b"hbin", 0, len(bins), 0, 0, 0)[:32].ljust(32, b"\x00")
        base = bytearray(4096)
        seq2 = 2 if self.dirty else 1
        struct.pack_into("<4sIIQIIIIII", base, 0, b"regf", 1, seq2, to_filetime(self.default_time), 1, 5, 0, 1,
                         root_offset, len(bins))
        struct.pack_into("<I", base, 44, 1)
        name = self.embedded_name.encode("utf-16-le")[:64]
        base[48:48 + len(name)] = name
        checksum = 0
        for (dword,) in struct.iter_unpack("<I", bytes(base[:508])):
            checksum ^= dword
        struct.pack_into("<I", base, 508, checksum)
        return bytes(base) + bytes(bins)

    def save(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.build())
        return path

    def _alloc(self, data: bytes, free: bool = False) -> int:
        size = len(data) + 4
        size += -size % 8
        offset = len(self._bins)
        self._bins += struct.pack("<i", size if free else -size) + data + b"\x00" * (size - 4 - len(data))
        return offset

    def _patch(self, offset: int, data: bytes) -> None:
        self._bins[offset + 4:offset + 4 + len(data)] = data

    @staticmethod
    def _name(name: str) -> tuple[bytes, bool]:
        try:
            return name.encode("ascii"), True
        except UnicodeEncodeError:
            return name.encode("utf-16-le"), False

    def _emit_value(self, value: _Value, free: bool) -> int:
        vname, vcompressed = self._name(value.name)
        size = len(value.data)
        if size <= 4:
            data_field = struct.unpack("<I", value.data.ljust(4, b"\x00"))[0]
            size_field = size | 0x80000000
        elif size > 16344:
            segments = [self._alloc(value.data[i:i + 16344], free) for i in range(0, size, 16344)]
            seg_list = self._alloc(b"".join(struct.pack("<I", s) for s in segments), free)
            data_field = self._alloc(struct.pack("<2sHI", b"db", len(segments), seg_list), free)
            size_field = size
        else:
            data_field = self._alloc(value.data, free)
            size_field = size
        flags = 1 if vcompressed and vname else 0
        vk = struct.pack("<2sHIIIHH", b"vk", len(vname), size_field, data_field, value.type, flags, 0) + vname
        return self._alloc(vk, free)

    def _emit_key(self, key: _Key, parent: int, is_root: bool = False, free: bool = False) -> int:
        free = free or key.deleted  # a deleted key takes its whole subtree with it
        name, compressed = self._name(key.name)
        nk_offset = self._alloc(b"\x00" * (76 + len(name)), free)

        value_offsets = [self._emit_value(value, free) for value in key.values]
        for value in key.deleted_values:
            self._emit_value(value, True)
        values_list = self._alloc(b"".join(struct.pack("<I", o) for o in value_offsets), free) if value_offsets \
            else 0xFFFFFFFF

        children = sorted(key.subkeys.values(), key=lambda k: k.name.upper())
        emitted = [(self._emit_key(child, nk_offset, free=free), child) for child in children]
        linked = [(offset, child) for offset, child in emitted if free or not child.deleted]
        child_offsets = [offset for offset, _ in linked]
        if child_offsets:
            entries = b"".join(struct.pack("<I4s", off, child.name.encode("latin-1", "replace")[:4].ljust(4, b"\x00"))
                               for off, child in linked)
            subkey_list = self._alloc(struct.pack("<2sH", b"lf", len(child_offsets)) + entries, free)
        else:
            subkey_list = 0xFFFFFFFF

        flags = (0x2C if is_root else 0) | (0x20 if compressed else 0)
        nk = struct.pack("<2sHQIIIIIIIIIIIIIIIHH", b"nk", flags, to_filetime(key.last_written), 0, parent,
                         len(child_offsets), 0, subkey_list, 0xFFFFFFFF, len(value_offsets), values_list,
                         0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 0, len(name), 0) + name
        self._patch(nk_offset, nk)
        return nk_offset


def userassist_data(runs: int, last_run: datetime, focus_count: int = 1, focus_ms: int = 60000) -> bytes:
    data = bytearray(72)
    struct.pack_into("<III", data, 4, runs, focus_count, focus_ms)
    struct.pack_into("<Q", data, 60, to_filetime(last_run))
    return bytes(data)


def sam_f_value(rid: int, last_logon: Optional[datetime] = None, password_set: Optional[datetime] = None,
                last_failed: Optional[datetime] = None, logons: int = 0, failed: int = 0,
                disabled: bool = False, password_not_required: bool = False) -> bytes:
    data = bytearray(80)
    struct.pack_into("<QQQQ", data, 8, to_filetime(last_logon), to_filetime(password_set), 0x7FFFFFFFFFFFFFFF,
                     to_filetime(last_failed))
    acb = 0x0010 | (0x0001 if disabled else 0) | (0x0004 if password_not_required else 0)
    struct.pack_into("<I", data, 48, rid)
    struct.pack_into("<H", data, 56, acb)
    struct.pack_into("<HH", data, 64, failed, logons)
    return bytes(data)


def build_shimcache_win10(entries: list[tuple[str, datetime]]) -> bytes:
    out = bytearray(struct.pack("<I", 0x34).ljust(0x34, b"\x00"))
    for path, modified in entries:
        raw = path.encode("utf-16-le")
        body = struct.pack("<H", len(raw)) + raw + struct.pack("<QI", to_filetime(modified), 0)
        out += b"10ts" + struct.pack("<II", 0, len(body)) + body
    return bytes(out)


# --------------------------------------------------------------------------
# Shell links, Recycle Bin, $MFT
# --------------------------------------------------------------------------
def build_lnk(target: str, created: datetime, modified: datetime, accessed: datetime, size: int = 0,
              arguments: str = "", working_dir: str = "", drive_type: int = 3, serial: int = 0x1234ABCD,
              volume_label: str = "", machine_id: str = "", mac: Optional[str] = None,
              network_share: str = "") -> bytes:
    """Build a shell link with LinkInfo, StringData and a TrackerDataBlock."""
    flags = 0x2 | 0x80  # HasLinkInfo | IsUnicode
    if working_dir:
        flags |= 0x10
    if arguments:
        flags |= 0x20
    header = struct.pack("<I16sIIQQQIIIH10s", 0x4C, uuid.UUID("00021401-0000-0000-c000-000000000046").bytes_le,
                         flags, 0x20, to_filetime(created), to_filetime(accessed), to_filetime(modified), size, 0, 1,
                         0, b"\x00" * 10)

    if network_share:
        net_name = network_share.encode("cp1252") + b"\x00"
        net = struct.pack("<IIIII", 20 + len(net_name), 0x2, 20, 0, 0x20000) + net_name
        suffix = target.encode("cp1252") + b"\x00"
        info_header = 28
        net_off = info_header
        suffix_off = net_off + len(net)
        body = net + suffix
        info = struct.pack("<IIIIIII", info_header + len(body), info_header, 0x2, 0, 0, net_off, suffix_off) + body
    else:
        label = volume_label.encode("cp1252") + b"\x00"
        volume = struct.pack("<IIII", 16 + len(label), drive_type, serial, 16) + label
        base_path = target.encode("cp1252", errors="replace") + b"\x00"
        info_header = 28
        volume_off = info_header
        base_off = volume_off + len(volume)
        suffix_off = base_off + len(base_path)
        body = volume + base_path + b"\x00"
        info = struct.pack("<IIIIIII", info_header + len(body), info_header, 0x1, volume_off, base_off, 0,
                           suffix_off) + body

    strings = b""
    for flag, text in ((0x10, working_dir), (0x20, arguments)):
        if flags & flag:
            strings += struct.pack("<H", len(text)) + text.encode("utf-16-le")

    extra = b""
    if machine_id or mac:
        node = int(mac.replace(":", ""), 16) if mac else 0x001122334455
        object_id = uuid.uuid1(node=node, clock_seq=0x1234)
        volume_id = uuid.uuid4()
        machine = machine_id.encode("cp1252")[:15].ljust(16, b"\x00")
        droid = volume_id.bytes_le + object_id.bytes_le
        extra = struct.pack("<IIII", 0x60, 0xA0000003, 0x58, 0) + machine + droid + droid
    return header + info + strings + extra + b"\x00\x00\x00\x00"


def build_i_file(original_path: str, size: int, deleted: datetime, version: int = 2) -> bytes:
    if version == 1:
        path = original_path.encode("utf-16-le")[:518].ljust(520, b"\x00")
        return struct.pack("<QqQ", 1, size, to_filetime(deleted)) + path
    path = (original_path + "\x00").encode("utf-16-le")
    return struct.pack("<QqQI", 2, size, to_filetime(deleted), len(original_path) + 1) + path


def build_mft_record(record: int, name: str, parent: int, *, si: tuple, fn: tuple, sequence: int = 1,
                     parent_sequence: int = 1, in_use: bool = True, directory: bool = False, size: int = 0,
                     zone_identifier: str = "", record_size: int = 1024) -> bytes:
    """One FILE record with $STANDARD_INFORMATION, $FILE_NAME, $DATA and an optional Zone.Identifier.

    ``si`` and ``fn`` are (created, modified, mft_modified, accessed) FILETIME integers.
    """
    def resident(attr_type: int, content: bytes, attr_name: str = "") -> bytes:
        name_raw = attr_name.encode("utf-16-le")
        name_off = 24
        content_off = (name_off + len(name_raw) + 7) & ~7
        length = (content_off + len(content) + 7) & ~7
        attr = struct.pack("<IIBBHHHIHBB", attr_type, length, 0, len(attr_name), name_off, 0, 0, len(content),
                           content_off, 0, 0)
        attr = attr.ljust(name_off, b"\x00") + name_raw
        attr = attr.ljust(content_off, b"\x00") + content
        return attr.ljust(length, b"\x00")

    si_content = struct.pack("<QQQQ", *si) + b"\x00" * 16
    raw_name = name.encode("utf-16-le")
    fn_content = struct.pack("<QQQQQQQIIBB", (parent_sequence << 48) | parent, *fn, size, size,
                             0x10000000 if directory else 0x20, 0, len(name), 1) + raw_name
    attrs = resident(0x10, si_content) + resident(0x30, fn_content)
    if not directory:
        attrs += resident(0x80, b"\x00" * min(size, 64))
        if zone_identifier:
            attrs += resident(0x80, zone_identifier.encode("utf-8"), "Zone.Identifier")
    attrs += struct.pack("<I", 0xFFFFFFFF) + b"\x00" * 4

    first_attr = 56
    usa_offset, usa_count = 48, record_size // 512 + 1
    flags = (0x1 if in_use else 0) | (0x2 if directory else 0)
    header = struct.pack("<4sHHQHHHHIIQHHI", b"FILE", usa_offset, usa_count, 0, sequence, 1, first_attr, flags,
                         first_attr + len(attrs), record_size, 0, 0, 0, record)
    buf = bytearray(header.ljust(first_attr, b"\x00") + attrs)
    buf = buf.ljust(record_size, b"\x00")
    # Update sequence array: store the real sector tails and stamp the USN.
    usn = b"\x01\x00"
    buf[usa_offset:usa_offset + 2] = usn
    for i in range(1, usa_count):
        end = i * 512 - 2
        buf[usa_offset + i * 2:usa_offset + i * 2 + 2] = buf[end:end + 2]
        buf[end:end + 2] = usn
    return bytes(buf)


# --------------------------------------------------------------------------
# Browsers
# --------------------------------------------------------------------------
def build_chrome_history(path: Path, visits: list[tuple[str, str, datetime, int]],
                         downloads: list[tuple[str, str, datetime, int]]) -> Path:
    """``visits``: (url, title, time, transition); ``downloads``: (url, target_path, start, size)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER,
                           last_visit_time INTEGER, hidden INTEGER DEFAULT 0);
        CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER,
                             transition INTEGER);
        CREATE TABLE downloads (id INTEGER PRIMARY KEY, guid TEXT, current_path TEXT, target_path TEXT,
                                start_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state INTEGER,
                                danger_type INTEGER, end_time INTEGER, tab_url TEXT, referrer TEXT, mime_type TEXT);
        CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
    """)
    for i, (url, title, when, transition) in enumerate(visits, 1):
        conn.execute("INSERT INTO urls VALUES (?,?,?,?,?,?,0)",
                     (i, url, title, 1, 1 if transition == 1 else 0, to_webkit(when)))
        conn.execute("INSERT INTO visits VALUES (?,?,?,0,?)", (i, i, to_webkit(when), transition))
    for i, (url, target, start, size) in enumerate(downloads, 1):
        conn.execute("INSERT INTO downloads VALUES (?,?,?,?,?,?,?,1,0,?,?,?,?)",
                     (i, str(uuid.uuid4()), target, target, to_webkit(start), size, size, to_webkit(start) + 2_000_000,
                      url, "", "application/octet-stream"))
        conn.execute("INSERT INTO downloads_url_chains VALUES (?,0,?)", (i, url))
    conn.commit()
    conn.close()
    return path


def build_firefox_places(path: Path, visits: list[tuple[str, str, datetime, int]],
                         downloads: list[tuple[str, str, datetime]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed INTEGER,
                                 last_visit_date INTEGER);
        CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER,
                                        visit_date INTEGER, visit_type INTEGER);
        CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content TEXT,
                                dateAdded INTEGER);
        INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI');
    """)
    place = 0
    for url, title, when, visit_type in visits:
        place += 1
        conn.execute("INSERT INTO moz_places VALUES (?,?,?,1,?,?)",
                     (place, url, title, 1 if visit_type == 2 else 0, to_unix_us(when)))
        conn.execute("INSERT INTO moz_historyvisits VALUES (?,0,?,?,?)", (place, place, to_unix_us(when), visit_type))
    for url, target, when in downloads:
        place += 1
        conn.execute("INSERT INTO moz_places VALUES (?,?,?,1,0,?)", (place, url, "", to_unix_us(when)))
        conn.execute("INSERT INTO moz_annos VALUES (?,?,1,?,?)",
                     (place, place, "file:///" + target.replace("\\", "/"), to_unix_us(when)))
    conn.commit()
    conn.close()
    return path


# --------------------------------------------------------------------------
# Generic files (for carving and signature tests)
# --------------------------------------------------------------------------
def build_png(width: int = 4, height: int = 4, color: tuple = (200, 30, 30)) -> bytes:
    raw = b"".join(b"\x00" + bytes(color) * width for _ in range(height))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def build_jpeg(payload: bytes = bytes(range(0, 250)) * 4, thumbnail: Optional[bytes] = None) -> bytes:
    """Structurally valid JPEG (markers and segment lengths) with an optional EXIF-like thumbnail."""
    out = b"\xff\xd8"
    app0 = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    out += b"\xff\xe0" + struct.pack(">H", len(app0) + 2) + app0
    if thumbnail:
        app1 = b"Exif\x00\x00" + thumbnail
        out += b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1
    sos = b"\x01\x01\x00\x00\x3f\x00"
    out += b"\xff\xda" + struct.pack(">H", len(sos) + 2) + sos
    out += payload.replace(b"\xff", b"\xff\x00")
    return out + b"\xff\xd9"


GIF_1X1 = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
           b",\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")


def build_pdf(text: str = "Forense-Framework") -> bytes:
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        None,
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    stream = f"BT /F1 18 Tf 20 70 Td ({text}) Tj ET".encode("latin-1")
    objects[3] = b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + obj + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % off for off in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return bytes(out)


def build_zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buffer.getvalue()


# --------------------------------------------------------------------------
# Prefetch (uncompressed, format version 23 as written by Windows 7)
# --------------------------------------------------------------------------
def build_prefetch_v23(executable: str, prefetch_hash: int, run_count: int, last_run: datetime,
                       loaded_files: list[str], volume_device: str = "\\DEVICE\\HARDDISKVOLUME2",
                       volume_serial: int = 0x1A2B3C4D, volume_created: Optional[datetime] = None) -> bytes:
    """Minimal but structurally valid Windows 7 prefetch file (readable by libscca)."""
    names = b"".join((name + "\x00").encode("utf-16-le") for name in loaded_files)
    metrics = bytearray()
    traces = bytearray()
    offset = 0
    for index, name in enumerate(loaded_files):
        metrics += struct.pack("<IIIIIIQ", index, 1, 0, offset, len(name), 0x200, 0)
        traces += struct.pack("<IIBBH", 0xFFFFFFFF, 1, 0x02, 0x01, 0xFFFF)
        offset += (len(name) + 1) * 2
    header_size, info_size = 84, 156
    metrics_offset = header_size + info_size
    trace_offset = metrics_offset + len(metrics)
    names_offset = trace_offset + len(traces)
    volumes_offset = names_offset + len(names)
    volumes_offset += -volumes_offset % 8
    device = (volume_device + "\x00").encode("utf-16-le")
    directories = [d for d in dict.fromkeys("\\".join(f.split("\\")[:-1]) for f in loaded_files) if d]
    dir_blob = b"".join(struct.pack("<H", len(d)) + (d + "\x00").encode("utf-16-le") for d in directories)
    vol_header = 104
    device_off = vol_header
    refs_off = device_off + len(device)
    refs_off += -refs_off % 8
    refs = struct.pack("<IIQ", 1, 0, 0)
    dirs_off = refs_off + len(refs)
    volume = struct.pack("<IIQIIIII", device_off, len(volume_device), to_filetime(volume_created or last_run),
                         volume_serial, refs_off, len(refs), dirs_off, len(directories)).ljust(vol_header, b"\x00")
    volume = volume.ljust(device_off, b"\x00") + device
    volume = volume.ljust(refs_off, b"\x00") + refs + dir_blob
    info = struct.pack("<IIIIIIIII", metrics_offset, len(loaded_files), trace_offset, len(loaded_files),
                       names_offset, len(names), volumes_offset, 1, len(volume))
    info = info.ljust(44, b"\x00") + struct.pack("<Q", to_filetime(last_run))
    info = info.ljust(68, b"\x00") + struct.pack("<I", run_count)
    info = info.ljust(info_size, b"\x00")
    body = bytearray(info) + metrics + traces + names
    body = body.ljust(volumes_offset - header_size, b"\x00") + volume
    size = header_size + len(body)
    header = struct.pack("<I4sII", 23, b"SCCA", 0x11, size) + executable.encode("utf-16-le")[:58].ljust(60, b"\x00")
    header += struct.pack("<II", prefetch_hash, 0)
    return bytes(header + body)


# --------------------------------------------------------------------------
# Shell items (ShellBags)
# --------------------------------------------------------------------------
def shell_root(guid: str, sort_index: int = 0x50) -> bytes:
    return struct.pack("<HBB", 20, 0x1F, sort_index) + uuid.UUID(guid).bytes_le


def shell_volume(name: str) -> bytes:
    body = struct.pack("<B", 0x2F) + name.encode("ascii").ljust(20, b"\x00") + b"\x00\x00"
    return struct.pack("<H", len(body) + 2) + body


def _fat(dt: Optional[datetime]) -> bytes:
    if dt is None:
        return b"\x00\x00\x00\x00"
    date = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    time = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return struct.pack("<HH", date, time)


def shell_file_entry(name: str, modified: datetime, created: datetime, accessed: datetime, mft_entry: int = 0,
                     mft_sequence: int = 1, directory: bool = True) -> bytes:
    """File entry shell item (Windows 8.1/10 layout) with a version 9 0xBEEF0004 extension block."""
    short = name.upper()[:12].encode("ascii", "replace") + b"\x00"
    short += b"\x00" * (len(short) % 2)
    long_name = (name + "\x00").encode("utf-16-le")
    ext = struct.pack("<HHI", 0, 9, 0xBEEF0004) + _fat(created) + _fat(accessed) + struct.pack("<H", 0x2E)
    ext += struct.pack("<HQQ", 0, (mft_sequence << 48) | mft_entry, 0) + struct.pack("<H", 0)
    ext += struct.pack("<II", 0, 0) + long_name + struct.pack("<H", 0)
    ext = struct.pack("<H", len(ext)) + ext[2:]
    body = struct.pack("<BBI", 0x31 if directory else 0x32, 0, 0) + _fat(modified) + struct.pack("<H", 0x10)
    item = body + short + ext
    return struct.pack("<H", len(item) + 2) + item


def shell_network(location: str) -> bytes:
    body = struct.pack("<BBB", 0x41, 0, 0) + location.encode("ascii") + b"\x00\x00\x00"
    return struct.pack("<H", len(body) + 2) + body


def add_shellbags(hive: "HiveBuilder", root: str, tree: list, when: datetime) -> None:
    """Add a BagMRU tree. ``tree`` items are ``(shell_item_bytes, [children...])``; newest first."""
    def add(path: str, items: list) -> None:
        hive.key(path, when)
        for index, (item, children) in enumerate(items):
            hive.value(path, str(index), REG_BINARY, item + b"\x00\x00")
            if children is not None:
                add(f"{path}\\{index}", children)
        order = b"".join(struct.pack("<I", i) for i in range(len(items))) + b"\xff\xff\xff\xff"
        hive.value(path, "MRUListEx", REG_BINARY, order)

    add(root, tree)
