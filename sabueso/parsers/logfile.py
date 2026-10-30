"""Parser of the NTFS $LogFile, the write-ahead journal of the file system.

The log records every metadata change as LSN records: two restart pages
(``RSTR``) describe the log geometry and the rest are record pages (``RCRD``)
whose client data is an NTFS_LOG_RECORD with redo/undo operations. This basic
reader validates the update sequence of every page and yields the operations
that carry a file name inside their own data: MFT record initializations
(0x02, decoded with the $MFT record parser) and directory index entries added
or deleted (0x0C-0x0F) plus file name updates (0x13-0x14).

Attribute-level operations (create/delete attribute, value and mapping pairs
updates) name no file themselves: their context is the open attribute table.
``OpenAttributes`` rebuilds that table from the OpenNonresidentAttribute
records (0x1C, whose redo data is a logged OPEN_ATTRIBUTE_ENTRY and whose
undo data carries the attribute name) with the checkpoint dumps (0x1D table,
0x1E names) as fallback, so those operations can be reported with the file
and the attribute they touch.

Limitations: the log holds no timestamps, so the result is a table of
operations (LSN, transaction, operation, name) and not timeline events; and
operations whose open-attribute entry never appears in the log stay unnamed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator, Optional

from sabueso.parsers.mft import MftEntry, apply_fixups, parse_record

RESTART_MAGIC, RECORD_MAGIC = b"RSTR", b"RCRD"
RESTART_PAGES = 2
DEFAULT_PAGE_SIZE = 4096
RECORD_HEADER = 0x30  # LFS_RECORD header, then the client data
LOG_RECORD_HEADER = 0x28  # NTFS_LOG_RECORD header, then the redo/undo data

OP_INITIALIZE_FILE_RECORD = 0x02
OP_INDEX_ROOT_ADD, OP_INDEX_ROOT_DELETE = 0x0C, 0x0D
OP_INDEX_ALLOC_ADD, OP_INDEX_ALLOC_DELETE = 0x0E, 0x0F
OP_NAME_ROOT_UPDATE, OP_NAME_ALLOC_UPDATE = 0x13, 0x14
NAME_OPS = frozenset({OP_INITIALIZE_FILE_RECORD, OP_INDEX_ROOT_ADD, OP_INDEX_ROOT_DELETE,
                      OP_INDEX_ALLOC_ADD, OP_INDEX_ALLOC_DELETE, OP_NAME_ROOT_UPDATE, OP_NAME_ALLOC_UPDATE})
OP_OPEN_NONRESIDENT, OP_OPEN_ATTRIBUTE_TABLE_DUMP, OP_ATTRIBUTE_NAMES_DUMP = 0x1C, 0x1D, 0x1E
# Operations whose only context is the open attribute table (which file and which attribute they touch).
CONTEXT_OPS = frozenset({0x05, 0x06, 0x07, 0x08, 0x09, 0x0B})
OAT_ENTRY_SIZE = 0x28  # logged OPEN_ATTRIBUTE_ENTRY (log format 1.0+), verified against dfir_ntfs
ATTRIBUTE_TYPES = {
    0x10: "$STANDARD_INFORMATION", 0x20: "$ATTRIBUTE_LIST", 0x30: "$FILE_NAME", 0x40: "$OBJECT_ID",
    0x50: "$SECURITY_DESCRIPTOR", 0x60: "$VOLUME_NAME", 0x70: "$VOLUME_INFORMATION", 0x80: "$DATA",
    0x90: "$INDEX_ROOT", 0xA0: "$INDEX_ALLOCATION", 0xB0: "$BITMAP", 0xC0: "$REPARSE_POINT",
    0x100: "$LOGGED_UTILITY_STREAM",
}

OPERATIONS = {
    0x00: "noop", 0x01: "compensation_log_record", 0x02: "initialize_file_record_segment",
    0x03: "deallocate_file_record_segment", 0x04: "write_end_of_file_record_segment",
    0x05: "create_attribute", 0x06: "delete_attribute", 0x07: "update_resident_attribute_value",
    0x08: "update_non_resident_attribute_value", 0x09: "update_mapping_pairs", 0x0A: "delete_dirty_clusters",
    0x0B: "set_new_attribute_sizes", 0x0C: "add_index_entry_to_root", 0x0D: "delete_index_entry_from_root",
    0x0E: "add_index_entry_to_allocation", 0x0F: "delete_index_entry_from_allocation",
    0x10: "write_end_of_index_buffer", 0x11: "set_index_entry_vcn_in_root",
    0x12: "set_index_entry_vcn_in_allocation", 0x13: "update_file_name_in_root",
    0x14: "update_file_name_in_allocation", 0x15: "set_bits_in_non_resident_bitmap",
    0x16: "clear_bits_in_non_resident_bitmap", 0x17: "hot_fix", 0x18: "end_top_level_action",
    0x19: "prepare_transaction", 0x1A: "commit_transaction", 0x1B: "forget_transaction",
    0x1C: "open_non_resident_attribute", 0x1D: "open_attribute_table_dump", 0x1E: "attribute_names_dump",
    0x1F: "dirty_page_table_dump", 0x20: "transaction_table_dump", 0x21: "update_record_data_in_root",
    0x22: "update_record_data_in_allocation",
}


def operation_name(op: int) -> str:
    return OPERATIONS.get(op, f"unknown_{op:#06x}")


class LogFileError(ValueError):
    pass


@dataclass
class LogInfo:
    """Geometry of the log, from the first valid restart page."""

    page_size: int
    data_offset: int
    clients: int
    current_lsn: int
    file_size: int


@dataclass
class LogRecord:
    lsn: int
    record_type: int  # 1 = client record, 2 = client restart
    transaction_id: int
    redo_op: int
    undo_op: int
    redo_data: bytes
    undo_data: bytes
    target_attribute: int = 0  # open attribute table index (a byte offset; 0 is the $MFT itself)


def parse_restart(data: bytes) -> LogInfo:
    """Parse the two restart pages (4096 bytes each) and return the log geometry.

    Raises ``LogFileError`` when neither page is valid (the log is corrupt or not a $LogFile).
    """
    for start in range(RESTART_PAGES):
        page = data[start * DEFAULT_PAGE_SIZE:(start + 1) * DEFAULT_PAGE_SIZE]
        if len(page) < 64 or page[:4] != RESTART_MAGIC:
            continue
        buf = bytearray(page)
        if not apply_fixups(buf):
            continue
        log_page_size, = struct.unpack_from("<I", buf, 20)
        restart_offset, = struct.unpack_from("<H", buf, 24)
        if restart_offset + 0x28 > len(buf):
            continue
        current_lsn, clients = struct.unpack_from("<QH", buf, restart_offset)
        file_size, = struct.unpack_from("<Q", buf, restart_offset + 0x18)
        data_offset, = struct.unpack_from("<H", buf, restart_offset + 0x26)
        page_size = log_page_size if log_page_size in (4096, 8192, 16384, 32768, 65536) else DEFAULT_PAGE_SIZE
        data_offset = data_offset if 0x40 <= data_offset < page_size else 0x40
        return LogInfo(page_size, data_offset, clients, current_lsn, file_size)
    raise LogFileError("no valid restart page found")


def iter_records(fh: BinaryIO, info: Optional[LogInfo] = None) -> Iterator[LogRecord]:
    """Yield every client record of the valid record pages (``RCRD``).

    Pages that are not record pages or fail their update sequence are skipped;
    a record that does not fit its page ends that page. Never raises on log content.
    """
    if info is None:
        info = parse_restart(fh.read(RESTART_PAGES * DEFAULT_PAGE_SIZE))
    fh.seek(RESTART_PAGES * DEFAULT_PAGE_SIZE)
    while True:
        page = fh.read(info.page_size)
        if len(page) < info.page_size:
            return
        if page[:4] != RECORD_MAGIC:
            continue  # a tail copy or a hole: not a record page
        buf = bytearray(page)
        if not apply_fixups(buf):
            continue
        next_record, = struct.unpack_from("<H", buf, 24)
        end = min(next_record, info.page_size) if next_record else info.page_size
        off = info.data_offset
        while off + RECORD_HEADER <= end:
            lsn, _prev, _undo_next, client_len = struct.unpack_from("<QQQI", buf, off)
            record_type, transaction_id = struct.unpack_from("<II", buf, off + 0x20)
            if lsn == 0 and client_len == 0:
                break
            if client_len < LOG_RECORD_HEADER or off + RECORD_HEADER + client_len > info.page_size:
                break  # corrupt boundary: do not chase bytes across the page
            body = bytes(buf[off + RECORD_HEADER:off + RECORD_HEADER + client_len])
            redo_op = undo_op = 0
            redo_data = undo_data = b""
            if record_type == 1 and len(body) >= LOG_RECORD_HEADER:
                redo_op, undo_op, redo_off, redo_len, undo_off, undo_len = struct.unpack_from("<HHHHHH", body, 0)
                target_attribute = struct.unpack_from("<H", body, 0x0C)[0]
                redo_data = _slice(body, redo_off, redo_len)
                undo_data = _slice(body, undo_off, undo_len)
            yield LogRecord(lsn, record_type, transaction_id, redo_op, undo_op, redo_data, undo_data,
                            target_attribute)
            off += (RECORD_HEADER + client_len + 7) & ~7


def _slice(body: bytes, offset: int, length: int) -> bytes:
    if length <= 0 or offset < LOG_RECORD_HEADER or offset + length > len(body):
        return b""
    return body[offset:offset + length]


@dataclass
class OpenAttribute:
    """One entry of the open attribute table: which file and which attribute it points to."""

    reference: int  # MFT reference of the file owning the attribute
    type_code: int
    name: str = ""  # attribute name ("J" for the $J stream); empty for unnamed attributes


def open_attribute_from_data(data: bytes) -> Optional[OpenAttribute]:
    """The logged OPEN_ATTRIBUTE_ENTRY (format 1.0+): allocated flag, type, file reference."""
    if len(data) < OAT_ENTRY_SIZE:
        return None
    allocated, = struct.unpack_from("<I", data, 0)
    type_code, = struct.unpack_from("<I", data, 8)
    reference, = struct.unpack_from("<Q", data, 0x10)
    if allocated != 0xFFFFFFFF or not reference:
        return None  # a free slot (or a broken one) points to nothing
    return OpenAttribute(reference & 0xFFFFFFFFFFFF, type_code)


def attribute_name_from_data(data: bytes) -> str:
    """The attribute name carried by an OpenNonresidentAttribute undo value (UTF-16LE)."""
    if not data:
        return ""
    name = data.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
    return name if name and all(ch.isprintable() for ch in name) else ""


def attribute_type_name(type_code: int) -> str:
    return ATTRIBUTE_TYPES.get(type_code, f"type_{type_code:#06x}")


def attribute_display(entry: OpenAttribute) -> str:
    """How an open attribute entry is shown: ``$DATA``, or ``$DATA (J)`` when named."""
    return f"{attribute_type_name(entry.type_code)} ({entry.name})" if entry.name \
        else attribute_type_name(entry.type_code)


class OpenAttributes:
    """The open attribute table, rebuilt while the log records are walked.

    ``OpenNonresidentAttribute`` (0x1C) records register one entry each (the redo data is
    the logged OPEN_ATTRIBUTE_ENTRY, the undo data the attribute name); the checkpoint
    dumps (0x1D table, 0x1E names) are kept as a fallback: restart-table indices are byte
    offsets, so the entry for an index sits exactly at that offset inside the table dump.
    A broken 0x1C entry invalidates the incrementally built table, as the reference
    restart analysis does.
    """

    def __init__(self) -> None:
        self._entries: dict[int, OpenAttribute] = {}
        self._table_dump = b""
        self._names_dump = b""

    def update(self, record: LogRecord) -> None:
        if record.record_type != 1:
            return
        if record.redo_op == OP_OPEN_NONRESIDENT:
            entry = open_attribute_from_data(record.redo_data)
            if entry is None:
                self._entries.clear()
            else:
                entry.name = attribute_name_from_data(record.undo_data)
                self._entries[record.target_attribute] = entry
        elif record.redo_op == OP_OPEN_ATTRIBUTE_TABLE_DUMP:
            self._table_dump = record.redo_data
        elif record.redo_op == OP_ATTRIBUTE_NAMES_DUMP:
            self._names_dump = record.redo_data

    def lookup(self, index: int) -> Optional[OpenAttribute]:
        entry = self._entries.get(index)
        if entry is not None:
            return entry
        if 0 <= index <= len(self._table_dump) - OAT_ENTRY_SIZE:
            entry = open_attribute_from_data(self._table_dump[index:index + OAT_ENTRY_SIZE])
            if entry is not None:
                if not entry.name:
                    entry.name = self._name_from_dump(index)
                return entry
        return None

    def _name_from_dump(self, index: int) -> str:
        pos, buf = 0, self._names_dump
        while pos + 4 <= len(buf):
            entry_index, name_len = struct.unpack_from("<HH", buf, pos)
            if entry_index == 0 and name_len == 0:
                break  # the names dump ends with an all-zero entry
            if entry_index == index:
                raw = buf[pos + 4:pos + 4 + name_len]
                name = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
                return name if name and all(ch.isprintable() for ch in name) else ""
            pos += 4 + name_len + 2  # header plus name plus its terminating null
        return ""


def file_record_from_data(data: bytes) -> Optional[MftEntry]:
    """The MFT record image carried by an InitializeFileRecordSegment operation.

    The image keeps its update sequence when NTFS logged it before applying the
    fixups; in that case they are applied as usual, otherwise the record is
    parsed as-is (its sector tails are already the real bytes).
    """
    if len(data) < 56 or data[:4] != b"FILE":
        return None
    usa_offset, usa_count = struct.unpack_from("<HH", data, 4)
    usn = data[usa_offset:usa_offset + 2]
    stamped = all(data[i * 512 - 2:i * 512] == usn for i in range(1, min(usa_count, len(data) // 512) + 1))
    number, = struct.unpack_from("<I", data, 44)
    entry = parse_record(data, number)
    if entry is not None:
        entry.fixup_ok = stamped and entry.fixup_ok
    return entry


def file_name_from_content(content: bytes) -> Optional[tuple[int, str]]:
    """Decode a $FILE_NAME value: (parent reference, name)."""
    if len(content) < 66:
        return None
    name_len, namespace = content[64], content[65]
    if not name_len or name_len > 255 or namespace > 4:
        return None
    name = content[66:66 + name_len * 2].decode("utf-16-le", errors="replace")
    if not name.strip("\x00"):
        return None
    parent, = struct.unpack_from("<Q", content, 0)
    return parent & 0xFFFFFFFFFFFF, name


def index_entry_file_name(data: bytes) -> Optional[tuple[int, int, str]]:
    """(file reference, parent reference, name) of a directory INDEX_ENTRY blob."""
    if len(data) < 16 + 66:
        return None
    reference, = struct.unpack_from("<Q", data, 0)
    key_len, = struct.unpack_from("<H", data, 12)
    content = data[16:16 + key_len] if key_len else data[16:]
    decoded = file_name_from_content(content)
    if decoded is None or not reference:
        return None
    parent, name = decoded
    return reference & 0xFFFFFFFFFFFF, parent, name


def open_logfile(path: Path) -> tuple[BinaryIO, LogInfo]:
    """Open a $LogFile and validate its restart pages."""
    fh = open(path, "rb")
    try:
        info = parse_restart(fh.read(RESTART_PAGES * DEFAULT_PAGE_SIZE))
    except LogFileError:
        fh.close()
        raise
    fh.seek(0)
    return fh, info
