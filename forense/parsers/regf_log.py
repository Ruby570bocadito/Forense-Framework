"""Registry transaction logs: recovery of dirty hives (.LOG / .LOG1 / .LOG2).

Windows writes registry changes to the transaction logs first and flushes them
to the hive later, so a hive copied from a running or crashed system may lack
its most recent changes ("dirty": primary and secondary sequence numbers
differ). Replaying the logs in memory gives the state Windows would see.

* New format (Windows 8.1+): log entries ``HvLE`` with dirty page references
  and pages, validated with two Marvin32 hashes.
* Old format (Windows XP to 8): a ``DIRT`` bitmap of 512-byte dirty pages.

The evidence files are never modified: the recovered hive only exists in
memory. Format reference: https://github.com/msuhanov/regf (Windows registry
file format specification).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

BASE_BLOCK_SIZE = 4096
LOG_HEADER_SIZE = 512
MARVIN32_SEED = 0x82EF4D887A4E55C5
_MASK = 0xFFFFFFFF


def _rotl(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (32 - bits))) & _MASK


def _mix(lo: int, hi: int) -> tuple[int, int]:
    hi ^= lo
    lo = (_rotl(lo, 20) + hi) & _MASK
    hi = _rotl(hi, 9) ^ lo
    lo = (_rotl(lo, 27) + hi) & _MASK
    hi = _rotl(hi, 19)
    return lo, hi


def marvin32(data: bytes, seed: int = MARVIN32_SEED) -> int:
    """64-bit Marvin32 hash (the checksum used by registry log entries)."""
    lo, hi = seed & _MASK, seed >> 32
    length = len(data)
    whole = length - length % 4
    for (word,) in struct.iter_unpack("<I", data[:whole]):
        lo = (lo + word) & _MASK
        lo, hi = _mix(lo, hi)
    tail = data[whole:]
    if len(tail) == 0:
        final = 0x80
    elif len(tail) == 1:
        final = 0x8000 | tail[0]
    elif len(tail) == 2:
        final = 0x800000 | struct.unpack("<H", tail)[0]
    else:
        final = 0x80000000 | (tail[2] << 16) | struct.unpack("<H", tail[:2])[0]
    lo = (lo + final) & _MASK
    lo, hi = _mix(lo, hi)
    lo, hi = _mix(lo, hi)
    return (hi << 32) | lo


@dataclass
class LogEntry:
    sequence: int
    hbins_size: int
    pages: list[tuple[int, bytes]]  # (offset in hive bins data, data)


@dataclass
class TransactionLog:
    name: str
    format: str  # "new" | "old"
    sequence: int  # primary sequence number of the log base block
    entries: list[LogEntry] = field(default_factory=list)


def _checksum_ok(data: bytes) -> bool:
    checksum = 0
    for (dword,) in struct.iter_unpack("<I", bytes(data[:508])):
        checksum ^= dword
    checksum = {0: 1, 0xFFFFFFFF: 0xFFFFFFFE}.get(checksum, checksum)
    return checksum == struct.unpack_from("<I", data, 508)[0]


def _header(data: bytes) -> Optional[tuple[int, int, int]]:
    """(primary seq, secondary seq, hive bins size) of a log base block, or None."""
    if len(data) < LOG_HEADER_SIZE or data[:4] != b"regf" or not _checksum_ok(data):
        return None
    primary, secondary = struct.unpack_from("<II", data, 4)
    hbins_size = struct.unpack_from("<I", data, 40)[0]
    return primary, secondary, hbins_size


def parse_log(data: bytes, name: str = "") -> Optional[TransactionLog]:
    header = _header(data)
    if header is None:
        return None
    primary, secondary, hbins_size = header
    if data[LOG_HEADER_SIZE:LOG_HEADER_SIZE + 4] == b"HvLE":
        log = TransactionLog(name, "new", primary)
        pos, expected = LOG_HEADER_SIZE, primary
        while pos + 40 <= len(data) and data[pos:pos + 4] == b"HvLE":
            size, _flags, sequence, entry_hbins, count = struct.unpack_from("<IIIII", data, pos + 4)
            hash1, hash2 = struct.unpack_from("<QQ", data, pos + 24)
            if size < 40 or size % 512 or pos + size > len(data) or sequence != expected:
                break
            entry = bytes(data[pos:pos + size])
            if marvin32(entry[40:]) != hash1 or marvin32(entry[:32]) != hash2:
                break
            refs = [struct.unpack_from("<II", entry, 40 + 8 * i) for i in range(count)]
            cursor, pages = 40 + 8 * count, []
            for offset, length in refs:
                pages.append((offset, entry[cursor:cursor + length]))
                cursor += length
            if cursor > size:
                break
            log.entries.append(LogEntry(sequence, entry_hbins, pages))
            pos += size
            expected = (expected + 1) & _MASK
        return log
    if data[LOG_HEADER_SIZE:LOG_HEADER_SIZE + 4] == b"DIRT" and primary == secondary and hbins_size:
        bitmap_size = hbins_size // 4096
        bitmap = data[LOG_HEADER_SIZE + 4:LOG_HEADER_SIZE + 4 + bitmap_size]
        cursor = (LOG_HEADER_SIZE + 4 + bitmap_size + 511) // 512 * 512
        pages = []
        for index in range(bitmap_size * 8):
            if bitmap[index // 8] >> (index % 8) & 1:
                pages.append((index * 512, bytes(data[cursor:cursor + 512])))
                cursor += 512
        if cursor > len(data):
            return None
        return TransactionLog(name, "old", primary, [LogEntry(primary, hbins_size, pages)])
    return None


def log_files(hive_path: Path) -> list[Path]:
    """Transaction logs next to a hive (``SYSTEM.LOG``, ``SYSTEM.LOG1``, ``SYSTEM.LOG2``, any case)."""
    hive_path = Path(hive_path)
    try:
        siblings = {p.name.lower(): p for p in hive_path.parent.iterdir() if p.is_file()}
    except OSError:
        return []
    found = []
    for suffix in (".log", ".log1", ".log2"):
        path = siblings.get(hive_path.name.lower() + suffix)
        if path is not None and path.stat().st_size >= LOG_HEADER_SIZE:
            found.append(path)
    return found


@dataclass
class Recovery:
    data: bytearray
    logs: list[str]
    entries: int
    pages: int
    last_sequence: Optional[int]


def recover(hive: bytes, logs: list[TransactionLog]) -> Optional[Recovery]:
    """Apply the log entries newer than the hive (sequence >= secondary sequence number), in order."""
    if len(hive) < BASE_BLOCK_SIZE:
        return None
    secondary = struct.unpack_from("<I", hive, 8)[0]
    new_entries: dict[int, tuple[str, LogEntry]] = {}
    old_logs = []
    for log in logs:
        if log.format == "new":
            for entry in log.entries:
                if entry.sequence >= secondary:
                    new_entries.setdefault(entry.sequence, (log.name, entry))
        elif log.sequence >= secondary:
            old_logs.append(log)
    data = bytearray(hive)
    used: list[str] = []
    applied = pages = 0
    last = None
    if new_entries:
        sequence = min(new_entries)
        while sequence in new_entries:
            name, entry = new_entries[sequence]
            pages += _apply(data, entry)
            applied += 1
            last = sequence
            if name not in used:
                used.append(name)
            sequence = (sequence + 1) & _MASK
    elif old_logs:
        log = max(old_logs, key=lambda item: item.sequence)
        pages += _apply(data, log.entries[0])
        applied, last, used = 1, log.sequence, [log.name]
    if not applied:
        return None
    sequence = last + 1 if new_entries else last
    struct.pack_into("<II", data, 4, sequence, sequence)
    checksum = 0
    for (dword,) in struct.iter_unpack("<I", bytes(data[:508])):
        checksum ^= dword
    struct.pack_into("<I", data, 508, {0: 1, 0xFFFFFFFF: 0xFFFFFFFE}.get(checksum, checksum))
    return Recovery(data, used, applied, pages, last)


def _apply(data: bytearray, entry: LogEntry) -> int:
    end = BASE_BLOCK_SIZE + entry.hbins_size
    if len(data) < end:
        data.extend(b"\x00" * (end - len(data)))
    struct.pack_into("<I", data, 40, entry.hbins_size)
    for offset, page in entry.pages:
        start = BASE_BLOCK_SIZE + offset
        if start + len(page) > len(data):
            data.extend(b"\x00" * (start + len(page) - len(data)))
        data[start:start + len(page)] = page
    return len(entry.pages)


def build_log_entry(sequence: int, hbins_size: int, pages: list[tuple[int, bytes]]) -> bytes:
    """A valid HvLE log entry (used by the tests)."""
    body = b"".join(struct.pack("<II", offset, len(page)) for offset, page in pages) + b"".join(p for _, p in pages)
    size = (40 + len(body) + 511) // 512 * 512
    body = body.ljust(size - 40, b"\x00")
    head = struct.pack("<4sIIIII", b"HvLE", size, 0, sequence, hbins_size, len(pages))
    hash1 = marvin32(body)
    hash2 = marvin32(head + struct.pack("<Q", hash1))
    return head + struct.pack("<QQ", hash1, hash2) + body
