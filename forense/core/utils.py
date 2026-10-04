"""Common helpers: UTC timestamps, Windows time formats, file walking and exports.

All timestamps handled by the framework are normalised to UTC and stored as
fixed-width ISO 8601 strings (``YYYY-MM-DDTHH:MM:SS.ffffffZ``) so they sort
lexicographically.
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional, Union

ErrorHandler = Callable[[Path, BaseException], None]
TimeLike = Union[datetime, float, int, str, None]

_FRACTION = re.compile(r"(?<=\d)\.(\d+)")
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    """Fixed-width UTC ISO 8601 representation with microseconds."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return (
        f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}T"
        f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}.{dt.microsecond:06d}Z"
    )


def utc_now() -> str:
    return iso(datetime.now(timezone.utc))


def parse_datetime(value: str) -> datetime:
    """Parse ``YYYY-MM-DD`` or ISO 8601 (also ``Z`` and 7-digit fractions). Naive means UTC."""
    value = value.strip().replace(" ", "T", 1) if "T" not in value else value.strip()
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    # Windows emits 7 fractional digits (100 ns) and Python < 3.11 needs exactly 3 or 6:
    # normalise the fraction to 6 digits, keeping any UTC offset that follows it.
    fraction = _FRACTION.search(value)
    if fraction:
        digits = fraction.group(1)[:6].ljust(6, "0")
        value = f"{value[:fraction.start()]}.{digits}{value[fraction.end():]}"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_ts(value: TimeLike) -> Optional[str]:
    """Normalise a datetime, POSIX timestamp or ISO string to the storage format."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return iso(value)
    if isinstance(value, (int, float)):
        return iso(datetime.fromtimestamp(value, tz=timezone.utc))
    return iso(parse_datetime(str(value)))


def ts_to_iso(ts: float) -> str:
    return iso(datetime.fromtimestamp(ts, tz=timezone.utc))


def filetime_to_dt(value: int) -> Optional[datetime]:
    """Windows FILETIME (100 ns intervals since 1601-01-01) to datetime. 0/invalid -> None."""
    if not value or value <= 0 or value >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except OverflowError:
        return None


def webkit_to_dt(value: int) -> Optional[datetime]:
    """Chromium/WebKit time (microseconds since 1601-01-01) to datetime."""
    if not value or value <= 0:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=value)
    except OverflowError:
        return None


def unix_us_to_dt(value: int) -> Optional[datetime]:
    """Microseconds since the Unix epoch (Firefox PRTime) to datetime."""
    if not value or value <= 0:
        return None
    try:
        return _UNIX_EPOCH + timedelta(microseconds=value)
    except OverflowError:
        return None


def dt_or_none_iso(dt: Optional[datetime]) -> Optional[str]:
    return iso(dt) if dt else None


def iter_files(target: Path, on_error: Optional[ErrorHandler] = None) -> Iterator[Path]:
    """Yield regular files under ``target`` in a stable order.

    A file target yields itself. Symbolic links are never followed so the walk
    cannot escape the evidence.
    """
    target = Path(target)
    if target.is_file():
        yield target
        return

    def _walk_error(exc: OSError) -> None:
        if on_error:
            on_error(Path(exc.filename or target), exc)

    for root, dirs, files in os.walk(target, onerror=_walk_error, followlinks=False):
        dirs.sort()
        for name in sorted(files):
            path = Path(root) / name
            if path.is_symlink() or not path.is_file():
                continue
            yield path


def find_files(target: Path, predicate: Callable[[Path], bool],
               on_error: Optional[ErrorHandler] = None) -> list[Path]:
    """Files under ``target`` accepted by ``predicate``. A file target is always accepted."""
    target = Path(target)
    if target.is_file():
        return [target]
    return [path for path in iter_files(target, on_error) if predicate(path)]


def relative_name(path: Path, target: Path) -> str:
    """Path of ``path`` relative to the evidence root ``target`` using ``/`` separators."""
    path, target = Path(path), Path(target)
    if path == target:
        return path.name
    try:
        return path.relative_to(target).as_posix()
    except ValueError:
        return path.as_posix()


def human_size(num: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num) < 1024 or unit == "TiB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TiB"


def write_json(path: Path, data: object) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def write_csv(path: Path, records: Iterable[dict], headers: Optional[dict] = None) -> int:
    """Write dict records as CSV readable by Excel (UTF-8 with BOM). Returns the row count.

    ``headers`` optionally maps field names to display labels.
    """
    records = list(records)
    columns: list[str] = []
    for record in records:
        for key in record:
            if key not in columns:
                columns.append(key)
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow([(headers or {}).get(col, col) for col in columns])
        for record in records:
            writer.writerow([_csv_value(record.get(col)) for col in columns])
    return len(records)


_FORMULA_PREFIXES = ("=", "+", "@", "\t", "\r")


def _csv_value(value: object) -> object:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    if value is None:
        return ""
    if isinstance(value, str) and value and (
            value.startswith(_FORMULA_PREFIXES) or (value[0] == "-" and len(value) > 1 and value[1].isalpha())):
        # Evidence-controlled text (page titles, command lines...) must not run as a spreadsheet formula.
        return "'" + value
    return value


def user_from_path(path: Path) -> str:
    """Profile name in a path such as ``…/Users/<name>/…`` (``''`` when there is none)."""
    parts = list(Path(path).parts)
    lowered = [p.lower() for p in parts]
    for marker in ("users", "documents and settings"):
        if marker in lowered:
            idx = lowered.index(marker)
            if idx + 1 < len(parts) - 1:
                return parts[idx + 1]
    return ""


class ReadOnlySqlite:
    """Temporary copy of an SQLite database (plus WAL/journal) opened read-only.

    SQLite may write next to a database it opens (WAL checkpoints, -shm files),
    so evidence databases are never opened in place.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.tmp = Path(tempfile.mkdtemp(prefix="forense_sqlite_"))

    def __enter__(self) -> sqlite3.Connection:
        copy = self.tmp / "db.sqlite"
        shutil.copyfile(self.path, copy)
        for suffix in ("-wal", "-journal"):
            journal = self.path.with_name(self.path.name + suffix)
            if journal.exists():
                shutil.copyfile(journal, self.tmp / f"db.sqlite{suffix}")
        self.conn = sqlite3.connect(f"{copy.resolve().as_uri()}?mode=ro", uri=True)
        self.conn.row_factory = sqlite3.Row
        return self.conn

    def __exit__(self, *exc: object) -> None:
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


def is_sqlite(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False
