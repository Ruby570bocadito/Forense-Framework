"""System Resource Usage Monitor (SRUDB.dat) reading on top of libesedb (``pyesedb``).

SRUM keeps roughly 30-60 days of hourly per-application statistics: network
bytes sent/received per interface, network connectivity and CPU / disk usage.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Optional

from forense.core.utils import filetime_to_dt

NETWORK_USAGE = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
NETWORK_CONNECTIVITY = "{DD6636C4-8929-4683-974E-22C046A43763}"
APP_RESOURCE_USAGE = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
ID_MAP = "SruDbIdMapTable"

_OLE_EPOCH = datetime(1899, 12, 30, tzinfo=timezone.utc)
# ESE column types used by SRUM
_BIT, _UBYTE, _SHORT, _LONG, _CURRENCY, _IEEE_SINGLE, _IEEE_DOUBLE, _DATETIME = 1, 2, 3, 4, 5, 6, 7, 8
_BINARY, _TEXT, _LONG_BINARY, _LONG_TEXT, _ULONG, _LONGLONG, _GUID, _USHORT = 9, 10, 11, 12, 14, 15, 16, 17


def ole_to_dt(value: float) -> Optional[datetime]:
    if not value:
        return None
    try:
        return _OLE_EPOCH + timedelta(days=value)
    except OverflowError:
        return None


def sid_to_str(raw: bytes) -> str:
    """Binary security identifier -> ``S-1-5-21-...``."""
    if len(raw) < 8:
        return raw.hex()
    revision, count = raw[0], raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    subs = struct.unpack_from(f"<{count}I", raw, 8) if len(raw) >= 8 + 4 * count else ()
    return "S-" + "-".join(str(x) for x in (revision, authority, *subs))


def _value(record, index: int):
    data = record.get_value_data(index)
    if data is None:
        return None
    kind = record.get_column_type(index)
    if kind in (_UBYTE, _SHORT, _LONG, _ULONG, _LONGLONG, _USHORT, _CURRENCY):
        signed = kind in (_SHORT, _LONG, _LONGLONG, _CURRENCY)
        return int.from_bytes(data, "little", signed=signed)
    if kind == _BIT:
        return bool(data[0])
    if kind == _IEEE_DOUBLE or kind == _DATETIME:
        return struct.unpack("<d", data[:8])[0]
    if kind == _IEEE_SINGLE:
        return struct.unpack("<f", data[:4])[0]
    return data


@dataclass
class SrumDatabase:
    path: Path

    def __enter__(self) -> "SrumDatabase":
        import pyesedb

        self._fh = open(self.path, "rb")
        self._db = pyesedb.file()
        self._db.open_file_object(self._fh)
        self.ids = self._load_ids()
        return self

    def __exit__(self, *exc: object) -> None:
        self._db.close()
        self._fh.close()

    def _load_ids(self) -> dict[int, str]:
        table = self._db.get_table_by_name(ID_MAP)
        ids: dict[int, str] = {}
        if table is None:
            return ids
        for i in range(table.number_of_records):
            row = self._row(table.get_record(i))
            blob = row.get("IdBlob")
            index = row.get("IdIndex")
            if index is None or blob is None:
                continue
            if row.get("IdType") == 3:  # user SID
                ids[index] = sid_to_str(blob)
            else:
                try:
                    ids[index] = blob.decode("utf-16-le").rstrip("\x00")
                except UnicodeDecodeError:
                    ids[index] = blob.hex()
        return ids

    @staticmethod
    def _row(record) -> dict:
        return {record.get_column_name(i): _value(record, i) for i in range(record.number_of_values)}

    def has_table(self, name: str) -> bool:
        return self._db.get_table_by_name(name) is not None

    def rows(self, table_name: str) -> Iterator[dict]:
        """Rows with ``timestamp`` (UTC datetime), ``app`` and ``user`` resolved."""
        table = self._db.get_table_by_name(table_name)
        if table is None:
            return
        for i in range(table.number_of_records):
            try:
                row = self._row(table.get_record(i))
            except OSError:
                continue
            row["timestamp"] = ole_to_dt(row.pop("TimeStamp", None) or 0)
            row["app"] = self.ids.get(row.get("AppId"), str(row.get("AppId", "")))
            row["user"] = self.ids.get(row.get("UserId"), str(row.get("UserId", "")))
            if "ConnectStartTime" in row:
                row["ConnectStartTime"] = filetime_to_dt(row["ConnectStartTime"] or 0)
            yield row
