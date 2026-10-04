"""Utilidades comunes: fechas en UTC, recorrido de archivos y formatos."""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional

ErrorHandler = Callable[[Path, BaseException], None]


def utc_now() -> str:
    """Fecha y hora actual en UTC, en formato ISO 8601."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ts_to_iso(ts: float) -> str:
    """Convierte una marca de tiempo POSIX a ISO 8601 en UTC."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def parse_datetime(value: str) -> datetime:
    """Interpreta ``AAAA-MM-DD`` o una fecha ISO 8601. Sin zona horaria se asume UTC."""
    value = value.strip()
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def iter_files(target: Path, on_error: Optional[ErrorHandler] = None) -> Iterator[Path]:
    """Recorre los archivos regulares de ``target`` en orden estable.

    Si ``target`` es un archivo se devuelve solo él. Los enlaces simbólicos no
    se siguen, para no salir nunca del ámbito de la evidencia.
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


def relative_name(path: Path, target: Path) -> str:
    """Ruta de ``path`` relativa a la evidencia ``target`` (con ``/`` como separador)."""
    path, target = Path(path), Path(target)
    if path == target:
        return path.name
    return path.relative_to(target).as_posix()


def human_size(num: float) -> str:
    """Tamaño legible por humanos (1536 -> '1.5 KiB')."""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num) < 1024 or unit == "TiB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TiB"


def write_json(path: Path, data: object) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")


def read_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write_csv(path: Path, records: Iterable[dict]) -> None:
    """Escribe registros (diccionarios) en CSV compatible con Excel (UTF-8 con BOM)."""
    records = list(records)
    columns: list[str] = []
    for record in records:
        for key in record:
            if key not in columns:
                columns.append(key)
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        for record in records:
            writer.writerow({
                key: json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value
                for key, value in record.items()
            })
