"""Import of threat intelligence into Forense watchlists.

``forense intel misp`` converts a MISP JSON export (one event or a set of
events) into a watchlist for the ``ioc`` module: one indicator per line, with
the provenance of every source event kept as ``#`` comments. The resulting
file plugs directly into the module option ``watchlist``, the automation
configuration key ``intel.watchlists`` and, through the
``ioc.watchlist_match`` findings, into the correlation between cases.

The import never touches the network: the analyst exports the events from
their MISP instance and feeds the file here, so no API key or instance URL
ever reaches the case. Only well-known IOC attribute types are imported;
every other type is counted and reported as skipped instead of guessed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from forense.core.errors import ForenseError

MAX_MISP_BYTES = 256 * 1024 * 1024  # a MISP export beyond this is not a watchlist job anymore


def _whole(value: str) -> list[str]:
    return [value] if value else []


def _hash(value: str) -> list[str]:
    return [value.lower()] if value else []


def _hash_part(value: str) -> list[str]:
    """``filename|md5``-style values: only the hash is a safe literal to match."""
    return [part.lower() for part in value.split("|", 1)[1:]]


def _ip_part(value: str) -> list[str]:
    return [value.split("|", 1)[0]] if value else []


def _both_parts(value: str) -> list[str]:
    return [part for part in value.split("|", 1) if part]


# MISP attribute type -> extractor of the literal values worth matching.
TYPE_MAP: dict[str, Callable[[str], list[str]]] = {
    "md5": _hash, "sha1": _hash, "sha256": _hash, "sha512": _hash,
    "ip-src": _ip_part, "ip-dst": _ip_part, "ip-src|port": _ip_part, "ip-dst|port": _ip_part,
    "domain": _whole, "hostname": _whole,
    "hostname|ip": _both_parts, "domain|ip": _both_parts,
    "url": _whole, "uri": _whole, "link": _whole,
    "email": _whole, "email-src": _whole, "email-dst": _whole,
    "filename": _whole,
    "filename|md5": _hash_part, "filename|sha1": _hash_part,
    "filename|sha256": _hash_part, "filename|sha512": _hash_part,
    "regkey": _whole, "user-agent": _whole,
}


@dataclass
class MispImport:
    """Result of importing a MISP JSON export."""

    indicators: list[str] = field(default_factory=list)  # deduplicated, original order
    notes: list[str] = field(default_factory=list)  # one provenance comment per source event
    events: int = 0
    attributes: int = 0
    used: int = 0  # attributes that produced at least one indicator
    duplicates: int = 0
    skipped: dict[str, int] = field(default_factory=dict)  # type -> count, for non-importable types


def _events_of(payload: object, source: Path) -> list[dict]:
    """The ``Event`` dictionaries of the standard MISP JSON export shapes: a single
    ``{"Event": {...}}``, a ``{"response": [{"Event": ...}, ...]}`` export or a plain
    list of those wrappers (``Event`` itself may also be a list of events)."""
    if isinstance(payload, dict) and "Event" in payload:
        raw = payload["Event"] if isinstance(payload["Event"], list) else [payload["Event"]]
        events = [event for event in raw if isinstance(event, dict)]
    elif isinstance(payload, dict) and isinstance(payload.get("response"), list):
        events = [item["Event"] for item in payload["response"]
                  if isinstance(item, dict) and isinstance(item.get("Event"), dict)]
    elif isinstance(payload, list):
        events = [item["Event"] for item in payload
                  if isinstance(item, dict) and isinstance(item.get("Event"), dict)]
    else:
        raise ForenseError("error.intel_misp_invalid", path=str(source))
    if not events:
        raise ForenseError("error.intel_misp_invalid", path=str(source))
    return events


def _event_note(event: dict) -> str:
    uuid = str(event.get("uuid") or "").strip()
    info = " ".join(str(event.get("info") or "").split())[:120]
    date = str(event.get("date") or "").strip()
    note = f"misp: {uuid or '?'}"
    if info:
        note += f" | {info}"
    if date:
        note += f" | {date}"
    return note


def _attributes_of(event: dict) -> list[dict]:
    attrs = event.get("Attribute")
    if isinstance(attrs, dict):  # defensive: some exports map attribute uuid -> attribute
        attrs = list(attrs.values())
    return [a for a in attrs if isinstance(a, dict)] if isinstance(attrs, list) else []


def _deleted(attribute: dict) -> bool:
    flag = attribute.get("deleted")
    return flag is True or str(flag or "").strip().lower() in ("1", "true")


def import_misp(source: Path) -> MispImport:
    """Read a MISP JSON export and collect its watchlist indicators.

    Raises ``error.intel_input_missing`` when the file does not exist,
    ``error.intel_misp_too_large`` beyond ``MAX_MISP_BYTES``,
    ``error.intel_misp_invalid`` for broken JSON or an unknown structure and
    ``error.intel_misp_empty`` when no attribute of an importable type remains.
    """
    source = Path(source)
    if not source.is_file():
        raise ForenseError("error.intel_input_missing", path=str(source))
    if source.stat().st_size > MAX_MISP_BYTES:
        raise ForenseError("error.intel_misp_too_large", path=str(source),
                           limit=MAX_MISP_BYTES // (1024 * 1024))
    try:
        payload = json.loads(source.read_text(encoding="utf-8", errors="replace"))
    except (ValueError, RecursionError) as exc:
        raise ForenseError("error.intel_misp_invalid", path=str(source)) from exc

    result = MispImport()
    seen: set[str] = set()
    for event in _events_of(payload, source):
        result.events += 1
        result.notes.append(_event_note(event))
        for attribute in _attributes_of(event):
            result.attributes += 1
            if _deleted(attribute):
                continue
            kind = str(attribute.get("type") or "").strip().lower()
            extract = TYPE_MAP.get(kind)
            if extract is None:
                result.skipped[kind or "?"] = result.skipped.get(kind or "?", 0) + 1
                continue
            value = str(attribute.get("value") or "").strip()
            produced = extract(value)
            if produced:
                result.used += 1
            for indicator in produced:
                key = indicator.lower()
                if key in seen:
                    result.duplicates += 1
                    continue
                seen.add(key)
                result.indicators.append(indicator)
    if not result.indicators:
        raise ForenseError("error.intel_misp_empty", path=str(source))
    return result


def write_watchlist(result: MispImport, destination: Path) -> Path:
    """Write the watchlist file: provenance comments first, indicators sorted after."""
    destination = Path(destination)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [f"# Forense watchlist generated from a MISP export ({stamp})",
             *(f"# {note}" for note in result.notes), *sorted(result.indicators)]
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return destination
