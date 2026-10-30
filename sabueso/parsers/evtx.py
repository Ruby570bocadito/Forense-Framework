"""Windows XML Event Log (.evtx) reading and normalisation.

Binary parsing is delegated to the ``evtx`` package (a fast, well-tested Rust
implementation). This module turns its JSON output into flat
:class:`WinEvent` objects with the EventData / UserData fields as a dict.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional, Union


@dataclass
class WinEvent:
    timestamp: str
    event_id: int
    provider: str
    channel: str
    computer: str
    record_id: int
    level: Optional[int]
    user_sid: str
    data: dict = field(default_factory=dict)

    def get(self, name: str, default: str = "") -> str:
        value = self.data.get(name)
        if value is None or value == "-":
            return default
        return str(value)


def _attr(node: Any, name: str) -> Any:
    if isinstance(node, dict):
        return (node.get("#attributes") or {}).get(name)
    return None


def _text(node: Any) -> Any:
    if isinstance(node, dict):
        return node.get("#text")
    return node


def _flatten(node: Any) -> dict:
    """Flatten EventData / UserData into ``{name: value}``."""
    if not isinstance(node, dict):
        return {} if node is None else {"Data": node}
    result: dict = {}
    for key, value in node.items():
        if key == "#attributes":
            continue
        if key == "Data":  # unnamed <Data> elements
            values = _text(value)
            if isinstance(values, list):
                for i, item in enumerate(values, 1):
                    result[f"param{i}"] = item
            elif values is not None:
                result["param1"] = values
        elif isinstance(value, dict) and not any(k.startswith("#") for k in value if k != "#attributes"):
            # UserData wraps the fields in one provider-specific element.
            nested = _flatten(value)
            result.update(nested if nested else {key: None})
        else:
            result[key] = _text(value)
    return result


def normalize(event: dict) -> WinEvent:
    root = event.get("Event", event)
    system = root.get("System") or {}
    event_id = _text(system.get("EventID"))
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        event_id = -1
    level = system.get("Level")
    data = _flatten(root.get("EventData")) if root.get("EventData") is not None else {}
    if root.get("UserData") is not None:
        data.update(_flatten(root.get("UserData")))
    return WinEvent(
        timestamp=str(_attr(system.get("TimeCreated"), "SystemTime") or ""),
        event_id=event_id,
        provider=str(_attr(system.get("Provider"), "Name") or ""),
        channel=str(system.get("Channel") or ""),
        computer=str(system.get("Computer") or ""),
        record_id=int(system.get("EventRecordID") or 0),
        level=level if isinstance(level, int) else None,
        user_sid=str(_attr(system.get("Security"), "UserID") or ""),
        data=data,
    )


def iter_events(source: Union[str, Path], errors: Optional[list] = None,
                max_consecutive_errors: int = 1000) -> Iterator[WinEvent]:
    """Yield normalised events. Corrupt records are skipped and noted in ``errors``."""
    from evtx import PyEvtxParser

    parser = PyEvtxParser(str(source))
    iterator = parser.records_json()
    consecutive = 0
    while True:
        try:
            record = next(iterator)
        except StopIteration:
            return
        except Exception as exc:  # the Rust parser raises RuntimeError on corrupt records
            consecutive += 1
            if errors is not None:
                errors.append(str(exc))
            if consecutive >= max_consecutive_errors:
                return
            continue
        consecutive = 0
        try:
            yield normalize(json.loads(record["data"]))
        except (ValueError, KeyError, TypeError) as exc:
            if errors is not None:
                errors.append(str(exc))
