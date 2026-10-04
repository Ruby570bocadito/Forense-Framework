"""WMI persistence in the CIM repository (Windows\\System32\\wbem\\Repository\\OBJECTS.DATA).

A permanent WMI event subscription links an ``__EventFilter`` (a WQL query,
e.g. "60 seconds after boot") to a consumer that runs a command line or a
script. The repository keeps the binding as the text
``<Class>EventConsumer.Name="X"`` next to ``__EventFilter.Name="Y"``; the
consumer and filter definitions are located near their names. This is a
carving approach (like PyWMIPersistenceFinder): it also finds deleted
subscriptions still present in free pages.
"""

from __future__ import annotations

import mmap
import re
from pathlib import Path

from forense.core.heuristics import autostart_suspicion
from forense.core.utils import find_files, relative_name
from forense.modules.base import AnalysisContext, Module, register

_BINDING = re.compile(rb'(\w*EventConsumer)\.Name="([^"\x00]{1,256})"\x00{0,16}__EventFilter\.Name="([^"\x00]{1,256})"')
_STRINGS = re.compile(rb"[\x20-\x7e\t\r\n]{4,}")
_QUERY = re.compile(r"^\s*select\s.+\sfrom\s", re.IGNORECASE)
_COMMAND = re.compile(r"\.(exe|dll|ps1|bat|cmd|vbs|js|hta)\b|powershell|cmd\s*/c|wscript|cscript|mshta|rundll32"
                      r"|regsvr32|https?://|createobject|wscript\.shell|\.run\(", re.IGNORECASE)
# Subscriptions present on clean Windows installations.
DEFAULT_BINDINGS = {("NTEventLogEventConsumer", "scm event log consumer", "scm event log filter"),
                    ("CommandLineEventConsumer", "bvtconsumer", "bvtfilter")}
WINDOW = 4096


def _strings(data, start: int, end: int) -> list[str]:
    return [m.group().decode("ascii").strip() for m in _STRINGS.finditer(data, max(0, start), min(len(data), end))]


def scan_repository(data) -> list[dict]:
    """Bindings found in an OBJECTS.DATA buffer, with the consumer action and filter query near them."""
    found: dict[tuple, dict] = {}
    for match in _BINDING.finditer(data):
        consumer_type = match.group(1).decode("ascii", "replace")
        consumer = match.group(2).decode("utf-8", "replace")
        event_filter = match.group(3).decode("utf-8", "replace")
        key = (consumer_type, consumer, event_filter)
        if key in found:
            continue
        found[key] = {"consumer_type": consumer_type, "consumer": consumer, "filter": event_filter,
                      "offset": match.start(), "action": _consumer_action(data, consumer, consumer_type),
                      "query": _filter_query(data, event_filter)}
    return list(found.values())


def _occurrences(data, name: str, skip_binding: bool = True) -> list[int]:
    needle = name.encode("utf-8")
    positions, pos = [], data.find(needle)
    while pos != -1 and len(positions) < 50:
        before = bytes(data[max(0, pos - 7):pos])
        if not (skip_binding and before.endswith(b'.Name="')):
            positions.append(pos)
        pos = data.find(needle, pos + 1)
    return positions


def _consumer_action(data, name: str, consumer_type: str) -> str:
    for pos in _occurrences(data, name):
        candidates = [s for s in _strings(data, pos, pos + WINDOW) if s != name and _COMMAND.search(s)]
        if candidates:
            return " | ".join(dict.fromkeys(candidates[:3]))[:1000]
        if "ActiveScript" in consumer_type:
            scripts = [s for s in _strings(data, pos, pos + WINDOW) if len(s) > 20 and s != name]
            if scripts:
                return scripts[0][:1000]
    return ""


def _filter_query(data, name: str) -> str:
    for pos in _occurrences(data, name):
        for text in _strings(data, pos - 256, pos + WINDOW):
            if _QUERY.match(text):
                return text[:500]
    return ""


def is_default(binding: dict) -> bool:
    return (binding["consumer_type"], binding["consumer"].lower(), binding["filter"].lower()) in DEFAULT_BINDINGS


@register
class WmiModule(Module):
    name = "wmi"
    category = "windows"
    triage = True

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: p.name.upper() == "OBJECTS.DATA")

    def analyze(self, ctx: AnalysisContext) -> None:
        total = suspicious = 0
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            try:
                with open(path, "rb") as fh:
                    if path.stat().st_size == 0:
                        continue
                    with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as data:
                        bindings = scan_repository(data)
            except (OSError, ValueError) as exc:
                ctx.error(rel, exc)
                continue
            for binding in bindings:
                total += 1
                default = is_default(binding)
                ctx.record("wmi_subscription", {"file": rel, **binding, "default": default})
                if default:
                    continue
                suspicious += 1
                reasons = autostart_suspicion(binding["action"])
                active = any(k in binding["consumer_type"] for k in ("CommandLine", "ActiveScript"))
                ctx.finding("wmi.persistence", "high" if active or reasons else "medium", None,
                            consumer=f"{binding['consumer_type']} \"{binding['consumer']}\"",
                            filter=binding["filter"], action=binding["action"] or "-", query=binding["query"] or "-")
        ctx.summary.update({"subscriptions": total, "non_default": suspicious})
