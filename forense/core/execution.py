"""Program execution overview: one row per program, correlating every artifact of execution.

Prefetch, Amcache, ShimCache, BAM, UserAssist, SRUM, the Windows Timeline,
process creation events (Security 4688, Sysmon 1), RunMRU and memory are
each partial and use their own path notation (``\\VOLUME{…}\\PROGRAM FILES``,
``\\Device\\HarddiskVolume3\\…``, ``%ProgramFiles%``, known-folder GUIDs…).
Paths are normalised so the same executable seen by several sources becomes a
single row with its first and last known execution, run count, users, hashes
and the sources that support it — the classic "evidence of execution" table.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from forense.core.heuristics import is_suspicious_location, lookalike_of, strip_device, tool_category

# artifact -> source label
SOURCES = {
    "prefetch": "prefetch", "amcache_file": "amcache", "shimcache": "shimcache", "bam": "bam",
    "userassist": "userassist", "srum_app_usage": "srum", "timeline_activity": "timeline",
    "memory_process": "memory", "event": "evtx", "run_mru": "runmru",
}
_FOLDERS = {
    "%programfiles%": "\\program files", "%programfiles(x86)%": "\\program files (x86)",
    "%systemroot%": "\\windows", "%windir%": "\\windows", "%system32%": "\\windows\\system32",
    "%programdata%": "\\programdata",
    "{6d809377-6af0-444b-8957-a3773f02200e}": "\\program files",
    "{7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e}": "\\program files (x86)",
    "{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}": "\\windows\\system32",
    "{d65231b0-b2f1-4857-a4ce-a8e7c6ea7d27}": "\\windows\\syswow64",
    "{f38bf404-1d43-42f2-9305-67de0b28fc23}": "\\windows",
    "{62ab5d82-fdc1-4dc3-a9dd-070d1d495d97}": "\\programdata",
    "\\systemroot": "\\windows",
}
_DRIVE = re.compile(r"^[a-z]:")
_EXECUTABLE = re.compile(r'^\s*"?([^"]+?\.(?:exe|com|bat|cmd|ps1|vbs|js|hta|scr|msi|dll|cpl))\b', re.IGNORECASE)


def normalize_path(path: str) -> str:
    r"""Comparable form of an executable path: ``\program files\7-zip\7zg.exe`` (no drive, lowercase)."""
    text = strip_device((path or "").strip().strip('"').replace("/", "\\")).lower()
    for prefix, folder in _FOLDERS.items():
        if text.startswith(prefix):
            text = folder + text[len(prefix):]
            break
    text = _DRIVE.sub("", text)
    if "\\" in text and not text.startswith("\\"):
        text = "\\" + text
    return text


def executable_of(command: str) -> str:
    """Executable at the start of a command line (``"C:\\x.exe" -a`` -> ``C:\\x.exe``)."""
    command = re.sub(r"\\1$", "", (command or "").strip())  # RunMRU entries end with "\1"
    match = _EXECUTABLE.match(command)
    if match:
        return match.group(1)
    token = command.split(" ", 1)[0].strip('"')
    return token if "." in token.rsplit("\\", 1)[-1] or not token else token + ".exe"


@dataclass
class Program:
    name: str
    path: str = ""
    sources: dict = field(default_factory=dict)  # source -> number of records
    first: Optional[str] = None
    last: Optional[str] = None
    run_count: Optional[int] = None
    users: set = field(default_factory=set)
    sha1: set = field(default_factory=set)
    evidence: set = field(default_factory=set)
    command_lines: list = field(default_factory=list)

    def seen(self, when: Optional[str]) -> None:
        if when:
            self.first = min(self.first or when, when)
            self.last = max(self.last or when, when)

    @property
    def flags(self) -> list[str]:
        flags = []
        category = tool_category(self.name)
        if category:
            flags.append(category)
        if lookalike_of(self.name):
            flags.append("lookalike")
        if self.path and is_suspicious_location(self.path):
            flags.append("suspicious_location")
        return flags

    def as_dict(self) -> dict:
        return {"program": self.name, "path": self.path, "sources": ", ".join(sorted(self.sources)),
                "first": self.first, "last": self.last, "run_count": self.run_count,
                "users": ", ".join(sorted(self.users)), "sha1": ", ".join(sorted(self.sha1)),
                "flags": ", ".join(self.flags), "evidence": ", ".join(sorted(self.evidence)),
                "command_lines": " | ".join(self.command_lines[:3])}


def _observations(artifact: str, data: dict) -> Iterable[dict]:
    """Normalised observations (path, time, count, user, sha1, command) of one record."""
    if artifact == "prefetch":
        runs = [data.get("last_run"), *(data.get("previous_runs") or [])]
        path = data.get("path") or data.get("executable", "")
        yield {"path": path, "times": runs, "count": data.get("run_count")}
    elif artifact == "amcache_file":
        yield {"path": data.get("path", ""), "times": [data.get("key_last_written")], "sha1": data.get("sha1")}
    elif artifact == "shimcache":
        # ShimCache times are file modification times, not executions: the entry only proves presence.
        yield {"path": data.get("path", ""), "times": []}
    elif artifact == "bam":
        yield {"path": data.get("path", ""), "times": [data.get("last_execution")], "user": data.get("sid")}
    elif artifact == "userassist":
        program = data.get("program", "")
        if not program.lower().endswith(".lnk"):
            yield {"path": program, "times": [data.get("last_run")], "count": data.get("run_count"),
                   "user": data.get("user")}
    elif artifact == "srum_app_usage":
        yield {"path": data.get("application", ""), "times": [data.get("timestamp")], "user": data.get("user")}
    elif artifact == "timeline_activity":
        if data.get("type") in ("open", "in_focus") and "\\" in str(data.get("application", "")):
            yield {"path": data["application"], "times": [data.get("start")], "user": data.get("user")}
    elif artifact == "memory_process":
        yield {"path": data.get("path") or data.get("name", ""), "times": [data.get("created")],
               "command": data.get("cmdline")}
    elif artifact == "event":
        values = data.get("data") or {}
        if data.get("event_id") == 4688 and values.get("NewProcessName"):
            yield {"path": values["NewProcessName"], "times": [data.get("timestamp")],
                   "user": values.get("SubjectUserName"), "command": values.get("CommandLine")}
        elif data.get("event_id") == 1 and "sysmon" in str(data.get("channel", "")).lower() and values.get("Image"):
            yield {"path": values["Image"], "times": [data.get("timestamp")], "user": values.get("User"),
                   "command": values.get("CommandLine")}
    elif artifact == "run_mru":
        command = data.get("command", "")
        yield {"path": executable_of(command), "times": [], "user": data.get("user"),
               "command": command}


def _display_score(path: str) -> tuple[bool, bool, int]:
    """Prefer full paths with a drive letter and in their original case for display."""
    if not path:
        return False, False, -1
    return bool(_DRIVE.match(path.lower())), not path.islower(), len(path)


def build_overview(rows: Iterable[tuple[str, str, str]]) -> list[Program]:
    """Programs from ``(artifact, record JSON, evidence id)`` rows."""
    programs: dict[str, Program] = {}
    for artifact, raw, evidence_id in rows:
        source = SOURCES.get(artifact)
        if source is None:
            continue
        data = json.loads(raw) if isinstance(raw, str) else raw
        for obs in _observations(artifact, data):
            path = str(obs.get("path") or "").strip()
            if not path:
                continue
            normal = normalize_path(path)
            name = normal.rsplit("\\", 1)[-1]
            if not name or "." not in name:
                continue
            key = normal if "\\" in normal else name
            program = programs.setdefault(key, Program(name=path.replace("/", "\\").rsplit("\\", 1)[-1]))
            if "\\" in normal:
                display = path.replace("/", "\\") if _DRIVE.match(path.lower()) else normal
                if _display_score(display) > _display_score(program.path):
                    program.path, program.name = display, display.rsplit("\\", 1)[-1]
            program.sources[source] = program.sources.get(source, 0) + 1
            for when in obs.get("times") or []:
                program.seen(when)
            if obs.get("count"):
                program.run_count = max(program.run_count or 0, int(obs["count"]))
            if obs.get("user"):
                program.users.add(str(obs["user"]))
            if obs.get("sha1"):
                program.sha1.add(str(obs["sha1"]))
            if obs.get("command") and obs["command"] not in program.command_lines:
                program.command_lines.append(str(obs["command"])[:500])
            program.evidence.add(evidence_id)
    return _merge_names(programs)


def _merge_names(programs: dict[str, Program]) -> list[Program]:
    """Fold name-only rows (memory, RunMRU) into the single row with a path and the same file name."""
    by_name: dict[str, list[str]] = {}
    for key in programs:
        if "\\" in key:
            by_name.setdefault(key.rsplit("\\", 1)[-1], []).append(key)
    for key in [k for k in programs if "\\" not in k]:
        targets = by_name.get(key, [])
        if len(targets) != 1:
            continue
        source, target = programs.pop(key), programs[targets[0]]
        for name, count in source.sources.items():
            target.sources[name] = target.sources.get(name, 0) + count
        target.seen(source.first)
        target.seen(source.last)
        target.users |= source.users
        target.sha1 |= source.sha1
        target.evidence |= source.evidence
        target.command_lines += [c for c in source.command_lines if c not in target.command_lines]
        if source.run_count:
            target.run_count = max(target.run_count or 0, source.run_count)
    return sorted(programs.values(), key=lambda p: (not p.flags, -(len(p.sources)), p.name.lower()))


def execution_overview(case, search: str = "", suspicious: bool = False) -> list[Program]:
    """Program execution overview of a case (all analyses)."""
    placeholders = ",".join("?" * len(SOURCES))
    rows = case.conn.execute(
        f"SELECT r.artifact, r.data, a.evidence_id FROM records r JOIN analyses a ON a.id = r.analysis_id "
        f"WHERE r.artifact IN ({placeholders})", tuple(SOURCES))
    programs = build_overview((r[0], r[1], r[2]) for r in rows)
    if search:
        needle = search.lower()
        programs = [p for p in programs if needle in p.name.lower() or needle in p.path.lower()]
    if suspicious:
        programs = [p for p in programs if p.flags]
    return programs
