"""Windows Timeline (ActivitiesCache.db): applications and files used, time in focus and clipboard history.

Windows 10 (1803+) records user activity in
``Users\\<user>\\AppData\\Local\\ConnectedDevicesPlatform\\<account>\\ActivitiesCache.db``:
programs opened, documents opened with them, how long each was in focus and,
when clipboard history sync is enabled, the copied text.
"""

from __future__ import annotations

import base64
import binascii
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from forense.core.heuristics import is_suspicious_location, suspicious_command_rules, tool_category
from forense.core.utils import ReadOnlySqlite, find_files, is_sqlite, iso, relative_name, user_from_path
from forense.modules.base import AnalysisContext, Module, Option, register

ACTIVITY_TYPES = {2: "notification", 3: "backup", 5: "open", 6: "in_focus", 10: "clipboard", 11: "system",
                  12: "system", 15: "system", 16: "copy_paste"}
# Known folder GUIDs used in AppId paths.
KNOWN_FOLDERS = {
    "{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}": "C:\\Windows\\System32",
    "{d65231b0-b2f1-4857-a4ce-a8e7c6ea7d27}": "C:\\Windows\\SysWOW64",
    "{f38bf404-1d43-42f2-9305-67de0b28fc23}": "C:\\Windows",
    "{6d809377-6af0-444b-8957-a3773f02200e}": "C:\\Program Files",
    "{7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e}": "C:\\Program Files (x86)",
    "{62ab5d82-fdc1-4dc3-a9dd-070d1d495d97}": "C:\\ProgramData",
    "{374de290-123f-4565-9164-39c4925e467b}": "%USERPROFILE%\\Downloads",
    "{b4bfcc3a-db2c-424c-b029-7fe99a87c641}": "%USERPROFILE%\\Desktop",
    "{fdd39ad0-238f-46af-adb4-6c85480369c7}": "%USERPROFILE%\\Documents",
}


def _unix(value) -> Optional[datetime]:
    try:
        seconds = int(value or 0)
    except (TypeError, ValueError):
        return None
    if seconds <= 0 or seconds > 32503680000:  # year 3000
        return None
    return datetime.fromtimestamp(seconds, timezone.utc)


def _json(value) -> object:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None


def application(app_id) -> str:
    """Most useful application name from the AppId JSON list (executable path preferred)."""
    entries = _json(app_id)
    if not isinstance(entries, list):
        return str(app_id or "")
    by_platform = {str(e.get("platform", "")).lower(): str(e.get("application", "")) for e in entries
                   if isinstance(e, dict)}
    for platform in ("windows_win32", "x_exe_path", "windows_universal", "packageid", "afs_crossplatform"):
        name = by_platform.get(platform)
        if name:
            if name.startswith("{"):
                guid, _, rest = name.partition("}")
                folder = KNOWN_FOLDERS.get(guid.lower() + "}")
                if folder:
                    return f"{folder}{rest}"
            return name
    return next(iter(by_platform.values()), "")


def clipboard_text(value) -> str:
    entries = _json(value)
    texts = []
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict) and "content" in entry and "text" in str(entry.get("formatName", "")).lower():
            try:
                texts.append(base64.b64decode(entry["content"]).decode("utf-8", errors="replace"))
            except (binascii.Error, ValueError):
                continue
    return "\n".join(texts)


@register
class WindowsTimelineModule(Module):
    name = "wintimeline"
    category = "windows"
    triage = True
    options = (Option("include_system", False, "bool"),)

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: p.name.lower() == "activitiescache.db" and is_sqlite(p))

    def analyze(self, ctx: AnalysisContext) -> None:
        counts: dict[str, int] = {}
        clipboard = 0
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            user = user_from_path(path) or "-"
            try:
                with ReadOnlySqlite(path) as conn:
                    rows = conn.execute("SELECT * FROM Activity ORDER BY StartTime").fetchall()
            except (OSError, sqlite3.Error) as exc:
                ctx.error(rel, exc)
                continue
            for row in rows:
                data = dict(row)
                kind = ACTIVITY_TYPES.get(data.get("ActivityType"), str(data.get("ActivityType")))
                if kind in ("system", "notification", "backup") and not ctx.options["include_system"]:
                    continue
                counts[kind] = counts.get(kind, 0) + 1
                clipboard += kind == "clipboard"
                self._activity(ctx, rel, user, data, kind)
        ctx.summary.update({"activities": counts, "clipboard_items": clipboard})

    @staticmethod
    def _activity(ctx: AnalysisContext, rel: str, user: str, data: dict, kind: str) -> None:
        payload = _json(data.get("Payload"))
        payload = payload if isinstance(payload, dict) else {}
        app = application(data.get("AppId"))
        start, end = _unix(data.get("StartTime")), _unix(data.get("EndTime"))
        content = str(payload.get("description") or payload.get("contentUri") or payload.get("displayText") or "")
        clip = clipboard_text(data.get("ClipboardPayload")) if kind in ("clipboard", "copy_paste") else ""
        duration = payload.get("activeDurationSeconds")
        if duration is None and start and end and kind == "in_focus":
            duration = int((end - start).total_seconds())
        guid = data.get("Id")
        ctx.record("timeline_activity", {
            "file": rel, "user": user, "id": guid.hex() if isinstance(guid, bytes) else str(guid or ""),
            "type": kind, "application": app, "display_text": str(payload.get("displayText") or
                                                                 payload.get("appDisplayName") or ""),
            "content": content, "start": iso(start) if start else None, "end": iso(end) if end else None,
            "focus_seconds": duration, "clipboard": clip[:2000],
            "last_modified": iso(_unix(data.get("LastModifiedTime"))) if _unix(data.get("LastModifiedTime")) else None,
            "device_id": str(data.get("PlatformDeviceId") or ""),
        })
        details = f"{user} [{kind}] {app} {content}".strip()
        if duration:
            details += f" ({duration} s)"
        if clip:
            details += f" — {clip[:200]}"
        ctx.event(start, "timeline_activity", details, rel)
        executable = app.replace("/", "\\").rsplit("\\", 1)[-1]
        category = tool_category(executable)
        if category:
            ctx.finding(f"wintimeline.{category}", "high" if category == "attack_tool" else "medium", start,
                        application=app, user=user)
        elif "\\" in app and is_suspicious_location(app):
            ctx.finding("wintimeline.suspicious_location", "medium", start, application=app, user=user)
        if clip:
            rules = suspicious_command_rules(clip)
            if rules:
                ctx.finding("wintimeline.suspicious_clipboard", "medium", start, user=user, text=clip[:300],
                            rules=", ".join(rules))
