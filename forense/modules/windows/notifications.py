"""Windows toast notifications (wpndatabase.db): which app notified, when, and what it showed.

``Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\Notifications\\wpndatabase.db`` keeps every
toast the Action Center handled: the sending app (AUMID in NotificationHandler), arrival and
expiry FILETIMEs, and the payload with the rendered title and body. The texts are what the user
was shown, not evidence that they are true; they are stored as-is for the report.
"""

from __future__ import annotations

import html
import re
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path

from forense.core.utils import ReadOnlySqlite, filetime_to_dt, find_files, is_sqlite, iso, relative_name, user_from_path
from forense.modules.base import AnalysisContext, Module, register

_NOTIFICATION_TYPES = {1: "toast"}
_TEXT_TAG = re.compile(r"(?:\{[^}]*\})?text\s*$")
_XML_TEXT = re.compile(r"<text[^>]*>(.*?)</text>", re.IGNORECASE | re.DOTALL)


def _decode_payload(payload: object) -> str:
    """Payload blob to text: UTF-16 first (the usual shape), then UTF-8, then latin-1."""
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    if not isinstance(payload, (bytes, bytearray)):
        return str(payload)
    raw = bytes(payload)
    for encoding in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        printable = sum(ch.isprintable() or ch.isspace() for ch in text) / max(len(text), 1)
        if printable > 0.8 and "\x00" not in text:
            return text
    return raw.decode("latin-1", errors="replace")


def _texts(payload: object) -> tuple[str, str]:
    """(title, body) of a toast payload: the first two <text> elements (id 1 and 2 when present)."""
    text = _decode_payload(payload)
    if not text:
        return "", ""
    texts: list[str] = []
    try:
        root = ET.fromstring(text)
        texts = [(element.text or "") for element in root.iter() if _TEXT_TAG.match(element.tag)]
    except ET.ParseError:
        texts = [html.unescape(found) for found in _XML_TEXT.findall(text)]
    texts = [t.strip() for t in texts if t and t.strip()]
    title = texts[0] if texts else ""
    body = texts[1] if len(texts) > 1 else ""
    return title[:500], body[:2000]


@register
class NotificationsModule(Module):
    name = "notifications"
    category = "windows"
    triage = True

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: p.name.lower() == "wpndatabase.db" and is_sqlite(p))

    def analyze(self, ctx: AnalysisContext) -> None:
        per_app: dict[str, int] = {}
        total = 0
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            user = user_from_path(path) or "-"
            try:
                rows = self._rows(path)
            except (OSError, sqlite3.Error) as exc:
                ctx.error(rel, exc)
                continue
            for row in rows:
                total += 1
                app = str(row.get("app") or row.get("PrimaryId") or "-")
                per_app[app] = per_app.get(app, 0) + 1
                title, body = _texts(row.get("Payload"))
                arrival = filetime_to_dt(row.get("ArrivalTime"))
                expiry = filetime_to_dt(row.get("ExpiryTime"))
                kind = _NOTIFICATION_TYPES.get(row.get("Type"), str(row.get("Type") or ""))
                ctx.record("notification", {
                    "file": rel, "user": user, "app": app, "type": kind, "title": title, "body": body,
                    "arrival": iso(arrival) if arrival else None, "expiry": iso(expiry) if expiry else None,
                })
                ctx.event(arrival, "notification", " — ".join(filter(None, (f"{user} [{app}]", title, body))), rel)
        ctx.summary.update({"notifications": total, "per_app": per_app})

    @staticmethod
    def _rows(path: Path) -> list[dict]:
        """Notifications with their app id; older or partial schemas degrade to the bare table."""
        with ReadOnlySqlite(path) as conn:
            try:
                rows = conn.execute(
                    "SELECT n.*, h.PrimaryId AS app FROM Notification n "
                    "LEFT JOIN NotificationHandler h ON n.HandlerId = h.HandlerId ORDER BY n.ArrivalTime"
                ).fetchall()
            except sqlite3.Error:
                rows = conn.execute("SELECT * FROM Notification ORDER BY ArrivalTime").fetchall()
            return [dict(row) for row in rows]
