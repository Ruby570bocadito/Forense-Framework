"""Web browser history and downloads: Chrome, Edge, Brave, Opera (Chromium) and Firefox.

Databases are copied (with their ``-wal`` journal) to a temporary folder and
opened read-only, so SQLite never writes next to the evidence.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path, PureWindowsPath
from typing import Iterator
from urllib.parse import unquote, urlparse

from forense.core.heuristics import EXECUTABLE_EXTENSIONS
from forense.core.utils import (
    ReadOnlySqlite,
    dt_or_none_iso,
    find_files,
    relative_name,
    unix_us_to_dt,
    user_from_path,
    webkit_to_dt,
)
from forense.modules.base import AnalysisContext, Module, register

CHROMIUM_TRANSITIONS = {
    0: "link", 1: "typed", 2: "auto_bookmark", 3: "auto_subframe", 4: "manual_subframe", 5: "generated",
    6: "auto_toplevel", 7: "form_submit", 8: "reload", 9: "keyword", 10: "keyword_generated",
}
FIREFOX_VISIT_TYPES = {
    1: "link", 2: "typed", 3: "bookmark", 4: "embed", 5: "redirect_permanent", 6: "redirect_temporary",
    7: "download", 8: "framed_link", 9: "reload",
}
SUSPICIOUS_DOMAINS = (
    "pastebin.com", "paste.ee", "ghostbin", "hastebin", "transfer.sh", "anonfiles", "file.io", "mega.nz",
    "ngrok.io", "ngrok-free.app", "temp.sh", "gofile.io", "sendspace.com", "wetransfer.com", "ufile.io",
    "raw.githubusercontent.com", "discord.gg", "cdn.discordapp.com", "trycloudflare.com",
)


def _browser_name(path: Path) -> str:
    text = str(path).lower().replace("/", "\\")
    for marker, name in (("\\microsoft\\edge", "Edge"), ("\\google\\chrome", "Chrome"),
                         ("\\bravesoftware", "Brave"), ("\\opera", "Opera"), ("\\vivaldi", "Vivaldi"),
                         ("\\mozilla\\firefox", "Firefox"), ("\\chromium", "Chromium")):
        if marker in text:
            return name
    return "Firefox" if path.name.lower() == "places.sqlite" else "Chromium"


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _suspicious_domain(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    for domain in SUSPICIOUS_DOMAINS:
        if host == domain or host.endswith("." + domain) or domain in host:
            return host
    return ""


@register
class BrowsersModule(Module):
    name = "browsers"
    category = "windows"
    triage = True

    def discover(self, target: Path) -> list[Path]:
        def candidate(p: Path) -> bool:
            if p.name not in ("History", "places.sqlite"):
                return False
            try:
                with open(p, "rb") as fh:
                    return fh.read(16) == b"SQLite format 3\x00"
            except OSError:
                return False

        return find_files(target, candidate)

    def analyze(self, ctx: AnalysisContext) -> None:
        stats: dict[str, dict[str, int]] = {}
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            browser, user = _browser_name(path), user_from_path(path)
            ctx.progress(rel)
            try:
                with ReadOnlySqlite(path) as conn:
                    tables = _tables(conn)
                    if {"urls", "visits"} <= tables:
                        visits = self._emit_visits(ctx, rel, browser, user, self._chromium_visits(conn))
                        downloads = self._emit_downloads(ctx, rel, browser, user, self._chromium_downloads(conn))
                    elif {"moz_places", "moz_historyvisits"} <= tables:
                        visits = self._emit_visits(ctx, rel, browser, user, self._firefox_visits(conn))
                        downloads = self._emit_downloads(ctx, rel, browser, user, self._firefox_downloads(conn))
                    else:
                        continue
            except (OSError, sqlite3.DatabaseError) as exc:
                ctx.error(rel, exc)
                continue
            stats[f"{browser} ({user or rel})"] = {"visits": visits, "downloads": downloads}
        ctx.summary["profiles"] = stats

    # -- Chromium -----------------------------------------------------------
    @staticmethod
    def _chromium_visits(conn: sqlite3.Connection) -> Iterator[dict]:
        rows = conn.execute(
            "SELECT urls.url AS url, urls.title AS title, visits.visit_time AS t, visits.transition AS tr, "
            "urls.visit_count AS count, urls.typed_count AS typed FROM visits JOIN urls ON visits.url = urls.id "
            "ORDER BY visits.visit_time")
        for row in rows:
            yield {"url": row["url"], "title": row["title"] or "", "time": webkit_to_dt(row["t"]),
                   "transition": CHROMIUM_TRANSITIONS.get((row["tr"] or 0) & 0xFF, "other"),
                   "visit_count": row["count"], "typed_count": row["typed"]}

    @staticmethod
    def _chromium_downloads(conn: sqlite3.Connection) -> Iterator[dict]:
        if "downloads" not in _tables(conn):
            return
        cols = _columns(conn, "downloads")
        chains: dict[int, str] = {}
        if "downloads_url_chains" in _tables(conn):
            for row in conn.execute("SELECT id, chain_index, url FROM downloads_url_chains ORDER BY id, chain_index"):
                chains[row["id"]] = row["url"]
        pick = [c for c in ("id", "target_path", "current_path", "start_time", "end_time", "received_bytes",
                            "total_bytes", "danger_type", "tab_url", "referrer", "mime_type", "url") if c in cols]
        for row in conn.execute(f"SELECT {', '.join(pick)} FROM downloads ORDER BY start_time"):
            data = dict(row)
            yield {"url": chains.get(data.get("id")) or data.get("url") or data.get("tab_url") or "",
                   "path": data.get("target_path") or data.get("current_path") or "",
                   "start": webkit_to_dt(data.get("start_time") or 0), "end": webkit_to_dt(data.get("end_time") or 0),
                   "size": data.get("total_bytes") or data.get("received_bytes"),
                   "danger_type": data.get("danger_type"), "referrer": data.get("referrer") or "",
                   "mime_type": data.get("mime_type") or ""}

    # -- Firefox ------------------------------------------------------------
    @staticmethod
    def _firefox_visits(conn: sqlite3.Connection) -> Iterator[dict]:
        rows = conn.execute(
            "SELECT p.url AS url, p.title AS title, v.visit_date AS t, v.visit_type AS vt, p.visit_count AS count, "
            "p.typed AS typed FROM moz_historyvisits v JOIN moz_places p ON v.place_id = p.id ORDER BY v.visit_date")
        for row in rows:
            yield {"url": row["url"], "title": row["title"] or "", "time": unix_us_to_dt(row["t"]),
                   "transition": FIREFOX_VISIT_TYPES.get(row["vt"], "other"), "visit_count": row["count"],
                   "typed_count": row["typed"]}

    @staticmethod
    def _firefox_downloads(conn: sqlite3.Connection) -> Iterator[dict]:
        if not {"moz_annos", "moz_anno_attributes"} <= _tables(conn):
            return
        rows = conn.execute(
            "SELECT p.url AS url, a.content AS content, a.dateAdded AS added FROM moz_annos a "
            "JOIN moz_anno_attributes n ON a.anno_attribute_id = n.id JOIN moz_places p ON a.place_id = p.id "
            "WHERE n.name = 'downloads/destinationFileURI' ORDER BY a.dateAdded")
        for row in rows:
            dest = row["content"] or ""
            if dest.startswith("file:///"):
                dest = unquote(dest[8:]).replace("/", "\\")
            yield {"url": row["url"], "path": dest, "start": unix_us_to_dt(row["added"]), "end": None,
                   "size": None, "danger_type": None, "referrer": "", "mime_type": ""}

    # -- output -------------------------------------------------------------
    @staticmethod
    def _emit_visits(ctx: AnalysisContext, rel: str, browser: str, user: str, visits: Iterator[dict]) -> int:
        count = 0
        flagged: set[str] = set()
        for visit in visits:
            count += 1
            ctx.record("web_visit", {
                "file": rel, "browser": browser, "user": user, "visited": dt_or_none_iso(visit["time"]),
                "url": visit["url"], "title": visit["title"], "transition": visit["transition"],
                "visit_count": visit["visit_count"], "typed_count": visit["typed_count"],
            })
            ctx.event(visit["time"], "web_visit", f"{browser} {user}: {visit['url']}", rel)
            host = _suspicious_domain(visit["url"])
            if host and host not in flagged:
                flagged.add(host)
                ctx.finding("browser.suspicious_domain", "low", visit["time"], domain=host, url=visit["url"],
                            browser=browser, user=user or "-")
        return count

    @staticmethod
    def _emit_downloads(ctx: AnalysisContext, rel: str, browser: str, user: str, downloads: Iterator[dict]) -> int:
        count = 0
        for item in downloads:
            count += 1
            ctx.record("web_download", {
                "file": rel, "browser": browser, "user": user, "started": dt_or_none_iso(item["start"]),
                "finished": dt_or_none_iso(item["end"]), "url": item["url"], "saved_to": item["path"],
                "size": item["size"], "mime_type": item["mime_type"], "referrer": item["referrer"],
                "danger_type": item["danger_type"],
            })
            ctx.event(item["start"], "web_download", f"{browser} {user}: {item['url']} -> {item['path']}", rel,
                      "low")
            ext = PureWindowsPath(item["path"]).suffix.lower().lstrip(".")
            if ext in EXECUTABLE_EXTENSIONS:
                ctx.finding("browser.executable_download", "medium", item["start"], path=item["path"],
                            url=item["url"], browser=browser, user=user or "-")
            elif item["danger_type"] not in (None, 0):
                ctx.finding("browser.dangerous_download", "medium", item["start"], path=item["path"],
                            url=item["url"], browser=browser, user=user or "-")
        return count
