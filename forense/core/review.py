"""Analyst review: finding verdicts, bookmarked events and versioned conclusions.

Reviews are append-only: every verdict, bookmark or note is a new row and a
new chain-of-custody entry, so the history of the analyst's reasoning is kept
and the current state is simply the latest row per target.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from forense.core.errors import CaseError
from forense.core.utils import utc_now

REVIEW_SCHEMA = """
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, target_id INTEGER NOT NULL,
    status TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', actor TEXT NOT NULL, timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reviews_target ON reviews(target, target_id);
CREATE TABLE IF NOT EXISTS conclusions (
    version INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT NOT NULL, actor TEXT NOT NULL, timestamp TEXT NOT NULL,
    sha256 TEXT NOT NULL
);
"""

FINDING_STATUSES = ("confirmed", "false_positive", "needs_review")
EVENT_STATUSES = ("bookmarked", "unbookmarked")
STATUS_ALIASES = {
    "confirmado": "confirmed", "confirmar": "confirmed", "falso_positivo": "false_positive", "fp": "false_positive",
    "descartado": "false_positive", "pendiente": "needs_review", "pending": "needs_review",
}


def latest_review_sql(target: str) -> str:
    """Sub-query with the latest review row of every ``target`` (finding/event)."""
    return (f"(SELECT r.target_id, r.status, r.note, r.actor, r.timestamp FROM reviews r "
            f"JOIN (SELECT target_id, MAX(id) AS mid FROM reviews WHERE target = '{target}' GROUP BY target_id) l "
            f"ON r.id = l.mid)")


def normalize_status(status: str) -> str:
    status = status.strip().lower().replace("-", "_").replace(" ", "_")
    return STATUS_ALIASES.get(status, status)


class ReviewMixin:
    """Methods mixed into :class:`forense.core.case.Case`."""

    def _review(self, target: str, target_id: int, status: str, note: str, actor: Optional[str]) -> dict:
        from forense.core.case import transaction

        actor = self.actor(actor)
        note = (note or "").strip()
        timestamp = utc_now()
        with transaction(self.conn):
            cur = self.conn.execute(
                "INSERT INTO reviews (target, target_id, status, note, actor, timestamp) VALUES (?,?,?,?,?,?)",
                (target, target_id, status, note, actor, timestamp))
            self.custody.append("review_recorded", actor, {
                "target": target, "id": target_id, "status": status, "note": note[:200],
                "note_sha256": hashlib.sha256(note.encode("utf-8")).hexdigest() if note else None,
            })
        return {"id": cur.lastrowid, "status": status, "note": note, "actor": actor, "timestamp": timestamp}

    def review_finding(self, finding_id: int, status: str, note: str = "", actor: Optional[str] = None) -> dict:
        status = normalize_status(status)
        if status not in FINDING_STATUSES:
            raise CaseError("error.review_status", status=status, allowed=", ".join(FINDING_STATUSES))
        if self.conn.execute("SELECT 1 FROM findings WHERE id = ?", (int(finding_id),)).fetchone() is None:
            raise CaseError("error.finding_unknown", finding=finding_id)
        return self._review("finding", int(finding_id), status, note, actor)

    def bookmark_event(self, event_id: int, note: str = "", actor: Optional[str] = None,
                       remove: bool = False) -> dict:
        if self.conn.execute("SELECT 1 FROM events WHERE id = ?", (int(event_id),)).fetchone() is None:
            raise CaseError("error.event_unknown", event=event_id)
        return self._review("event", int(event_id), "unbookmarked" if remove else "bookmarked", note, actor)

    def review_history(self, target: str, target_id: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT status, note, actor, timestamp FROM reviews WHERE target = ? AND target_id = ? ORDER BY id",
            (target, int(target_id))).fetchall()
        return [dict(r) for r in rows]

    def review_progress(self) -> dict:
        """Counts of findings per review state (``pending`` = not reviewed or marked for review)."""
        rows = self.conn.execute(
            f"SELECT COALESCE(rv.status, 'needs_review') AS s, COUNT(*) FROM findings f "
            f"LEFT JOIN {latest_review_sql('finding')} rv ON rv.target_id = f.id GROUP BY s").fetchall()
        counts = {status: 0 for status in FINDING_STATUSES}
        for status, count in rows:
            counts[status] = count
        counts["total"] = sum(counts[s] for s in FINDING_STATUSES)
        counts["reviewed"] = counts["confirmed"] + counts["false_positive"]
        bookmarks = self.conn.execute(
            f"SELECT COUNT(*) FROM events e JOIN {latest_review_sql('event')} rv ON rv.target_id = e.id "
            f"WHERE rv.status = 'bookmarked'").fetchone()[0]
        counts["bookmarked_events"] = bookmarks
        return counts

    # -- conclusions ------------------------------------------------------------
    def set_conclusions(self, text: str, actor: Optional[str] = None) -> dict:
        from forense.core.case import transaction

        actor = self.actor(actor)
        text = text.strip()
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        timestamp = utc_now()
        with transaction(self.conn):
            cur = self.conn.execute("INSERT INTO conclusions (text, actor, timestamp, sha256) VALUES (?,?,?,?)",
                                    (text, actor, timestamp, digest))
            self.custody.append("conclusions_updated", actor, {"version": cur.lastrowid, "sha256": digest,
                                                               "length": len(text)})
        return {"version": cur.lastrowid, "text": text, "actor": actor, "timestamp": timestamp, "sha256": digest}

    def conclusions(self) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM conclusions ORDER BY version DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def conclusions_history(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT version, actor, timestamp, sha256, length(text) AS length FROM conclusions ORDER BY version DESC")]
