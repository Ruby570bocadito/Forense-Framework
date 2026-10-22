"""Standalone printable HTML export of the case timeline.

Same delivery path as the CSV/JSON exports (file inside the case, chain-of-custody
entry with the SHA-256 of the document), but the document itself is print-oriented:
no JavaScript, no external resources, inline styles only, table header repeated on
every printed page. Event text comes from the evidence, so everything is rendered
through Jinja autoescape.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from forense.core.case import Case
from forense.core.hashing import hash_file
from forense.core.utils import utc_now
from forense.i18n import get_language, normalize
from forense.report import template_environment


def _row(event: dict) -> dict:
    """Display-ready row; values stay raw — the template escapes them."""
    return {"id": event["id"], "timestamp": event["timestamp"], "evidence_id": event["evidence_id"],
            "source": event["source"], "type": event["type"], "details": event["details"],
            "path": event["path"], "severity": event["severity"],
            "note": (event["bookmark"] or {}).get("note", "")}


def export_timeline_html(case: Case, path: Path, lang: Optional[str] = None, actor: Optional[str] = None,
                         **filters: object) -> Path:
    """Write the timeline (all events matching ``filters``) as a self-contained HTML file."""
    lang = normalize(lang) or get_language()
    rows = [_row(e) for e in case.iter_events(**filters)]
    recorded = {k: str(v) for k, v in filters.items() if v}
    analyst = case.actor(actor)
    html = template_environment(lang).get_template("timeline_export.html").render(
        case=case.info, rows=rows, filters=recorded, generated=utc_now(), analyst=analyst)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    digest = hash_file(path, ("sha256",))["sha256"]
    case.custody.append("export_created", analyst, {
        "kind": "timeline", "file": str(path), "rows": len(rows), "sha256": digest, "format": "html",
        "filters": recorded,
    })
    return path
