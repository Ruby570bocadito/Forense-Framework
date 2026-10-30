"""Standalone printable HTML export of the case findings.

Same delivery path as the timeline export (file inside the case, chain-of-custody
entry with the SHA-256 of the document), but print-oriented: no JavaScript, no
external resources, inline styles only, table header repeated on every printed
page. Finding text comes from the case, so everything is rendered through Jinja
autoescape.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from sabueso.core.attack import techniques_for
from sabueso.core.case import Case
from sabueso.core.hashing import hash_file
from sabueso.core.utils import utc_now
from sabueso.i18n import get_language, normalize
from sabueso.report import template_environment


def export_findings_html(case: Case, path: Path, lang: Optional[str] = None, actor: Optional[str] = None,
                         **filters: object) -> Path:
    """Write the findings (all matching ``filters``) as a self-contained HTML file.

    ``filters`` uses the names of the findings page: ``severity`` (minimum), ``status``
    (review status) and ``technique`` (ATT&CK id). Every accepted filter is recorded in
    the custody entry, like the timeline export does.
    """
    lang = normalize(lang) or get_language()
    items = case.findings(min_severity=filters.get("severity"), review_status=filters.get("status"))
    technique = filters.get("technique")
    if technique:
        items = [f for f in items if technique in techniques_for(f)]
    for f in items:  # print view has no pagination: every row carries its ATT&CK techniques
        f["techniques"] = techniques_for(f)
    rows = items
    recorded = {k: str(v) for k, v in filters.items() if v}
    analyst = case.actor(actor)
    html = template_environment(lang).get_template("findings_export.html").render(
        case=case.info, rows=rows, filters=recorded, generated=utc_now(), analyst=analyst)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    digest = hash_file(path, ("sha256",))["sha256"]
    case.custody.append("export_created", analyst, {
        "kind": "findings", "file": str(path), "rows": len(rows), "sha256": digest, "format": "html",
        "filters": recorded,
    })
    return path
