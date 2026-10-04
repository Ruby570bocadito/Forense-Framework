"""Exports of case data (CSV / JSON). Every export is hashed and logged in the chain of custody."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from forense.core.case import Case
from forense.core.hashing import hash_file
from forense.core.utils import write_csv
from forense.i18n import label
from forense.presentation import (
    artifact_label,
    custody_action_label,
    event_type_label,
    finding_description,
    finding_title,
    severity_label,
)

FORMATS = ("csv", "json")


def _write(path: Path, rows: list[dict], fmt: str, lang: Optional[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, ensure_ascii=False, indent=1)
    else:
        columns: Iterable[str] = {key for row in rows for key in row}
        write_csv(path, rows, headers={c: label(c, lang) for c in columns})


def _log(case: Case, path: Path, kind: str, rows: int, actor: Optional[str], **details: object) -> Path:
    digest = hash_file(path, ("sha256",))["sha256"]
    case.custody.append("export_created", case.actor(actor), {
        "kind": kind, "file": str(path), "rows": rows, "sha256": digest, **details,
    })
    return path


def export_analysis(case: Case, analysis_id: int, path: Path, fmt: str = "csv", lang: Optional[str] = None,
                    actor: Optional[str] = None, artifact: Optional[str] = None) -> Path:
    analysis = case.get_analysis(analysis_id)
    page = case.records(analysis.id, artifact=artifact, limit=None)
    rows = [{"artifact": artifact_label(kind, lang), **data} for kind, data in page.rows]
    _write(path, rows, fmt, lang)
    return _log(case, path, "analysis", len(rows), actor, analysis_id=analysis.id, module=analysis.module)


def export_timeline(case: Case, path: Path, fmt: str = "csv", lang: Optional[str] = None,
                    actor: Optional[str] = None, **filters: object) -> Path:
    rows = [{
        "timestamp": e["timestamp"], "evidence": e["evidence_id"], "source": e["source"],
        "type": event_type_label(e["type"], lang), "details": e["details"], "path": e["path"],
        "severity": severity_label(e["severity"], lang),
    } for e in case.iter_events(**filters)]
    _write(path, rows, fmt, lang)
    return _log(case, path, "timeline", len(rows), actor,
                filters={k: str(v) for k, v in filters.items() if v})


def export_findings(case: Case, path: Path, fmt: str = "csv", lang: Optional[str] = None,
                    actor: Optional[str] = None, min_severity: Optional[str] = None) -> Path:
    rows = [{
        "severity": severity_label(f["severity"], lang), "timestamp": f["timestamp"], "evidence": f["evidence_id"],
        "analysis": f["analysis_id"], "title": finding_title(f, lang), "description": finding_description(f, lang),
        "code": f["code"],
    } for f in case.findings(min_severity=min_severity)]
    _write(path, rows, fmt, lang)
    return _log(case, path, "findings", len(rows), actor)


def export_custody(case: Case, path: Path, fmt: str = "json", lang: Optional[str] = None,
                   actor: Optional[str] = None) -> Path:
    entries = [e.as_dict() for e in case.custody.entries()]
    if fmt == "csv":
        for entry in entries:
            entry["action"] = custody_action_label(entry["action"], lang)
    _write(path, entries, fmt, lang)
    return _log(case, path, "custody", len(entries), actor, head=case.custody.head())
