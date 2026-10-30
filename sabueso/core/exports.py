"""Exports of case data (CSV / JSON). Every export is hashed and logged in the chain of custody."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from sabueso.core.case import Case
from sabueso.core.hashing import hash_file
from sabueso.core.utils import parse_datetime, write_csv
from sabueso.i18n import label, t
from sabueso.presentation import (
    artifact_label,
    custody_action_label,
    event_type_label,
    finding_description,
    finding_title,
    rule_label,
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
        "id": e["id"], "timestamp": e["timestamp"], "evidence": e["evidence_id"], "source": e["source"],
        "type": event_type_label(e["type"], lang), "details": e["details"], "path": e["path"],
        "severity": severity_label(e["severity"], lang), "bookmarked": bool(e["bookmark"]),
        "note": e["bookmark"]["note"] if e["bookmark"] else "",
    } for e in case.iter_events(**filters)]
    _write(path, rows, fmt, lang)
    return _log(case, path, "timeline", len(rows), actor,
                filters={k: str(v) for k, v in filters.items() if v})


def export_findings(case: Case, path: Path, fmt: str = "csv", lang: Optional[str] = None,
                    actor: Optional[str] = None, min_severity: Optional[str] = None) -> Path:
    rows = [{
        "id": f["id"], "severity": severity_label(f["severity"], lang), "timestamp": f["timestamp"],
        "evidence": f["evidence_id"], "analysis": f["analysis_id"], "title": finding_title(f, lang),
        "description": finding_description(f, lang), "code": f["code"],
        "review_status": t(f"review.{f['review']['status']}", lang), "note": f["review"]["note"],
        "reviewer": f["review"]["actor"] or "",
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


def export_execution(case: Case, path: Path, fmt: str = "csv", lang: Optional[str] = None,
                     actor: Optional[str] = None, search: str = "", suspicious: bool = False) -> Path:
    from sabueso.core.execution import execution_overview

    rows = []
    for program in execution_overview(case, search, suspicious):
        row = program.as_dict()
        row["flags"] = ", ".join(rule_label(f, lang) for f in program.flags)
        rows.append(row)
    _write(path, rows, fmt, lang)
    return _log(case, path, "execution", len(rows), actor)


def _timesketch_time(timestamp: str) -> tuple[str, int]:
    """Timesketch's ``datetime`` (ISO 8601 with offset) and ``timestamp`` (microseconds since the epoch)."""
    moment = parse_datetime(timestamp)
    return moment.isoformat(), int(moment.timestamp() * 1_000_000)


def export_timesketch(case: Case, path: Path, lang: Optional[str] = None, actor: Optional[str] = None,
                      **filters: object) -> Path:
    """Timeline and findings as Timesketch JSONL (``message``, ``datetime``, ``timestamp_desc`` per line).

    Undated items are left out (Timesketch needs a time). Findings carry the ``sabueso_finding`` tag and
    their severity, bookmarked events the ``bookmark`` tag, so the analyst's work travels with the timeline.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = 0
    info = case.info
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        def write(item: dict) -> None:
            nonlocal rows
            fh.write(json.dumps(item, ensure_ascii=False) + "\n")
            rows += 1

        for event in case.iter_events(**filters):
            if not event["timestamp"]:
                continue
            when, micros = _timesketch_time(event["timestamp"])
            write({
                "message": event["details"] or event_type_label(event["type"], lang), "datetime": when,
                "timestamp": micros, "timestamp_desc": event_type_label(event["type"], lang),
                "data_type": f"sabueso:event:{event['type']}", "evidence": event["evidence_id"],
                "source": event["source"], "path": event["path"], "severity": event["severity"] or "info",
                "case_id": info.get("id"), "tag": ["bookmark"] if event["bookmark"] else [],
                **({"bookmark_note": event["bookmark"]["note"]} if event["bookmark"] else {}),
            })
        for finding in case.findings():
            if not finding["timestamp"]:
                continue
            when, micros = _timesketch_time(finding["timestamp"])
            write({
                "message": f"{finding_title(finding, lang)} — {finding_description(finding, lang)}", "datetime": when,
                "timestamp": micros, "timestamp_desc": t("report.finding", lang).capitalize(),
                "data_type": f"sabueso:finding:{finding['code']}", "evidence": finding["evidence_id"],
                "analysis": finding["analysis_id"], "severity": finding["severity"], "case_id": info.get("id"),
                "review_status": finding["review"]["status"], "tag": ["sabueso_finding", finding["severity"]],
            })
    return _log(case, path, "timesketch", rows, actor, filters={k: str(v) for k, v in filters.items() if v})
