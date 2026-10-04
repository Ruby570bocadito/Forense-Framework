"""Self-contained HTML case report (printable to PDF from any browser)."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from forense import __version__
from forense.core.case import Case
from forense.core.execution import execution_overview
from forense.core.hashing import hash_file
from forense.core.utils import stamped_path, utc_now
from forense.i18n import get_language, label, normalize, t
from forense.modules.base import get_module
from forense.presentation import (
    SEVERITY_COLORS,
    artifact_label,
    custody_action_label,
    display_ts,
    event_type_label,
    finding_description,
    finding_title,
    format_value,
    rule_label,
    severity_label,
    status_label,
)

TEMPLATES = Path(__file__).parent / "templates"


def template_environment(lang: str) -> Environment:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html"]),
                      trim_blocks=True, lstrip_blocks=True)
    env.globals.update(
        _=lambda key, **params: t(key, lang, **params), lang=lang, version=__version__, colors=SEVERITY_COLORS,
        finding_title=lambda f: finding_title(f, lang), finding_description=lambda f: finding_description(f, lang),
        module_title=lambda name: _module_title(name, lang),
    )
    env.filters.update(
        ts=display_ts, val=lambda v, limit=None: format_value(v, lang, limit), label=lambda f: label(f, lang),
        sev=lambda s: severity_label(s, lang), etype=lambda e: event_type_label(e, lang),
        artifact=lambda a: artifact_label(a, lang), action=lambda a: custody_action_label(a, lang),
        status=lambda s: status_label(s, lang), rule=lambda r: rule_label(r, lang),
    )
    return env


def _module_title(name: str, lang: str) -> str:
    try:
        return get_module(name).title(lang)
    except Exception:  # noqa: BLE001 - module removed since the analysis ran
        return name


def generate_report(case: Case, lang: Optional[str] = None, output: Optional[Path] = None, verify: bool = False,
                    actor: Optional[str] = None, max_events: int = 1000, max_programs: int = 300) -> Path:
    lang = normalize(lang) or get_language()
    actor = case.actor(actor)
    evidence = case.evidence_list()
    if verify:
        for item in evidence:
            case.verify_evidence(item.id, actor)
    verifications = case.last_verifications()
    analyses = case.analyses()
    results_ok = {a.id: case.verify_results(a.id) for a in analyses if a.status == "completed"}
    custody_problems = case.custody.verify()
    entries = case.custody.entries()
    events = case.events(min_severity="low", limit=max_events)

    html = template_environment(lang).get_template("report.html").render(
        case=case.info, stats=case.stats(), evidence=evidence, verifications=verifications, analyses=analyses,
        results_ok=results_ok, findings=case.findings(), events=events.rows, events_total=events.total,
        max_events=max_events, custody=entries, custody_problems=custody_problems,
        custody_head=case.custody.head(), generated=utc_now(), analyst=actor,
        records_by_analysis={a.id: case.record_artifacts(a.id) for a in analyses},
        conclusions=case.conclusions(), progress=case.review_progress(),
        bookmarks=case.events(bookmarked=True, limit=None).rows,
        execution=execution_overview(case)[:max_programs],
    )
    if output is None:
        output = stamped_path(case.root / "reports", "report", f"_{lang}.html")
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")
    digest = hash_file(output, ("sha256",))["sha256"]
    case.custody.append("report_generated", actor, {
        "file": str(output), "sha256": digest, "language": lang, "verified_evidence": verify,
        "custody_head": entries[-1].hash if entries else None,
    })
    return output
