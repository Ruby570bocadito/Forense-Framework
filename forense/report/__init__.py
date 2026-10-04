"""Self-contained HTML case report (printable to PDF from any browser)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from forense import __version__
from forense.core.attack import techniques_for
from forense.core.case import Case
from forense.core.execution import execution_overview
from forense.core.hashing import hash_file
from forense.core.utils import human_size, stamped_path, utc_now
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
LOGO = Path(__file__).parent.parent / "web" / "static" / "logo.svg"


def template_environment(lang: str) -> Environment:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html"]),
                      trim_blocks=True, lstrip_blocks=True)
    env.globals.update(
        _=lambda key, /, **params: t(key, lang, **params), lang=lang, version=__version__, colors=SEVERITY_COLORS,
        finding_title=lambda f: finding_title(f, lang), finding_description=lambda f: finding_description(f, lang),
        module_title=lambda name: _module_title(name, lang), techniques_for=techniques_for,
    )
    env.filters.update(
        ts=display_ts, val=lambda v, limit=None: format_value(v, lang, limit), label=lambda f: label(f, lang),
        sev=lambda s: severity_label(s, lang), etype=lambda e: event_type_label(e, lang),
        artifact=lambda a: artifact_label(a, lang), action=lambda a: custody_action_label(a, lang),
        status=lambda s: status_label(s, lang), rule=lambda r: rule_label(r, lang),
        size=lambda n: f"{human_size(n)} ({n:,} B)" if isinstance(n, int) and n >= 1024 else f"{n} B",
    )
    return env


def _module_title(name: str, lang: str) -> str:
    try:
        return get_module(name).title(lang)
    except Exception:  # noqa: BLE001 - module removed since the analysis ran
        return name


def _sections(lang: str, matrix: dict, indicators: dict, bookmarks: list, execution: list) -> list[tuple[str, str]]:
    """Numbered sections of the report (anchor, title); optional ones only when they have content."""
    items = [("summary", "report.executive_summary"), ("conclusions", "report.conclusions")]
    if matrix:
        items.append(("attack", "report.attack"))
    if indicators:
        items.append(("iocs", "report.iocs"))
    items += [("evidence", "nav.evidence"), ("findings", "nav.findings")]
    if bookmarks:
        items.append(("bookmarks", "report.bookmarked_events"))
    if execution:
        items.append(("execution", "nav.execution"))
    items += [("chronology", "report.chronology"), ("analyses", "report.analyses"), ("custody", "nav.custody"),
              ("methodology", "report.methodology")]
    return [(anchor, t(key, lang)) for anchor, key in items]


def _charts(overview: dict, lang: str) -> dict:
    from forense.charts import SEVERITIES, activity_chart, severity_bar

    labels = {s: severity_label(s, lang) for s in SEVERITIES}
    labels.update(title=t("report.activity", lang), events=t("report.events", lang),
                  flagged=t("web.alerts", lang), findings=t("report.findings", lang).capitalize())
    points = [{"timestamp": f["timestamp"], "severity": f["severity"], "label": finding_title(f, lang)}
              for f in overview["findings"] if f["severity"] in ("medium", "high", "critical")
              and (f.get("review") or {}).get("status") != "false_positive"]
    return {"activity": activity_chart(overview["buckets"], overview["unit"], points, labels)
            if overview["buckets"] else "",
            "severity": severity_bar(overview["severity_counts"], {**labels, "title": t("report.severity", lang)})}


def generate_report(case: Case, lang: Optional[str] = None, output: Optional[Path] = None, verify: bool = False,
                    actor: Optional[str] = None, max_events: int = 1000, max_programs: int = 300) -> Path:
    from forense.core.attack import storyline
    from forense.core.overview import case_overview
    from forense.core.stix import collect_indicators

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
    overview = case_overview(case)
    indicators = collect_indicators(case)
    bookmarks = case.events(bookmarked=True, limit=None).rows
    execution = execution_overview(case)[:max_programs]
    info = case.info

    html = template_environment(lang).get_template("report.html").render(
        case=info, stats=case.stats(), evidence=evidence, verifications=verifications, analyses=analyses,
        results_ok=results_ok, findings=overview["findings"], events=events.rows, events_total=events.total,
        max_events=max_events, custody=entries, custody_problems=custody_problems,
        custody_head=case.custody.head(), generated=utc_now(), analyst=actor,
        records_by_analysis={a.id: case.record_artifacts(a.id) for a in analyses},
        conclusions=case.conclusions(), progress=case.review_progress(), bookmarks=bookmarks, execution=execution,
        overview=overview, matrix=overview["matrix"], phases=storyline(overview["findings"]),
        indicators=sorted(indicators.values(), key=lambda i: (i["first_seen"] or "9999", i["type"], i["value"])),
        charts=_charts(overview, lang), sections=_sections(lang, overview["matrix"], indicators, bookmarks, execution),
        logo=Markup(LOGO.read_text(encoding="utf-8")) if LOGO.is_file() else "",
        page_label=re.sub(r"[^A-Za-z0-9 ._-]", "", f"{info.get('id', '')}")[:60],
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
