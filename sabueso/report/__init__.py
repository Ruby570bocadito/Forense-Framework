"""Self-contained HTML case report (printable to PDF from any browser)."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from sabueso import __version__
from sabueso.core.attack import techniques_for
from sabueso.core.case import Case
from sabueso.core.execution import execution_overview
from sabueso.core.hashing import hash_file
from sabueso.core.utils import human_size, stamped_path, utc_now
from sabueso.i18n import get_language, label, normalize, t
from sabueso.modules.base import get_module
from sabueso.presentation import (
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

# Sections every forensic report carries; the caller may drop any of the others.
CORE_SECTIONS = frozenset({"summary", "evidence", "analyses", "custody", "limitations", "methodology",
                           "scope", "declaration"})
BUILTIN_SIGMA_RULES = 15  # rules shipped in sabueso/sigma/rules, measured in docs/VALIDACION.md
OPTIONAL_SECTIONS = ("conclusions", "attack", "iocs", "correlation", "findings", "bookmarks",
                     "execution", "chronology")


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


def _sections(lang: str, matrix: dict, indicators: dict, bookmarks: list, execution: list,
              shared: list = (), include: Optional[set[str]] = None, expert: bool = False) -> list[tuple[str, str]]:
    """Numbered sections of the report (anchor, title); optional ones only when they have content.

    ``include`` (None = no restriction) lets the caller drop optional sections; the core ones
    (summary, evidence, analyses, custody, methodology) always stay: a forensic report without
    them would contradict its own chain of custody.
    """
    items = [("scope", "report.scope")] if expert else []
    items += [("summary", "report.executive_summary"), ("conclusions", "report.conclusions")]
    if matrix:
        items.append(("attack", "report.attack"))
    if indicators:
        items.append(("iocs", "report.iocs"))
    if shared:
        items.append(("correlation", "report.correlation"))
    items += [("evidence", "nav.evidence"), ("findings", "nav.findings")]
    if bookmarks:
        items.append(("bookmarks", "report.bookmarked_events"))
    if execution:
        items.append(("execution", "nav.execution"))
    items += [("chronology", "report.chronology"), ("analyses", "report.analyses"), ("custody", "nav.custody"),
              ("limitations", "report.limitations"), ("methodology", "report.methodology")]
    if expert:
        items.append(("declaration", "report.declaration"))
    if include is not None:
        items = [(a, k) for a, k in items if a in CORE_SECTIONS or a in include]
    return [(anchor, t(key, lang)) for anchor, key in items]


def _limitations(evidence: list, verifications: dict, analyses: list, results_ok: dict, lang: str) -> list[str]:
    """What this case's report cannot assert, read from its own data (an expert report must state it)."""
    notes = []
    for item in evidence:
        check = verifications.get(item.id)
        if check is None:
            notes.append(t("report.limit.not_verified", lang, id=item.id))
        elif check.get("result") != "ok":
            notes.append(t("report.limit.verify_failed", lang, id=item.id))
    builtin_only = False
    for analysis in analyses:
        title = _module_title(analysis.module, lang)
        if analysis.status != "completed":
            notes.append(t("report.limit.analysis_failed", lang, id=analysis.id, module=title,
                           status=status_label(analysis.status, lang)))
            continue
        if analysis.errors:
            notes.append(t("report.limit.analysis_errors", lang, id=analysis.id, module=title,
                           count=len(analysis.errors)))
        if results_ok.get(analysis.id) is False:
            notes.append(t("report.limit.results_changed", lang, id=analysis.id))
        if analysis.module == "evtx" and not analysis.options.get("sigma_rules"):
            builtin_only = True
    if builtin_only:
        notes.append(t("report.limit.sigma_builtin", lang, count=BUILTIN_SIGMA_RULES))
    return notes


def _correlations(case: Case) -> list:
    """Observables of this case that also appear in other cases of the same workspace.

    Never raises: a damaged neighbouring case (or a correlation failure) must not block
    the report. Uses the shared cache, so consecutive reports stay cheap.
    """
    from sabueso.core.correlation import case_dirs, correlate, workspace_indexes

    try:
        if len(case_dirs(case.root.parent)) < 2:  # cheap check first: no indexing, no cache dir
            return []
        indexes = workspace_indexes(case.root.parent)
    except Exception:  # noqa: BLE001 - the report is the deliverable, correlation is a bonus
        return []
    if len(indexes) < 2:
        return []
    return correlate(indexes, focus=case.root.name)


def _charts(overview: dict, lang: str) -> dict:
    from sabueso.charts import SEVERITIES, activity_chart, severity_bar

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
                    actor: Optional[str] = None, max_events: int = 1000, max_programs: int = 300,
                    sign: bool = False, include: Optional[set[str]] = None, confirmed_only: bool = False,
                    max_findings: int = 0, expert: bool = False, scope: Optional[str] = None,
                    proceeding: Optional[dict] = None) -> Path:
    """Write the HTML report and record it in the chain of custody.

    ``expert`` turns it into an expert witness report (dictamen pericial, UNE 71506): it adds the purpose and
    scope (``scope``, or the case description) and the expert's declaration of article 335.2 LEC; ``proceeding``
    (``requester``, ``court``, ``number``) goes on the cover."""
    proceeding = {k: str(v).strip() for k, v in (proceeding or {}).items()
                  if k in ("requester", "court", "number") and v and str(v).strip()} if expert else {}
    from sabueso.core.attack import attack_matrix, storyline
    from sabueso.core.overview import case_overview
    from sabueso.core.stix import collect_indicators

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
    findings_total = len(overview["findings"])  # before any filter: the note shows the full case scale
    if confirmed_only:  # the ATT&CK matrix and the storyline follow the same verdict filter
        overview["findings"] = [f for f in overview["findings"] if f["review"]["status"] == "confirmed"]
        overview["matrix"] = attack_matrix(overview["findings"])
    if max_findings and len(overview["findings"]) > max_findings:
        overview["findings"] = overview["findings"][:max_findings]
    shared = _correlations(case)
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
        findings_total=findings_total, findings_shown=len(overview["findings"]),
        findings_trimmed=findings_total - len(overview["findings"]),
        indicators=sorted(indicators.values(), key=lambda i: (i["first_seen"] or "9999", i["type"], i["value"])),
        charts=_charts(overview, lang),
        sections=_sections(lang, overview["matrix"], indicators, bookmarks, execution, shared=shared,
                           include=include, expert=expert),
        limitations=_limitations(evidence, verifications, analyses, results_ok, lang),
        expert=expert, scope=(scope or "").strip() or info.get("description") or "", proceeding=proceeding,
        shared=shared, case_slug=info.get("slug") or case.root.name, include=include,
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
        "sections": sorted(include) if include is not None else "all",
        "detail": {"confirmed_only": confirmed_only, "max_findings": max_findings or None},
        **({"expert": True, "scope_sha256": hashlib.sha256((scope or "").encode("utf-8")).hexdigest(),
            "proceeding": proceeding} if expert else {}),
    })
    if sign:
        from sabueso.report.signing import sign_into_custody

        sign_into_custody(case, output, actor)
    return output
