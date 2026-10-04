"""Command line interface (Spanish / English).

Commands have English names with Spanish aliases (``analyze`` / ``analizar``),
and the interface language follows ``--lang``, ``FORENSE_LANG`` or the system
locale.
"""

from __future__ import annotations

import argparse
import copy
import getpass
import os
import shutil
import sqlite3
import sys
from pathlib import Path
from typing import Callable, Optional, Sequence

from forense import __version__
from forense.core.case import Case
from forense.core.config import DEFAULTS, Config, get_config, load_config, set_config
from forense.core.errors import ForenseError
from forense.core.utils import human_size
from forense.i18n import SUPPORTED, get_language, label, set_language, t
from forense.presentation import (
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

EXIT_OK, EXIT_ERROR, EXIT_INTEGRITY = 0, 1, 2


# -- output helpers -----------------------------------------------------------
def _out(text: str = "") -> None:
    print(text)


def _err(text: str) -> None:
    print(text, file=sys.stderr)


def _table(headers: Sequence[str], rows: Sequence[Sequence[object]], max_width: Optional[int] = None) -> None:
    if not rows:
        _out(t("common.no_rows"))
        return
    max_width = max_width or max(60, shutil.get_terminal_size((140, 20)).columns)
    cells = [[format_value(c) for c in row] for row in rows]
    widths = [max(len(str(h)), *(len(r[i]) for r in cells)) for i, h in enumerate(headers)]
    budget = max_width - 2 * (len(widths) - 1)
    while sum(widths) > budget and max(widths) > 12:
        widest = widths.index(max(widths))
        widths[widest] -= 1

    def fit(text: str, width: int) -> str:
        return text if len(text) <= width else text[:max(1, width - 1)] + "…"

    _out("  ".join(fit(str(h), w).ljust(w) for h, w in zip(headers, widths, strict=True)))
    _out("  ".join("-" * w for w in widths))
    for row in cells:
        _out("  ".join(fit(c, w).ljust(w) for c, w in zip(row, widths, strict=True)))


def _kv(items: dict, indent: int = 0) -> None:
    for key, value in items.items():
        if isinstance(value, dict):
            _out(" " * indent + f"{label(key)}:")
            _kv(value, indent + 2)
        else:
            _out(" " * indent + f"{label(key)}: {format_value(value)}")


class _Progress:
    """Single-line progress on stderr (only when it is a terminal)."""

    def __init__(self) -> None:
        self.enabled = sys.stderr.isatty()

    def bytes(self, files: int, done: int) -> None:
        if self.enabled:
            sys.stderr.write(f"\r  {t('cli.progress_hash', files=files, size=human_size(done))}   ")
            sys.stderr.flush()

    def message(self, text: str) -> None:
        if self.enabled:
            sys.stderr.write(f"\r  … {text[:100]}".ljust(110))
            sys.stderr.flush()

    def done(self) -> None:
        if self.enabled:
            sys.stderr.write("\r" + " " * 110 + "\r")
            sys.stderr.flush()


def _open_case(args: argparse.Namespace) -> Case:
    return Case.open(Path(args.case))


def _parse_options(pairs: Sequence[str]) -> dict:
    options = {}
    for pair in pairs:
        if "=" not in pair:
            raise ForenseError("error.option_format", value=pair)
        key, value = pair.split("=", 1)
        options[key.strip()] = value.strip()
    return options


# -- commands -------------------------------------------------------------------
def cmd_new(args: argparse.Namespace) -> int:
    with Case.create(Path(args.directory), args.name, args.investigator, args.description or "",
                     args.reference or "", args.organization or "") as case:
        info = case.info
        _out(t("cli.case_created", name=info["name"], id=info["id"], path=str(case.root)))
        _out(t("cli.case_next_steps", path=str(case.root)))
    return EXIT_OK


def cmd_info(args: argparse.Namespace) -> int:
    with _open_case(args) as case:
        info, stats = case.info, case.stats()
        for key in ("id", "name", "investigator", "organization", "reference", "description", "created",
                    "framework_version"):
            if info.get(key):
                _out(f"{t('case.' + key)}: {format_value(info[key])}")
        _out(f"{t('case.path')}: {case.root}")
        _out()
        _out(f"{t('nav.evidence')}: {stats['evidence']}   {t('nav.analyses')}: {stats['analyses']}   "
             f"{t('report.timeline_events')}: {stats['events']}   {t('nav.findings')}: {stats['findings']}")
        sev = stats["findings_by_severity"]
        if sev:
            _out("  " + "  ".join(f"{severity_label(s)}: {sev[s]}" for s in
                                  ("critical", "high", "medium", "low", "info") if s in sev))
        if stats["first_event"]:
            _out(t("report.activity_span", first=display_ts(stats["first_event"]),
                   last=display_ts(stats["last_event"])))
    return EXIT_OK


def cmd_evidence_add(args: argparse.Namespace) -> int:
    with _open_case(args) as case:
        progress = _Progress()
        _out(t("cli.hashing", path=args.path))
        evidence = case.add_evidence(Path(args.path), args.description or "", args.copy, args.analyst,
                                     progress=progress.bytes)
        progress.done()
        _out(t("cli.evidence_added", id=evidence.id, files=evidence.file_count, size=human_size(evidence.size)))
        for algo, value in evidence.hashes.items():
            _out(f"  {algo.upper():7} {value}")
    return EXIT_OK


def cmd_evidence_list(args: argparse.Namespace) -> int:
    with _open_case(args) as case:
        _table(["ID", label("kind"), label("files"), label("size"), "SHA-256", label("description"), label("path")],
               [(e.id, t("evidence.kind." + e.kind), e.file_count, human_size(e.size), e.hashes.get("sha256"),
                 e.description, e.path) for e in case.evidence_list()])
    return EXIT_OK


def cmd_evidence_verify(args: argparse.Namespace) -> int:
    with _open_case(args) as case:
        ids = [args.id] if args.id else [e.id for e in case.evidence_list()]
        failed = False
        progress = _Progress()
        for evidence_id in ids:
            result = case.verify_evidence(evidence_id, args.analyst, progress=progress.bytes)
            progress.done()
            if result.ok:
                _out(f"[OK]    {result.evidence_id}  {t('verify.result.ok')}")
            else:
                failed = True
                reason = t(result.error) if result.error else t("verify.result.mismatch")
                _out(f"[FAIL]  {result.evidence_id}  {reason}")
                for algo, expected in result.expected.items():
                    _out(f"        {algo}: {expected} -> {result.current.get(algo, '-')}")
    return EXIT_INTEGRITY if failed else EXIT_OK


def cmd_modules(args: argparse.Namespace) -> int:
    from forense.modules import available_modules

    for module in available_modules():
        targets = "/".join(t("evidence.kind." + k) for k in module.targets)
        auto = f" [{t('cli.triage_tag')}]" if module.triage else ""
        _out(f"{module.name:12} {module.title()}  ({t('category.' + module.category)}; {targets}){auto}")
        _out(f"{'':12} {module.description()}")
        for option in module.options:
            default = format_value(list(option.default) if isinstance(option.default, tuple) else option.default)
            required = f" ({t('cli.required')})" if option.required else ""
            _out(f"{'':14}-o {option.name}=…  {module.option_help(option)}{required}"
                 + (f" [{t('cli.default')}: {default}]" if default else ""))
        _out()
    return EXIT_OK


def _print_analysis(analysis) -> None:
    _out(t("cli.analysis_done", id=analysis.id, module=analysis.module, status=status_label(analysis.status),
           records=analysis.record_count, events=analysis.event_count, findings=analysis.finding_count))
    if analysis.summary:
        _kv(analysis.summary, 2)
    if analysis.errors:
        _out(t("cli.analysis_errors", count=len(analysis.errors)))
        for error in analysis.errors[:10]:
            _out(f"  ! {error['path']}: {error['error']}")


def cmd_analyze(args: argparse.Namespace) -> int:
    with _open_case(args) as case:
        options = _parse_options(args.option)
        targets = [e.id for e in case.evidence_list()] if args.evidence.lower() in ("all", "todas") \
            else [args.evidence]
        progress = _Progress()
        for evidence_id in targets:
            _out(t("cli.analysis_running", module=args.module, evidence=evidence_id))
            analysis = case.run_analysis(args.module, evidence_id, options, args.analyst, progress=progress.message)
            progress.done()
            _print_analysis(analysis)
            _findings_brief(case, analysis.id)
    return EXIT_OK


def cmd_triage(args: argparse.Namespace) -> int:
    with _open_case(args) as case:
        progress = _Progress()
        _out(t("cli.triage_running", evidence=args.evidence))
        results = case.triage(args.evidence, args.analyst, progress=progress.message)
        progress.done()
        rows = []
        for module, analysis, error in results:
            if analysis is None:
                rows.append((module, t(error), "", "", ""))
            else:
                rows.append((module, status_label(analysis.status), analysis.record_count, analysis.event_count,
                             analysis.finding_count))
        _table([label("module"), label("status"), t("report.records"), t("report.events"), t("report.findings")],
               rows)
        _out()
        _findings_brief(case, None, min_severity="medium")
    return EXIT_OK


def cmd_image(args: argparse.Namespace) -> int:
    with _open_case(args) as case:
        options = {"verify": args.verify, "all_files": args.all_files, "vss": args.vss}
        if args.pattern:
            options["patterns"] = ",".join(args.pattern)
        for option, value in (("bitlocker_recovery", args.bitlocker_recovery),
                              ("bitlocker_password", args.bitlocker_password)):
            if value == "-":  # ask without echoing it (it would otherwise stay in the shell history)
                value = getpass.getpass(t(f"cli.prompt.{option}") + ": ")
            if value:
                options[option] = value
        if args.bitlocker_key:
            options["bitlocker_startup_key"] = args.bitlocker_key
        progress = _Progress()
        _out(t("cli.image_running", evidence=args.evidence))
        analysis, derived = case.extract_image(args.evidence, options, args.analyst, progress=progress.message)
        progress.done()
        _print_analysis(analysis)
        verification = analysis.summary.get("verification")
        if verification and verification.get("match") is False:
            _err(t("cli.image_hash_mismatch"))
        if derived is None:
            _out(t("cli.image_nothing_extracted"))
            return EXIT_ERROR if analysis.status != "completed" else EXIT_OK
        _out(t("cli.image_derived", id=derived.id, files=analysis.summary.get("files_extracted", 0)))
        if args.triage:
            args.evidence = derived.id
    if args.triage:
        return cmd_triage(args)
    _out(t("cli.image_next", id=derived.id))
    return EXIT_OK


def cmd_collect(args: argparse.Namespace) -> int:
    from forense.collector import collect

    progress = _Progress()
    dest = Path(args.destination).resolve()
    _out(t("cli.collect_running", source=args.source or t("cli.collect_system_drive"), dest=str(dest)))
    result = collect(dest, args.source, volatile=args.volatile, progress=progress.message)
    progress.done()
    _out(t("cli.collect_done", files=result["files"], size=human_size(result["bytes"]), errors=len(result["errors"]),
           manifest=result["manifest_sha256"]))
    for error in result["errors"][:10]:
        _out(f"  ! {error['path']}: {error['error']}")
    if args.add_to_case:
        with _open_case(args) as case:
            evidence = case.add_evidence(dest, t("cli.collect_evidence", host=result["host"], date=result["started"]),
                                         copy=args.copy, actor=args.analyst)
        _out(t("cli.evidence_added", id=evidence.id, files=evidence.file_count, size=human_size(evidence.size)))
    return EXIT_OK


def _findings_brief(case: Case, analysis_id: Optional[int], min_severity: str = "low", limit: int = 15) -> None:
    findings = case.findings(min_severity=min_severity, analysis_id=analysis_id)
    if not findings:
        return
    _out(t("cli.top_findings", count=len(findings)))
    for f in findings[:limit]:
        _out(f"  [{severity_label(f['severity']).upper()}] {display_ts(f['timestamp']) or '-'}  "
             f"{finding_title(f)} — {finding_description(f)}")
    if len(findings) > limit:
        _out("  " + t("cli.more_findings", count=len(findings) - limit))


def cmd_analyses(args: argparse.Namespace) -> int:
    with _open_case(args) as case:
        _table(["#", label("module"), label("evidence"), label("status"), label("started"), t("report.records"),
                t("report.events"), t("report.findings"), label("actor")],
               [(a.id, a.module, a.evidence_id, status_label(a.status), display_ts(a.started), a.record_count,
                 a.event_count, a.finding_count, a.actor) for a in case.analyses()])
    return EXIT_OK


def cmd_show(args: argparse.Namespace) -> int:
    with _open_case(args) as case:
        analysis = case.get_analysis(args.analysis)
        _print_analysis(analysis)
        artifacts = case.record_artifacts(analysis.id)
        if artifacts:
            _out(t("cli.artifacts") + ": " + ", ".join(f"{a} = {artifact_label(a)} ({n})" for a, n in artifacts))
        artifact = args.artifact or (artifacts[0][0] if len(artifacts) == 1 else None)
        if artifact is None and artifacts:
            _out(t("cli.choose_artifact"))
            return EXIT_OK
        page = case.records(analysis.id, artifact=artifact, search=args.search or "", limit=args.limit)
        if page.rows:
            columns = list(dict.fromkeys(k for _, row in page.rows for k in row))
            _out()
            _table([label(c) for c in columns], [[row.get(c) for c in columns] for _, row in page.rows])
            _out(t("cli.showing", shown=len(page.rows), total=page.total))
    return EXIT_OK


def cmd_findings(args: argparse.Namespace) -> int:
    from forense.core.review import normalize_status

    with _open_case(args) as case:
        status = normalize_status(args.status) if args.status else None
        findings = case.findings(min_severity=args.min_severity, review_status=status)
        _table(["#", label("severity"), label("timestamp"), label("evidence"), t("report.finding"),
                label("description"), t("report.review_status")],
               [(f["id"], severity_label(f["severity"]), display_ts(f["timestamp"]), f["evidence_id"], finding_title(f),
                 finding_description(f), t("review." + f["review"]["status"])
                 + (f" — {f['review']['note']}" if f["review"]["note"] else "")) for f in findings])
        progress = case.review_progress()
        if progress["total"]:
            _out(t("review.progress", **progress))
    return EXIT_OK


def cmd_review(args: argparse.Namespace) -> int:
    with _open_case(args) as case:
        review = case.review_finding(args.finding, args.status, args.note or "", args.analyst)
        _out(t("cli.review_saved", id=args.finding, status=t("review." + review["status"])))
    return EXIT_OK


def cmd_bookmark(args: argparse.Namespace) -> int:
    with _open_case(args) as case:
        review = case.bookmark_event(args.event, args.note or "", args.analyst, remove=args.remove)
        _out(t("cli.bookmark_saved", id=args.event, status=t("review." + review["status"])))
    return EXIT_OK


def cmd_conclusions(args: argparse.Namespace) -> int:
    with _open_case(args) as case:
        text = Path(args.file).read_text(encoding="utf-8") if args.file else args.text
        if text is not None:
            if not text.strip():
                raise ForenseError("error.conclusions_empty")
            saved = case.set_conclusions(text, args.analyst)
            _out(t("cli.conclusions_saved", version=saved["version"], sha256=saved["sha256"]))
            return EXIT_OK
        current = case.conclusions()
        if current is None:
            _out(t("cli.no_conclusions"))
            return EXIT_OK
        _out(t("report.conclusions_meta", version=current["version"], actor=current["actor"],
               timestamp=display_ts(current["timestamp"]), sha256=current["sha256"]))
        _out()
        _out(current["text"])
    return EXIT_OK


def cmd_timeline(args: argparse.Namespace) -> int:
    from forense.core.utils import normalize_ts, range_end

    try:
        start = normalize_ts(args.start) if args.start else None
        end = range_end(args.end) if args.end else None
    except (ValueError, OverflowError) as exc:
        raise ForenseError("error.invalid_date", value=args.start or args.end) from exc
    with _open_case(args) as case:
        filters = {"start": start, "end": end,
                   "search": args.search or "", "source": args.source, "min_severity": args.min_severity,
                   "bookmarked": args.bookmarked}
        page = case.events(limit=args.limit, **filters)
        _table(["#", label("timestamp") + " (UTC)", label("severity"), label("source"), label("type"), label("details")],
               [(("★ " if e["bookmark"] else "") + str(e["id"]), display_ts(e["timestamp"]),
                 severity_label(e["severity"]), e["source"], event_type_label(e["type"]),
                 e["details"] + (f" — {e['bookmark']['note']}" if e["bookmark"] and e["bookmark"]["note"] else ""))
                for e in page.rows])
        _out(t("cli.showing", shown=len(page.rows), total=page.total))
    return EXIT_OK


def cmd_export(args: argparse.Namespace) -> int:
    from forense.core import exports

    with _open_case(args) as case:
        fmt = "json" if args.what == "stix" else args.format or Path(args.output).suffix.lstrip(".").lower() or "csv"
        if fmt not in exports.FORMATS:
            raise ForenseError("error.export_format", format=fmt)
        output = Path(args.output)
        if args.what == "analysis":
            if args.id is None:
                raise ForenseError("error.export_needs_id")
            path = exports.export_analysis(case, args.id, output, fmt, actor=args.analyst)
        elif args.what == "timeline":
            path = exports.export_timeline(case, output, fmt, actor=args.analyst)
        elif args.what == "findings":
            path = exports.export_findings(case, output, fmt, actor=args.analyst)
        elif args.what == "execution":
            path = exports.export_execution(case, output, fmt, actor=args.analyst)
        elif args.what == "stix":
            from forense.core.stix import export_stix

            path = export_stix(case, output, actor=args.analyst)
        else:
            path = exports.export_custody(case, output, fmt, actor=args.analyst)
        _out(t("cli.exported", path=str(path)))
    return EXIT_OK


def cmd_execution(args: argparse.Namespace) -> int:
    from forense.core.execution import execution_overview

    with _open_case(args) as case:
        programs = execution_overview(case, args.search or "", args.suspicious)
        rows = [(p.name, p.path or "-", ", ".join(sorted(p.sources)), display_ts(p.first) or "-",
                 display_ts(p.last) or "-", p.run_count if p.run_count is not None else "-",
                 ", ".join(rule_label(f) for f in p.flags)) for p in programs[: args.limit]]
        _table([label("program"), label("path"), label("sources"), label("first"), label("last"),
                label("run_count"), label("flags")], rows)
        if len(programs) > args.limit:
            _out(t("cli.showing", shown=args.limit, total=len(programs)))
    return EXIT_OK


def cmd_attack(args: argparse.Namespace) -> int:
    from forense.core.attack import attack_matrix, draft_summary

    with _open_case(args) as case:
        findings = case.findings()
        if args.summary:
            _out(draft_summary(findings))
            return EXIT_OK
        rows = []
        for tactic, hits in attack_matrix(findings).items():
            for hit in hits:
                rows.append((t(f"tactic.{tactic}"), hit.technique, hit.name, len(hit.findings),
                             severity_label(hit.severity), display_ts(hit.first) or "-"))
        _table([t("attack.tactic"), t("attack.technique"), label("name"), t("report.findings"), label("severity"),
                label("first")], rows)
    return EXIT_OK


def cmd_custody(args: argparse.Namespace) -> int:
    with _open_case(args) as case:
        entries = case.custody.entries()
        if not args.verify:
            _table(["#", label("timestamp"), label("action"), label("actor"), label("details"), label("hash")],
                   [(e.seq, display_ts(e.timestamp), custody_action_label(e.action), e.actor,
                     ", ".join(f"{k}={format_value(v, limit=60)}" for k, v in e.details.items()), e.hash[:16])
                    for e in entries])
        problems = case.custody.verify()
        if problems:
            _out(t("custody.broken"))
            for problem in problems:
                _out(f"  #{problem.seq}: {t(problem.code)}")
            return EXIT_INTEGRITY
        _out(t("custody.intact", count=len(entries)))
        _out(f"{t('custody.head')}: {case.custody.head()}")
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    """Full integrity check: custody chain, evidence hashes and stored results."""
    with _open_case(args) as case:
        failed = False
        problems = case.custody.verify()
        _out(("[OK]   " if not problems else "[FAIL] ") + t("verify.custody"))
        failed |= bool(problems)
        progress = _Progress()
        for evidence in case.evidence_list():
            result = case.verify_evidence(evidence.id, args.analyst, progress=progress.bytes)
            progress.done()
            _out(("[OK]   " if result.ok else "[FAIL] ") + t("verify.evidence", id=evidence.id))
            failed |= not result.ok
        for analysis in case.analyses():
            if analysis.status != "completed":
                continue
            ok = case.verify_results(analysis.id)
            _out(("[OK]   " if ok else "[FAIL] ") + t("verify.results", id=analysis.id, module=analysis.module))
            failed |= not ok
        _out(t("verify.summary_fail") if failed else t("verify.summary_ok"))
    return EXIT_INTEGRITY if failed else EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    from forense.report import generate_report

    with _open_case(args) as case:
        path = generate_report(case, args.lang, Path(args.output) if args.output else None, args.verify,
                               args.analyst)
        _out(t("cli.report_written", path=str(path)))
    return EXIT_OK


def cmd_sigma(args: argparse.Namespace) -> int:
    from forense.sigma import SigmaRuleSet
    from forense.sigma.download import download_sigmahq

    if args.action == "download":
        count = download_sigmahq(Path(args.path))
        _out(t("cli.sigma_downloaded", path=str(Path(args.path).resolve()), count=count))
        return EXIT_OK
    ruleset, errors = SigmaRuleSet.load([Path(args.path)], min_level=args.min_level or "info")
    for file, error in errors[:50]:
        _out(f"  ! {file}: {error}")
    _out(t("cli.sigma_loaded", rules=len(ruleset.rules), errors=len(errors)))
    return EXIT_OK


def cmd_web(args: argparse.Namespace) -> int:
    from forense.web import run_server

    workspace = Path(args.workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    password = args.password or os.environ.get("FORENSE_WEB_PASSWORD")
    if args.host not in ("127.0.0.1", "localhost", "::1") and not password:
        _err(t("cli.web_exposed_warning"))
    run_server(workspace, args.host, args.port, password)
    return EXIT_OK


def cmd_demo(args: argparse.Namespace) -> int:
    from forense.demo import generate_demo

    dest = Path(args.directory).resolve()
    paths = generate_demo(dest / "evidence")
    _out(t("cli.demo_created", path=str(dest / "evidence")))
    if args.no_case:
        return EXIT_OK
    case_dir = dest / "case_demo"
    with Case.create(case_dir, t("demo.case_name"), args.analyst or "Demo Analyst", t("demo.case_description"),
                     "DEMO-001") as case:
        triage = case.add_evidence(paths["triage"], t("demo.evidence_triage"), copy=True)
        image = case.add_evidence(paths["image"], t("demo.evidence_image"), copy=True)
        memory = case.add_evidence(paths["memory"], t("demo.evidence_memory"), copy=True)
        case.triage(triage.id)
        case.run_analysis("ioc", triage.id, {"watchlist": str(paths["watchlist"])})
        case.run_analysis("hashset", triage.id, {"hash_list": str(paths["hashes"])})
        case.run_analysis("yara", triage.id, {"rules": str(paths["yara"])})
        case.run_analysis("carving", image.id)
        case.run_analysis("memory", memory.id)
        stats = case.stats()
    _out(t("cli.demo_case", path=str(case_dir), findings=stats["findings"], events=stats["events"]))
    _out(t("cli.demo_next", case=str(case_dir), workspace=str(dest)))
    return EXIT_OK


def cmd_config(args: argparse.Namespace) -> int:
    from forense.core.config import default_path, get_config, write_template

    if args.action == "init":
        _out(t("cli.config_written", path=str(write_template(Path(args.path) if args.path else None, args.force))))
    elif args.action == "path":
        _out(str(get_config().path or default_path()))
    else:
        config = get_config()
        _out(t("cli.config_file", path=str(config.path), state=t("cli.config_loaded" if config.loaded
                                                                 else "cli.config_missing")))
        import yaml

        _out(yaml.safe_dump(dict(config), allow_unicode=True, sort_keys=False).rstrip())
    return EXIT_OK


def _print_automation(result) -> int:
    _out()
    for step in result.steps:
        mark = {"ok": "OK ", "completed": "OK ", "skipped": "-- ", "failed": "!! "}.get(step.status, "?? ")
        _out(f"  {mark}{step.step}: {step.detail}")
    with Case.open(result.case_path) as case:
        stats = case.stats()
        _out()
        _out(t("cli.auto_done", path=str(result.case_path), findings=stats["findings"], events=stats["events"]))
        _findings_brief(case, None, min_severity="high", limit=10)
    for path in result.reports + result.exports:
        _out(f"  → {path}")
    return EXIT_ERROR if any(s.status == "failed" for s in result.steps) else EXIT_OK


def cmd_auto(args: argparse.Namespace) -> int:
    from forense.automation import auto

    progress = _Progress()
    case_dir = Path(args.case) if args.case_explicit else None
    result = auto([Path(p) for p in args.paths], case_dir=case_dir, new_case=Path(args.new) if args.new else None,
                  name=args.name, investigator=args.investigator, playbook=args.playbook, copy=args.copy,
                  description=args.description or "", actor=args.analyst, progress=lambda m: (progress.message(m)))
    progress.done()
    return _print_automation(result)


def cmd_watch(args: argparse.Namespace) -> int:
    from forense.automation import watch
    from forense.core.config import get_config

    workspace = Path(args.workspace or get_config().value("workspace") or ".")
    _out(t("cli.watch_started", inbox=str(Path(args.inbox).resolve()), workspace=str(workspace.resolve()),
           interval=args.interval))
    results = watch(Path(args.inbox), workspace, args.playbook, args.interval, args.once, progress=_out)
    for result in results:
        _print_automation(result)
    return EXIT_OK


# -- parser -----------------------------------------------------------------------
def _add(sub: argparse._SubParsersAction, name: str, alias: str, help_key: str,
         func: Callable, parents: Sequence[argparse.ArgumentParser] = ()) -> argparse.ArgumentParser:
    aliases = [alias] if alias and alias != name else []
    parser = sub.add_parser(name, aliases=aliases, help=t(help_key), description=t(help_key), parents=list(parents))
    parser.set_defaults(func=func)
    return parser


def build_parser() -> argparse.ArgumentParser:
    # -c/-a are accepted both before and after the command (``forense -c X info`` / ``forense info -c X``).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--case", "--caso", default=None, metavar="DIR", help=t("cli.opt.case"))
    common.add_argument("-a", "--analyst", "--analista", default=None, metavar="NAME", help=t("cli.opt.analyst"))

    parser = argparse.ArgumentParser(prog="forense", description=t("cli.description"),
                                     epilog=t("cli.epilog"), formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"Forense-Framework {__version__}")
    parser.add_argument("-L", "--lang", "--idioma", choices=SUPPORTED, help=t("cli.opt.lang"))
    parser.add_argument("-c", "--case", "--caso", dest="global_case", metavar="DIR", help=t("cli.opt.case"))
    parser.add_argument("-a", "--analyst", "--analista", dest="global_analyst", metavar="NAME",
                        help=t("cli.opt.analyst"))
    sub = parser.add_subparsers(dest="command", required=True, metavar=t("cli.command"))

    p = _add(sub, "new", "nuevo", "cli.cmd.new", cmd_new)
    p.add_argument("directory")
    p.add_argument("-n", "--name", "--nombre", required=True, help=t("cli.opt.name"))
    p.add_argument("-i", "--investigator", "--investigador", required=True, help=t("cli.opt.investigator"))
    p.add_argument("-d", "--description", "--descripcion", help=t("cli.opt.description"))
    p.add_argument("-r", "--reference", "--referencia", help=t("cli.opt.reference"))
    p.add_argument("-o", "--organization", "--organizacion", help=t("cli.opt.organization"))

    _add(sub, "info", "", "cli.cmd.info", cmd_info, [common])

    p = _add(sub, "evidence", "evidencia", "cli.cmd.evidence", lambda a: EXIT_ERROR)
    esub = p.add_subparsers(dest="action", required=True, metavar=t("cli.action"))
    e = _add(esub, "add", "agregar", "cli.cmd.evidence_add", cmd_evidence_add, [common])
    e.add_argument("path")
    e.add_argument("-d", "--description", "--descripcion", help=t("cli.opt.description"))
    e.add_argument("--copy", "--copiar", action="store_true", help=t("cli.opt.copy"))
    _add(esub, "list", "listar", "cli.cmd.evidence_list", cmd_evidence_list, [common])
    e = _add(esub, "verify", "verificar", "cli.cmd.evidence_verify", cmd_evidence_verify, [common])
    e.add_argument("id", nargs="?")

    _add(sub, "modules", "modulos", "cli.cmd.modules", cmd_modules)

    p = _add(sub, "analyze", "analizar", "cli.cmd.analyze", cmd_analyze, [common])
    p.add_argument("module")
    p.add_argument("evidence", help=t("cli.opt.evidence"))
    p.add_argument("-o", "--option", "--opcion", action="append", default=[], metavar="KEY=VALUE",
                   help=t("cli.opt.option"))

    p = _add(sub, "triage", "triaje", "cli.cmd.triage", cmd_triage, [common])
    p.add_argument("evidence")

    p = _add(sub, "auto", "", "cli.cmd.auto", cmd_auto, [common])
    p.add_argument("paths", nargs="+", metavar="EVIDENCE")
    p.add_argument("--new", "--nuevo", metavar="DIR", help=t("cli.opt.auto_new"))
    p.add_argument("-n", "--name", "--nombre", help=t("cli.opt.name"))
    p.add_argument("-i", "--investigator", "--investigador", help=t("cli.opt.investigator"))
    p.add_argument("-d", "--description", "--descripcion", help=t("cli.opt.description"))
    p.add_argument("-p", "--playbook", help=t("cli.opt.playbook"))
    p.add_argument("--copy", "--copiar", action="store_true", help=t("cli.opt.copy"))

    p = _add(sub, "watch", "vigilar", "cli.cmd.watch", cmd_watch)
    p.add_argument("inbox", metavar="FOLDER")
    p.add_argument("-w", "--workspace", "--espacio", help=t("cli.opt.workspace"))
    p.add_argument("-p", "--playbook", help=t("cli.opt.playbook"))
    p.add_argument("--interval", "--intervalo", type=float, default=15.0, help=t("cli.opt.interval"))
    p.add_argument("--once", "--una-vez", action="store_true", help=t("cli.opt.once"))

    p = _add(sub, "config", "configuracion", "cli.cmd.config", cmd_config)
    p.add_argument("action", nargs="?", choices=("show", "init", "path"), default="show", metavar="show|init|path")
    p.add_argument("path", nargs="?")
    p.add_argument("--force", "--forzar", action="store_true")

    p = _add(sub, "image", "imagen", "cli.cmd.image", cmd_image, [common])
    p.add_argument("evidence")
    p.add_argument("--verify", "--verificar", action="store_true", help=t("cli.opt.image_verify"))
    p.add_argument("--all-files", "--todo", action="store_true", help=t("cli.opt.image_all"))
    p.add_argument("-p", "--pattern", "--patron", action="append", default=[], help=t("cli.opt.image_pattern"))
    p.add_argument("--triage", "--triaje", action="store_true", help=t("cli.opt.image_triage"))
    p.add_argument("--vss", action="store_true", help=t("cli.opt.image_vss"))
    p.add_argument("--bitlocker-recovery", "--bitlocker-recuperacion", metavar="KEY|-",
                   help=t("cli.opt.bitlocker_recovery"))
    p.add_argument("--bitlocker-password", "--bitlocker-clave", metavar="PASSWORD|-",
                   help=t("cli.opt.bitlocker_password"))
    p.add_argument("--bitlocker-key", "--bitlocker-bek", metavar="FILE.BEK", help=t("cli.opt.bitlocker_key"))

    p = _add(sub, "collect", "recolectar", "cli.cmd.collect", cmd_collect, [common])
    p.add_argument("destination")
    p.add_argument("-s", "--source", "--origen", help=t("cli.opt.collect_source"))
    p.add_argument("--volatile", "--volatil", action="store_true", help=t("cli.opt.collect_volatile"))
    p.add_argument("--add-to-case", "--agregar-al-caso", action="store_true", help=t("cli.opt.collect_add"))
    p.add_argument("--copy", "--copiar", action="store_true", help=t("cli.opt.copy"))

    _add(sub, "analyses", "analisis", "cli.cmd.analyses", cmd_analyses, [common])

    p = _add(sub, "show", "mostrar", "cli.cmd.show", cmd_show, [common])
    p.add_argument("analysis", type=int)
    p.add_argument("--artifact", "--artefacto")
    p.add_argument("--search", "--buscar")
    p.add_argument("--limit", "--limite", type=int, default=50)

    p = _add(sub, "findings", "hallazgos", "cli.cmd.findings", cmd_findings, [common])
    p.add_argument("--min-severity", "--severidad", choices=("info", "low", "medium", "high", "critical"))
    p.add_argument("--status", "--estado", help="confirmed | false_positive | needs_review")

    p = _add(sub, "review", "revisar", "cli.cmd.review", cmd_review, [common])
    p.add_argument("finding", type=int)
    p.add_argument("status", help="confirmed/confirmado | false_positive/falso_positivo | needs_review/pendiente")
    p.add_argument("-n", "--note", "--nota", help=t("cli.opt.note"))

    p = _add(sub, "bookmark", "destacar", "cli.cmd.bookmark", cmd_bookmark, [common])
    p.add_argument("event", type=int)
    p.add_argument("-n", "--note", "--nota", help=t("cli.opt.note"))
    p.add_argument("--remove", "--quitar", action="store_true")

    p = _add(sub, "conclusions", "conclusiones", "cli.cmd.conclusions", cmd_conclusions, [common])
    group = p.add_mutually_exclusive_group()
    group.add_argument("--text", "--texto")
    group.add_argument("--file", "--archivo")

    p = _add(sub, "execution", "ejecucion", "cli.cmd.execution", cmd_execution, [common])
    p.add_argument("--search", "--buscar")
    p.add_argument("--suspicious", "--sospechosos", action="store_true", help=t("cli.opt.suspicious"))
    p.add_argument("--limit", "--limite", type=int, default=200)

    p = _add(sub, "attack", "mitre", "cli.cmd.attack", cmd_attack, [common])
    p.add_argument("--summary", "--resumen", action="store_true", help=t("cli.opt.attack_summary"))

    p = _add(sub, "timeline", "cronologia", "cli.cmd.timeline", cmd_timeline, [common])
    p.add_argument("--from", "--desde", dest="start")
    p.add_argument("--to", "--hasta", dest="end")
    p.add_argument("--search", "--buscar")
    p.add_argument("--source", "--fuente")
    p.add_argument("--min-severity", "--severidad", choices=("info", "low", "medium", "high", "critical"))
    p.add_argument("--bookmarked", "--destacados", action="store_true")
    p.add_argument("--limit", "--limite", type=int, default=100)

    p = _add(sub, "export", "exportar", "cli.cmd.export", cmd_export, [common])
    p.add_argument("what", choices=("analysis", "timeline", "findings", "execution", "stix", "custody"))
    p.add_argument("id", nargs="?", type=int)
    p.add_argument("-o", "--output", "--salida", required=True)
    p.add_argument("-f", "--format", "--formato", choices=("csv", "json"))

    p = _add(sub, "custody", "custodia", "cli.cmd.custody", cmd_custody, [common])
    p.add_argument("--verify", "--verificar", action="store_true")

    _add(sub, "verify", "verificar", "cli.cmd.verify", cmd_verify, [common])

    p = _add(sub, "report", "informe", "cli.cmd.report", cmd_report, [common])
    p.add_argument("-o", "--output", "--salida")
    p.add_argument("--verify", "--verificar", action="store_true", help=t("cli.opt.report_verify"))

    p = _add(sub, "sigma", "", "cli.cmd.sigma", cmd_sigma)
    p.add_argument("action", choices=("check", "download"), metavar="check|download")
    p.add_argument("path")
    p.add_argument("--min-level", "--nivel", choices=("info", "low", "medium", "high", "critical"))

    config = get_config()
    p = _add(sub, "web", "", "cli.cmd.web", cmd_web)
    p.add_argument("-w", "--workspace", "--espacio",
                   default=os.environ.get("FORENSE_WORKSPACE") or config.value("workspace") or ".",
                   help=t("cli.opt.workspace"))
    p.add_argument("--host", default=config.value("web.host") or "127.0.0.1")
    p.add_argument("--port", "--puerto", type=int, default=int(config.value("web.port") or 8765))
    p.add_argument("--password", "--clave", help=t("cli.opt.password"))

    p = _add(sub, "demo", "", "cli.cmd.demo", cmd_demo)
    p.add_argument("directory")
    p.add_argument("--no-case", "--sin-caso", action="store_true")
    p.add_argument("-a", "--analyst", "--analista", default=None, metavar="NAME", help=t("cli.opt.analyst"))
    return parser


def _extract_language(argv: list[str]) -> tuple[list[str], Optional[str]]:
    """Remove ``-L/--lang/--idioma`` wherever it appears so it works before or after the command."""
    rest: list[str] = []
    lang = None
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-L", "--lang", "--idioma") and i + 1 < len(argv) and argv[i + 1] in SUPPORTED:
            lang = argv[i + 1]
            i += 2
            continue
        if arg.startswith(("--lang=", "--idioma=")) and arg.split("=", 1)[1] in SUPPORTED:
            lang = arg.split("=", 1)[1]
        else:
            rest.append(arg)
        i += 1
    return rest, lang


def _extract_config(argv: list[str]) -> tuple[list[str], Optional[str]]:
    """Remove ``--config FILE`` wherever it appears (the configuration is needed before parsing)."""
    rest, path, i = [], None, 0
    while i < len(argv):
        if argv[i] in ("--config", "--configuracion") and i + 1 < len(argv):
            path = argv[i + 1]
            i += 2
            continue
        if argv[i].startswith(("--config=", "--configuracion=")):
            path = argv[i].split("=", 1)[1]
        else:
            rest.append(argv[i])
        i += 1
    return rest, path


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv, lang = _extract_language(list(sys.argv[1:] if argv is None else argv))
    argv, config_path = _extract_config(argv)
    try:
        config = load_config(Path(config_path) if config_path else None)
    except ForenseError as exc:
        _err(f"{t('common.error')}: {exc.message()}")
        config = Config(copy.deepcopy(DEFAULTS))
    set_config(config)
    if lang is None and not os.environ.get("FORENSE_LANG") and config.value("language") in SUPPORTED:
        lang = config.value("language")
    set_language(lang)  # None falls back to FORENSE_LANG / the system locale
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except (ValueError, OSError):
                pass
    parser = build_parser()
    args = parser.parse_args(argv)
    args.case_explicit = bool(getattr(args, "case", None) or args.global_case)
    if getattr(args, "case", None) is None:
        args.case = args.global_case or os.environ.get("FORENSE_CASE", ".")
    if getattr(args, "analyst", None) is None:
        args.analyst = args.global_analyst or config.value("analyst") or None
    args.lang = lang or get_language()
    try:
        return args.func(args)
    except ForenseError as exc:
        _err(f"{t('common.error')}: {exc.message()}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        _err(t("common.interrupted"))
        return 130
    except BrokenPipeError:  # output piped to e.g. `head`
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return EXIT_OK
    except OSError as exc:
        _err(f"{t('common.error')}: {exc}")
        return EXIT_ERROR
    except sqlite3.DatabaseError as exc:  # damaged or foreign case.db
        _err(f"{t('common.error')}: {t('error.case_database', error=str(exc))}")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
