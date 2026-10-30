"""Web interface (Flask). Bilingual, local by default, every action logged in the chain of custody.

Security model: the server binds to 127.0.0.1 unless told otherwise, all
state-changing requests carry a CSRF token, an optional password enables HTTP
Basic authentication, and evidence is only ever read.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import time
from datetime import timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    stream_with_context,
    url_for,
)
from werkzeug.exceptions import NotFound

from sabueso import __version__
from sabueso.core.case import Case
from sabueso.core.errors import CaseError, SabuesoError
from sabueso.core.utils import normalize_ts, range_end, stamped_path
from sabueso.i18n import SUPPORTED, detect_language, label, normalize, set_language, t
from sabueso.modules.base import SEVERITIES, available_modules, get_module
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
from sabueso.web import filters as filters_store
from sabueso.web.jobs import JobManager

_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,99}$")
PAGE_SIZE = 100
_BULK_LIMIT = 1000  # hard cap of findings per bulk review request


def create_app(workspace: Path, password: Optional[str] = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SABUESO_SECRET") or secrets.token_hex(32),
        WORKSPACE=Path(workspace).resolve(),
        PASSWORD=password,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        # Every route is a small HTML form (evidence is added by server-side path, never uploaded),
        # so any body larger than this is hostile buffering: fail with 413 instead of spooling it.
        MAX_CONTENT_LENGTH=1_048_576,
    )
    jobs = JobManager()
    app.extensions["sabueso_jobs"] = jobs
    _mark_interrupted(app.config["WORKSPACE"])

    # -- request lifecycle --------------------------------------------------------
    @app.before_request
    def _host_guard() -> Optional[Response]:
        """Reject DNS-rebinding hosts when running without a password.

        A page the analyst visits can rebind its own domain to 127.0.0.1 and, being
        then same-origin, read the case and harvest the CSRF token. Basic auth makes
        this moot (credentials are not replayed cross-origin), so the guard only runs
        in password-less mode and accepts loopback names and literal IPs (which
        cannot be rebound); any other DNS name is refused with 403. /healthz stays
        open (it exposes no data and container probes may use service DNS names).
        """
        if app.config["PASSWORD"] or request.path == "/healthz":
            return None
        name = urlsplit(f"http://{request.host or ''}").hostname or ""
        try:
            ipaddress.ip_address(name)
            return None  # literal IP: cannot be rebound
        except ValueError:
            pass
        if name in ("localhost", "127.0.0.1", "::1"):
            return None
        return Response(t("web.host_forbidden"), 403)

    @app.before_request
    def _before() -> Optional[Response]:
        if request.path == "/healthz":  # liveness probe (containers): no data, no authentication
            return None
        if app.config["PASSWORD"]:
            auth = request.authorization
            if not auth or not hmac.compare_digest((auth.password or "").encode("utf-8", "surrogatepass"),
                                                   app.config["PASSWORD"].encode("utf-8")):
                return Response(t("web.auth_required"), 401, {"WWW-Authenticate": 'Basic realm="Sabueso-Framework"'})
        lang = normalize(request.args.get("lang")) or normalize(request.cookies.get("lang")) or detect_language()
        set_language(lang)
        g.lang = lang
        g.analyst = request.cookies.get("analyst", "")
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        if request.method == "POST":
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(token.encode("utf-8", "surrogatepass"), session["csrf"].encode("utf-8")):
                abort(400, t("web.csrf_failed"))
        return None

    @app.after_request
    def _headers(response: Response) -> Response:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
        if request.args.get("lang") in SUPPORTED:
            response.set_cookie("lang", request.args["lang"], max_age=31536000, samesite="Strict")
        return response

    @app.context_processor
    def _globals() -> dict:
        lang = g.get("lang", "en")
        return {
            "_": lambda key, /, **params: t(key, lang, **params), "lang": lang, "languages": SUPPORTED,
            "csrf_token": session.get("csrf", ""), "version": __version__, "analyst": g.get("analyst", ""),
            "auth_enabled": bool(app.config["PASSWORD"]),
            "colors": SEVERITY_COLORS, "severities": SEVERITIES,
            "finding_title": lambda f: finding_title(f, lang),
            "finding_description": lambda f: finding_description(f, lang),
        }

    for name, func in {
        "ts": display_ts, "val": lambda v, limit=None: format_value(v, g.get("lang"), limit),
        "label": lambda f: label(f, g.get("lang")), "sev": lambda s: severity_label(s, g.get("lang")),
        "etype": lambda e: event_type_label(e, g.get("lang")), "artifact": lambda a: artifact_label(a, g.get("lang")),
        "action": lambda a: custody_action_label(a, g.get("lang")), "status": lambda s: status_label(s, g.get("lang")),
        "rule": lambda r: rule_label(r, g.get("lang")),
        "reject_keys": lambda d, *keys: {k: v for k, v in d.items() if k not in keys},
    }.items():
        app.jinja_env.filters[name] = func

    @app.errorhandler(OverflowError)
    def _too_large(_exc: OverflowError):  # an identifier too large for SQLite cannot exist
        return NotFound()

    @app.errorhandler(SabuesoError)
    def _sabueso_error(exc: SabuesoError):
        flash(exc.message(g.get("lang")), "error")
        return redirect(_back(url_for("index")))

    # -- helpers --------------------------------------------------------------------
    def case_dir(slug: str) -> Path:
        if not _SLUG.match(slug):
            abort(404)
        path = app.config["WORKSPACE"] / slug
        if path.parent != app.config["WORKSPACE"] or not Case.is_case(path):
            abort(404)
        return path

    def open_case(slug: str) -> Case:
        return Case.open(case_dir(slug))

    def actor() -> str:
        return g.get("analyst") or ""

    def submit(slug: str, kind: str, description: str, func) -> None:
        job = jobs.submit(case_dir(slug), slug, kind, description, func, g.lang)
        flash(t("web.job_started", description=description), "info")
        return job

    # -- workspace --------------------------------------------------------------------
    @app.route("/")
    def index():
        cases = []
        for path in sorted(p for p in app.config["WORKSPACE"].iterdir() if p.is_dir()):
            if Case.is_case(path):
                try:
                    with Case.open(path) as case:
                        cases.append({"slug": path.name, "info": case.info, "stats": case.stats()})
                except Exception:  # noqa: BLE001 - a broken case must not hide the others
                    cases.append({"slug": path.name, "info": {"name": path.name}, "stats": None})
        return render_template("index.html", cases=cases, workspace=app.config["WORKSPACE"])

    @app.route("/correlation")
    def correlation():
        from sabueso.core.correlation import KINDS, correlate, workspace_indexes

        kind = request.args.get("type") or None
        indexes = workspace_indexes(app.config["WORKSPACE"])
        shared = correlate(indexes)
        counts = {k: sum(1 for s in shared if s.kind == k) for k in KINDS}
        def source_label(source: str) -> str:
            if source.startswith("evtx_"):
                return f"EVTX {source[5:]}"
            return t(f"correlation.source.{source}", g.lang)

        return render_template("correlation.html", indexes=indexes, kinds=KINDS, kind=kind, counts=counts,
                               source_label=source_label,
                               shared=[s for s in shared if kind is None or s.kind == kind], total=len(shared),
                               iocs=sum(1 for s in shared if s.ioc))

    @app.post("/cases")
    def create_case():
        slug = request.form.get("slug", "").strip()
        if not _SLUG.match(slug):
            flash(t("web.invalid_slug"), "error")
            return redirect(url_for("index"))
        with Case.create(app.config["WORKSPACE"] / slug, request.form.get("name", ""),
                         request.form.get("investigator", ""), request.form.get("description", ""),
                         request.form.get("reference", ""), request.form.get("organization", "")):
            pass
        return redirect(url_for("dashboard", slug=slug))

    @app.post("/analyst")
    def set_analyst():
        response = redirect(_back(url_for("index")))
        response.set_cookie("analyst", request.form.get("analyst", "").strip()[:80], max_age=31536000,
                            samesite="Strict", httponly=True)
        return response

    # -- case pages ----------------------------------------------------------------------
    def _chart_labels() -> dict:
        lang = g.get("lang")
        labels = {s: severity_label(s, lang) for s in SEVERITIES}
        labels.update(title=t("web.activity", lang), events=t("report.events", lang),
                      flagged=t("web.alerts", lang), findings=t("report.findings", lang).capitalize(),
                      techniques=t("web.techniques", lang))
        return labels

    def _shared_with_other_cases(slug: str) -> Optional[list]:
        """Observables of this case seen in other cases (only cached indexes of the others: never slow)."""
        from sabueso.core.correlation import correlate, index_case, workspace_indexes

        workspace = app.config["WORKSPACE"]
        try:
            others = [i for i in workspace_indexes(workspace, build=False) if i.slug != slug]
            if not others:
                return None
            current = index_case(case_dir(slug), workspace)
            return correlate([current, *others], focus=slug)[:8] if current else None
        except Exception:  # noqa: BLE001 - correlation is a convenience: it must never break the dashboard
            return None

    @app.route("/c/<slug>/")
    def dashboard(slug: str):
        from sabueso.charts import activity_chart, severity_bar, tactic_bars
        from sabueso.core.execution import execution_overview
        from sabueso.core.overview import case_overview

        with open_case(slug) as case:
            overview = case_overview(case)
            labels = _chart_labels()
            points = [{"timestamp": f["timestamp"], "severity": f["severity"],
                       "label": f"{severity_label(f['severity'], g.lang)} · {finding_title(f, g.lang)}"}
                      for f in overview["findings"] if f["severity"] in ("medium", "high", "critical")]
            charts = {
                "activity": activity_chart(overview["buckets"], overview["unit"], points, labels,
                                           link=url_for("timeline", slug=slug)) if overview["buckets"] else "",
                "severity": severity_bar(overview["severity_counts"], labels),
                "tactics": tactic_bars([(t(f"tactic.{name}", g.lang), count)
                                        for name, count in overview["tactic_rows"]], labels),
            }
            return render_template(
                "dashboard.html", slug=slug, case=case.info, stats=case.stats(), evidence=case.evidence_list(),
                findings=[f for f in overview["findings"] if f["severity"] in ("medium", "high", "critical")][:10],
                progress=case.review_progress(), overview=overview, charts=charts,
                suspicious_programs=len(execution_overview(case, suspicious=True)),
                shared=_shared_with_other_cases(slug))

    @app.route("/c/<slug>/attack")
    def attack(slug: str):
        from sabueso.core.attack import TACTICS, attack_matrix, draft_summary, storyline

        with open_case(slug) as case:
            findings = case.findings()
            matrix = attack_matrix(findings)
            maximum = max((len(h.findings) for hits in matrix.values() for h in hits), default=1)
            steps = [max(1, round(maximum * i / 5)) for i in range(1, 6)]

            def level(count: int) -> int:
                return next((i + 1 for i, top in enumerate(steps) if count <= top), 5)

            legend = []
            low = 1
            for top in steps:
                legend.append(str(low) if top <= low else f"{low}–{top}")
                low = top + 1
            return render_template("attack.html", slug=slug, case=case.info, matrix=matrix, tactics=TACTICS,
                                   phases=storyline(findings), draft=draft_summary(findings, g.lang), level=level,
                                   legend=legend, techniques=len({h.technique for hits in matrix.values()
                                                                  for h in hits}))

    @app.post("/c/<slug>/auto")
    def auto_analysis(slug: str):
        from sabueso.automation import BUILTIN_PLAYBOOKS
        from sabueso.core.config import get_config

        evidence_id = request.form.get("evidence", "")
        playbook = request.form.get("playbook", "")  # only the built-in ones from the browser
        if playbook not in BUILTIN_PLAYBOOKS:
            playbook = get_config().value("automation.playbook") or "full"
        who = actor()

        def work(case: Case, progress) -> tuple[str, str]:
            from sabueso.automation import load_playbook, run_playbook
            from sabueso.core.config import get_config

            config = get_config()
            steps = load_playbook(playbook)
            progress.metrics(total=len(steps))
            result = run_playbook(case, [evidence_id], steps, config, who, progress)
            failed = sum(1 for step in result.steps if step.status == "failed")
            return t("web.auto_done", steps=len(result.steps), failed=failed), ("dashboard", {"slug": slug})

        submit(slug, "auto", t("web.job.auto", evidence=evidence_id), work)
        return redirect(url_for("dashboard", slug=slug))

    @app.route("/c/<slug>/evidence")
    def evidence(slug: str):
        with open_case(slug) as case:
            return render_template("evidence.html", slug=slug, case=case.info, evidence=case.evidence_list(),
                                   verifications=case.last_verifications())

    @app.post("/c/<slug>/evidence")
    def add_evidence(slug: str):
        path = request.form.get("path", "").strip()
        description = request.form.get("description", "")
        copy = request.form.get("copy") == "on"
        who = actor()

        def work(case: Case, progress) -> tuple[str, str]:
            ev = case.add_evidence(Path(path), description, copy, who,
                                   progress=lambda files, size: progress.metrics(done=files,
                                                                                 stage=f"{files} · {size} B"))
            message = t("web.evidence_added", id=ev.id)
            if ev.duplicate_of:  # H-005 residual: the web announces the twin just like the CLI does
                message += " " + t("web.evidence_duplicate", id=ev.duplicate_of,
                                   hash=ev.hashes.get("sha256", ""))
            return message, ("evidence", {"slug": slug})

        submit(slug, "evidence", t("web.job.evidence", path=path), work)
        return redirect(url_for("evidence", slug=slug))

    @app.post("/c/<slug>/evidence/<evidence_id>/verify")
    def verify_evidence(slug: str, evidence_id: str):
        who = actor()

        def work(case: Case, progress) -> tuple[str, str]:
            result = case.verify_evidence(evidence_id, who)
            return t("verify.result.ok" if result.ok else "verify.result.mismatch"), ("evidence", {"slug": slug})

        submit(slug, "verify", t("web.job.verify", id=evidence_id), work)
        return redirect(url_for("evidence", slug=slug))

    @app.route("/c/<slug>/analyses")
    def analyses(slug: str):
        with open_case(slug) as case:
            return render_template("analyses.html", slug=slug, case=case.info, analyses=case.analyses()[::-1],
                                   evidence=case.evidence_list(), modules=available_modules(),
                                   jobs=jobs.active(slug))

    @app.post("/c/<slug>/analyses")
    def run_analysis(slug: str):
        module_name = request.form.get("module", "")
        evidence_id = request.form.get("evidence", "")
        module = get_module(module_name)
        prefix = f"opt_{module.name}_"
        options = {k[len(prefix):]: v for k, v in request.form.items() if k.startswith(prefix) and v.strip()}
        module.parse_options(options)  # validate now so errors show immediately
        who = actor()

        def work(case: Case, progress) -> tuple[str, str]:
            analysis = case.run_analysis(module.name, evidence_id, options, who, progress=progress)
            return (t("web.analysis_done", id=analysis.id, findings=analysis.finding_count),
                    ("analysis", {"slug": slug, "analysis_id": analysis.id}))

        submit(slug, "analysis", t("web.job.analysis", module=module.title(g.lang), evidence=evidence_id), work)
        return redirect(url_for("analyses", slug=slug))

    @app.post("/c/<slug>/triage")
    def triage(slug: str):
        evidence_id = request.form.get("evidence", "")
        who = actor()

        def work(case: Case, progress) -> tuple[str, str]:
            from sabueso.i18n import get_language
            from sabueso.image import evidence_kind

            titles = {m.name: m.title(get_language()) for m in available_modules() if m.triage}
            kind = evidence_kind(case.disk_path(case.get_evidence(evidence_id).path))
            if kind in ("memory", "volatility"):
                progress.metrics(total=1)
            elif kind == "disk_image":
                progress.metrics(total=1 + len(titles))  # the extraction, then every triage module
            else:
                progress.metrics(total=len(titles))

            def checkpoints(name: str) -> None:
                if name in titles or name in ("image", "memory"):  # triage's own progress points
                    progress.checkpoint(name, title=titles.get(name, name))
                else:  # nested text from the extraction or a module: snapshot, not a count
                    progress(name)

            results = case.triage(evidence_id, who, progress=checkpoints)
            done = sum(1 for _, a, _ in results if a is not None)
            return t("web.triage_done", modules=done), ("findings", {"slug": slug})

        submit(slug, "triage", t("web.job.triage", evidence=evidence_id), work)
        return redirect(url_for("analyses", slug=slug))

    @app.route("/c/<slug>/analyses/<int:analysis_id>")
    def analysis(slug: str, analysis_id: int):
        with open_case(slug) as case:
            item = case.get_analysis(analysis_id)
            artifacts = case.record_artifacts(item.id)
            artifact = request.args.get("artifact") or (artifacts[0][0] if artifacts else None)
            search = request.args.get("q", "")
            page = min(max(1, request.args.get("page", 1, type=int)), 1_000_000)
            records = case.records(item.id, artifact=artifact, search=search, offset=(page - 1) * PAGE_SIZE,
                                   limit=PAGE_SIZE)
            columns = list(dict.fromkeys(k for _, row in records.rows for k in row))
            return render_template(
                "analysis.html", slug=slug, case=case.info, analysis=item, module=_safe_module(item.module),
                artifacts=artifacts, artifact=artifact, records=records, columns=columns, search=search,
                page=page, pages=max(1, math.ceil(records.total / PAGE_SIZE)),
                findings=case.findings(analysis_id=item.id), results_ok=case.verify_results(item.id)
                if item.status == "completed" else None)

    @app.post("/c/<slug>/analyses/<int:analysis_id>/delete")
    def delete_analysis(slug: str, analysis_id: int):
        with open_case(slug) as case:
            case.delete_analysis(analysis_id, actor())
        flash(t("web.analysis_deleted", id=analysis_id), "info")
        return redirect(url_for("analyses", slug=slug))

    @app.route("/c/<slug>/findings")
    def findings(slug: str):
        from sabueso.core.attack import techniques_for

        severity = request.args.get("severity") or None
        status = request.args.get("status") or None
        technique = request.args.get("technique") or None
        page = min(max(1, request.args.get("page", 1, type=int)), 1_000_000)
        filter_args = {k: request.args[k] for k in ("severity", "status", "technique") if request.args.get(k)}
        with open_case(slug) as case:
            items = case.findings(min_severity=severity, review_status=status)
            if technique:
                for item in items:
                    item["techniques"] = techniques_for(item)
                items = [f for f in items if technique in f["techniques"]]
            total = len(items)
            rows = items[(page - 1) * PAGE_SIZE:page * PAGE_SIZE]
            if not technique:  # only the visible page needs its ATT&CK techniques
                for item in rows:
                    item["techniques"] = techniques_for(item)
            return render_template("findings.html", slug=slug, case=case.info, severity=severity, status=status,
                                   technique=technique, findings=rows, total=total, page=page,
                                   pages=max(1, math.ceil(total / PAGE_SIZE)), filter_args=filter_args,
                                   progress=case.review_progress(),
                                   saved=filters_store.parsed(filters_store.load(case.root), "findings"))

    @app.post("/c/<slug>/findings/<int:finding_id>/review")
    def review_finding(slug: str, finding_id: int):
        with open_case(slug) as case:
            case.review_finding(finding_id, request.form.get("status", ""), request.form.get("note", ""), actor())
        flash(t("web.review_saved"), "info")
        return redirect(_back(url_for("findings", slug=slug)) + f"#f{finding_id}")

    @app.post("/c/<slug>/findings/bulk-review")
    def bulk_review(slug: str):
        """Apply one review status (and optional note) to several findings at once.

        Every finding is still reviewed individually through Case.review_finding, so the
        custody trail keeps one entry per finding, with actor and UTC timestamp.
        """
        from sabueso.core.review import FINDING_STATUSES, normalize_status

        ids: list[int] = []
        for raw in request.form.getlist("ids"):
            if raw.isascii() and raw.isdigit() and len(raw) < 12:
                value = int(raw)
                if value not in ids:
                    ids.append(value)
        ids = ids[:_BULK_LIMIT]
        status = request.form.get("status", "")
        note = request.form.get("note", "").strip()
        # Fail loudly on an invalid status instead of silently skipping the whole batch.
        if normalize_status(status) not in FINDING_STATUSES:
            raise CaseError("error.review_status", status=status, allowed=", ".join(FINDING_STATUSES))
        if not ids:
            flash(t("web.bulk_none"), "warn")
            return redirect(_back(url_for("findings", slug=slug)))
        done = failed = 0
        with open_case(slug) as case:
            for finding_id in ids:
                try:
                    case.review_finding(finding_id, status, note, actor())
                    done += 1
                except CaseError:  # a finding deleted between render and submit must not sink the batch
                    failed += 1
        flash(t("web.bulk_partial", done=done, failed=failed) if failed else t("web.bulk_done", done=done),
              "warn" if failed else "info")
        return redirect(_back(url_for("findings", slug=slug, **request.args)))

    @app.post("/c/<slug>/filters/save")
    def save_filter(slug: str):
        """Save the current findings/timeline filters under a name, for one-click reuse."""
        page = request.form.get("page", "")
        if page not in filters_store.PAGES:  # only our own forms post here; anything else is forged
            abort(404)
        with open_case(slug) as case:
            try:
                filters_store.save(case.root, page, request.form.get("name", ""),
                                   request.form.get("query", ""), actor())
            except SabuesoError as exc:  # user input problem: warn and return, not an error page
                flash(exc.message(g.lang), "warn")
            else:
                flash(t("web.filters_saved", name=request.form.get("name", "").strip()[:80]), "info")
        return redirect(_back(url_for(page if page in filters_store.PAGES else "findings", slug=slug)))

    @app.post("/c/<slug>/filters/<filter_id>/delete")
    def delete_filter(slug: str, filter_id: str):
        if not re.fullmatch(r"[0-9a-f]{8}", filter_id):
            abort(404)
        with open_case(slug) as case:
            filters_store.delete(case.root, filter_id)
        flash(t("web.filters_deleted"), "info")
        return redirect(_back(url_for("findings", slug=slug)))

    @app.post("/c/<slug>/events/<int:event_id>/bookmark")
    def bookmark_event(slug: str, event_id: int):
        with open_case(slug) as case:
            case.bookmark_event(event_id, request.form.get("note", ""), actor(),
                                remove=request.form.get("remove") == "1")
        return redirect(_back(url_for("timeline", slug=slug)) + f"#e{event_id}")

    @app.route("/c/<slug>/conclusions", methods=["GET", "POST"])
    def conclusions(slug: str):
        with open_case(slug) as case:
            if request.method == "POST":
                text = request.form.get("text", "")
                if not text.strip():
                    raise SabuesoError("error.conclusions_empty")
                saved = case.set_conclusions(text, actor())
                flash(t("web.conclusions_saved", version=saved["version"]), "info")
                return redirect(url_for("conclusions", slug=slug))
            return render_template("conclusions.html", slug=slug, case=case.info, current=case.conclusions(),
                                   history=case.conclusions_history(), progress=case.review_progress())

    @app.route("/c/<slug>/timeline")
    def timeline(slug: str):
        filters = _timeline_filters()
        page = min(max(1, request.args.get("page", 1, type=int)), 1_000_000)
        with open_case(slug) as case:
            events = case.events(offset=(page - 1) * PAGE_SIZE, limit=PAGE_SIZE, **filters)
            filter_args = {k: request.args[k] for k in ("from", "to", "q", "source", "severity", "evidence",
                                                        "bookmarked") if request.args.get(k)}
            chart = _timeline_chart(case, slug, filters, filter_args) if events.total else ""
            return render_template("timeline.html", slug=slug, case=case.info, events=events, page=page,
                                   pages=max(1, math.ceil(events.total / PAGE_SIZE)), sources=case.event_sources(),
                                   args=request.args, filter_args=filter_args, chart=chart,
                                   saved=filters_store.parsed(filters_store.load(case.root), "timeline"))

    def _timeline_chart(case: Case, slug: str, filters: dict, filter_args: dict):
        """Events over time for the current filters; each bar narrows the timeline to its interval."""
        from sabueso.charts import activity_chart, bucketize
        from sabueso.core.overview import _parse

        rows, first, last, resolution = case.event_histogram(**filters)
        start = _parse(filters.get("start")) or _parse(first)
        end = _parse(filters.get("end")) or _parse(last)
        if not rows or start is None or end is None:
            return ""
        if end <= start:
            end = start + timedelta(hours=1)
        buckets, unit = bucketize(rows, start, end, min_seconds=min(resolution, 3600) if resolution < 86400 else 86400)
        findings = [{"timestamp": f["timestamp"], "severity": f["severity"],
                     "label": f"{severity_label(f['severity'], g.lang)} · {finding_title(f, g.lang)}"}
                    for f in case.findings() if f["severity"] in ("medium", "high", "critical") and f.get("timestamp")
                    and (f.get("review") or {}).get("status") != "false_positive"]
        others = {k: v for k, v in filter_args.items() if k not in ("from", "to")}
        return activity_chart(buckets, unit, findings, _chart_labels(), link=url_for("timeline", slug=slug, **others))

    @app.route("/c/<slug>/search")
    def search(slug: str):
        from sabueso.core.search import search_case

        query = request.args.get("q", "").strip()[:200]
        with open_case(slug) as case:
            results = search_case(case, query, g.lang)
            return render_template("search.html", slug=slug, case=case.info, query=query, results=results)

    @app.route("/c/<slug>/execution")
    def execution(slug: str):
        from sabueso.core.execution import execution_overview

        search = request.args.get("q", "")
        suspicious = request.args.get("suspicious") == "1"
        page = min(max(1, request.args.get("page", 1, type=int)), 1_000_000)
        with open_case(slug) as case:
            programs = execution_overview(case, search, suspicious)
            total = len(programs)
            return render_template("execution.html", slug=slug, case=case.info,
                                   programs=programs[(page - 1) * PAGE_SIZE:page * PAGE_SIZE], total=total,
                                   page=page, pages=max(1, math.ceil(total / PAGE_SIZE)), args=request.args,
                                   filter_args={k: v for k, v in (("q", search), ("suspicious", "1" if suspicious
                                                                                       else "")) if v})

    @app.route("/c/<slug>/custody")
    def custody(slug: str):
        with open_case(slug) as case:
            return render_template("custody.html", slug=slug, case=case.info, entries=case.custody.entries(),
                                   problems=case.custody.verify(), head=case.custody.head())

    @app.route("/c/<slug>/reports")
    def reports(slug: str):
        directory = case_dir(slug) / "reports"
        files = sorted((p for p in directory.iterdir() if p.suffix in (".html", ".pdf")),
                       key=lambda p: p.stat().st_mtime, reverse=True) if directory.exists() else []
        signed = {p.name[:-4] for p in directory.glob("*.sig")} if directory.exists() else set()
        with open_case(slug) as case:
            from sabueso.core.hashing import hash_file
            from sabueso.report.pdf import find_browser
            from sabueso.report.signing import signing_key_path

            recorded: dict[str, str] = {}
            for entry in case.custody.entries():
                if entry.action in ("report_generated", "report_pdf_generated"):
                    name = Path(str(entry.details.get("file", "")).replace("\\", "/")).name
                    if name:
                        recorded[name] = str(entry.details.get("sha256", ""))
            items = [{"path": f, "name": f.name, "size": f.stat().st_size,
                      "sha256": hash_file(f, ("sha256",))["sha256"], "recorded": recorded.get(f.name),
                      "signed": f.name in signed} for f in files]
            return render_template("reports.html", slug=slug, case=case.info, files=items, signed=signed,
                                   jobs=jobs.active(slug), pdf_available=bool(find_browser()),
                                   sign_available=bool(signing_key_path()))

    @app.post("/c/<slug>/reports")
    def generate(slug: str):
        from sabueso.report import OPTIONAL_SECTIONS

        report_lang = normalize(request.form.get("language")) or g.lang
        verify = request.form.get("verify") == "on"
        pdf = request.form.get("pdf") == "on"
        sign = request.form.get("sign") == "on"
        if request.form.get("sections_form"):  # the UI form: whatever it checked (even nothing)
            include = {s for s in OPTIONAL_SECTIONS if request.form.get(f"section_{s}") == "on"}
        else:  # callers without a section picker keep the full report
            include = None
        confirmed_only = request.form.get("confirmed") == "on"
        expert = request.form.get("expert") == "on"
        scope = (request.form.get("scope") or "").strip()[:4000]
        try:
            max_findings = min(max(0, int(request.form.get("max_findings") or 0)), 1_000_000)
        except ValueError:
            max_findings = 0
        who = actor()

        def work(case: Case, progress) -> tuple[str, str]:
            from sabueso.report import generate_report

            progress(t("web.job.report"))
            path = generate_report(case, report_lang, verify=verify, actor=who, sign=sign, include=include,
                                   confirmed_only=confirmed_only, max_findings=max_findings, expert=expert,
                                   scope=scope)
            if pdf:
                from sabueso.report.pdf import html_to_pdf

                progress("PDF")
                path = html_to_pdf(path, case=case, actor=who, sign=sign)
            return t("cli.report_written", path=path.name), ("report_file", {"slug": slug, "name": path.name})

        submit(slug, "report", t("web.job.report"), work)
        return redirect(url_for("reports", slug=slug))

    @app.route("/c/<slug>/reports/<path:name>")
    def report_file(slug: str, name: str):
        return send_from_directory(case_dir(slug) / "reports", name)

    @app.post("/c/<slug>/reports/<path:name>/verify-signature")
    def verify_signature(slug: str, name: str):
        from sabueso.report.signing import record_verification, verify_file

        path = case_dir(slug) / "reports" / name
        if Path(name).name != name or path.suffix not in (".html", ".pdf") or not path.is_file():
            abort(404)
        try:
            ok = verify_file(path)
            failure = ""
        except SabuesoError as exc:
            ok, failure = False, f" ({exc.message(g.lang)})"
        with open_case(slug) as case:
            record_verification(case, path, actor(), ok)
        flash(t("web.report_signature_ok" if ok else "web.report_signature_bad", name=name, error=failure),
              "info" if ok else "error")
        return redirect(url_for("reports", slug=slug))

    @app.post("/c/<slug>/export/<what>")
    def export(slug: str, what: str):
        from sabueso.core import exports

        fmt = "json" if what == "custody" else "csv"
        with open_case(slug) as case:
            exports_dir = case.root / "exports"
            if what == "timeline":
                path = exports.export_timeline(case, stamped_path(exports_dir, "timeline", ".csv"), fmt, g.lang, actor(),
                                               **_timeline_filters())
            elif what == "timeline_html":
                from sabueso.report.timeline_html import export_timeline_html

                path = export_timeline_html(case, stamped_path(exports_dir, "timeline", ".html"), g.lang, actor(),
                                            **_timeline_filters())
            elif what == "findings_html":
                from sabueso.report.findings_html import export_findings_html

                path = export_findings_html(case, stamped_path(exports_dir, "findings", ".html"), g.lang, actor(),
                                            **_findings_filters())
            elif what == "findings":
                path = exports.export_findings(case, stamped_path(exports_dir, "findings", ".csv"), fmt, g.lang, actor())
            elif what == "execution":
                path = exports.export_execution(case, stamped_path(exports_dir, "execution", ".csv"), fmt, g.lang, actor(),
                                                search=request.args.get("q", ""),
                                                suspicious=request.args.get("suspicious") == "1")
            elif what == "stix":
                from sabueso.core.stix import export_stix

                path = export_stix(case, stamped_path(exports_dir, "iocs", ".stix.json"), actor())
            elif what == "custody":
                path = exports.export_custody(case, stamped_path(exports_dir, "custody", ".json"), fmt, g.lang, actor())
            elif what.isascii() and what.isdigit() and len(what) < 12:
                path = exports.export_analysis(case, int(what), stamped_path(exports_dir, f"analysis_{what}", ".csv"), fmt,
                                               g.lang, actor(), artifact=request.form.get("artifact") or None)
            else:
                abort(404)
        return send_from_directory(path.parent, path.name, as_attachment=True)

    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok"})

    # -- API ---------------------------------------------------------------------------
    @app.route("/api/jobs")
    def api_jobs():
        slug = request.args.get("case")
        result = []
        for job in jobs.list(slug)[:20]:
            item = job.as_dict()
            item["link"] = url_for(job.link[0], **job.link[1]) if job.link else ""
            item["cancellable"] = job.cancellable()
            result.append(item)
        return jsonify(result)

    @app.route("/api/jobs/stream")
    def api_jobs_stream():
        """Server-Sent Events feed of the job queue: one snapshot per second while there
        is activity. The stream ends when the queue is idle and the client falls back to
        plain polling of /api/jobs, so idle workspaces hold no connections."""
        slug = request.args.get("case")

        def stream():
            def snapshot() -> str:
                result = []
                for job in jobs.list(slug)[:20]:
                    item = job.as_dict()
                    item["link"] = url_for(job.link[0], **job.link[1]) if job.link else ""
                    item["cancellable"] = job.cancellable()
                    result.append(item)
                return "data: " + json.dumps(result) + "\n\n"

            idle = 0
            for _ in range(300):  # ~5 minutes per connection; EventSource reconnects on its own
                yield snapshot()
                idle = idle + 1 if not jobs.active(slug) else 0
                if idle >= 2:
                    return
                time.sleep(1)

        return Response(stream_with_context(stream()), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    @app.post("/c/<slug>/jobs/<job_id>/cancel")
    def cancel_job(slug: str, job_id: str):
        """Cancel a background job. Queued ones never start; triage and playbook jobs
        stop at their next checkpoint, so a running module is never cut in half."""
        job = jobs.get(job_id)
        if job is None or job.case != slug:
            flash(t("web.job_cancel_gone"), "error")
        else:
            outcome = jobs.cancel(job_id)
            if outcome == "queued":
                flash(t("web.job_cancel_queued"))
            elif outcome == "requested":
                flash(t("web.job_cancel_requested"))
            elif outcome == "unavailable":
                flash(t("web.job_cancel_unavailable"), "error")
            else:  # finished between the lookup and the cancel
                flash(t("web.job_cancel_gone"), "error")
        return redirect(_back(url_for("analyses", slug=slug)))

    return app


def _back(default: str) -> str:
    """Return to the referring page of this same site (never to an external URL)."""
    ref = (request.referrer or "").split("#")[0]
    return ref if ref.startswith(request.host_url) else default


def _timeline_filters() -> dict:
    def ts(name: str, parse=normalize_ts) -> Optional[str]:
        value = request.args.get(name, "").strip()
        if not value:
            return None
        try:
            return parse(value)
        except (ValueError, OverflowError):
            return None

    return {"start": ts("from"), "end": ts("to", range_end), "search": request.args.get("q", "").strip(),
            "source": request.args.get("source") or None, "min_severity": request.args.get("severity") or None,
            "evidence_id": request.args.get("evidence") or None, "bookmarked": request.args.get("bookmarked") == "1"}


def _findings_filters() -> dict:
    """Non-empty findings-page filters (severity, review status, ATT&CK technique)."""
    return {k: request.args[k] for k in ("severity", "status", "technique") if request.args.get(k)}


def _safe_module(name: str):
    try:
        return get_module(name)
    except SabuesoError:
        return None


def _mark_interrupted(workspace: Path) -> None:
    if not workspace.exists():
        return
    for path in workspace.iterdir():
        if path.is_dir() and Case.is_case(path):
            try:
                with Case.open(path) as case:
                    case.mark_interrupted()
            except Exception:  # noqa: BLE001
                continue


def run_server(workspace: Path, host: str = "127.0.0.1", port: int = 8765, password: Optional[str] = None) -> None:
    app = create_app(workspace, password)
    print(t("web.listening", url=f"http://{host}:{port}/", workspace=str(workspace)))
    try:
        from waitress import serve
    except ImportError:  # a source checkout without the dependency installed: Flask's own server still works
        app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)
        return
    serve(app, host=host, port=port, threads=8, ident="Sabueso")
