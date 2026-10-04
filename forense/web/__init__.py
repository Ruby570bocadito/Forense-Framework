"""Web interface (Flask). Bilingual, local by default, every action logged in the chain of custody.

Security model: the server binds to 127.0.0.1 unless told otherwise, all
state-changing requests carry a CSRF token, an optional password enables HTTP
Basic authentication, and evidence is only ever read.
"""

from __future__ import annotations

import hmac
import math
import os
import re
import secrets
from pathlib import Path
from typing import Optional

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
    url_for,
)

from forense import __version__
from forense.core.case import Case
from forense.core.errors import ForenseError
from forense.core.utils import normalize_ts
from forense.i18n import SUPPORTED, detect_language, label, normalize, set_language, t
from forense.modules.base import SEVERITIES, available_modules, get_module
from forense.presentation import (
    SEVERITY_COLORS,
    artifact_label,
    custody_action_label,
    display_ts,
    event_type_label,
    finding_description,
    finding_title,
    format_value,
    severity_label,
    status_label,
)
from forense.web.jobs import JobManager

_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,99}$")
PAGE_SIZE = 100


def create_app(workspace: Path, password: Optional[str] = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("FORENSE_SECRET") or secrets.token_hex(32),
        WORKSPACE=Path(workspace).resolve(),
        PASSWORD=password,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )
    jobs = JobManager()
    app.extensions["forense_jobs"] = jobs
    _mark_interrupted(app.config["WORKSPACE"])

    # -- request lifecycle --------------------------------------------------------
    @app.before_request
    def _before() -> Optional[Response]:
        if app.config["PASSWORD"]:
            auth = request.authorization
            if not auth or not hmac.compare_digest(auth.password or "", app.config["PASSWORD"]):
                return Response(t("web.auth_required"), 401, {"WWW-Authenticate": 'Basic realm="Forense-Framework"'})
        lang = normalize(request.args.get("lang")) or normalize(request.cookies.get("lang")) or detect_language()
        set_language(lang)
        g.lang = lang
        g.analyst = request.cookies.get("analyst", "")
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        if request.method == "POST":
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(token, session["csrf"]):
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
            "_": lambda key, **params: t(key, lang, **params), "lang": lang, "languages": SUPPORTED,
            "csrf_token": session.get("csrf", ""), "version": __version__, "analyst": g.get("analyst", ""),
            "colors": SEVERITY_COLORS, "severities": SEVERITIES,
            "finding_title": lambda f: finding_title(f, lang),
            "finding_description": lambda f: finding_description(f, lang),
        }

    for name, func in {
        "ts": display_ts, "val": lambda v, limit=None: format_value(v, g.get("lang"), limit),
        "label": lambda f: label(f, g.get("lang")), "sev": lambda s: severity_label(s, g.get("lang")),
        "etype": lambda e: event_type_label(e, g.get("lang")), "artifact": lambda a: artifact_label(a, g.get("lang")),
        "action": lambda a: custody_action_label(a, g.get("lang")), "status": lambda s: status_label(s, g.get("lang")),
    }.items():
        app.jinja_env.filters[name] = func

    @app.errorhandler(ForenseError)
    def _forense_error(exc: ForenseError):
        flash(exc.message(g.get("lang")), "error")
        return redirect(request.referrer or url_for("index"))

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
        response = redirect(request.referrer or url_for("index"))
        response.set_cookie("analyst", request.form.get("analyst", "").strip()[:80], max_age=31536000,
                            samesite="Strict", httponly=True)
        return response

    # -- case pages ----------------------------------------------------------------------
    @app.route("/c/<slug>/")
    def dashboard(slug: str):
        with open_case(slug) as case:
            return render_template(
                "dashboard.html", slug=slug, case=case.info, stats=case.stats(), evidence=case.evidence_list(),
                analyses=case.analyses()[-8:][::-1], findings=case.findings(min_severity="medium")[:12])

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
                                   progress=lambda files, size: progress(f"{files} · {size} B"))
            return t("web.evidence_added", id=ev.id), ("evidence", {"slug": slug})

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
            results = case.triage(evidence_id, who, progress=progress)
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
            page = max(1, request.args.get("page", 1, type=int))
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
        severity = request.args.get("severity") or None
        with open_case(slug) as case:
            return render_template("findings.html", slug=slug, case=case.info,
                                   findings=case.findings(min_severity=severity), severity=severity)

    @app.route("/c/<slug>/timeline")
    def timeline(slug: str):
        filters = _timeline_filters()
        page = max(1, request.args.get("page", 1, type=int))
        with open_case(slug) as case:
            events = case.events(offset=(page - 1) * PAGE_SIZE, limit=PAGE_SIZE, **filters)
            filter_args = {k: request.args[k] for k in ("from", "to", "q", "source", "severity", "evidence")
                           if request.args.get(k)}
            return render_template("timeline.html", slug=slug, case=case.info, events=events, page=page,
                                   pages=max(1, math.ceil(events.total / PAGE_SIZE)), sources=case.event_sources(),
                                   args=request.args, filter_args=filter_args)

    @app.route("/c/<slug>/custody")
    def custody(slug: str):
        with open_case(slug) as case:
            return render_template("custody.html", slug=slug, case=case.info, entries=case.custody.entries(),
                                   problems=case.custody.verify(), head=case.custody.head())

    @app.route("/c/<slug>/reports")
    def reports(slug: str):
        directory = case_dir(slug) / "reports"
        files = sorted((p for p in directory.glob("*.html")), key=lambda p: p.stat().st_mtime, reverse=True) \
            if directory.exists() else []
        with open_case(slug) as case:
            return render_template("reports.html", slug=slug, case=case.info, files=files,
                                   jobs=jobs.active(slug))

    @app.post("/c/<slug>/reports")
    def generate(slug: str):
        report_lang = normalize(request.form.get("language")) or g.lang
        verify = request.form.get("verify") == "on"
        who = actor()

        def work(case: Case, progress) -> tuple[str, str]:
            from forense.report import generate_report

            progress(t("web.job.report"))
            path = generate_report(case, report_lang, verify=verify, actor=who)
            return t("cli.report_written", path=path.name), ("report_file", {"slug": slug, "name": path.name})

        submit(slug, "report", t("web.job.report"), work)
        return redirect(url_for("reports", slug=slug))

    @app.route("/c/<slug>/reports/<path:name>")
    def report_file(slug: str, name: str):
        return send_from_directory(case_dir(slug) / "reports", name)

    @app.post("/c/<slug>/export/<what>")
    def export(slug: str, what: str):
        from datetime import datetime, timezone

        from forense.core import exports

        fmt = "json" if what == "custody" else "csv"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        with open_case(slug) as case:
            exports_dir = case.root / "exports"
            if what == "timeline":
                path = exports.export_timeline(case, exports_dir / f"timeline_{stamp}.csv", fmt, g.lang, actor(),
                                               **_timeline_filters())
            elif what == "findings":
                path = exports.export_findings(case, exports_dir / f"findings_{stamp}.csv", fmt, g.lang, actor())
            elif what == "custody":
                path = exports.export_custody(case, exports_dir / f"custody_{stamp}.json", fmt, g.lang, actor())
            elif what.isdigit():
                path = exports.export_analysis(case, int(what), exports_dir / f"analysis_{what}_{stamp}.csv", fmt,
                                               g.lang, actor(), artifact=request.form.get("artifact") or None)
            else:
                abort(404)
        return send_from_directory(path.parent, path.name, as_attachment=True)

    # -- API ---------------------------------------------------------------------------
    @app.route("/api/jobs")
    def api_jobs():
        slug = request.args.get("case")
        result = []
        for job in jobs.list(slug)[:20]:
            item = job.as_dict()
            item["link"] = url_for(job.link[0], **job.link[1]) if job.link else ""
            result.append(item)
        return jsonify(result)

    return app


def _timeline_filters() -> dict:
    def ts(name: str) -> Optional[str]:
        value = request.args.get(name, "").strip()
        if not value:
            return None
        try:
            return normalize_ts(value)
        except ValueError:
            return None

    end = ts("to")
    if end and len(request.args.get("to", "").strip()) == 10:  # whole day
        end = end[:11] + "23:59:59.999999Z"
    return {"start": ts("from"), "end": end, "search": request.args.get("q", "").strip(),
            "source": request.args.get("source") or None, "min_severity": request.args.get("severity") or None,
            "evidence_id": request.args.get("evidence") or None}


def _safe_module(name: str):
    try:
        return get_module(name)
    except ForenseError:
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
    app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)
