"""Notifications when automated analysis finishes: Microsoft Teams, Slack, Discord, Mattermost or plain JSON.

Configured in ``notify.webhook`` (an incoming-webhook URL). The message carries
the case, the outcome of each step and the most severe findings. Every message
sent is recorded in the case's chain of custody with the destination host (not
the URL, which usually contains a secret token).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Optional
from urllib.parse import urlparse

from forense import __version__
from forense.core.errors import ForenseError
from forense.i18n import t

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def detect_format(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    if host.endswith("hooks.slack.com") or urlparse(url).path.startswith("/hooks/"):
        return "slack"  # Slack and Slack-compatible (Mattermost, Rocket.Chat)
    if host.endswith(("webhook.office.com", "logic.azure.com", "office.com")) or "powerautomate" in host:
        return "teams"
    if host.endswith(("discord.com", "discordapp.com")):
        return "discord"
    return "json"


def summary(case, result, min_severity: str = "high", lang: Optional[str] = None) -> dict:
    """Facts about a finished automation run, used to build the message."""
    from forense.presentation import finding_title, severity_label

    threshold = SEVERITY_ORDER.index(min_severity) if min_severity in SEVERITY_ORDER else 3
    findings = case.findings()
    counts = {s: 0 for s in SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    top = [f for f in findings if SEVERITY_ORDER.index(f["severity"]) >= threshold][:8]
    failed = [s for s in result.steps if s.status == "failed"]
    info = case.info
    return {
        "case": info.get("name", ""), "case_id": info.get("id", ""), "path": str(case.root),
        "status": "failed" if failed else "ok", "evidence": list(result.evidence),
        "steps": [{"step": s.step, "status": s.status, "detail": s.detail} for s in result.steps],
        "findings": counts, "total_findings": len(findings),
        "top_findings": [{"id": f["id"], "severity": f["severity"], "severity_label": severity_label(f["severity"], lang),
                          "title": finding_title(f, lang), "timestamp": f.get("timestamp")} for f in top],
        "reports": [str(p) for p in result.reports], "exports": [str(p) for p in result.exports],
    }


def render_text(facts: dict, lang: Optional[str] = None, markdown: bool = True) -> str:
    bold = (lambda s: f"**{s}**") if markdown else (lambda s: s)
    status = t("notify.status_failed" if facts["status"] == "failed" else "notify.status_ok", lang)
    lines = [f"{bold(t('notify.title', lang, case=facts['case']))} ({facts['case_id']}) — {status}"]
    counts = facts["findings"]
    lines.append(t("notify.findings", lang, total=facts["total_findings"], critical=counts.get("critical", 0),
                   high=counts.get("high", 0), medium=counts.get("medium", 0)))
    for finding in facts["top_findings"]:
        lines.append(f"- [{finding['severity_label'].upper()}] {finding['title']}")
    failed = [s for s in facts["steps"] if s["status"] == "failed"]
    for step in failed:
        lines.append(f"- {t('notify.failed_step', lang)} {step['step']}: {step['detail']}")
    if facts["reports"]:
        lines.append(t("notify.report", lang, path=facts["reports"][0]))
    lines.append(t("notify.path", lang, path=facts["path"]))
    return "\n".join(lines)


def payload(facts: dict, fmt: str, lang: Optional[str] = None) -> dict:
    text = render_text(facts, lang, markdown=fmt != "json")
    if fmt == "slack":
        return {"text": text.replace("**", "*")}
    if fmt == "teams":
        return {"@type": "MessageCard", "@context": "https://schema.org/extensions", "summary": facts["case"],
                "themeColor": "B42318" if facts["status"] == "failed" or facts["findings"].get("critical") else "1F5F99",
                "text": text.replace("\n", "\n\n")}
    if fmt == "discord":
        return {"content": text[:1990]}
    return {"source": "forense-framework", "version": __version__, "event": "automation_finished",
            "text": text, **facts}


def send(url: str, body: dict, timeout: float = 15.0) -> int:
    request = urllib.request.Request(url, data=json.dumps(body, ensure_ascii=False).encode("utf-8"), method="POST",
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": f"Forense-Framework/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL from the config
            return response.status
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ForenseError("error.notify_failed", host=urlparse(url).hostname or url[:40], error=str(exc)) from exc


def notify(case, result, config, actor: Optional[str] = None) -> Optional[str]:
    """Send the notification configured in ``notify.webhook``; returns the destination host (or None)."""
    url = str(config.value("notify.webhook") or "").strip()
    if not url:
        return None
    if urlparse(url).scheme not in ("http", "https"):
        raise ForenseError("error.notify_failed", host=url[:40], error="http(s) URL expected")
    fmt = str(config.value("notify.format") or "auto")
    fmt = detect_format(url) if fmt == "auto" else fmt
    facts = summary(case, result, str(config.value("notify.min_severity") or "high"),
                    config.value("language") or None)
    status = send(url, payload(facts, fmt, config.value("language") or None))
    host = urlparse(url).hostname or ""
    case.custody.append("notification_sent", case.actor(actor), {
        "destination": host, "format": fmt, "status": status, "findings": facts["total_findings"]})
    return host
