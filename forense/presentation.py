"""Rendering helpers shared by the CLI, the web interface and the reports."""

from __future__ import annotations

import json
from typing import Any, Optional

from forense.i18n import has, t, yes_no

SEVERITY_COLORS = {"critical": "#b42318", "high": "#d9480f", "medium": "#b7791f", "low": "#2f6fab", "info": "#5f6b7a"}


_RULE_PARAMS = ("rules", "reasons")


def _display_params(params: dict, lang: Optional[str]) -> dict:
    """Readable parameters: formatted timestamps and translated rule names."""
    shown = {}
    for key, value in params.items():
        if key in _RULE_PARAMS and isinstance(value, str) and value not in ("", "-"):
            shown[key] = ", ".join(rule_label(part.strip(), lang) for part in value.split(","))
        else:
            shown[key] = format_value(value, lang)
    return shown


def rule_label(rule: str, lang: Optional[str] = None) -> str:
    key = f"rule.{rule}"
    return t(key, lang) if has(key, lang) or has(key, "en") else rule


def finding_title(finding: dict, lang: Optional[str] = None) -> str:
    return t(f"finding.{finding['code']}.title", lang, **_display_params(finding.get("params", {}), lang))


def finding_description(finding: dict, lang: Optional[str] = None) -> str:
    params = _display_params(finding.get("params", {}), lang)
    key = f"finding.{finding['code']}.description"
    if not has(key, lang) and not has(key, "en"):
        return ", ".join(f"{k}={v}" for k, v in params.items())
    return t(key, lang, **params)


def severity_label(severity: str, lang: Optional[str] = None) -> str:
    return t(f"severity.{severity}", lang)


def event_type_label(event_type: str, lang: Optional[str] = None) -> str:
    key = f"etype.{event_type}"
    return t(key, lang) if has(key, lang) or has(key, "en") else event_type


def artifact_label(artifact: str, lang: Optional[str] = None) -> str:
    key = f"artifact.{artifact}"
    return t(key, lang) if has(key, lang) or has(key, "en") else artifact


def custody_action_label(action: str, lang: Optional[str] = None) -> str:
    key = f"custody.action.{action}"
    return t(key, lang) if has(key, lang) or has(key, "en") else action


def status_label(status: str, lang: Optional[str] = None) -> str:
    return t(f"status.{status}", lang)


def display_ts(value: Optional[str], precise: bool = False) -> str:
    """``2026-09-14T02:35:00.123456Z`` -> ``2026-09-14 02:35:00`` (UTC)."""
    if not value:
        return ""
    text = str(value)
    if len(text) >= 19 and text[10] == "T":
        return text[:10] + " " + (text[11:23] if precise else text[11:19])
    return text


def format_value(value: Any, lang: Optional[str] = None, limit: Optional[int] = None) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return yes_no(value, lang)
    if isinstance(value, (list, tuple)) and all(not isinstance(v, (dict, list)) for v in value):
        text = ", ".join(format_value(v, lang) for v in value)
    elif isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
    elif isinstance(value, str) and len(value) >= 20 and value[10:11] == "T" and value.endswith("Z"):
        text = display_ts(value)
    else:
        text = str(value)
    if limit and len(text) > limit:
        return text[:limit - 1] + "…"
    return text
