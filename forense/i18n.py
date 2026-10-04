"""Internationalisation (Spanish / English).

Persisted data uses stable, language-neutral codes (field names, custody
actions, finding codes). Text is only produced at presentation time through
:func:`t`, so the same case can be reviewed or reported in either language.

Language resolution: explicit argument > :func:`set_language` (per thread /
request) > ``FORENSE_LANG`` > system locale > English.
"""

from __future__ import annotations

import json
import locale
import os
from contextvars import ContextVar
from functools import lru_cache
from pathlib import Path
from typing import Optional

SUPPORTED = ("es", "en")
DEFAULT = "en"
_LOCALES_DIR = Path(__file__).parent / "locales"
_current: ContextVar[Optional[str]] = ContextVar("forense_lang", default=None)


@lru_cache(maxsize=None)
def catalog(lang: str) -> dict[str, str]:
    with open(_LOCALES_DIR / f"{lang}.json", encoding="utf-8") as fh:
        return json.load(fh)


_LANGUAGE_NAMES = {"spanish": "es", "español": "es", "espanol": "es", "english": "en"}
_WINDOWS_PRIMARY_LANGIDS = {0x0A: "es", 0x09: "en"}


def normalize(lang: Optional[str]) -> Optional[str]:
    """``es``, ``es_ES.UTF-8``, ``Spanish_Spain`` (Windows locale names)... -> ``es``."""
    if not lang:
        return None
    code = lang.strip().lower().replace("-", "_").split("_")[0].split(".")[0]
    code = _LANGUAGE_NAMES.get(code, code)
    return code if code in SUPPORTED else None


def _windows_ui_language() -> Optional[str]:
    if os.name != "nt":
        return None
    try:
        import ctypes

        langid = ctypes.windll.kernel32.GetUserDefaultUILanguage()  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return None
    return _WINDOWS_PRIMARY_LANGIDS.get(langid & 0x3FF)


def detect_language() -> str:
    env = normalize(os.environ.get("FORENSE_LANG"))
    if env:
        return env
    for getter in (_windows_ui_language, lambda: locale.getlocale()[0], lambda: os.environ.get("LANG")):
        try:
            code = normalize(getter())
        except (ValueError, TypeError):
            code = None
        if code:
            return code
    return DEFAULT


def set_language(lang: Optional[str]) -> None:
    _current.set(normalize(lang))


def get_language() -> str:
    return _current.get() or detect_language()


class _Missing(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def t(key: str, lang: Optional[str] = None, **params: object) -> str:
    """Translate ``key``; unknown keys fall back to English and then to the key itself."""
    lang = normalize(lang) or get_language()
    text = catalog(lang).get(key)
    if text is None:
        text = catalog(DEFAULT).get(key, key)
    if params:
        text = text.format_map(_Missing(params))
    return text


def has(key: str, lang: Optional[str] = None) -> bool:
    return key in catalog(normalize(lang) or get_language())


def label(field: str, lang: Optional[str] = None) -> str:
    """Display label of a record/summary field name."""
    key = f"field.{field}"
    if has(key, lang) or has(key, DEFAULT):
        return t(key, lang)
    return field.replace("_", " ").capitalize()


def yes_no(value: bool, lang: Optional[str] = None) -> str:
    return t("common.yes" if value else "common.no", lang)
