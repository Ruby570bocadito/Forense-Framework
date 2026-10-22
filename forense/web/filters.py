"""Saved case filters for the web interface (findings and timeline).

Stored per case in ``<case>/ui/saved_filters.json`` so the analyst's review
shortcuts travel with the case. This is interface state, not evidence: no chain
of custody entry. Filter queries are allowlisted per page — anything else in the
saved query string is dropped, so a forged form can never smuggle parameters.
"""

from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode

from forense.core.errors import ForenseError

MAX_FILTERS = 20
MAX_NAME = 80
MAX_QUERY = 500

# Allowlisted filter keys per page (order matters for the stored query string).
PAGES: dict[str, tuple[str, ...]] = {
    "findings": ("severity", "status", "technique"),
    "timeline": ("from", "to", "q", "source", "severity", "evidence", "bookmarked"),
}

_PATH_NAME = "saved_filters.json"


def _path(case_root: Path) -> Path:
    return Path(case_root) / "ui" / _PATH_NAME


def sanitize_query(page: str, query: str) -> str:
    """Keep only the allowlisted keys of ``page``, drop the rest and cap the length."""
    allowed = PAGES.get(page, ())
    pairs = [(k, v) for k, v in parse_qsl(query, keep_blank_values=True)
             if k in allowed and len(v) <= 200]
    return urlencode(pairs)[:MAX_QUERY]


def load(case_root: Path) -> list[dict]:
    """All saved filters of the case; a missing or damaged file never breaks the page."""
    try:
        data = json.loads(_path(case_root).read_text(encoding="utf-8"))
        entries = data.get("filters", [])
        return [e for e in entries if isinstance(e, dict) and e.get("page") in PAGES]
    except (OSError, ValueError):
        return []


def parsed(entries: list[dict], page: str) -> list[dict]:
    """Entries of one page with their query already parsed for ``url_for(**args)``."""
    result = []
    for e in entries:
        if e.get("page") != page:
            continue
        result.append({**e, "args": dict(parse_qsl(str(e.get("query", "")), keep_blank_values=True))})
    return result


def save(case_root: Path, page: str, name: str, query: str, actor: str) -> dict:
    """Persist one saved filter; raises ForenseError with a locale key on misuse."""
    if page not in PAGES:
        raise ForenseError("web.filters_unknown_page")
    name = " ".join(name.split())[:MAX_NAME]
    if not name:
        raise ForenseError("web.filters_name_required")
    clean = sanitize_query(page, query)
    if not clean:
        raise ForenseError("web.filters_empty")
    entries = load(case_root)
    if len(entries) >= MAX_FILTERS:
        raise ForenseError("web.filters_limit", n=MAX_FILTERS)
    entry = {"id": secrets.token_hex(4), "page": page, "name": name, "query": clean,
             "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "actor": actor}
    entries.append(entry)
    _write(case_root, {"version": 1, "filters": entries})
    return entry


def delete(case_root: Path, filter_id: str) -> bool:
    """Remove one saved filter by id; returns whether it existed."""
    entries = load(case_root)
    kept = [e for e in entries if e.get("id") != filter_id]
    if len(kept) == len(entries):
        return False
    _write(case_root, {"version": 1, "filters": kept})
    return True


def _write(case_root: Path, data: dict) -> None:
    path = _path(case_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, path)
