"""Import of threat intelligence into Forense watchlists.

``forense intel misp`` converts a MISP JSON export (one event or a set of
events) and ``forense intel opencti`` an OpenCTI STIX 2.1 bundle into a
watchlist for the ``ioc`` module: one indicator per line, with the provenance
of every source event kept as ``#`` comments. The resulting file plugs
directly into the module option ``watchlist``, the automation configuration
key ``intel.watchlists`` and, through the ``ioc.watchlist_match`` findings,
into the correlation between cases.

The imports never touch the network: the analyst exports the events or the
bundle from their MISP/OpenCTI instance and feeds the file here, so no API
key or instance URL ever reaches the case. Only well-known attribute types
and plain ``[path = 'literal']`` STIX patterns are imported; everything else
is counted and reported as skipped instead of guessed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from forense.core.errors import ForenseError

MAX_INTEL_BYTES = 256 * 1024 * 1024  # an intelligence export beyond this is not a watchlist job anymore


def _whole(value: str) -> list[str]:
    return [value] if value else []


def _hash(value: str) -> list[str]:
    return [value.lower()] if value else []


def _hash_part(value: str) -> list[str]:
    """``filename|md5``-style values: only the hash is a safe literal to match."""
    return [part.lower() for part in value.split("|", 1)[1:]]


def _ip_part(value: str) -> list[str]:
    return [value.split("|", 1)[0]] if value else []


def _both_parts(value: str) -> list[str]:
    return [part for part in value.split("|", 1) if part]


# MISP attribute type -> extractor of the literal values worth matching.
TYPE_MAP: dict[str, Callable[[str], list[str]]] = {
    "md5": _hash, "sha1": _hash, "sha256": _hash, "sha512": _hash,
    "ip-src": _ip_part, "ip-dst": _ip_part, "ip-src|port": _ip_part, "ip-dst|port": _ip_part,
    "domain": _whole, "hostname": _whole,
    "hostname|ip": _both_parts, "domain|ip": _both_parts,
    "url": _whole, "uri": _whole, "link": _whole,
    "email": _whole, "email-src": _whole, "email-dst": _whole,
    "filename": _whole,
    "filename|md5": _hash_part, "filename|sha1": _hash_part,
    "filename|sha256": _hash_part, "filename|sha512": _hash_part,
    "regkey": _whole, "user-agent": _whole,
}


@dataclass
class MispImport:
    """Result of importing a MISP JSON export."""

    indicators: list[str] = field(default_factory=list)  # deduplicated, original order
    notes: list[str] = field(default_factory=list)  # one provenance comment per source event
    events: int = 0
    attributes: int = 0
    used: int = 0  # attributes that produced at least one indicator
    duplicates: int = 0
    skipped: dict[str, int] = field(default_factory=dict)  # type -> count, for non-importable types


def _events_of(payload: object, source: Path) -> list[dict]:
    """The ``Event`` dictionaries of the standard MISP JSON export shapes: a single
    ``{"Event": {...}}``, a ``{"response": [{"Event": ...}, ...]}`` export or a plain
    list of those wrappers (``Event`` itself may also be a list of events)."""
    if isinstance(payload, dict) and "Event" in payload:
        raw = payload["Event"] if isinstance(payload["Event"], list) else [payload["Event"]]
        events = [event for event in raw if isinstance(event, dict)]
    elif isinstance(payload, dict) and isinstance(payload.get("response"), list):
        events = [item["Event"] for item in payload["response"]
                  if isinstance(item, dict) and isinstance(item.get("Event"), dict)]
    elif isinstance(payload, list):
        events = [item["Event"] for item in payload
                  if isinstance(item, dict) and isinstance(item.get("Event"), dict)]
    else:
        raise ForenseError("error.intel_misp_invalid", path=str(source))
    if not events:
        raise ForenseError("error.intel_misp_invalid", path=str(source))
    return events


def _event_note(event: dict) -> str:
    uuid = str(event.get("uuid") or "").strip()
    info = " ".join(str(event.get("info") or "").split())[:120]
    date = str(event.get("date") or "").strip()
    note = f"misp: {uuid or '?'}"
    if info:
        note += f" | {info}"
    if date:
        note += f" | {date}"
    return note


def _attributes_of(event: dict) -> list[dict]:
    attrs = event.get("Attribute")
    if isinstance(attrs, dict):  # defensive: some exports map attribute uuid -> attribute
        attrs = list(attrs.values())
    return [a for a in attrs if isinstance(a, dict)] if isinstance(attrs, list) else []


def _deleted(attribute: dict) -> bool:
    flag = attribute.get("deleted")
    return flag is True or str(flag or "").strip().lower() in ("1", "true")


def import_misp(source: Path) -> MispImport:
    """Read a MISP JSON export and collect its watchlist indicators.

    Raises ``error.intel_input_missing`` when the file does not exist,
    ``error.intel_misp_too_large`` beyond ``MAX_INTEL_BYTES``,
    ``error.intel_misp_invalid`` for broken JSON or an unknown structure and
    ``error.intel_misp_empty`` when no attribute of an importable type remains.
    """
    source = Path(source)
    if not source.is_file():
        raise ForenseError("error.intel_input_missing", path=str(source))
    if source.stat().st_size > MAX_INTEL_BYTES:
        raise ForenseError("error.intel_misp_too_large", path=str(source),
                           limit=MAX_INTEL_BYTES // (1024 * 1024))
    try:
        payload = json.loads(source.read_text(encoding="utf-8", errors="replace"))
    except (ValueError, RecursionError) as exc:
        raise ForenseError("error.intel_misp_invalid", path=str(source)) from exc

    result = MispImport()
    seen: set[str] = set()
    for event in _events_of(payload, source):
        result.events += 1
        result.notes.append(_event_note(event))
        for attribute in _attributes_of(event):
            result.attributes += 1
            if _deleted(attribute):
                continue
            kind = str(attribute.get("type") or "").strip().lower()
            extract = TYPE_MAP.get(kind)
            if extract is None:
                result.skipped[kind or "?"] = result.skipped.get(kind or "?", 0) + 1
                continue
            value = str(attribute.get("value") or "").strip()
            produced = extract(value)
            if produced:
                result.used += 1
            for indicator in produced:
                key = indicator.lower()
                if key in seen:
                    result.duplicates += 1
                    continue
                seen.add(key)
                result.indicators.append(indicator)
    if not result.indicators:
        raise ForenseError("error.intel_misp_empty", path=str(source))
    return result


def write_watchlist(result: MispImport | OpenctiImport, destination: Path) -> Path:
    """Write the watchlist file: provenance comments first, indicators sorted after."""
    origin = "an OpenCTI STIX bundle" if isinstance(result, OpenctiImport) else "a MISP export"
    destination = Path(destination)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [f"# Forense watchlist generated from {origin} ({stamp})",
             *(f"# {note}" for note in result.notes), *sorted(result.indicators)]
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return destination


# --- OpenCTI STIX 2.1 bundles ------------------------------------------------
#
# OpenCTI exports indicators as a STIX bundle: {"type": "bundle", "objects":
# [...]}. Only plain single-comparison equality patterns are imported
# (``[file:hashes.'SHA-256' = '...']``, ``[domain-name:value = '...']``, ...);
# everything else (operators, lists, multi-term expressions, observables
# without a watchable literal) is counted in ``skipped`` instead of guessed,
# the same way unknown MISP attribute types are.

MAX_OPENCTI_NOTES = 100  # provenance comments beyond this are summarized in one line

_OPERATOR_WORDS = {"and", "or", "like", "matches", "in", "issubset", "issuperset", "followedby"}
_STIX_HASH_ALGORITHMS = {"sha256", "sha1", "md5", "sha512"}
_PATH_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.:'\"")


def _closing_bracket(text: str, start: int) -> int | None:
    """Index of the ``]`` closing the observation expression opened at ``start``,
    honouring quoted string literals. ``None`` when the shape is not a plain one."""
    quote = ""
    i = start + 1
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "]":
            return i
        elif ch == "[":  # nested observation expression
            return None
        i += 1
    return None


def _top_level_equal(expr: str) -> int:
    """Index of the first ``=`` outside quotes and parentheses, or -1."""
    quote = ""
    depth = 0
    i = 0
    n = len(expr)
    while i < n:
        ch = expr[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "=" and depth == 0:
            return i
        i += 1
    return -1


def _has_operator_word(expr: str) -> bool:
    """Whether a STIX comparison/relational operator appears at the top level."""
    quote = ""
    depth = 0
    word: list[str] = []
    i = 0
    n = len(expr)
    while i < n:
        ch = expr[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            word = []
            i += 1
            continue
        if ch == "(":
            depth += 1
            word = []
        elif ch == ")":
            depth -= 1
            word = []
        elif depth == 0 and (ch.isalpha() or ch == "-"):
            word.append(ch.lower())
        else:
            if "".join(word) in _OPERATOR_WORDS:
                return True
            word = []
        i += 1
    return "".join(word) in _OPERATOR_WORDS


def _object_path(lhs: str) -> str | None:
    """Normalized STIX object path (``file:hashes.'SHA-256'`` -> ``file|hashes.sha-256``)."""
    if not lhs or any(ch not in _PATH_CHARS for ch in lhs):
        return None
    obj, sep, prop = lhs.partition(":")
    if not sep or not prop or not re.fullmatch(r"[a-z0-9_-]+", obj.strip().lower()):
        return None
    prop = prop.strip().lower().replace("'", "").replace('"', "")
    return f"{obj.strip().lower()}|{prop}"


def _stix_extractor(path: str) -> Callable[[str], list[str]] | None:
    """The extractor of the literals worth matching for a normalized object path."""
    obj, _, prop = path.partition("|")
    if obj == "file":
        if prop.startswith("hashes"):
            algorithm = prop.partition(".")[2].replace("-", "").replace("_", "")
            return _hash if algorithm in _STIX_HASH_ALGORITHMS else None
        return _whole if prop == "name" else None
    if (obj, prop) in {("domain-name", "value"), ("hostname", "value")}:
        return _whole
    if obj in ("ipv4-addr", "ipv6-addr") and prop == "value":
        return _whole
    if (obj, prop) in {("url", "value"), ("email-addr", "value"),
                       ("windows-registry-key", "key"),
                       ("network-traffic", "src_ref.value"), ("network-traffic", "dst_ref.value"),
                       ("user-agent", "user_agent"), ("user-agent", "user-agent")}:
        return _whole
    return None


def _string_literal(rhs: str) -> str | None:
    """The value of a quoted STIX string literal covering all of ``rhs``, or None."""
    if len(rhs) < 2 or rhs[0] not in ("'", '"'):
        return None
    quote = rhs[0]
    out: list[str] = []
    i = 1
    n = len(rhs)
    while i < n:
        ch = rhs[i]
        if ch == "\\" and i + 1 < n:
            out.append(rhs[i + 1])
            i += 2
            continue
        if ch == quote:
            return "".join(out) if i == n - 1 else None  # trailing content: not a plain one
        out.append(ch)
        i += 1
    return None


def _stix_pattern_value(pattern: str) -> tuple[str | None, Callable[[str], list[str]] | None, str]:
    """(reason, extractor, literal) of a STIX pattern; ``reason`` is None when the
    pattern is a plain single equality whose literal is worth watching."""
    text = pattern.strip()
    if "-->" in text or not text.startswith("["):
        return ("pattern_complex", None, "")
    end = _closing_bracket(text, 0)
    if end is None or text[end + 1:].strip():  # qualifiers (REPEATS/WITHIN) or more expressions
        return ("pattern_complex", None, "")
    expr = text[1:end].strip()
    eq = _top_level_equal(expr)
    if eq < 0 or (eq > 0 and expr[eq - 1] in "!<>=") or (eq + 1 < len(expr) and expr[eq + 1] == "="):
        return ("pattern_not_equality", None, "")
    path = _object_path(expr[:eq].strip())
    extractor = _stix_extractor(path) if path else None
    if extractor is None:
        reason = "pattern_complex" if _has_operator_word(expr) else "pattern_unknown_path"
        return (reason, None, "")
    rhs = expr[eq + 1:].strip()
    literal = _string_literal(rhs)
    if literal is None:
        reason = "pattern_complex" if rhs[:1] in ("'", '"', "(") else "pattern_no_literal"
        return (reason, None, "")
    return (None, extractor, literal)


@dataclass
class OpenctiImport:
    """Result of importing an OpenCTI STIX bundle."""

    indicators: list[str] = field(default_factory=list)  # deduplicated, original order
    notes: list[str] = field(default_factory=list)  # provenance comments, bounded
    objects: int = 0  # every well-formed object of the bundle
    indicators_seen: int = 0
    used: int = 0  # indicators that produced at least one watchable literal
    duplicates: int = 0
    skipped: dict[str, int] = field(default_factory=dict)  # reason -> count


def _objects_of(payload: object, source: Path) -> list[object]:
    """The objects of the accepted bundle shapes: ``{"type": "bundle", "objects":
    [...]}`` (also without the envelope or as an id -> object map) or a plain list."""
    if isinstance(payload, dict):
        raw = payload.get("objects")
    elif isinstance(payload, list):
        raw = payload
    else:
        raise ForenseError("error.intel_opencti_invalid", path=str(source))
    if isinstance(raw, dict):  # defensive: some producers map object id -> object
        raw = list(raw.values())
    if not isinstance(raw, list) or not raw:
        raise ForenseError("error.intel_opencti_invalid", path=str(source))
    return raw


def _indicator_note(obj: dict) -> str:
    stix_id = str(obj.get("id") or "").strip()
    uuid = stix_id.split("--", 1)[1] if "--" in stix_id else stix_id
    labels = obj.get("labels")
    label_text = "; ".join(str(label).strip() for label in labels if str(label).strip()) \
        if isinstance(labels, list) else ""
    info = label_text or " ".join(str(obj.get("name") or "").split()) \
        or " ".join(str(obj.get("description") or "").split())
    note = f"opencti: {uuid or '?'} | {info[:120]}" if info else f"opencti: {uuid or '?'}"
    created = str(obj.get("created") or "").strip()[:10]
    if created:
        note += f" | {created}"
    return note


def import_opencti(source: Path) -> OpenctiImport:
    """Read an OpenCTI STIX 2.1 bundle and collect its watchlist indicators.

    Raises ``error.intel_input_missing`` when the file does not exist,
    ``error.intel_opencti_too_large`` beyond ``MAX_INTEL_BYTES``,
    ``error.intel_opencti_invalid`` for broken JSON or an unknown structure and
    ``error.intel_opencti_empty`` when no indicator of the bundle can be used.
    """
    source = Path(source)
    if not source.is_file():
        raise ForenseError("error.intel_input_missing", path=str(source))
    if source.stat().st_size > MAX_INTEL_BYTES:
        raise ForenseError("error.intel_opencti_too_large", path=str(source),
                           limit=MAX_INTEL_BYTES // (1024 * 1024))
    try:
        payload = json.loads(source.read_text(encoding="utf-8", errors="replace"))
    except (ValueError, RecursionError) as exc:
        raise ForenseError("error.intel_opencti_invalid", path=str(source)) from exc

    result = OpenctiImport()
    seen_notes: set[str] = set()
    omitted_notes = 0
    seen: set[str] = set()
    for raw_object in _objects_of(payload, source):
        if not isinstance(raw_object, dict):
            result.skipped["malformed_object"] = result.skipped.get("malformed_object", 0) + 1
            continue
        result.objects += 1
        kind = str(raw_object.get("type") or "").strip().lower()
        if kind != "indicator":  # identities, relationships, markings... are not indicators
            if not kind:
                result.skipped["malformed_object"] = result.skipped.get("malformed_object", 0) + 1
            continue
        result.indicators_seen += 1
        if raw_object.get("revoked") is True:
            result.skipped["revoked"] = result.skipped.get("revoked", 0) + 1
            continue
        pattern_type = str(raw_object.get("pattern_type") or "stix").strip().lower()
        if pattern_type != "stix":
            key = f"pattern_type:{pattern_type or '?'}"
            result.skipped[key] = result.skipped.get(key, 0) + 1
            continue
        reason, extractor, literal = _stix_pattern_value(str(raw_object.get("pattern") or ""))
        if reason is not None or extractor is None:
            result.skipped[reason or "pattern_unknown_path"] = \
                result.skipped.get(reason or "pattern_unknown_path", 0) + 1
            continue
        produced = extractor(literal)
        if not produced:
            result.skipped["pattern_no_literal"] = result.skipped.get("pattern_no_literal", 0) + 1
            continue
        result.used += 1
        note = _indicator_note(raw_object)
        if note not in seen_notes:
            seen_notes.add(note)
            if len(result.notes) < MAX_OPENCTI_NOTES:
                result.notes.append(note)
            else:
                omitted_notes += 1
        for indicator in produced:
            key = indicator.lower()
            if key in seen:
                result.duplicates += 1
                continue
            seen.add(key)
            result.indicators.append(indicator)
    if omitted_notes:
        result.notes.append(f"opencti: (+{omitted_notes} more indicator sources omitted "
                            f"from these comments, cap {MAX_OPENCTI_NOTES})")
    if not result.indicators:
        raise ForenseError("error.intel_opencti_empty", path=str(source))
    return result
