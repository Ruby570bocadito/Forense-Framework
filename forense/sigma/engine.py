"""A Sigma rule engine for Windows event logs (.evtx).

Supports the Sigma features used by the SigmaHQ Windows rule set: field
selections (maps and lists of maps), keyword lists, wildcards, the modifiers
``contains``, ``startswith``, ``endswith``, ``all``, ``re`` (with ``i``, ``m``,
``s``), ``windash``, ``cidr``, ``base64``, ``base64offset``, ``wide``/``utf16*``,
``exists``, ``gt``/``gte``/``lt``/``lte`` and ``fieldref``, and conditions with
``and``/``or``/``not``, parentheses, ``1 of``/``all of``/``any of`` (with
wildcards and ``them``). Aggregations (``| count()``) are not supported.

Log sources are mapped to event log channels; ``process_creation`` rules also
run against Security 4688 events with Sysmon field names translated.
"""

from __future__ import annotations

import base64
import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

BUILTIN_RULES = Path(__file__).parent / "rules"

LEVELS = {"informational": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
LEVEL_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

SYSMON = "microsoft-windows-sysmon/operational"
PS_OPERATIONAL = "microsoft-windows-powershell/operational"

# Sysmon field names -> Security 4688 field names
PROCESS_CREATION_4688 = {
    "Image": "NewProcessName", "ParentImage": "ParentProcessName", "CommandLine": "CommandLine",
    "User": "SubjectUserName", "IntegrityLevel": "MandatoryLabel", "ProcessId": "NewProcessId",
    "ParentProcessId": "ProcessId", "LogonId": "SubjectLogonId",
}

SERVICES = {
    "security": "security", "system": "system", "application": "application", "sysmon": SYSMON,
    "powershell": PS_OPERATIONAL, "powershell-classic": "windows powershell",
    "windefend": "microsoft-windows-windows defender/operational",
    "taskscheduler": "microsoft-windows-taskscheduler/operational",
    "wmi": "microsoft-windows-wmi-activity/operational",
    "bits-client": "microsoft-windows-bits-client/operational",
    "terminalservices-localsessionmanager": "microsoft-windows-terminalservices-localsessionmanager/operational",
    "codeintegrity-operational": "microsoft-windows-codeintegrity/operational",
    "firewall-as": "microsoft-windows-windows firewall with advanced security/firewall",
    "dns-client": "microsoft-windows-dns client events/operational", "dns-server": "dns server",
    "ntlm": "microsoft-windows-ntlm/operational", "applocker": "microsoft-windows-applocker/exe and dll",
    "appxdeployment-server": "microsoft-windows-appxdeploymentserver/operational",
    "security-mitigations": "microsoft-windows-security-mitigations/kernel mode",
    "msexchange-management": "msexchange management", "smbclient-security": "microsoft-windows-smbclient/security",
    "printservice-admin": "microsoft-windows-printservice/admin",
    "printservice-operational": "microsoft-windows-printservice/operational",
    "openssh": "openssh/operational", "shell-core": "microsoft-windows-shell-core/operational",
    "lsa-server": "microsoft-windows-lsa/operational", "driver-framework": "microsoft-windows-driverframeworks-usermode/operational",
    "iis-configuration": "microsoft-iis-configuration/operational", "vhdmp": "microsoft-windows-vhdmp-operational",
    "appmodel-runtime": "microsoft-windows-appmodel-runtime/admin",
    "appxpackaging-om": "microsoft-windows-appxpackaging/operational", "capi2": "microsoft-windows-capi2/operational",
    "certificateservicesclient-lifecycle-system":
        "microsoft-windows-certificateservicesclient-lifecycle-system/operational",
    "diagnosis-scripted": "microsoft-windows-diagnosis-scripted/operational",
    "ldap": "microsoft-windows-ldap-client/debug", "microsoft-servicebus-client": "microsoft-servicebus-client",
    "smbserver-connectivity": "microsoft-windows-smbserver/connectivity",
}

# category -> [(channel, event ids, field map)]
CATEGORIES: dict[str, list[tuple[str, tuple[int, ...], Optional[dict]]]] = {
    "process_creation": [(SYSMON, (1,), None), ("security", (4688,), PROCESS_CREATION_4688)],
    "network_connection": [(SYSMON, (3,), None)],
    "process_termination": [(SYSMON, (5,), None)],
    "driver_load": [(SYSMON, (6,), None)],
    "image_load": [(SYSMON, (7,), None)],
    "create_remote_thread": [(SYSMON, (8,), None)],
    "raw_access_thread": [(SYSMON, (9,), None)],
    "process_access": [(SYSMON, (10,), None)],
    "file_event": [(SYSMON, (11,), None)],
    "registry_add": [(SYSMON, (12,), None)],
    "registry_delete": [(SYSMON, (12,), None)],
    "registry_set": [(SYSMON, (13,), None)],
    "registry_rename": [(SYSMON, (14,), None)],
    "registry_event": [(SYSMON, (12, 13, 14), None)],
    "create_stream_hash": [(SYSMON, (15,), None)],
    "pipe_created": [(SYSMON, (17, 18), None)],
    "wmi_event": [(SYSMON, (19, 20, 21), None)],
    "dns_query": [(SYSMON, (22,), None)],
    "file_delete": [(SYSMON, (23, 26), None)],
    "file_change": [(SYSMON, (2,), None)],
    "clipboard_capture": [(SYSMON, (24,), None)],
    "process_tampering": [(SYSMON, (25,), None)],
    "file_executable_detected": [(SYSMON, (29,), None)],
    "sysmon_status": [(SYSMON, (4, 16), None)],
    "sysmon_error": [(SYSMON, (255,), None)],
    "ps_script": [(PS_OPERATIONAL, (4104,), None)],
    "ps_module": [(PS_OPERATIONAL, (4103,), None), ("windows powershell", (800,), None)],
    "ps_classic_start": [("windows powershell", (400,), None)],
    "ps_classic_provider_start": [("windows powershell", (600,), None)],
}


class SigmaError(ValueError):
    pass


# -- value matching ------------------------------------------------------------------------
def _wildcard_tokens(value: str) -> list[str]:
    """Sigma wildcards (``*``, ``?``, backslash escapes) to regular-expression tokens (``**`` -> one ``.*``)."""
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))  # escaped wildcard or backslash: literal character
            i += 2
            continue
        token = ".*" if ch == "*" else "." if ch == "?" else re.escape(ch)
        if not (token == ".*" and out and out[-1] == ".*"):
            out.append(token)
        i += 1
    return out


def _value_matcher(value: str, mode: str, flags: int) -> Callable[[str], bool]:
    """Match ``value`` (with wildcards) as ``exact``, ``contains``, ``startswith`` or ``endswith``.

    The pattern is split at each ``*`` into fixed-width segments that are found
    left to right (the leftmost occurrence of each segment is always the best
    choice), so the cost stays linear in the length of the field instead of the
    backtracking of a ``.*a.*b.*`` regular expression.
    """
    tokens = _wildcard_tokens(value)
    if mode in ("contains", "endswith"):
        tokens = [".*"] + tokens
    if mode in ("contains", "startswith"):
        tokens = tokens + [".*"]
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token == ".*":
            segments.append([])
        else:
            segments[-1].append(token)
    if len(segments) == 1:  # no wildcard: the whole field
        rx = re.compile("".join(segments[0]), flags)
        return lambda text: rx.fullmatch(text) is not None
    head, *middle, tail = (("".join(seg), len(seg)) for seg in segments)
    head_rx = re.compile(head[0], flags) if head[1] else None
    tail_rx = re.compile(tail[0], flags) if tail[1] else None
    middle_rx = [re.compile(body, flags) for body, width in middle if width]

    def test(text: str) -> bool:
        pos, limit = 0, len(text) - tail[1]
        if limit < head[1]:
            return False
        if head_rx is not None:
            if head_rx.match(text, 0, head[1]) is None:
                return False
            pos = head[1]
        if tail_rx is not None and tail_rx.fullmatch(text, limit) is None:
            return False
        for rx in middle_rx:
            found = rx.search(text, pos, limit)
            if found is None:
                return False
            pos = found.end()
        return True
    return test


def _windash(value: str) -> list[str]:
    variants = {value}
    for dash in ("/", "–", "—", "―"):
        variants.add(re.sub(r"(^|\s)-", lambda m, d=dash: m.group(1) + d, value))
    return sorted(variants)


def _base64offset(value: bytes) -> list[str]:
    results = []
    for offset in range(3):
        encoded = base64.b64encode(b"\x00" * offset + value).decode()
        start = (0, 2, 3)[offset]
        end = len(encoded) - ((0, 3, 2)[(len(value) + offset) % 3])
        results.append(encoded[start:end])
    return results


def _encode(value: str, modifiers: list[str]) -> bytes:
    if "wide" in modifiers or "utf16le" in modifiers:
        return value.encode("utf-16-le")
    if "utf16be" in modifiers:
        return value.encode("utf-16-be")
    if "utf16" in modifiers:
        return value.encode("utf-16")
    return value.encode("utf-8")


Predicate = Callable[[Callable[[str], Any]], bool]


def _to_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def _compile_field(field_spec: str, raw_values: Any) -> Predicate:
    name, *modifiers = field_spec.split("|")
    modifiers = [m.lower() for m in modifiers]
    values = raw_values if isinstance(raw_values, list) else [raw_values]
    require_all = "all" in modifiers

    if "exists" in modifiers:
        expected = bool(values[0])
        return lambda get: (get(name) not in (None, "")) == expected

    if "fieldref" in modifiers:
        def ref(get: Callable[[str], Any]) -> bool:
            current = _to_text(get(name))
            results = [current is not None and current.lower() == (_to_text(get(v)) or "").lower() for v in values]
            return all(results) if require_all else any(results)
        return ref

    if any(m in modifiers for m in ("gt", "gte", "lt", "lte")):
        op = next(m for m in modifiers if m in ("gt", "gte", "lt", "lte"))

        def numeric(get: Callable[[str], Any]) -> bool:
            try:
                current = float(get(name))
            except (TypeError, ValueError):
                return False
            checks = [{"gt": current > float(v), "gte": current >= float(v), "lt": current < float(v),
                       "lte": current <= float(v)}[op] for v in values]
            return all(checks) if require_all else any(checks)
        return numeric

    if "cidr" in modifiers:
        networks = [ipaddress.ip_network(str(v), strict=False) for v in values]

        def cidr(get: Callable[[str], Any]) -> bool:
            try:
                address = ipaddress.ip_address(str(get(name)).strip("[]"))
            except ValueError:
                return False
            results = [address in net for net in networks]
            return all(results) if require_all else any(results)
        return cidr

    matchers: list[Callable[[str], bool]] = []
    for value in values:
        if value is None:
            matchers.append(lambda text: text in (None, ""))
            continue
        if "re" in modifiers:
            flags = (re.IGNORECASE if "i" in modifiers else 0) | (re.MULTILINE if "m" in modifiers else 0) \
                | (re.DOTALL if "s" in modifiers else 0)
            pattern = re.compile(str(value), flags)
            matchers.append(lambda text, p=pattern: text is not None and p.search(text) is not None)
            continue
        candidates = [str(value)] if isinstance(value, (str, int, float, bool)) else [str(value)]
        if "windash" in modifiers:
            candidates = [c for v in candidates for c in _windash(v)]
        if "base64offset" in modifiers:
            candidates = [re.sub(r"([*?\\])", r"\\\1", c) for v in candidates for c in _base64offset(_encode(v, modifiers))]
        elif "base64" in modifiers:
            candidates = [re.sub(r"([*?\\])", r"\\\1", base64.b64encode(_encode(v, modifiers)).decode())
                          for v in candidates]
        mode = next((m for m in ("contains", "startswith", "endswith") if m in modifiers), "exact")
        flags = re.DOTALL | (0 if "cased" in modifiers else re.IGNORECASE)
        tests = tuple(_value_matcher(candidate, mode, flags) for candidate in candidates)
        matchers.append(lambda text, tests=tests: text is not None and any(test(text) for test in tests))

    def predicate(get: Callable[[str], Any]) -> bool:
        text = _to_text(get(name))
        results = (m(text) for m in matchers)
        return all(results) if require_all else any(results)
    return predicate


def _compile_selection(definition: Any) -> Predicate:
    if isinstance(definition, dict):
        parts = [_compile_field(k, v) for k, v in definition.items()]
        return lambda get: all(p(get) for p in parts)
    if isinstance(definition, list) and definition and all(isinstance(d, dict) for d in definition):
        options = [_compile_selection(d) for d in definition]
        return lambda get: any(o(get) for o in options)
    if isinstance(definition, (list, str, int)):
        keywords = definition if isinstance(definition, list) else [definition]
        tests = [_value_matcher(str(k), "contains", re.DOTALL | re.IGNORECASE) for k in keywords]

        def keyword(get: Callable[[str], Any]) -> bool:
            text = get("__fulltext__") or ""
            return any(test(text) for test in tests)
        return keyword
    raise SigmaError(f"unsupported selection: {definition!r}")


# -- conditions ------------------------------------------------------------------------------
_TOKEN = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|\b1 of\b|\ball of\b|\bany of\b|[\w*]+)", re.IGNORECASE)


def _compile_condition(text: str, selections: dict[str, Predicate]) -> Callable[[Callable[[str], Any]], bool]:
    if "|" in text:
        raise SigmaError("aggregations are not supported")
    tokens = [t.lower() if t.lower() in ("and", "or", "not", "1 of", "all of", "any of") else t
              for t in _TOKEN.findall(text) if t.strip()]
    pos = 0

    def peek() -> Optional[str]:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        if pos >= len(tokens):
            raise SigmaError(f"unexpected end of condition: {text}")
        pos += 1
        return tokens[pos - 1]

    def names(pattern: str) -> list[str]:
        if pattern == "them":
            return [n for n in selections if not n.startswith("_")]
        found = [n for n in selections if fnmatch.fnmatchcase(n, pattern)]
        if not found:
            raise SigmaError(f"no selection matches {pattern}")
        return found

    def expr():
        left = term()
        while peek() == "or":
            take()
            right = term()
            left = (lambda a, b: lambda m: a(m) or b(m))(left, right)
        return left

    def term():
        left = factor()
        while peek() == "and":
            take()
            right = factor()
            left = (lambda a, b: lambda m: a(m) and b(m))(left, right)
        return left

    def factor():
        tok = take()
        if tok == "not":
            inner = factor()
            return lambda m: not inner(m)
        if tok == "(":
            inner = expr()
            if take() != ")":
                raise SigmaError(f"missing ')' in {text}")
            return inner
        if tok in ("1 of", "any of", "all of"):
            group = names(take())
            if tok == "all of":
                return lambda m: all(m(n) for n in group)
            return lambda m: any(m(n) for n in group)
        if tok not in selections:
            raise SigmaError(f"unknown selection {tok}")
        return lambda m, n=tok: m(n)

    compiled = expr()
    if pos != len(tokens):
        raise SigmaError(f"unexpected token {tokens[pos]!r} in condition: {text}")
    return compiled


# -- rules -------------------------------------------------------------------------------
@dataclass
class SigmaRule:
    title: str
    id: str
    level: str
    status: str
    description: str
    tags: list[str]
    path: str
    targets: list[tuple[str, tuple[int, ...], Optional[dict]]]
    _selections: dict[str, Predicate] = field(repr=False, default_factory=dict)
    _condition: Callable = field(repr=False, default=lambda m: False)

    def matches(self, event: dict, field_map: Optional[dict] = None) -> bool:
        cache: dict[str, bool] = {}

        def get(name: str) -> Any:
            if name == "__fulltext__":
                return " ".join(str(v) for v in event.values() if v is not None)
            if field_map and name in field_map:
                return event.get(field_map[name])
            if name in event:
                return event[name]
            lowered = name.lower()
            for key, value in event.items():
                if key.lower() == lowered:
                    return value
            return None

        def selection(name: str) -> bool:
            if name not in cache:
                cache[name] = self._selections[name](get)
            return cache[name]

        return self._condition(selection)


def _targets(logsource: dict) -> list[tuple[str, tuple[int, ...], Optional[dict]]]:
    if (logsource.get("product") or "windows").lower() != "windows":
        raise SigmaError("not a Windows rule")
    category, service = logsource.get("category"), logsource.get("service")
    if category:
        if category not in CATEGORIES:
            raise SigmaError(f"unsupported category {category}")
        targets = CATEGORIES[category]
        if service:
            channel = SERVICES.get(service.lower())
            targets = [t for t in targets if channel is None or t[0] == channel]
        return targets
    if service:
        channel = SERVICES.get(service.lower())
        if channel is None:
            raise SigmaError(f"unsupported service {service}")
        return [(channel, (), None)]
    raise SigmaError("log source without category or service")


def compile_rule(doc: dict, path: str = "") -> SigmaRule:
    if not isinstance(doc, dict) or "detection" not in doc:
        raise SigmaError("not a detection rule")
    detection = dict(doc["detection"])
    condition = detection.pop("condition", None)
    detection.pop("timeframe", None)
    if condition is None:
        raise SigmaError("missing condition")
    selections = {name: _compile_selection(definition) for name, definition in detection.items()}
    conditions = condition if isinstance(condition, list) else [condition]
    compiled = [_compile_condition(str(c), selections) for c in conditions]
    return SigmaRule(
        title=str(doc.get("title", "")), id=str(doc.get("id", "")),
        level=LEVELS.get(str(doc.get("level", "medium")).lower(), "medium"),
        status=str(doc.get("status", "")), description=str(doc.get("description", "")).strip(),
        tags=[str(t) for t in doc.get("tags") or []], path=path, targets=_targets(doc.get("logsource") or {}),
        _selections=selections, _condition=lambda m: any(c(m) for c in compiled),
    )


class SigmaRuleSet:
    def __init__(self, rules: Iterable[SigmaRule]) -> None:
        self.rules = list(rules)
        self._index: dict[tuple[str, Optional[int]], list[tuple[SigmaRule, Optional[dict]]]] = {}
        for rule in self.rules:
            for channel, event_ids, field_map in rule.targets:
                for event_id in event_ids or (None,):
                    self._index.setdefault((channel, event_id), []).append((rule, field_map))

    @classmethod
    def load(cls, paths: Iterable[Path], min_level: str = "info",
             skip_status: tuple[str, ...] = ("deprecated", "unsupported")) -> tuple["SigmaRuleSet", list[tuple[str, str]]]:
        """Load ``.yml``/``.yaml`` rules from files or folders. Returns ``(ruleset, [(file, error)])``."""
        import yaml

        rules, errors = [], []
        files: list[Path] = []
        for path in paths:
            path = Path(path)
            files += sorted(p for p in path.rglob("*") if p.suffix.lower() in (".yml", ".yaml")) if path.is_dir() \
                else [path]
        for file in files:
            try:
                docs = [d for d in yaml.safe_load_all(file.read_text(encoding="utf-8")) if d]
            except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
                errors.append((str(file), f"YAML: {exc}"))
                continue
            for doc in docs:
                if isinstance(doc, dict) and doc.get("status") in skip_status:
                    continue
                try:
                    rule = compile_rule(doc, str(file))
                except (SigmaError, re.error, ValueError, TypeError) as exc:
                    errors.append((str(file), str(exc)))
                    continue
                if LEVEL_RANK[rule.level] >= LEVEL_RANK.get(min_level, 0):
                    rules.append(rule)
        return cls(rules), errors

    def match(self, channel: str, event_id: int, event: dict) -> list[SigmaRule]:
        channel = channel.lower()
        hits = []
        for key in ((channel, event_id), (channel, None)):
            for rule, field_map in self._index.get(key, ()):
                try:
                    if rule.matches(event, field_map):
                        hits.append(rule)
                except (TypeError, ValueError):
                    continue
        return hits
