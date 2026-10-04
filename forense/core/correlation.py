"""Correlation between the cases of a workspace: what one case shares with the others.

Each case is reduced to an index of *observables*: indicators of compromise
(the same ones exported to STIX), USB device serial numbers, remote IP
addresses (memory connections, network and RDP logons, RDP destinations, UNC
paths), computer names and domain accounts seen in remote logons. An
observable present in two or more cases links them: the same USB stick on two
computers, the same attacker IP, the same implant hash, the same account
moving laterally.

The index of each case is cached in ``<workspace>/.forense-correlation`` and
rebuilt only when the case's chain of custody changes (every analysis, review or
new evidence adds an entry), so the cases themselves are never written to.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from forense.core.case import Case

CACHE_DIR = ".forense-correlation"
INDEX_VERSION = 1
KINDS = ("file", "ip", "domain", "url", "email", "usb", "host", "account")
REMOTE_LOGON_EVENTS = (4624, 4625, 4648, 4778, 1149, 21, 24, 25)
_IGNORED_ACCOUNTS = {"system", "anonymous logon", "local service", "network service", "-", "", "dwm-1", "umfd-0",
                     "umfd-1", "defaultaccount", "wdagutilityaccount"}
_UNC = re.compile(r"^\\\\([^\\/]+)[\\/]")
_SERIAL = re.compile(r"^[A-Z0-9][A-Z0-9&_.-]{3,127}$")
_HOSTNAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9-]{1,63})*$", re.IGNORECASE)


@dataclass
class Observation:
    kind: str
    value: str  # normalised: lower case, hashes in hex
    display: str
    sources: set[str] = field(default_factory=set)
    first_seen: Optional[str] = None
    ioc: bool = False  # comes from a finding (known-bad list, YARA, watchlist, flagged program...)

    def merge(self, source: str, when: Optional[str], ioc: bool = False) -> None:
        self.sources.add(source)
        if when and (not self.first_seen or when < self.first_seen):
            self.first_seen = when
        self.ioc = self.ioc or ioc

    def to_json(self) -> dict:
        return {"kind": self.kind, "value": self.value, "display": self.display, "sources": sorted(self.sources),
                "first_seen": self.first_seen, "ioc": self.ioc}

    @classmethod
    def from_json(cls, data: dict) -> "Observation":
        return cls(data["kind"], data["value"], data["display"], set(data["sources"]), data["first_seen"],
                   data["ioc"])


@dataclass
class CaseIndex:
    slug: str
    path: Path
    name: str
    case_id: str
    observations: dict[tuple[str, str], Observation]


@dataclass
class Shared:
    kind: str
    value: str
    display: str
    cases: list[tuple[CaseIndex, Observation]]

    @property
    def ioc(self) -> bool:
        return any(o.ioc for _, o in self.cases)

    @property
    def first_seen(self) -> Optional[str]:
        times = [o.first_seen for _, o in self.cases if o.first_seen]
        return min(times) if times else None


# -- building the index of one case --------------------------------------------------------------
def _ip(value: str) -> Optional[str]:
    value = value.strip().strip("[]")
    if value.startswith("::ffff:"):
        value = value[7:]
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified or address.is_link_local or address.is_multicast:
        return None
    return str(address)


def _host(value: str) -> Optional[str]:
    value = value.strip().rstrip(".").lower()
    if not value or value in ("localhost", "-") or not _HOSTNAME.match(value):
        return None
    return value


def _records(case: Case, artifacts: Iterable[str]) -> Iterable[tuple[str, dict]]:
    names = list(artifacts)
    marks = ",".join("?" * len(names))
    for artifact, data in case.conn.execute(f"SELECT artifact, data FROM records WHERE artifact IN ({marks})",
                                            names):
        try:
            yield artifact, json.loads(data)
        except ValueError:
            continue


def _logon_records(case: Case) -> Iterable[dict]:
    """EVTX records of remote logons (network, RDP, explicit credentials)."""
    try:
        rows = case.conn.execute(
            "SELECT data FROM records WHERE artifact = 'event' AND json_extract(data, '$.event_id') IN "
            f"({','.join(str(e) for e in REMOTE_LOGON_EVENTS)})")
    except Exception:  # noqa: BLE001 - SQLite built without JSON1: filter in Python
        rows = case.conn.execute("SELECT data FROM records WHERE artifact = 'event'")
    for (data,) in rows:
        try:
            record = json.loads(data)
        except ValueError:
            continue
        if record.get("event_id") in REMOTE_LOGON_EVENTS:
            yield record


def build_index(case: Case) -> dict[tuple[str, str], Observation]:
    from forense.core.stix import collect_indicators

    found: dict[tuple[str, str], Observation] = {}

    def add(kind: str, value: Optional[str], display: str, source: str, when: Optional[str] = None,
            ioc: bool = False) -> None:
        if not value:
            return
        key = (kind, value)
        if key not in found:
            found[key] = Observation(kind, value, display)
        found[key].merge(source, when, ioc)

    for item in collect_indicators(case).values():
        kind = item["type"]
        value = item["value"].lower()
        if kind == "ip":
            value = _ip(value) or value
        add(kind, value, item["value"], "ioc", item["first_seen"], ioc=True)

    for artifact, data in _records(case, ("usb_device", "device_install", "memory_connection", "rdp_destination",
                                          "typed_path", "system_info")):
        if artifact == "usb_device" and _SERIAL.match(str(data.get("serial", "")).upper()):
            serial = str(data["serial"]).upper()
            add("usb", serial, f"{serial} ({data.get('friendly_name') or data.get('product') or 'USB'})",
                "usb_device", data.get("first_install") or data.get("last_connected"))
        elif (artifact == "device_install" and _SERIAL.match(str(data.get("serial", "")).upper())
              and "usbstor" in str(data.get("device", "")).lower()):
            serial = str(data["serial"]).upper()
            add("usb", serial, f"{serial} ({data.get('product') or 'USB'})", "setupapi", data.get("first_install"))
        elif artifact == "memory_connection":
            host = str(data.get("remote", "")).rsplit(":", 1)[0]
            add("ip", _ip(host), host.strip("[]"), "memory_connection", data.get("created"))
        elif artifact == "rdp_destination":
            server = str(data.get("server", ""))
            ip = _ip(server)
            when = data.get("key_last_written")
            add("ip" if ip else "host", ip or _host(server), server, "rdp_destination", when)
            hint = str(data.get("username_hint") or "")
            if "\\" in hint:
                add("account", hint.lower(), hint, "rdp_destination", when)
        elif artifact == "typed_path":
            match = _UNC.match(str(data.get("path", "")))
            if match:
                ip = _ip(match.group(1))
                add("ip" if ip else "host", ip or _host(match.group(1)), match.group(1), "typed_path")
        elif artifact == "system_info":
            name = str(data.get("computer_name") or "")
            add("host", _host(name), name, "computer_name")

    for record in _logon_records(case):
        values = record.get("data") or {}
        when = record.get("timestamp")
        source = f"evtx_{record.get('event_id')}"
        ip = _ip(str(values.get("IpAddress") or values.get("Address") or values.get("ClientAddress") or ""))
        add("ip", ip, ip or "", source, when)
        workstation = str(values.get("WorkstationName") or values.get("ClientName") or "")
        add("host", _host(workstation), workstation, source, when)
        user, domain = str(values.get("TargetUserName") or ""), str(values.get("TargetDomainName") or "")
        logon_type = str(values.get("LogonType") or "")
        if (user.lower() not in _IGNORED_ACCOUNTS and not user.endswith("$") and domain
                and logon_type in ("3", "10", "") and domain.lower() not in ("nt authority", "window manager",
                                                                             "font driver host")):
            account = f"{domain}\\{user}"
            add("account", account.lower(), account, source, when)
    return found


# -- workspace ----------------------------------------------------------------------------------
def case_dirs(workspace: Path) -> list[Path]:
    workspace = Path(workspace)
    return sorted(p for p in workspace.iterdir() if p.is_dir() and Case.is_case(p)) if workspace.is_dir() else []


def _cache_file(workspace: Path, slug: str) -> Path:
    return Path(workspace) / CACHE_DIR / f"{slug}.json"


def index_case(path: Path, workspace: Optional[Path] = None, cache: bool = True,
               build: bool = True) -> Optional[CaseIndex]:
    """Index of one case, from the cache when the custody chain has not changed since."""
    path = Path(path)
    workspace = Path(workspace) if workspace else path.parent
    with Case.open(path) as case:
        info = case.info
        stamp = f"{INDEX_VERSION}:{case.custody.head()}"
        cached = _cache_file(workspace, path.name)
        if cache and cached.is_file():
            try:
                data = json.loads(cached.read_text(encoding="utf-8"))
                if data.get("stamp") == stamp:
                    observations = {(o["kind"], o["value"]): Observation.from_json(o) for o in data["observations"]}
                    return CaseIndex(path.name, path, info.get("name", path.name), info.get("id", ""), observations)
            except (OSError, ValueError, KeyError):
                pass
        if not build:
            return None
        observations = build_index(case)
    if cache:
        try:
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_text(json.dumps({"stamp": stamp, "case": path.name,
                                          "observations": [o.to_json() for o in observations.values()]},
                                         ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass  # read-only workspace: correlation still works, only slower
    return CaseIndex(path.name, path, info.get("name", path.name), info.get("id", ""), observations)


def workspace_indexes(workspace: Path, cache: bool = True, build: bool = True,
                      progress=None) -> list[CaseIndex]:
    indexes = []
    for path in case_dirs(workspace):
        if progress:
            progress(path.name)
        try:
            index = index_case(path, workspace, cache, build)
        except Exception:  # noqa: BLE001 - a damaged case must not stop the correlation of the others
            continue
        if index is not None:
            indexes.append(index)
    return indexes


def correlate(indexes: list[CaseIndex], min_cases: int = 2, kinds: Optional[Iterable[str]] = None,
              focus: Optional[str] = None) -> list[Shared]:
    """Observables seen in at least ``min_cases`` cases (with ``focus``: only those of that case)."""
    wanted = set(kinds) if kinds else None
    by_key: dict[tuple[str, str], list[tuple[CaseIndex, Observation]]] = {}
    for index in indexes:
        for key, observation in index.observations.items():
            if wanted is None or key[0] in wanted:
                by_key.setdefault(key, []).append((index, observation))
    shared = []
    for (kind, value), cases in by_key.items():
        if len(cases) < max(2, min_cases):
            continue
        if focus and focus not in {index.slug for index, _ in cases}:
            continue
        display = next((o.display for _, o in cases if o.display), value)
        shared.append(Shared(kind, value, display, sorted(cases, key=lambda c: c[1].first_seen or "9999")))
    return sorted(shared, key=lambda s: (not s.ioc, -len(s.cases), KINDS.index(s.kind) if s.kind in KINDS else 99,
                                         s.value))
