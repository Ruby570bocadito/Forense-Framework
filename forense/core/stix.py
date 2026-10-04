"""STIX 2.1 export: indicators of compromise found in a case, plus the ATT&CK techniques observed.

Indicators come from what the analysis established, not from every string
seen: known-bad hashes matched, files matched by YARA (hashed now), suspicious
programs with an Amcache SHA-1, external IPs of suspicious connections, URLs
and domains of downloads and watchlist hits. Intelligence matches are always
exported; other findings once the analyst confirmed them, or while still
pending if their severity is high or critical. False positives are left out. Identifiers are deterministic (UUIDv5), so
exporting twice gives the same objects.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from forense import __version__
from forense.core.attack import TECHNIQUES, attack_matrix
from forense.core.case import Case
from forense.core.execution import execution_overview
from forense.core.utils import utc_now

NAMESPACE = uuid.UUID("5d7a3c1e-6f0b-4b8e-9d55-2c1f0e4a9b77")
_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)


def _id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, kind + ':' + key)}"


def _stix_time(value: Optional[str]) -> str:
    """STIX timestamps: ``YYYY-MM-DDTHH:MM:SS.mmmZ``."""
    value = value or utc_now()
    return value[:23] + "Z" if len(value) >= 23 else value


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified) or \
        ip in ipaddress.ip_network("198.51.100.0/24") or ip in ipaddress.ip_network("203.0.113.0/24") or \
        ip in ipaddress.ip_network("192.0.2.0/24")


def collect_indicators(case: Case) -> dict[str, dict]:
    """``pattern -> {type, value, description, first_seen, findings}``."""
    found: dict[str, dict] = {}

    def add(pattern: str, kind: str, value: str, description: str, when: Optional[str], finding: Optional[int]):
        item = found.setdefault(pattern, {"type": kind, "value": value, "description": description,
                                          "first_seen": when, "findings": []})
        if when and (not item["first_seen"] or when < item["first_seen"]):
            item["first_seen"] = when
        if finding is not None and finding not in item["findings"]:
            item["findings"].append(finding)

    findings = [f for f in case.findings() if _exportable(f)]
    for f in findings:
        p, when, fid = f["params"], f.get("timestamp"), f["id"]
        if f["code"] == "hashset.match" and p.get("hash"):
            algo = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}.get(str(p.get("algorithm")).lower(), "SHA-256")
            add(f"[file:hashes.'{algo}' = '{p['hash'].lower()}']", "file", p["hash"].lower(),
                f"{p.get('description') or 'Known-bad hash'}: {p.get('path')}", when, fid)
        elif f["code"] == "yara.match":
            digest = _evidence_sha256(case, f["evidence_id"], p.get("file", ""))
            if digest:
                add(f"[file:hashes.'SHA-256' = '{digest}']", "file", digest,
                    f"YARA {p.get('rule')}: {p.get('file')}", when, fid)
        elif f["code"] == "memory.suspicious_connection":
            host = str(p.get("remote", "")).rsplit(":", 1)[0].strip("[]")
            if _public_ip(host):
                add(f"[ipv4-addr:value = '{host}']" if ":" not in host else f"[ipv6-addr:value = '{host}']",
                    "ip", host, f"Connection from {p.get('process')}", when, fid)
        elif f["code"] in ("browser.executable_download", "browser.dangerous_download", "mft.downloaded_executable",
                           "browser.suspicious_domain"):
            url = str(p.get("url") or "")
            if url.startswith(("http://", "https://")):
                add(f"[url:value = '{_escape(url)}']", "url", url, f"{f['code']}: {p.get('path') or ''}".strip(),
                    when, fid)
                host = urlparse(url).hostname or ""
                if _DOMAIN.match(host):
                    add(f"[domain-name:value = '{host.lower()}']", "domain", host.lower(), f"Host of {url}", when, fid)
                elif _public_ip(host):
                    add(f"[ipv4-addr:value = '{host}']", "ip", host, f"Host of {url}", when, fid)
        elif f["code"] == "ioc.watchlist_match":
            value = str(p.get("indicator") or "")
            if _public_ip(value):
                add(f"[ipv4-addr:value = '{value}']", "ip", value, "Watchlist indicator found", when, fid)
            elif _DOMAIN.match(value):
                add(f"[domain-name:value = '{value.lower()}']", "domain", value.lower(), "Watchlist indicator found",
                    when, fid)
            elif "@" in value:
                add(f"[email-addr:value = '{_escape(value)}']", "email", value, "Watchlist indicator found", when, fid)
    for program in execution_overview(case, suspicious=True):
        for sha1 in program.sha1:
            if re.fullmatch(r"[0-9a-f]{40}", sha1.lower()):
                add(f"[file:hashes.'SHA-1' = '{sha1.lower()}']", "file", sha1.lower(),
                    f"{program.name} ({', '.join(program.flags)}): {program.path}", program.first, None)
    return found


INTEL_MATCHES = ("hashset.match", "yara.match", "ioc.watchlist_match")


def _exportable(finding: dict) -> bool:
    """Intelligence matches always; other findings once confirmed, or while pending if high or critical."""
    status = (finding.get("review") or {}).get("status") or "pending"
    if status == "false_positive":
        return False
    return finding["code"] in INTEL_MATCHES or status == "confirmed" or finding["severity"] in ("high", "critical")


def _evidence_sha256(case: Case, evidence_id: str, relative: str) -> Optional[str]:
    try:
        root = Path(case.get_evidence(evidence_id).path)
    except Exception:  # noqa: BLE001 - evidence removed
        return None
    path = root if root.is_file() else root / relative
    try:
        if not path.is_file() or path.stat().st_size > 512 * 1024 * 1024:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def build_bundle(case: Case) -> dict:
    info = case.info
    now = _stix_time(utc_now())
    identity = {"type": "identity", "spec_version": "2.1", "id": _id("identity", info.get("organization") or
                                                                       info.get("investigator") or "forense"),
                "created": now, "modified": now, "name": info.get("organization") or info.get("investigator") or
                "Forense-Framework", "identity_class": "organization" if info.get("organization") else "individual"}
    objects: list[dict] = [identity]
    refs: list[str] = []
    for pattern, item in sorted(collect_indicators(case).items()):
        indicator = {
            "type": "indicator", "spec_version": "2.1", "id": _id("indicator", pattern), "created": now,
            "modified": now, "created_by_ref": identity["id"], "name": f"{item['type']}: {item['value']}",
            "description": item["description"], "indicator_types": ["malicious-activity"], "pattern": pattern,
            "pattern_type": "stix", "valid_from": _stix_time(item["first_seen"]),
            "labels": [f"forense-finding-{fid}" for fid in item["findings"]][:20],
        }
        objects.append(indicator)
        refs.append(indicator["id"])
    for hits in attack_matrix(case.findings()).values():
        for hit in hits:
            pattern_id = _id("attack-pattern", hit.technique)
            if pattern_id in refs:
                continue
            objects.append({
                "type": "attack-pattern", "spec_version": "2.1", "id": pattern_id, "created": now, "modified": now,
                "name": TECHNIQUES.get(hit.technique, (hit.name,))[0],
                "external_references": [{"source_name": "mitre-attack", "external_id": hit.technique,
                                         "url": hit.url}],
            })
            refs.append(pattern_id)
    report = {
        "type": "report", "spec_version": "2.1", "id": _id("report", info.get("id", "case")), "created": now,
        "modified": now, "created_by_ref": identity["id"], "name": f"{info.get('id')} — {info.get('name')}",
        "description": info.get("description") or "", "report_types": ["incident"],
        "published": now, "object_refs": refs or [identity["id"]],
        "external_references": [{"source_name": "Forense-Framework", "description": f"version {__version__}",
                                  "external_id": info.get("id", "")}],
    }
    objects.append(report)
    return {"type": "bundle", "id": _id("bundle", info.get("id", "case") + now), "objects": objects}


def export_stix(case: Case, path: Path, actor: Optional[str] = None) -> Path:
    from forense.core.exports import _log

    bundle = build_bundle(case)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, ensure_ascii=False, indent=1), encoding="utf-8")
    indicators = sum(1 for o in bundle["objects"] if o["type"] == "indicator")
    return _log(case, path, "stix", indicators, actor)
