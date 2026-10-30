"""Microsoft Defender support logs (MPLog) and detection history files.

``ProgramData\\Microsoft\\Windows Defender\\Support\\MPLog-*.log`` (UTF-16 text)
keeps weeks of activity even when the event logs were cleared:

* process performance lines (``ProcessImageName: x.exe, Pid: .., Count: ..``):
  processes that ran while Defender scanned their activity — evidence of
  execution;
* cloud queries (``SDN:Issuing SDN query for <file> (sha1=.., sha2=..)``):
  files examined with their SHA-1 and SHA-256;
* detections (``DETECTION_ADD``, ``DETECTIONEVENT``, ``DETECTION_CLEAN``):
  threat name, resource and what was done with it.

``Scans\\History\\Service\\DetectionHistory\\*\\*`` binary files describe one
detection each; their UTF-16 strings hold the threat name, the resources
(``file:_C:\\...``) and the user, and the file's modification time is when the
detection was written.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, Optional

_LINE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(?P<text>.*)$")
_PROCESS = re.compile(r"ProcessImageName:\s*(?P<name>[^,]+?),\s*Pid:\s*(?P<pid>\d+),\s*TotalTime:\s*(?P<total>\d+),"
                      r"\s*Count:\s*(?P<count>\d+),\s*MaxTime:\s*\d+,\s*MaxTimeFile:\s*(?P<file>.*?),"
                      r"\s*EstimatedImpact:\s*(?P<impact>\d+)%?", re.IGNORECASE)
_SDN = re.compile(r"SDN:Issuing SDN query for (?P<path>.+?) \((?P<device>[^()]*)\) "
                  r"\(sha1=(?P<sha1>[0-9a-f]{40}), sha2=(?P<sha256>[0-9a-f]{64})\)", re.IGNORECASE)
THREAT = r"[A-Za-z]+:[A-Za-z0-9]+/[^\s;,]+"
_DETECTION = re.compile(rf"(?P<action>DETECTION_(?:ADD|CLEAN|REMOVE|QUARANTINE)|DETECTIONEVENT)\S*\s+"
                        rf"(?:(?P<source>MPSOURCE_\w+)\s+)?(?P<threat>{THREAT})\s+(?P<kind>\w+):(?P<resource>.+?)"
                        rf"(?:;|\s+PidTid:|\s+Process:|$)")
_THREAT = re.compile(rf"^{THREAT}$")
_RESOURCE = re.compile(r"^(?P<kind>file|containerfile|process|regkey|regkeyvalue|webfile|amsi|behavior)"
                       r":_(?P<path>.+)$", re.IGNORECASE)
_ACCOUNT = re.compile(r"^[A-Za-z0-9 ._-]{1,63}\\[^\\\s]{1,104}$")


@dataclass
class MpLogEntry:
    kind: str  # process | file | detection
    timestamp: Optional[str]
    data: dict = field(default_factory=dict)


def decode_text(raw: bytes) -> str:
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    if raw[1:200:2].count(0) > 50:  # UTF-16LE without a byte order mark
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("utf-8", errors="replace")


def _timestamp(text: str) -> str:
    return text if text.endswith("Z") else text + "Z"


def parse_mplog(text: str) -> Iterator[MpLogEntry]:
    seen: set[tuple] = set()
    for line in text.splitlines():
        match = _LINE.match(line.strip("\ufeff \t\r"))
        if not match:
            continue
        when, body = _timestamp(match.group("ts")), match.group("text")
        process = _PROCESS.search(body)
        if process:
            path = process.group("file").split("->", 1)[0].strip()
            yield MpLogEntry("process", when, {
                "name": process.group("name").strip(), "pid": int(process.group("pid")),
                "count": int(process.group("count")), "total_ms": int(process.group("total")),
                "impact_percent": int(process.group("impact")), "slowest_file": path})
            continue
        sdn = _SDN.search(body)
        if sdn:
            key = ("file", sdn.group("sha256").lower())
            if key not in seen:
                seen.add(key)
                yield MpLogEntry("file", when, {"path": sdn.group("path"), "sha1": sdn.group("sha1").lower(),
                                                "sha256": sdn.group("sha256").lower()})
            continue
        detection = _DETECTION.search(body)
        if detection:
            action = detection.group("action")
            resource = detection.group("resource").strip()
            key = ("detection", action, detection.group("threat"), resource.lower())
            if key not in seen:
                seen.add(key)
                yield MpLogEntry("detection", when, {
                    "threat": detection.group("threat"), "resource_type": detection.group("kind").lower(),
                    "resource": resource, "action": action.replace("DETECTION_", "").replace("DETECTIONEVENT",
                                                                                            "EVENT").lower(),
                    "source": (detection.group("source") or "").replace("MPSOURCE_", "").lower()})


def utf16_strings(raw: bytes, minimum: int = 4) -> list[str]:
    """Printable UTF-16LE strings (Latin-1 range) of at least ``minimum`` characters."""
    pattern = re.compile(rb"(?:[\x20-\x7e\xa0-\xff]\x00){%d,}" % minimum)
    return [match.group(0).decode("utf-16-le") for match in pattern.finditer(raw)]


@dataclass
class Detection:
    threat: str
    resources: list[tuple[str, str]]  # (kind, path)
    user: str = ""
    process: str = ""
    written: Optional[datetime] = None


def parse_detection_history(raw: bytes) -> Optional[Detection]:
    strings = utf16_strings(raw)
    threat = next((s for s in strings if _THREAT.match(s)), None)
    if threat is None:
        return None
    resources = []
    for text in strings:
        match = _RESOURCE.match(text)
        if match and (match.group("kind").lower(), match.group("path")) not in resources:
            resources.append((match.group("kind").lower(), match.group("path")))
    user = next((s for s in strings if _ACCOUNT.match(s) and not s.lower().startswith(("c:\\", "nt authority"))),
                "")
    process = next((s for s in strings if s.lower().endswith(".exe") and ":\\" in s and not _RESOURCE.match(s)
                    and all(s != path for _, path in resources)), "")
    return Detection(threat, resources, user, process)


def threat_category(threat: str) -> str:
    """``HackTool``, ``Trojan``, ``Ransom``... (the part before the colon)."""
    return threat.split(":", 1)[0]
