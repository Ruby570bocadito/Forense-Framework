"""Microsoft Defender: support logs (MPLog) and detection history.

MPLog files survive event-log clearing and show processes that ran (with how
much file activity Defender saw for each), files examined with their SHA-1 and
SHA-256, and every detection with what was done about it. Detection history
files keep one detection each (threat, resources, user).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from forense.core.heuristics import is_suspicious_location, strip_device, tool_category
from forense.core.utils import find_files, relative_name
from forense.modules.base import AnalysisContext, Module, register
from forense.parsers.defender import decode_text, parse_detection_history, parse_mplog, threat_category

MAX_SIZE = 256 * 1024 * 1024
SEVERE_CATEGORIES = {"ransom", "backdoor", "trojan", "hacktool", "exploit", "behavior", "virtool", "trojandownloader",
                     "trojandropper", "pws", "worm"}


def _is_mplog(path: Path) -> bool:
    return path.name.lower().startswith("mplog-") and path.suffix.lower() in (".log", ".bak", "")


def _is_detection_history(path: Path) -> bool:
    return "detectionhistory" in str(path).lower().replace("\\", "/") and path.is_file() and path.suffix == ""


@register
class DefenderModule(Module):
    name = "defender"
    category = "windows"
    triage = True

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: _is_mplog(p) or _is_detection_history(p))

    def analyze(self, ctx: AnalysisContext) -> None:
        counts = {"mplog_files": 0, "processes": 0, "files": 0, "detections": 0, "detection_history": 0}
        tools: set[str] = set()
        threats: dict[tuple[str, str], str] = {}
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            ctx.progress(rel)
            try:
                if path.stat().st_size > MAX_SIZE:
                    raise ValueError("file too large")
                raw = path.read_bytes()
            except (OSError, ValueError) as exc:
                ctx.error(rel, exc)
                continue
            if _is_mplog(path):
                counts["mplog_files"] += 1
                self._mplog(ctx, decode_text(raw), rel, counts, tools, threats)
            else:
                detection = parse_detection_history(raw)
                if detection is None:
                    continue
                counts["detection_history"] += 1
                written = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
                resources = "; ".join(f"{kind}: {res}" for kind, res in detection.resources)
                ctx.record("defender_detection_history", {
                    "file": rel, "threat": detection.threat, "category": threat_category(detection.threat),
                    "resources": resources, "user": detection.user, "process": detection.process,
                    "written": written.isoformat().replace("+00:00", "Z")})
                resource = detection.resources[0][1] if detection.resources else ""
                ctx.event(written, "defender_detection", f"{detection.threat} — {resource}", rel, "high")
                self._detection_finding(ctx, written, detection.threat, resource, "history", detection.user,
                                        threats)
        ctx.summary.update(counts)
        if tools:
            ctx.summary["attack_tools_seen"] = sorted(tools)

    def _mplog(self, ctx: AnalysisContext, text: str, rel: str, counts: dict, tools: set,
               threats: dict) -> None:
        for entry in parse_mplog(text):
            data = entry.data
            if entry.kind == "process":
                data["slowest_file"] = strip_device(data["slowest_file"])
                counts["processes"] += 1
                ctx.record("defender_process", {"file": rel, "timestamp": entry.timestamp, **data})
                ctx.event(entry.timestamp, "defender_process_activity",
                          f"{data['name']} PID {data['pid']} ×{data['count']}", rel)
                category = tool_category(data["name"])
                if category and data["name"].lower() not in tools:
                    tools.add(data["name"].lower())
                    ctx.finding("defender.attack_tool", "high", entry.timestamp, program=data["name"],
                                pid=data["pid"], file=data["slowest_file"] or "-", category=category)
            elif entry.kind == "file":
                counts["files"] += 1
                path = strip_device(data["path"])
                ctx.record("defender_file", {"file": rel, "timestamp": entry.timestamp, **data, "path": path})
                if is_suspicious_location(path) and path.lower().endswith((".exe", ".dll", ".ps1", ".bat", ".js",
                                                                          ".vbs", ".hta", ".scr")):
                    ctx.event(entry.timestamp, "defender_file_scanned", f"{path} (SHA-256 {data['sha256']})", rel,
                              "low")
            else:
                counts["detections"] += 1
                ctx.record("defender_detection", {"file": rel, "timestamp": entry.timestamp, **data})
                ctx.event(entry.timestamp, "defender_detection",
                          f"{data['threat']} — {data['resource']} ({data['action']})", rel, "high")
                self._detection_finding(ctx, entry.timestamp, data["threat"], data["resource"], data["action"],
                                        "", threats)

    @staticmethod
    def _detection_finding(ctx: AnalysisContext, when, threat: str, resource: str, action: str, user: str,
                           threats: dict) -> None:
        """One finding per threat and resource, whatever the number of log lines about it."""
        key = (threat, resource.lower())
        if threats.get(key) == "reported":
            return
        threats[key] = "reported"
        category = threat_category(threat)
        severity = "critical" if category.lower() in ("ransom", "backdoor") else \
            "high" if category.lower() in SEVERE_CATEGORIES else "medium"
        ctx.finding("defender.detection", severity, when, threat=threat, resource=resource or "-",
                    category=category, user=user or "-")
