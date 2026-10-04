"""Scheduled tasks (Windows\\System32\\Tasks): persistence through the Task Scheduler.

Each task is an XML file (UTF-16) with its author, registration date, triggers,
principal and actions. Hidden tasks, tasks running interpreters or binaries from
user-writable folders and tasks running as SYSTEM are the usual persistence
indicators.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from forense.core.heuristics import autostart_suspicion, tool_category
from forense.core.utils import find_files, iso, relative_name
from forense.modules.base import AnalysisContext, Module, register

MAX_SIZE = 1024 * 1024
TRIGGERS = ("LogonTrigger", "BootTrigger", "TimeTrigger", "CalendarTrigger", "EventTrigger", "IdleTrigger",
            "RegistrationTrigger", "SessionStateChangeTrigger", "WnfStateChangeTrigger")
SYSTEM_ACCOUNTS = {"s-1-5-18": "SYSTEM", "s-1-5-19": "LOCAL SERVICE", "s-1-5-20": "NETWORK SERVICE",
                   "system": "SYSTEM", "nt authority\\system": "SYSTEM"}


def _text(node, path: str) -> str:
    found = node.find(path) if node is not None else None
    return (found.text or "").strip() if found is not None and found.text else ""


def _decode(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    if len(data) > 1 and data[1:2] == b"\x00":
        return data.decode("utf-16-le")
    return data.decode("utf-8-sig", errors="replace")


def parse_task(data: bytes) -> dict:
    """Fields of a task XML definition. Raises ValueError for anything that is not one."""
    text = _decode(data)
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise ValueError("DTDs are not allowed in task definitions")
    root = ET.fromstring(re.sub(r"^\s*<\?xml[^>]*\?>", "", text))
    if root.tag.rsplit("}", 1)[-1] != "Task":
        raise ValueError("not a Task document")
    info = root.find("{*}RegistrationInfo")
    principal = root.find("{*}Principals/{*}Principal")
    settings = root.find("{*}Settings")
    triggers = []
    for trigger in root.findall("{*}Triggers/*"):
        kind = trigger.tag.rsplit("}", 1)[-1]
        detail = _text(trigger, "{*}StartBoundary") or _text(trigger, "{*}Subscription")[:200] or _text(trigger, "{*}UserId")
        interval = _text(trigger, "{*}Repetition/{*}Interval")
        triggers.append(f"{kind}" + (f" {detail}" if detail else "") + (f" (every {interval})" if interval else ""))
    actions = []
    for action in root.findall("{*}Actions/*"):
        kind = action.tag.rsplit("}", 1)[-1]
        if kind == "Exec":
            actions.append({"type": "exec", "command": _text(action, "{*}Command"),
                            "arguments": _text(action, "{*}Arguments"),
                            "working_directory": _text(action, "{*}WorkingDirectory")})
        elif kind == "ComHandler":
            actions.append({"type": "com", "command": _text(action, "{*}ClassId"), "arguments": _text(action, "{*}Data"),
                            "working_directory": ""})
        else:
            actions.append({"type": kind.lower(), "command": "", "arguments": "", "working_directory": ""})
    user = _text(principal, "{*}UserId") or _text(principal, "{*}GroupId")
    return {
        "uri": _text(info, "{*}URI"), "author": _text(info, "{*}Author"), "description": _text(info, "{*}Description"),
        "registered": _text(info, "{*}Date"), "source": _text(info, "{*}Source"),
        "user": SYSTEM_ACCOUNTS.get(user.lower(), user), "run_level": _text(principal, "{*}RunLevel"),
        "logon_type": _text(principal, "{*}LogonType"),
        "hidden": _text(settings, "{*}Hidden").lower() == "true",
        "enabled": _text(settings, "{*}Enabled").lower() != "false",
        "triggers": triggers, "actions": actions,
    }


@register
class ScheduledTasksModule(Module):
    name = "tasks"
    category = "windows"
    triage = True

    def discover(self, target: Path) -> list[Path]:
        def candidate(path: Path) -> bool:
            parts = [p.lower() for p in path.parts]
            if "tasks" not in parts[:-1] or path.suffix.lower() in (".job", ".log", ".txt", ".dat"):
                return False
            try:
                with open(path, "rb") as fh:
                    head = fh.read(200)
            except OSError:
                return False
            return b"<\x00?\x00x\x00m\x00l" in head or b"<?xml" in head or b"<\x00T\x00a\x00s\x00k" in head

        return find_files(target, candidate)

    def analyze(self, ctx: AnalysisContext) -> None:
        total = hidden = 0
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            try:
                if path.stat().st_size > MAX_SIZE:
                    continue
                task = parse_task(path.read_bytes())
                modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            except (OSError, ValueError, ET.ParseError) as exc:
                ctx.error(rel, exc)
                continue
            total += 1
            hidden += task["hidden"]
            name = task["uri"] or "\\" + rel.split("Tasks/", 1)[-1].replace("/", "\\")
            commands = [f"{a['command']} {a['arguments']}".strip() for a in task["actions"]]
            ctx.record("scheduled_task", {
                "file": rel, "name": name, "author": task["author"], "description": task["description"][:500],
                "registered": task["registered"], "user": task["user"], "run_level": task["run_level"],
                "hidden": task["hidden"], "enabled": task["enabled"], "triggers": "; ".join(task["triggers"]),
                "actions": " | ".join(commands), "file_modified": iso(modified),
            })
            ctx.event(modified, "task_file_modified", f"{name}: {' | '.join(commands)}", rel)
            self._check(ctx, name, task, commands, modified)
        ctx.summary.update({"tasks": total, "hidden_tasks": hidden})

    @staticmethod
    def _check(ctx: AnalysisContext, name: str, task: dict, commands: list[str], when: datetime) -> None:
        reasons: list[str] = []
        for action, command in zip(task["actions"], commands, strict=True):
            if action["type"] != "exec":
                continue
            reasons += autostart_suspicion(command)
            if tool_category(action["command"].strip('"')):
                reasons.append(tool_category(action["command"].strip('"')))
        if not reasons and not task["hidden"]:
            return
        if task["hidden"]:
            reasons.append("hidden_task")
        if task["user"] == "SYSTEM" and reasons != ["hidden_task"]:
            reasons.append("runs_as_system")
        severity = "medium" if reasons == ["hidden_task"] else "high"
        if reasons == ["hidden_task"] and name.lower().startswith("\\microsoft\\"):
            return  # several built-in Microsoft tasks are hidden
        ctx.finding("tasks.suspicious_task", severity, when, task=name, command=" | ".join(commands) or "-",
                    user=task["user"] or "-", reasons=", ".join(dict.fromkeys(reasons)))
