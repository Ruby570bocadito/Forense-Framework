"""PowerShell command history (PSReadLine ConsoleHost_history.txt), one file per user and host.

PSReadLine keeps every command typed in an interactive PowerShell session
(except those it considers to contain secrets). The file has no timestamps:
its modification time is that of the last command.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from forense.core.heuristics import ATTACK_TOOLS, suspicious_command_rules
from forense.core.utils import find_files, relative_name, user_from_path
from forense.modules.base import AnalysisContext, Module, register

MAX_SIZE = 64 * 1024 * 1024
_TOOLS = re.compile(r"(?<![\w.-])(" + "|".join(re.escape(n[:-4]) for n in sorted(ATTACK_TOOLS) if n.endswith(".exe"))
                    + r")(\.exe)?(?![\w-])", re.IGNORECASE)


def parse_history(text: str) -> list[tuple[int, str]]:
    """``(line number, command)`` pairs; lines ending with a backtick continue on the next one."""
    commands: list[tuple[int, str]] = []
    pending: list[str] = []
    start = 0
    for number, line in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        if line.endswith("`"):
            pending.append(line[:-1])
            continue
        pending.append(line)
        command = "\n".join(pending).strip()
        pending = []
        if command:
            commands.append((start, command))
    if pending and "\n".join(pending).strip():
        commands.append((start, "\n".join(pending).strip()))
    return commands


@register
class PsReadLineModule(Module):
    name = "psreadline"
    category = "windows"
    triage = True

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: p.name.lower().endswith("_history.txt")
                          and "psreadline" in str(p).lower().replace("\\", "/"))

    def analyze(self, ctx: AnalysisContext) -> None:
        per_user: dict[str, int] = {}
        flagged = 0
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            try:
                if path.stat().st_size > MAX_SIZE:
                    raise ValueError("file too large")
                text = path.read_bytes().decode("utf-8-sig", errors="replace")
                modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            except (OSError, ValueError) as exc:
                ctx.error(rel, exc)
                continue
            user = user_from_path(path) or "-"
            host = path.name[: -len("_history.txt")]
            commands = parse_history(text)
            per_user[user] = per_user.get(user, 0) + len(commands)
            for position, (line, command) in enumerate(commands, 1):
                ctx.record("powershell_command", {"file": rel, "user": user, "host": host, "line": line,
                                                  "position": position, "command": command})
                rules = suspicious_command_rules(command)
                tools = sorted({m.group(1).lower() for m in _TOOLS.finditer(command)})
                if rules or tools:
                    flagged += 1
                    ctx.finding("psreadline.suspicious_command", "high", None, user=user, line=line,
                                command=command[:500], rules=", ".join(rules + [f"tool:{t}" for t in tools]))
            if commands:
                ctx.event(modified, "powershell_history", f"{user} ({host}), {len(commands)} commands; "
                          f"last: {commands[-1][1][:300]}", rel)
        ctx.summary.update({"commands_per_user": per_user, "suspicious_commands": flagged})
