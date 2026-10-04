"""Running Volatility 3 and reading its JSON output.

Volatility is executed as a separate process (``vol -q -r json -f IMAGE PLUGIN``)
so its own dependencies and symbol downloads stay out of the framework; its raw
output is kept next to the analysis. Outputs produced earlier by the analyst
(``vol -r json ... > pslist.json``) can be imported instead.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

# Short name -> Volatility plugin names to try (newer releases first).
PLUGINS: dict[str, tuple[str, ...]] = {
    "info": ("windows.info.Info",),
    "pslist": ("windows.pslist.PsList",),
    "psscan": ("windows.psscan.PsScan",),
    "pstree": ("windows.pstree.PsTree",),
    "cmdline": ("windows.cmdline.CmdLine",),
    "netscan": ("windows.netscan.NetScan",),
    "malfind": ("windows.malware.malfind.Malfind", "windows.malfind.Malfind"),
    "svcscan": ("windows.svcscan.SvcScan",),
}
DEFAULT_PLUGINS = tuple(PLUGINS)
MEMORY_SUFFIXES = {".raw", ".mem", ".vmem", ".dmp", ".lime", ".bin", ".img", ".dump", ".core", ".vmss", ".vmsn"}


class VolatilityError(Exception):
    pass


def volatility_command(vol_path: Optional[str] = None) -> Optional[list[str]]:
    """The command that runs Volatility 3, or ``None`` when it is not installed."""
    if vol_path:
        return [sys.executable, vol_path] if vol_path.lower().endswith(".py") else [vol_path]
    if importlib.util.find_spec("volatility3") is not None:
        return [sys.executable, "-c", "import sys; from volatility3.cli import main; sys.argv[0] = 'vol'; main()"]
    for name in ("vol", "vol.exe", "vol.py"):
        found = shutil.which(name)
        if found:
            return volatility_command(found)
    return None


def run_plugin(command: list[str], image: Path, plugin: str, output: Path, symbols: Optional[str] = None,
               offline: bool = False, timeout: int = 3600) -> list[dict]:
    """Run one plugin (trying the alternative names) and save its JSON output to ``output``."""
    errors = []
    for name in PLUGINS.get(plugin, (plugin,)):
        args = [*command, "-q", "-r", "json", "-f", str(image)]
        if symbols:
            args += ["-s", symbols]
        if offline:
            args.append("--offline")
        try:
            result = subprocess.run([*args, name], capture_output=True, timeout=timeout, check=False)  # noqa: S603
        except subprocess.TimeoutExpired as exc:
            raise VolatilityError(f"{name}: timeout ({timeout} s)") from exc
        except OSError as exc:
            raise VolatilityError(f"{name}: {exc}") from exc
        stdout = result.stdout.decode("utf-8", errors="replace")
        if result.returncode == 0:
            output.write_text(stdout, encoding="utf-8")
            return parse_output(stdout)
        message = _last_lines(result.stderr.decode("utf-8", errors="replace") + "\n" + stdout)
        errors.append(f"{name}: {message}")
        if "invalid choice" not in message and "argument PLUGIN" not in message:
            break
    raise VolatilityError("; ".join(errors))


def _last_lines(text: str, count: int = 3) -> str:
    """The informative part of a Volatility error (requirement failures, argparse errors, tracebacks)."""
    lines = [line.strip()[:300] for line in text.splitlines() if line.strip() and not line.startswith("Volatility 3")]
    key = [line for line in lines if re.match(r"(Unable to|Unsatisfied requirement|vol(\.py|\.exe)?: error|\w*Error\b)",
                                              line)]
    return " | ".join((key or lines)[-count:]) or "error"


def parse_output(text: str) -> list[dict]:
    """Rows of a ``-r json`` (array) or ``-r jsonl`` output, with tree children flattened."""
    text = text.lstrip("﻿")
    start = text.find("[")
    if start >= 0:
        try:
            data = json.loads(text[start:])
        except json.JSONDecodeError:
            data = None
        if isinstance(data, list):
            return flatten(data)
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            rows.append(json.loads(line))
    if not rows and text.strip():
        raise VolatilityError("not a Volatility JSON output")
    return flatten(rows)


def flatten(rows: list, depth: int = 0) -> list[dict]:
    flat = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        children = row.get("__children") or []
        flat.append({**{k: v for k, v in row.items() if k != "__children"}, "__depth": depth})
        flat.extend(flatten(children, depth + 1))
    return flat


def find_outputs(folder: Path) -> dict[str, Path]:
    """Volatility outputs saved by the analyst, recognised by the plugin name in the file name."""
    found: dict[str, Path] = {}
    for path in sorted(folder.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in (".json", ".jsonl", ".txt"):
            continue
        name = path.name.lower()
        for plugin in PLUGINS:
            if re.search(rf"(^|[^a-z]){plugin}([^a-z]|$)", name) and plugin not in found:
                found[plugin] = path
                break
    return found


def find_memory_image(folder: Path) -> Optional[Path]:
    candidates = [p for p in sorted(folder.iterdir()) if p.is_file() and p.suffix.lower() in MEMORY_SUFFIXES]
    return max(candidates, key=lambda p: p.stat().st_size) if candidates else None
