"""`forense update`: check for and install a newer version from GitHub.

* installed with pip / the installers: upgrades the package in its own
  environment from the GitHub archive of the branch (``main`` first, then the
  development branch), keeping the Volatility extra if it is installed;
* standalone executable: points to the Releases page (the folder is replaced);
* development checkout (``pip install -e``): use ``git pull`` instead.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from forense import __version__
from forense.core.errors import ForenseError

REPOSITORY = "Ruby570bocadito/Forense-Framework"
REFS = ("main", "claude/inspiring-cray-xn35zk")
RELEASES = f"https://github.com/{REPOSITORY}/releases"
_VERSION = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']', re.MULTILINE)


@dataclass
class UpdateInfo:
    current: str
    latest: Optional[str]
    ref: Optional[str]
    mode: str  # pip | frozen | development

    @property
    def available(self) -> bool:
        return self.latest is not None and version_tuple(self.latest) > version_tuple(self.current)


def version_tuple(version: str) -> tuple:
    return tuple(int(part) if part.isdigit() else 0 for part in re.split(r"[.\-+]", version)[:4])


def install_mode() -> str:
    if getattr(sys, "frozen", False):
        return "frozen"
    if (Path(__file__).resolve().parent.parent / ".git").exists():
        return "development"
    return "pip"


def _fetch(url: str, timeout: float = 15.0) -> Optional[str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - fixed GitHub URLs
            return response.read(65536).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError):
        return None


def check(refs: tuple[str, ...] = REFS, fetch: Callable[[str], Optional[str]] = _fetch) -> UpdateInfo:
    """The newest version published on the first branch that answers."""
    for ref in refs:
        text = fetch(f"https://raw.githubusercontent.com/{REPOSITORY}/{ref}/forense/__init__.py")
        match = _VERSION.search(text or "")
        if match:
            return UpdateInfo(__version__, match.group(1), ref, install_mode())
    return UpdateInfo(__version__, None, None, install_mode())


def upgrade(info: UpdateInfo, run: Callable = subprocess.run) -> list[str]:
    """Install the version of ``info.ref`` in this environment; returns the pip command that was run."""
    if info.mode == "frozen":
        raise ForenseError("error.update_frozen", url=RELEASES)
    if info.mode == "development":
        raise ForenseError("error.update_development")
    if not info.ref:
        raise ForenseError("error.update_unreachable", repo=REPOSITORY)
    url = f"https://github.com/{REPOSITORY}/archive/refs/heads/{info.ref}.zip"
    spec = f"forense-framework[memory] @ {url}" if importlib.util.find_spec("volatility3") else url
    command = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--upgrade", spec]
    moved = _move_running_launcher()
    completed = run(command, check=False)  # noqa: S603 - fixed command, URL built from constants
    if getattr(completed, "returncode", 1) != 0:
        if moved and not moved[0].exists():
            moved[1].rename(moved[0])
        raise ForenseError("error.update_failed", code=getattr(completed, "returncode", "?"))
    return command


def _move_running_launcher() -> Optional[tuple[Path, Path]]:
    """Windows locks the running forense.exe but lets it be renamed: move it aside so pip can write the new one."""
    if sys.platform != "win32":
        return None
    launcher = Path(sys.executable).parent / "forense.exe"
    old = launcher.with_name("forense.exe.old")
    try:
        if old.exists():
            old.unlink()
        if launcher.exists():
            launcher.rename(old)
            return launcher, old
    except OSError:
        pass
    return None
