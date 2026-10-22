"""Helpers to run the installed ``forense`` CLI as a subprocess.

Intentionally NOT named ``conftest.py``: ``tests/`` has no ``__init__.py``,
so a second conftest would shadow the root one and break
``from conftest import ...`` in tests/test_report.py and tests/test_web.py.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def forense_path() -> str:
    """Path of the installed ``forense`` console script."""
    exe = shutil.which("forense")
    if not exe:
        pytest.fail("the 'forense' console script is not on PATH (pip install -e .)")
    return exe


def run(*args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    """Run the CLI the way a user does and return the completed process."""
    return subprocess.run(
        [forense_path(), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def make_demo_lab(parent: Path) -> Path:
    """Generate a fresh ``forense demo`` lab (fast, offline)."""
    lab = parent / "lab"
    proc = run("demo", str(lab), timeout=300)
    assert proc.returncode == 0, proc.stderr
    return lab
