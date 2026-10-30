"""Helpers to run the installed ``sabueso`` CLI as a subprocess.

Intentionally NOT named ``conftest.py``: ``tests/`` has no ``__init__.py``,
so a second conftest would shadow the root one and break
``from conftest import ...`` in tests/test_report.py and tests/test_web.py.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


def sabueso_path() -> str:
    """Path of the installed ``sabueso`` console script."""
    exe = shutil.which("sabueso")
    if not exe:
        pytest.fail("the 'sabueso' console script is not on PATH (pip install -e .)")
    return exe


def run(*args: str, timeout: int = 120, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run the CLI the way a user does and return the completed process.

    ``env`` entries override ``os.environ`` for the child process (None values remove them).
    """
    child = dict(os.environ)
    for key, value in (env or {}).items():
        if value is None:
            child.pop(key, None)
        else:
            child[key] = value
    return subprocess.run(
        [sabueso_path(), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=child,
    )


def make_demo_lab(parent: Path) -> Path:
    """Generate a fresh ``sabueso demo`` lab (fast, offline)."""
    lab = parent / "lab"
    proc = run("demo", str(lab), timeout=300)
    assert proc.returncode == 0, proc.stderr
    return lab
