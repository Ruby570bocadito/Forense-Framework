"""E2E: ``forense verificar`` exit codes on a healthy and a tampered case.

Regression test of the custody guarantee documented in the README:
a healthy case verifies (exit 0) and any altered evidence must fail
verification (exit 2) so the analyst cannot miss the change.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from _cli import make_demo_lab, run


@pytest.fixture(scope="module")
def demo_lab(tmp_path_factory) -> Path:
    """A fresh ``forense demo`` lab shared by the tests of this module."""
    return make_demo_lab(tmp_path_factory.mktemp("e2e-lab"))


def test_verificar_healthy_demo_case(demo_lab: Path) -> None:
    proc = run("verificar", "-c", str(demo_lab / "case_demo"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "FAIL" not in proc.stdout, proc.stdout


def test_verificar_detects_tampered_evidence(demo_lab: Path) -> None:
    # Flip a byte of an evidence file inside a COPY of the case, so the
    # shared demo lab of the module stays healthy for the other test.
    copy = demo_lab.parent / "case_tampered"
    proc = run("new", str(copy), "-n", "tampered copy", "-i", "e2e")
    assert proc.returncode == 0, proc.stderr
    # Register the same demo triage folder; --copy makes a read-only working
    # copy inside the case, so the shared demo lab stays untouched.
    triage = demo_lab / "evidence" / "triage_WS-CONTAB01"
    proc = run("-c", str(copy), "evidencia", "agregar", str(triage), "-d", "copied triage", "--copy")
    assert proc.returncode == 0, proc.stderr
    stored_dir = copy / "evidence"
    assert stored_dir.is_dir() and any(stored_dir.rglob("*")), "evidence was not copied into the case"

    # The fresh copy verifies.
    proc = run("verificar", "-c", str(copy))
    assert proc.returncode == 0, proc.stdout + proc.stderr

    # Tamper with one stored file (a copy, never the shared demo lab).
    stored = sorted(
        (p for p in stored_dir.rglob("*") if p.is_file()),
        key=lambda p: p.stat().st_size,
    )
    assert stored, "no stored files found in the case copy"
    target = stored[0]
    # Stored evidence is read-only by design; the analyst would have to lift
    # that protection deliberately, which is exactly what tampering means.
    assert not target.stat().st_mode & stat.S_IWUSR, "stored evidence should be read-only"
    os.chmod(target, target.stat().st_mode | stat.S_IWUSR)
    target.write_bytes(target.read_bytes() + b"\x00")

    proc = run("verificar", "-c", str(copy))
    assert proc.returncode == 2, f"expected exit 2 on tampered evidence, got {proc.returncode}: {proc.stdout}"
    assert "FAIL" in proc.stdout or "FAIL" in proc.stderr, proc.stdout + proc.stderr
