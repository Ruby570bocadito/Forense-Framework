"""E2E regression for H-007 (closed by IMP-1 in dfe9cde).

A case directory copied with ``cp -r``/rsync must verify ITSELF:
the stored paths are re-based to the case root, so tampering a file
inside the copy fails (exit 2) while the original stays green (exit 0),
and the copy keeps verifying after being moved elsewhere.
"""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

from _cli import make_demo_lab, run


def _case_with_copied_evidence(ws: Path, name: str) -> Path:
    case = ws / name
    assert run("new", str(case), "-n", name, "-i", "e2e").returncode == 0
    triage = ws.parent / "evidence" / "triage_WS-CONTAB01"
    if not triage.is_dir():
        triage = Path("tests/data")  # fallback when there is no demo lab
    assert run("-c", str(case), "evidencia", "agregar", str(triage), "-d", "copiado", "--copy").returncode == 0
    return case


def _tamper_one_file(case: Path) -> Path:
    stored = sorted(p for p in (case / "evidence").rglob("*") if p.is_file())
    assert stored, "no stored evidence files in the case"
    target = stored[0]
    assert not target.stat().st_mode & stat.S_IWUSR, "stored evidence should be read-only"
    os.chmod(target, target.stat().st_mode | stat.S_IWUSR)
    target.write_bytes(target.read_bytes() + b"\x00")
    return target


def test_copia_cp_verifica_contra_si_misma(tmp_path) -> None:
    ws = tmp_path / "ws"
    lab = make_demo_lab(ws)
    triage = lab / "evidence" / "triage_WS-CONTAB01"

    case = ws / "caso"
    assert run("new", str(case), "-n", "caso", "-i", "e2e").returncode == 0
    assert run("-c", str(case), "evidencia", "agregar", str(triage), "-d", "x", "--copy").returncode == 0
    assert run("verificar", "-c", str(case)).returncode == 0

    # cp -r of the whole case: the copy must verify independently (H-007).
    copia = tmp_path / "caso-copia"
    shutil.copytree(case, copia)
    proc = run("verificar", "-c", str(copia))
    assert proc.returncode == 0, f"an untouched cp -r copy must verify: {proc.stdout}"

    # Tamper INSIDE the copy: it must fail against its own file, exit 2...
    _tamper_one_file(copia)
    proc = run("-L", "es", "verificar", "-c", str(copia))
    assert proc.returncode == 2, f"expected exit 2 on tampered copy: {proc.stdout}"
    assert "FAIL" in proc.stdout + proc.stderr, proc.stdout

    # ...while the original stays green.
    assert run("verificar", "-c", str(case)).returncode == 0

    # And the (moved) copy keeps resolving its own evidence: rename and re-check.
    movida = tmp_path / "caso-movido"
    shutil.copytree(copia, movida)  # copy of the tampered copy, in a new place
    proc = run("verificar", "-c", str(movida))
    assert proc.returncode == 2, "the moved copy must still verify its own (tampered) evidence"
    assert "FAIL" in proc.stdout + proc.stderr
