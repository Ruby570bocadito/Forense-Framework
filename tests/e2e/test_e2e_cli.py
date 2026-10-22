"""E2E battery (personas-r1, TEST): the complete CLI flow over real subprocesses.

Fast tests and without network: each one mounts its own demo in tmp_path and asserts
exit codes and indispensable markers (never exact texts that the locales can move).
Self-contained on purpose: no conftest here, so that the module name `conftest` keeps
resolving to tests/conftest.py for the rest of the suite (tests/ has no __init__.py).
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _cli() -> list[str]:
    script = Path(sys.executable).with_name("forense")
    return [str(script)] if script.exists() else [sys.executable, "-m", "forense"]


@pytest.fixture
def run(tmp_path: Path):
    cli = _cli()

    def _run_case(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(cli + list(args), capture_output=True, text=True, timeout=120,
                              cwd=cwd or tmp_path)

    return _run_case


@pytest.fixture
def demo(run, tmp_path: Path) -> Path:
    """Demo scenario in tmp_path; returns the lab folder (contains evidence/ and case_demo)."""
    lab = tmp_path / "lab"
    proc = run("demo", str(lab))
    assert proc.returncode == 0, proc.stderr
    return lab


@pytest.fixture
def demo_triage_dir(demo: Path) -> Path:
    """Folder with the synthetic triage of the demo equipment."""
    return next((demo / "evidence").glob("triage_*"))


@pytest.fixture
def nuevo_caso(run, tmp_path: Path):
    def _nuevo(name: str) -> Path:
        case = tmp_path / "caso"
        proc = run("-L", "es", "nuevo", str(case), "-n", name, "-i", "Perito E2E")
        assert proc.returncode == 0, proc.stderr
        return case

    return _nuevo


def _evidence_hashes(case: Path, evidence_id: str) -> dict:
    db = sqlite3.connect(f"file:{case / 'forense.db'}?mode=ro", uri=True)
    try:
        row = db.execute("SELECT hashes FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
    finally:
        db.close()
    assert row is not None
    return json.loads(row[0])


def test_flujo_perito_completo_sobre_demo(run, tmp_path: Path, nuevo_caso, demo_triage_dir: Path) -> None:
    """New -> evidence add --copiar -> triage -> analyze -> verify, all exit 0."""
    case = nuevo_caso("Flujo")
    assert run("-L", "es", "-c", str(case), "evidencia", "agregar",
               str(demo_triage_dir), "--copiar", "-d", "Triaje sintetico").returncode == 0
    assert run("-L", "es", "-c", str(case), "triaje", "EV-001").returncode == 0
    assert run("-L", "es", "-c", str(case), "analizar", "registry", "EV-001").returncode == 0
    proc = run("-L", "es", "-c", str(case), "verificar")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[FAIL]" not in proc.stdout
    assert run("-L", "es", "-c", str(case), "custodia").returncode == 0


def test_verificar_sale_2_con_hash_manipulado_en_copia(run, tmp_path: Path, nuevo_caso,
                                                       demo_triage_dir: Path) -> None:
    """The evidence hashes are manipulated in a COPY of the case; verify detects it with exit 2.

    The original case is not touched: only the copy is modified.
    """
    case = nuevo_caso("Copia")
    assert run("-L", "es", "-c", str(case), "evidencia", "agregar",
               str(demo_triage_dir), "--copiar", "-d", "Triaje").returncode == 0
    copia = tmp_path / "caso-copia"
    shutil.copytree(case, copia)
    db = sqlite3.connect(copia / "forense.db")
    try:
        hashes = _evidence_hashes(case, "EV-001")
        hashes["sha256"] = "0" * 64
        db.execute("UPDATE evidence SET hashes = ? WHERE id = 'EV-001'", (json.dumps(hashes),))
        db.commit()
    finally:
        db.close()
    proc = run("-L", "es", "-c", str(copia), "verificar")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "[FAIL]" in proc.stdout


def test_caso_inexistente_mensaje_limpio(run, tmp_path: Path) -> None:
    """A case that does not exist: clean error, exit 1 and no traceback."""
    fantasma = tmp_path / "no-existe"
    proc = run("-L", "es", "-c", str(fantasma), "hallazgos")
    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr
    assert str(fantasma) in proc.stderr or str(fantasma) in proc.stdout


def test_evidencia_truncada_tolerada_sin_traceback(run, tmp_path: Path, nuevo_caso,
                                                   demo_triage_dir: Path) -> None:
    """EVTX and registry hive truncated to hammer blows: triage exits 0 and without traceback."""
    logs = tmp_path / "corruptos" / "C" / "Windows" / "System32" / "winevt" / "Logs"
    config = tmp_path / "corruptos" / "C" / "Windows" / "System32" / "config"
    logs.mkdir(parents=True)
    config.mkdir(parents=True)
    evtx = (REPO / "tests" / "data" / "Security_short_selected.evtx").read_bytes()
    (logs / "Security.evtx").write_bytes(evtx[: len(evtx) // 2])
    hive = next(demo_triage_dir.glob("C/Windows/System32/config/SOFTWARE")).read_bytes()
    (config / "SOFTWARE").write_bytes(hive[: int(len(hive) * 0.6)])
    case = nuevo_caso("Truncados")
    assert run("-L", "es", "-c", str(case), "evidencia", "agregar",
               str(config.parent.parent), "--copiar", "-d", "Truncados").returncode == 0
    proc = run("-L", "es", "-c", str(case), "triaje", "EV-001")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Traceback" not in proc.stderr
    assert run("-L", "es", "-c", str(case), "verificar").returncode == 0


def test_ruta_con_espacios_y_tildes(run, tmp_path: Path, nuevo_caso) -> None:
    """Evidence in a path with spaces, accents and ampersand: registers and triages without error."""
    dificil = tmp_path / "año 2026 - copia (seguridad)"
    dificil.mkdir()
    evtx = (REPO / "tests" / "data" / "Security_short_selected.evtx").read_bytes()
    (dificil / "Evidencia ñ á & espacios.evtx").write_bytes(evtx)
    case = nuevo_caso("Rutas")
    assert run("-L", "es", "-c", str(case), "evidencia", "agregar",
               str(dificil / "Evidencia ñ á & espacios.evtx"), "--copiar").returncode == 0
    proc = run("-L", "es", "-c", str(case), "triaje", "EV-001")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Traceback" not in proc.stderr
