"""E2E: ``forense verificar`` catches tampered custody entries and analysis results.

The evidence vector is covered by ``test_e2e_verify_exit_codes``; the other two
integrity vectors documented in the README (chain of custody, results hash) get
their own regression here, verified by hand in the personas round: rewriting a
custody entry in the case database must break the chain, and editing an
analysis result row after the fact must break the results hash. Both exit 2.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from _cli import make_demo_lab, run


@pytest.fixture(scope="module")
def demo_lab(tmp_path_factory) -> Path:
    """A fresh ``forense demo`` lab shared by the tests of this module."""
    return make_demo_lab(tmp_path_factory.mktemp("e2e-tamper-vectors"))


def _case_with_records(parent: Path, lab: Path) -> Path:
    """A fresh case holding one copied evidence and one module analysis."""
    case = parent / "case_with_records"
    proc = run("new", str(case), "-n", "tamper vectors", "-i", "e2e")
    assert proc.returncode == 0, proc.stderr
    triage = lab / "evidence" / "triage_WS-CONTAB01"
    proc = run("-c", str(case), "evidencia", "agregar", str(triage), "-d", "triage copy", "--copy")
    assert proc.returncode == 0, proc.stderr
    proc = run("-c", str(case), "triage", "EV-001", timeout=300)
    assert proc.returncode == 0, proc.stderr
    db = sqlite3.connect(case / "forense.db")
    try:
        rows = db.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    finally:
        db.close()
    assert rows, "the triage produced no records to tamper with"
    return case


def _tamper_one_row(case: Path, sql: str) -> None:
    """Apply one UPDATE to the case database (the way an attacker with the file would)."""
    db = sqlite3.connect(case / "forense.db")
    try:
        assert db.execute(sql).rowcount == 1, f"tampering UPDATE matched no row: {sql}"
        db.commit()
    finally:
        db.close()


def test_verificar_detects_tampered_custody_entry(demo_lab, tmp_path) -> None:
    case = _case_with_records(tmp_path, demo_lab)
    proc = run("verificar", "-c", str(case))
    assert proc.returncode == 0, proc.stdout + proc.stderr

    # A custody entry edited after the fact no longer hashes to its recorded
    # hash, so the chain reported by the case must break.
    _tamper_one_row(case, "UPDATE custody SET action = action || ' ' WHERE seq = (SELECT MIN(seq) FROM custody)")
    proc = run("verificar", "-c", str(case))
    assert proc.returncode == 2, f"expected exit 2 on tampered custody, got {proc.returncode}: {proc.stdout}"
    assert "FAIL" in proc.stdout or "FAIL" in proc.stderr, proc.stdout + proc.stderr


def test_verificar_detects_tampered_analysis_results(demo_lab, tmp_path) -> None:
    case = _case_with_records(tmp_path, demo_lab)
    proc = run("verificar", "-c", str(case))
    assert proc.returncode == 0, proc.stdout + proc.stderr

    # One stored result row is edited in its content (the demo scenario's
    # svchost.exe is renamed): the results hash recorded by the analysis no
    # longer matches the recomputed one. Whitespace-only edits are ignored by
    # design (verification canonicalises), so the tampering must be semantic.
    sql = (
        "UPDATE records SET data = replace(data, 'svchost.exe', 'forged.exe') "
        "WHERE rowid = (SELECT MIN(rowid) FROM records WHERE data LIKE '%svchost.exe%')"
    )
    _tamper_one_row(case, sql)
    proc = run("verificar", "-c", str(case))
    assert proc.returncode == 2, f"expected exit 2 on tampered results, got {proc.returncode}: {proc.stdout}"
    assert "FAIL" in proc.stdout or "FAIL" in proc.stderr, proc.stdout + proc.stderr
