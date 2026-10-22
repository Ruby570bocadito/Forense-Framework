"""E2E regression for H-004 (closed: tool names no longer match inside noise).

``find_files`` still accepts a loose file without applying the module
predicate (documented behaviour), but the tool-name rules must require a
word boundary before the name: ``aacmeaa`` (embedded in padding) is noise,
not CrackMapExec. A triage over such a file must produce zero findings.
"""

from __future__ import annotations

import sqlite3

from _cli import run


def test_triaje_sobre_ruido_con_herramienta_incrustada(tmp_path) -> None:
    sample = tmp_path / "SYSTEM-basura"
    sample.write_bytes(b"a" * 100_000 + b"cme" + b"a" * 100_000)

    case = tmp_path / "c"
    assert run("new", str(case), "-n", "ruido", "-i", "e2e").returncode == 0
    assert run("-c", str(case), "evidencia", "agregar", str(sample), "-d", "x").returncode == 0
    proc = run("-c", str(case), "triaje", "EV-001", timeout=300)
    assert proc.returncode == 0, proc.stderr

    conn = sqlite3.connect(case / "forense.db")
    rows = conn.execute("select id, severity, code from findings").fetchall()
    conn.close()
    assert rows == [], f"triage fabricated findings out of noise: {rows}"
