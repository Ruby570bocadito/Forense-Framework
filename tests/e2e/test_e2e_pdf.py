"""E2E regression for H-008 (PDF pipeline, closed by IMP-2 in b1edf5b).

The CLI must handle every browser outcome without a traceback:
* no browser installed      -> clean localized error, exit 1
* browser exits without PDF -> clean localized error, exit 1
* browser writes a real PDF -> exit 0, PDF starts with %PDF, custody logs it
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from _cli import run

EVTX = "tests/data/Security_short_selected.evtx"

FAKE_OK = r"""#!/bin/sh
out=""
for arg in "$@"; do
  case "$arg" in
    --print-to-pdf=*) out="${arg#--print-to-pdf=}" ;;
  esac
done
[ -n "$out" ] && printf '%%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%%%EOF\n' > "$out"
exit 0
"""


def _case_with_evtx(ws: Path, name: str) -> Path:
    case_dir = ws / name
    assert run("new", str(case_dir), "-n", name, "-i", "e2e").returncode == 0
    assert run("-c", str(case_dir), "evidencia", "agregar", EVTX, "-d", "pdf e2e").returncode == 0
    assert run("-c", str(case_dir), "analizar", "evtx", "EV-001").returncode == 0
    return case_dir


def _fake_browser(ws: Path, body: str) -> str:
    script = ws / "fake_browser.sh"
    script.write_text(body, encoding="utf-8")
    script.chmod(0o755)
    return str(script)


@pytest.mark.skipif(os.name == "nt", reason="fake browser is a POSIX shell script")
def test_informe_pdf_navegador_falso_genera_pdf(tmp_path) -> None:
    case = _case_with_evtx(tmp_path, "pdf-ok")
    browser = _fake_browser(tmp_path, FAKE_OK)
    out = tmp_path / "informe"
    proc = run("-L", "en", "-c", str(case), "informe", "--pdf", "-o", str(out / "i.html"),
               env={"SABUESO_BROWSER": browser})
    assert proc.returncode == 0, proc.stderr
    assert "Traceback" not in proc.stderr
    pdf = out / "i.pdf"
    assert pdf.is_file() and pdf.stat().st_size > 0
    assert pdf.read_bytes().startswith(b"%PDF")
    # The PDF generation must be visible in the chain of custody (verificar stays green).
    check = run("-L", "en", "-c", str(case), "verificar")
    assert check.returncode == 0, check.stdout + check.stderr


def test_informe_pdf_navegador_sin_salida(tmp_path) -> None:
    case = _case_with_evtx(tmp_path, "pdf-vacio")
    out = tmp_path / "informe"
    proc = run("-L", "es", "-c", str(case), "informe", "--pdf", "-o", str(out / "i.html"),
               env={"SABUESO_BROWSER": "/bin/true"})
    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr
    assert "No se pudo generar el PDF" in proc.stderr, proc.stderr
    assert not (out / "i.pdf").exists()


def test_informe_pdf_sin_navegador_mensaje_limpio(tmp_path) -> None:
    # Reachable only where no PDF browser is discoverable (CI runners with one skip this).
    probe = subprocess.run(
        [sys.executable, "-c", "from sabueso.report.pdf import find_browser; print(find_browser() or 'NONE')"],
        capture_output=True, text=True, timeout=60)
    if probe.stdout.strip() != "NONE":
        pytest.skip("a PDF browser is installed on this machine; the no-browser path is not reachable")
    case = _case_with_evtx(tmp_path, "pdf-ninguno")
    out = tmp_path / "informe"
    proc = run("-L", "es", "-c", str(case), "informe", "--pdf", "-o", str(out / "i.html"),
               env={"SABUESO_BROWSER": None})
    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr
    assert "no se encontró Edge, Chrome ni Chromium" in proc.stderr, proc.stderr
