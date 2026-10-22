"""E2E: hostile text survives every surface without becoming code (petition of SEG).

A case whose evidence description and finding note carry HTML and spreadsheet
formulas must render them inert:
* HTML report  -> tags and formulas escaped (text, never markup or attributes)
* CSV export   -> formula-like cells neutralised with a leading apostrophe
"""

from __future__ import annotations

import csv
import sqlite3

from _cli import make_demo_lab, run

DESC_HOSTIL = '<script>alert(1)</script> =HYPERLINK("http://x","y") "comillas" ruta_ñ'
NOTA_HOSTIL = "=cmd|'/c calc'!A1 <img src=x onerror=alert(1)> nota_ñ"


def test_informe_y_csv_con_texto_hostil(tmp_path) -> None:
    lab = make_demo_lab(tmp_path)
    case = lab / "case_demo"

    # Evidence whose description is hostile: it flows into the HTML report.
    evtx = "tests/data/Security_short_selected.evtx"
    assert run("-c", str(case), "evidencia", "agregar", evtx, "-d", DESC_HOSTIL).returncode == 0

    # A real finding, reviewed with a hostile note: it flows into report and CSV.
    listing = run("-L", "en", "-c", str(case), "hallazgos")
    assert listing.returncode == 0, listing.stderr
    fid = next(int(words[0]) for line in listing.stdout.splitlines()
               if (words := line.split()) and words[0].isdigit())
    assert run("-c", str(case), "revisar", str(fid), "confirmado", "-n", NOTA_HOSTIL).returncode == 0

    informe = tmp_path / "informe.html"
    assert run("-L", "es", "-c", str(case), "informe", "-o", str(informe)).returncode == 0
    html = informe.read_text(encoding="utf-8")

    # Nothing hostile may reach the report as markup or as an attribute value.
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;alert(1)" in html                      # description, escaped
    assert "<img src=x onerror" not in html
    assert "&lt;img src=x onerror" in html                       # review note, escaped
    assert 'href="=cmd' not in html and 'src="=cmd' not in html  # no formula in attributes
    assert "&#34;http://x&#34;" in html                          # quotes escaped too

    export = tmp_path / "hallazgos.csv"
    assert run("-c", str(case), "exportar", "findings", "-o", str(export), "-f", "csv").returncode == 0
    rows = list(csv.reader(export.read_text(encoding="utf-8-sig").splitlines()))
    cells = [c for row in rows for c in row]
    assert not [c for c in cells if c.startswith(("=", "+", "@"))], "formula cell without the ' guard"
    assert any(c.startswith("'=cmd") for c in cells), "review note must carry the ' guard"

    # The case stays intact: custody verifies after all of the above.
    assert run("-c", str(case), "verificar").returncode == 0
    conn = sqlite3.connect(case / "forense.db")
    findings = conn.execute("select count(*) from findings where severity='critical'").fetchone()[0]
    conn.close()
    assert findings >= 1  # sanity: the demo case really had findings to export
