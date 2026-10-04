"""Case report: structure, executive summary, ATT&CK and IOC sections, PDF export."""

from __future__ import annotations

import os
import re
import stat
import sys

import pytest

from forense.cli import EXIT_ERROR, EXIT_OK, main
from forense.core.case import Case
from forense.report import generate_report
from forense.report.pdf import find_browser, html_to_pdf


@pytest.fixture(scope="module")
def demo_case(tmp_path_factory):
    root = tmp_path_factory.mktemp("report")
    assert main(["demo", str(root), "-a", "Tester"]) == EXIT_OK
    return root / "case_demo"


def test_report_structure(demo_case, tmp_path):
    with Case.open(demo_case) as case:
        html = generate_report(case, "en", tmp_path / "report.html").read_text(encoding="utf-8")
        findings = case.findings()
    toc = re.search(r'<nav class="toc".*?</nav>', html, re.S).group(0)
    anchors = re.findall(r'href="#([a-z]+)"', toc)
    assert anchors[:4] == ["summary", "conclusions", "attack", "iocs"] and anchors[-1] == "methodology"
    for anchor in anchors:  # every entry of the contents has its numbered heading
        assert re.search(rf'<h2 id="{anchor}"><span class="num">{anchors.index(anchor) + 1}\.</span>', html)
    assert "viz-activity" in html and "viz-severity" in html and "<svg" in html
    assert "attack.mitre.org/techniques/T1003/" in html and "198.51.100.23" in html
    assert all(f'id="f-{f["id"]}"' in html for f in findings)  # findings are linkable from the summary
    linked = set(re.findall(r'href="#f-(\d+)"', html))
    assert linked and linked <= {str(f["id"]) for f in findings}
    assert "@page" in html and "counter(pages)" in html and "CASE-" in re.search(r"@bottom-left \{[^}]*\}", html).group(0)
    assert "<script" not in html  # self-contained and static


def test_report_without_findings_hides_optional_sections(case, evidence_dir, tmp_path):
    evidence = case.add_evidence(evidence_dir)
    case.run_analysis("inventory", evidence.id)
    html = generate_report(case, "es", tmp_path / "r.html").read_text(encoding="utf-8")
    assert 'id="attack"' not in html and 'id="iocs"' not in html and 'id="summary"' in html
    assert "Resumen ejecutivo" in html and "Índice" in html


def _fake_browser(tmp_path):
    """A stand-in for Edge/Chrome that writes a minimal PDF where --print-to-pdf asks."""
    script = tmp_path / "fake-browser"
    script.write_text(f"#!{sys.executable}\n"
                      "import sys\n"
                      "out = next(a.split('=', 1)[1] for a in sys.argv if a.startswith('--print-to-pdf='))\n"
                      "open(out, 'wb').write(b'%PDF-1.4\\n%fake\\n')\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


@pytest.mark.skipif(os.name == "nt", reason="shebang script")
def test_cli_report_pdf_is_hashed_into_the_custody(demo_case, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("FORENSE_BROWSER", str(_fake_browser(tmp_path)))
    target = tmp_path / "out" / "informe.pdf"
    assert main(["-c", str(demo_case), "informe", "-o", str(target), "-L", "es"]) == EXIT_OK
    assert target.read_bytes().startswith(b"%PDF") and target.with_suffix(".html").is_file()
    with Case.open(demo_case) as case:
        entries = case.custody.entries()
        assert entries[-1].action == "report_pdf_generated" and entries[-1].details["file"] == str(target.resolve())
        assert entries[-2].action == "report_generated"
        assert case.custody.verify() == []


def test_pdf_errors_are_reported(tmp_path, monkeypatch, capsys):
    html = tmp_path / "r.html"
    html.write_text("<p>x</p>", encoding="utf-8")
    monkeypatch.setenv("FORENSE_BROWSER", str(tmp_path / "no-such-browser"))
    assert find_browser() == str(tmp_path / "no-such-browser")
    with pytest.raises(Exception) as info:
        html_to_pdf(html)
    assert getattr(info.value, "code", "") == "error.pdf_failed"
    case = tmp_path / "case"
    assert main(["new", str(case), "-n", "PDF", "-i", "Ana"]) == EXIT_OK
    capsys.readouterr()
    assert main(["-c", str(case), "report", "--pdf"]) == EXIT_ERROR
    assert "PDF" in capsys.readouterr().err
