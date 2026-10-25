"""Case report: structure, executive summary, ATT&CK and IOC sections, PDF export."""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path

import pytest
from conftest import make_signing_key

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


def test_report_correlation_section(tmp_path):
    import shutil

    root = tmp_path / "ws"
    assert main(["demo", str(root), "-a", "Tester"]) == EXIT_OK
    case_dir = root / "case_demo"

    with Case.open(case_dir) as case:  # a single case in the workspace: no section
        html = generate_report(case, "en", tmp_path / "solo.html").read_text(encoding="utf-8")
    assert 'id="s-correlation"' not in html

    shutil.copytree(case_dir, root / "case_twin")  # twin case shares the demo observables
    with Case.open(case_dir) as case:
        html = generate_report(case, "en", tmp_path / "pair.html").read_text(encoding="utf-8")
    assert 'id="s-correlation"' in html and "Cross-case correlation" in html
    assert "60A44C3FAE2BE2B0E9160123" in html and "WS-CONTAB01" in html  # USB device and host (display form)
    assert "198.51.100.23" in html and "This case" in html and "(case_twin)" in html
    anchors = re.findall(r'<h2 id="([a-z]+)">', html)
    assert "correlation" in anchors and anchors.index("correlation") == anchors.index("iocs") + 1

    with Case.open(case_dir) as case:
        generate_report(case, "es", tmp_path / "pair_es.html")
    es_text = Path(tmp_path / "pair_es.html").read_text(encoding="utf-8")
    assert "Correlación entre casos" in es_text and "Este caso" in es_text


def test_report_without_findings_hides_optional_sections(case, evidence_dir, tmp_path):
    evidence = case.add_evidence(evidence_dir)
    case.run_analysis("inventory", evidence.id)
    html = generate_report(case, "es", tmp_path / "r.html").read_text(encoding="utf-8")
    assert 'id="attack"' not in html and 'id="iocs"' not in html and 'id="summary"' in html
    assert "Resumen ejecutivo" in html and "Índice" in html


def _fake_browser(folder: Path) -> Path:
    """A stand-in for Edge/Chrome that writes a minimal PDF where --print-to-pdf asks.

    Cross-platform: a shebang script on POSIX, a .bat wrapper around the same Python
    implementation on Windows, so the PDF path is exercised on both CI systems.
    """
    impl = folder / "fake-browser-impl.py"
    impl.write_text("import sys\n"
                    "out = next(a.split('=', 1)[1] for a in sys.argv if a.startswith('--print-to-pdf='))\n"
                    "open(out, 'wb').write(b'%PDF-1.4\\n%fake\\n')\n", encoding="utf-8")
    if os.name == "nt":
        script = folder / "fake-browser.bat"
        script.write_text(f'@echo off\r\n"{sys.executable}" "{impl}" %*\r\n', encoding="ascii")
    else:
        script = folder / "fake-browser"
        script.write_text(f"#!{sys.executable}\nimport runpy\nrunpy.run_path({str(impl)!r}, run_name='__main__')\n",
                          encoding="utf-8")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


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


@pytest.mark.skipif(os.name == "nt", reason="orphan child keeps the pipes open past the kill")
def test_pdf_timeout_is_reported(tmp_path, monkeypatch):
    slow = tmp_path / "fake-slow.py"
    slow.write_text("import time\ntime.sleep(3)\n", encoding="utf-8")
    browser = tmp_path / "fake-slow"
    browser.write_text(f"#!{sys.executable}\nimport runpy\nrunpy.run_path({str(slow)!r}, run_name='__main__')\n",
                       encoding="utf-8")
    browser.chmod(browser.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("FORENSE_BROWSER", str(browser))
    html = tmp_path / "r.html"
    html.write_text("<p>x</p>", encoding="utf-8")
    with pytest.raises(Exception) as info:
        html_to_pdf(html, timeout=1)
    assert getattr(info.value, "code", "") == "error.pdf_failed"


def test_no_browser_error_and_path_lookup(tmp_path, monkeypatch):
    from forense.core.errors import ForenseError
    from forense.report import pdf

    html = tmp_path / "r.html"
    html.write_text("<p>x</p>", encoding="utf-8")
    monkeypatch.delenv("FORENSE_BROWSER", raising=False)
    monkeypatch.setattr(pdf, "_WINDOWS", ())
    monkeypatch.setattr(pdf, "_MAC", ())
    monkeypatch.setattr(pdf, "_NAMES", ())
    monkeypatch.setattr(pdf, "_GLOBS", ())
    assert pdf.find_browser() is None
    with pytest.raises(ForenseError) as info:
        html_to_pdf(html)
    assert info.value.code == "error.pdf_no_browser"

    fake = tmp_path / "found-chrome"  # a browser discovered through PATH
    fake.write_text("", encoding="utf-8")
    monkeypatch.setattr(pdf, "_NAMES", ("chromium",))
    monkeypatch.setattr(pdf.shutil, "which", lambda name: str(fake) if name == "chromium" else None)
    assert pdf.find_browser() == str(fake)


# -- digital signatures of the reports -----------------------------------------------

def test_signing_roundtrip(tmp_path, monkeypatch):
    from forense.core.errors import ForenseError
    from forense.report import signing

    document = tmp_path / "report.html"
    document.write_text("<html>informe</html>", encoding="utf-8")
    pem, pub = make_signing_key(tmp_path)
    key = signing.load_private_key(pem)
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", signing.fingerprint(key.public_key()))
    sig = signing.sign_file(document, key)
    assert sig.is_file() and re.fullmatch(r"[A-Za-z0-9+/]{86}==", sig.read_text(encoding="ascii"))
    assert signing.verify_file(document, signing.load_public_key(pub))
    document.write_text("<html>informe alterado</html>", encoding="utf-8")
    assert not signing.verify_file(document, signing.load_public_key(pub))
    other, _ = make_signing_key(tmp_path, "other")
    assert not signing.verify_file(document, signing.load_private_key(other).public_key())
    with pytest.raises(ForenseError):
        signing.verify_file(tmp_path / "missing.html", signing.load_public_key(pub))
    bogus = tmp_path / "bogus.pem"
    bogus.write_text("not a pem", encoding="utf-8")
    with pytest.raises(ForenseError):
        signing.load_private_key(bogus)
    document.write_text("<html>informe</html>", encoding="utf-8")  # original content again
    monkeypatch.setenv("FORENSE_SIGN_KEY", str(pem))
    assert signing.verify_file(document)  # public key derived from the configured signing key


def test_generate_report_signed_and_custody(demo_case, tmp_path, monkeypatch):
    from forense.report import signing

    pem, pub = make_signing_key(tmp_path)
    monkeypatch.setenv("FORENSE_SIGN_KEY", str(pem))
    with Case.open(demo_case) as case:
        output = generate_report(case, "en", tmp_path / "signed.html", sign=True)
    assert signing.signature_path(output).is_file()
    monkeypatch.setenv("FORENSE_SIGN_PUB", str(pub))
    with Case.open(demo_case) as case:
        assert signing.verify_file(output)
        entry = [e for e in case.custody.entries() if e.action == "report_signed"][-1]
        assert case.custody.verify() == []
    details = entry.details
    assert details["signature_file"] == "signed.html.sig" and details["algorithm"] == "ed25519"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", details["key_fingerprint"])
    assert "BEGIN PRIVATE KEY" not in str(details)  # the key never enters the case


def test_timeline_html_export_is_standalone_and_custody_logged(demo_case, tmp_path):
    from forense.report.timeline_html import export_timeline_html

    with Case.open(demo_case) as case:
        total = case.events(limit=1).total
        path = export_timeline_html(case, tmp_path / "timeline.html", "en", "Ana")
        html = path.read_text(encoding="utf-8")
        entry = case.custody.entries()[-1]
        assert case.custody.verify() == []
    assert "<script" not in html and "<style>" in html  # no JS, inline styles only
    assert "src=" not in html and "href=" not in html  # no external resources at all
    assert "Generated on" in html and "Ana" in html and "(UTC)" in html
    assert entry.action == "export_created" and entry.actor == "Ana"
    assert entry.details["kind"] == "timeline" and entry.details["format"] == "html"
    assert entry.details["rows"] == total and len(entry.details["sha256"]) == 64


def test_timeline_html_export_applies_filters(demo_case, tmp_path):
    from forense.report.timeline_html import export_timeline_html

    with Case.open(demo_case) as case:
        total = case.events(limit=1).total
        path = export_timeline_html(case, tmp_path / "high.html", "en", min_severity="high")
        html = path.read_text(encoding="utf-8")
        entry = case.custody.entries()[-1]
    assert entry.details["rows"] < total  # the demo has events below high severity
    assert entry.details["filters"] == {"min_severity": "high"}
    assert "Applied filters" in html and "Severity: high" in html


def test_timeline_html_export_empty_case(case, tmp_path):
    from forense.report.timeline_html import export_timeline_html

    path = export_timeline_html(case, tmp_path / "empty.html", "es", "Perito")
    html = path.read_text(encoding="utf-8")
    assert "0 eventos." in html and "Sin filtros" in html


def test_timeline_html_export_escapes_hostile_values(case, evidence_dir, tmp_path):
    from forense.core.case import _CaseSink
    from forense.report.timeline_html import export_timeline_html

    evidence = case.add_evidence(evidence_dir)
    analysis = case.run_analysis("inventory", evidence.id)
    _CaseSink(case.conn, analysis.id, evidence.id).add_events([{
        "timestamp": "2026-10-23T10:00:00Z", "source": "evil<script>", "type": "event",
        "details": '<script>alert(1)</script> & "quoted"', "path": "C:\\Users\\x<img src=y>", "severity": "high",
    }])
    path = export_timeline_html(case, tmp_path / "hostile.html", "en", "Ana")
    html = path.read_text(encoding="utf-8")
    assert "<script>alert" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=y>" not in html and "&lt;img" in html
    assert "evil&lt;script&gt;" in html


def test_findings_html_export_anchors_custody(demo_case, tmp_path):
    from forense.report.findings_html import export_findings_html

    with Case.open(demo_case) as case:
        total = len(case.findings())
        path = export_findings_html(case, tmp_path / "findings.html", "en", "Ana")
        html = path.read_text(encoding="utf-8")
        entry = case.custody.entries()[-1]
        assert case.custody.verify() == []
    assert "<script" not in html and "<style>" in html  # no JS, inline styles only
    assert "src=" not in html and "href=" not in html  # no external resources at all
    assert "Generated on" in html and "Ana" in html and "(UTC)" in html
    assert entry.action == "export_created" and entry.actor == "Ana"
    assert entry.details["kind"] == "findings" and entry.details["format"] == "html"
    assert entry.details["rows"] == total and len(entry.details["sha256"]) == 64


def test_findings_html_export_applies_filters(demo_case, tmp_path):
    from forense.core.attack import techniques_for
    from forense.report.findings_html import export_findings_html

    with Case.open(demo_case) as case:
        findings = case.findings()
        high = [f for f in findings if f["severity"] in ("high", "critical")]
        techniques = {t for f in findings for t in techniques_for(f)}
        path = export_findings_html(case, tmp_path / "high.html", "en", severity="high")
        html = path.read_text(encoding="utf-8")
        entry = case.custody.entries()[-1]
        if techniques:
            technique = sorted(techniques)[0]
            expected = sum(1 for f in findings if technique in techniques_for(f))
            export_findings_html(case, tmp_path / "tech.html", "en", technique=technique)
            tech_entry = case.custody.entries()[-1]
    assert entry.details["rows"] == len(high) and entry.details["filters"] == {"severity": "high"}
    assert "Applied filters" in html and "Severity: ≥ high" in html
    if techniques:
        assert tech_entry.details["rows"] == expected
        assert tech_entry.details["filters"] == {"technique": technique}


def test_findings_html_export_review_status(demo_case, tmp_path):
    from forense.report.findings_html import export_findings_html

    with Case.open(demo_case) as case:
        first = case.findings()[0]
        case.review_finding(first["id"], "confirmed", note="Verificado contra la evidencia", actor="Ana")
        path = export_findings_html(case, tmp_path / "confirmed.html", "es", status="confirmed")
        html = path.read_text(encoding="utf-8")
        entry = case.custody.entries()[-1]
    assert entry.details["filters"] == {"status": "confirmed"} and entry.details["rows"] == 1
    assert "Confirmado" in html and "Verificado contra la evidencia" in html
    assert "por Ana el" in html


def test_findings_html_export_empty_case(case, tmp_path):
    from forense.report.findings_html import export_findings_html

    path = export_findings_html(case, tmp_path / "empty.html", "es", "Perito")
    html = path.read_text(encoding="utf-8")
    assert "0 hallazgos." in html and "Sin filtros" in html


def test_findings_html_export_escapes_hostile_values(case, evidence_dir, tmp_path):
    from forense.core.case import _CaseSink
    from forense.report.findings_html import export_findings_html

    evidence = case.add_evidence(evidence_dir)
    analysis = case.run_analysis("inventory", evidence.id)
    _CaseSink(case.conn, analysis.id, evidence.id).add_findings([{
        "severity": "high", "code": "evtx.suspicious_command", "timestamp": "2026-10-25T10:00:00Z",
        "params": {"command": '<script>alert(1)</script> & "quoted" <img src=y> tail'},
    }])
    path = export_findings_html(case, tmp_path / "hostile.html", "en", "Ana")
    html = path.read_text(encoding="utf-8")
    assert "<script>alert" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=y>" not in html and "&lt;img" in html and "quoted" in html


def test_report_sections_included(demo_case, tmp_path):
    with Case.open(demo_case) as case:
        path = generate_report(case, "en", tmp_path / "short.html", include={"findings"})
        html = path.read_text(encoding="utf-8")
        entry = case.custody.entries()[-1]
    assert entry.details["sections"] == ["findings"]
    assert entry.details["detail"] == {"confirmed_only": False, "max_findings": None}
    toc = re.search(r'<nav class="toc".*?</nav>', html, re.S).group(0)
    anchors = re.findall(r'href="#([a-z]+)"', toc)
    assert anchors == ["summary", "evidence", "findings", "analyses", "custody", "methodology"]
    assert 'id="s-attack"' not in html and 'id="s-iocs"' not in html and 'id="s-conclusions"' not in html
    assert 'id="s-findings"' in html and 'id="s-custody"' in html  # the core stays


def test_report_core_sections_only(demo_case, tmp_path):
    with Case.open(demo_case) as case:
        path = generate_report(case, "en", tmp_path / "core.html", include=set())
        html = path.read_text(encoding="utf-8")
        entry = case.custody.entries()[-1]
    assert entry.details["sections"] == []
    toc = re.search(r'<nav class="toc".*?</nav>', html, re.S).group(0)
    assert re.findall(r'href="#([a-z]+)"', toc) == ["summary", "evidence", "analyses", "custody", "methodology"]
    assert 'id="s-findings"' not in html and 'id="s-chronology"' not in html


def test_report_confirmed_only_and_cap(demo_case, tmp_path):
    with Case.open(demo_case) as case:
        first = case.findings()[0]
        case.review_finding(first["id"], "confirmed", actor="Ana")
        path = generate_report(case, "en", tmp_path / "confirmed.html", confirmed_only=True, max_findings=1)
        html = path.read_text(encoding="utf-8")
        entry = case.custody.entries()[-1]
    assert entry.details["sections"] == "all"
    assert entry.details["detail"] == {"confirmed_only": True, "max_findings": 1}
    assert "Showing 1 of" in html and "(trimmed by the detail option)" in html
    assert "Pending findings" not in html and "Discarded findings" not in html
    assert "Findings confirmed by the analyst (1)" in html
    assert 'id="s-attack"' in html  # the matrix follows the same verdict filter
