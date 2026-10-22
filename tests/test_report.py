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
