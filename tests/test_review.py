"""Analyst workflow: finding verdicts, bookmarked events and versioned conclusions."""

from __future__ import annotations

import re

import pytest

from forense.cli import EXIT_OK, main
from forense.core.errors import CaseError
from forense.report import generate_report
from forense.web import create_app


@pytest.fixture
def analysed(case, demo):
    evidence = case.add_evidence(demo["triage"])
    case.run_analysis("registry", evidence.id)
    case.run_analysis("mft", evidence.id)
    return case


def _finding(case, code):
    return next(f for f in case.findings() if f["code"] == code)


def test_finding_review_history_and_filters(analysed):
    case = analysed
    ifeo = _finding(case, "registry.ifeo_debugger")
    usb = _finding(case, "registry.usb_device")
    assert ifeo["review"]["status"] == "needs_review"
    case.review_finding(ifeo["id"], "confirmado", "Backdoor de accesibilidad", actor="Ana")
    case.review_finding(usb["id"], "fp", "USB corporativo autorizado", actor="Ana")
    case.review_finding(usb["id"], "needs_review", actor="Luis")  # reopened later
    assert _finding(case, "registry.ifeo_debugger")["review"] == {
        "status": "confirmed", "note": "Backdoor de accesibilidad", "actor": "Ana",
        "timestamp": case.review_history("finding", ifeo["id"])[0]["timestamp"]}
    assert [h["status"] for h in case.review_history("finding", usb["id"])] == ["false_positive", "needs_review"]
    assert [f["id"] for f in case.findings(review_status="confirmed")] == [ifeo["id"]]
    progress = case.review_progress()
    assert progress["confirmed"] == 1 and progress["false_positive"] == 0 and progress["reviewed"] == 1
    reviews = [e for e in case.custody.entries() if e.action == "review_recorded"]
    assert len(reviews) == 3 and reviews[0].details["status"] == "confirmed" and reviews[0].actor == "Ana"
    assert case.custody.verify() == []
    with pytest.raises(CaseError):
        case.review_finding(ifeo["id"], "maybe")
    with pytest.raises(CaseError):
        case.review_finding(99999, "confirmed")


def test_bookmarks_and_conclusions(analysed):
    case = analysed
    event = case.events(search="svchost.exe", limit=1).rows[0]
    case.bookmark_event(event["id"], "Primera aparición del implante", actor="Ana")
    page = case.events(bookmarked=True)
    assert page.total == 1 and page.rows[0]["bookmark"]["note"] == "Primera aparición del implante"
    assert case.events(search="Primera aparición").total == 1  # notes are searchable
    case.bookmark_event(event["id"], remove=True)
    assert case.events(bookmarked=True).total == 0

    assert case.conclusions() is None
    first = case.set_conclusions("Borrador")
    second = case.set_conclusions("El equipo fue comprometido el 14/09/2026.", actor="Ana")
    assert (first["version"], second["version"]) == (1, 2)
    assert case.conclusions()["text"].startswith("El equipo")
    assert [h["version"] for h in case.conclusions_history()] == [2, 1]
    assert case.custody.entries()[-1].details["sha256"] == second["sha256"]


def test_report_reflects_review(analysed, tmp_path):
    case = analysed
    ifeo = _finding(case, "registry.ifeo_debugger")
    usb = _finding(case, "registry.usb_device")
    case.review_finding(ifeo["id"], "confirmed", "Confirmado con el volcado de memoria")
    case.review_finding(usb["id"], "false_positive", "USB autorizado")
    case.bookmark_event(case.events(search="svchost", limit=1).rows[0]["id"], "Inicio de la intrusión")
    case.set_conclusions("Conclusión pericial de prueba.")
    html = generate_report(case, "es", tmp_path / "r.html").read_text(encoding="utf-8")
    assert "Conclusiones del analista" in html and "Conclusión pericial de prueba." in html
    assert "Hallazgos confirmados por el analista" in html and "Confirmado con el volcado de memoria" in html
    assert "Hallazgos descartados (falsos positivos)" in html and "USB autorizado" in html
    assert "Eventos destacados por el analista" in html and "Inicio de la intrusión" in html


def test_cli_review_commands(tmp_path, capsys):
    case_dir = str(tmp_path / "demo" / "case_demo")
    main(["demo", str(tmp_path / "demo"), "--no-case"])
    main(["new", case_dir, "-n", "x", "-i", "y"])
    main(["evidence", "add", str(tmp_path / "demo" / "evidence" / "triage_WS-CONTAB01"), "-c", case_dir])
    main(["analyze", "registry", "EV-001", "-c", case_dir])
    capsys.readouterr()
    assert main(["hallazgos", "-c", case_dir, "-L", "es"]) == EXIT_OK
    out = capsys.readouterr().out
    finding_id = int(re.search(r"^(\d+)\s+crítico", out, re.M).group(1))
    assert main(["revisar", str(finding_id), "confirmado", "--nota", "verificado", "-c", case_dir, "-L", "es"]) == EXIT_OK
    assert "Confirmado" in capsys.readouterr().out
    assert main(["findings", "-c", case_dir, "--status", "confirmed"]) == EXIT_OK
    assert "verified" not in (out := capsys.readouterr().out) and "verificado" in out
    assert main(["timeline", "-c", case_dir, "--search", "svchost", "--limit", "1"]) == EXIT_OK
    event_id = int(re.search(r"^\s*(\d+)\s+20", capsys.readouterr().out, re.M).group(1))
    assert main(["destacar", str(event_id), "-n", "clave", "-c", case_dir]) == EXIT_OK
    assert main(["timeline", "-c", case_dir, "--bookmarked"]) == EXIT_OK
    assert "★" in capsys.readouterr().out
    assert main(["conclusiones", "-c", case_dir, "--texto", "Conclusión."]) == EXIT_OK
    assert main(["conclusions", "-c", case_dir]) == EXIT_OK
    assert "Conclusión." in capsys.readouterr().out


def test_web_review_flow(tmp_path, demo):
    from forense.core.case import Case

    with Case.create(tmp_path / "ws" / "c1", "Web", "W") as case:
        evidence = case.add_evidence(demo["triage"])
        case.run_analysis("registry", evidence.id)
        finding_id = _finding(case, "registry.ifeo_debugger")["id"]
        event_id = case.events(limit=1).rows[0]["id"]
    client = create_app(tmp_path / "ws").test_client()
    html = client.get("/c/c1/findings").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    referer = {"Referer": "http://localhost/c/c1/findings?severity=high"}
    response = client.post(f"/c/c1/findings/{finding_id}/review", headers=referer,
                           data={"csrf_token": token, "status": "confirmed", "note": "ok"})
    assert response.status_code == 302 and response.location.endswith(f"/c/c1/findings?severity=high#f{finding_id}")
    evil = client.post(f"/c/c1/findings/{finding_id}/review", headers={"Referer": "http://evil.example/x"},
                       data={"csrf_token": token, "status": "confirmed"})
    assert "evil.example" not in evil.location
    client.post(f"/c/c1/events/{event_id}/bookmark", data={"csrf_token": token, "note": "importante"})
    assert "importante" in client.get("/c/c1/timeline?bookmarked=1").get_data(as_text=True)
    client.post("/c/c1/conclusions", data={"csrf_token": token, "text": "Conclusiones web"})
    page = client.get("/c/c1/conclusions").get_data(as_text=True)
    assert "Conclusiones web" in page
    assert "review-confirmed" in client.get("/c/c1/findings?status=confirmed").get_data(as_text=True)
    with Case.open(tmp_path / "ws" / "c1") as case:
        assert case.review_progress()["confirmed"] == 1 and case.conclusions()["text"] == "Conclusiones web"
