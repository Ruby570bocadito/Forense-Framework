"""The next-step guide (sabueso.core.guide) and the CLI/web surfaces that show it."""

from __future__ import annotations

from sabueso.cli import EXIT_OK, main
from sabueso.core.case import Case
from sabueso.core.guide import next_step


def test_the_guide_walks_the_whole_workflow(case, evidence_dir, demo, tmp_path):
    assert next_step(case).code == "add_evidence"
    evidence = case.add_evidence(evidence_dir)
    step = next_step(case)
    assert (step.code, step.params) == ("analyse", {"id": evidence.id})
    case.run_analysis("inventory", evidence.id)
    assert next_step(case).code == "conclusions"  # nothing to review: the inventory raised no findings
    case.set_conclusions("Sin indicios.", "Tester")
    assert next_step(case).code == "report"
    from sabueso.report import generate_report

    generate_report(case, "en", tmp_path / "r.html")
    assert next_step(case).code == "done"
    case.set_conclusions("Sin indicios relevantes.", "Tester")  # the report is now out of date
    assert next_step(case).code == "report"


def test_the_guide_asks_to_review_pending_findings(demo, tmp_path):
    with Case.create(tmp_path / "c", "T", "Tester") as case:
        evidence = case.add_evidence(demo["triage"])
        case.run_analysis("registry", evidence.id)
        step = next_step(case)
        total = case.review_progress()["total"]
        assert step.code == "review" and step.params == {"pending": total, "total": total} and step.endpoint == "findings"
        first = case.findings()[0]["id"]
        case.review_finding(first, "confirmed", "", "Tester")
        assert next_step(case).params["pending"] == total - 1
        assert "revisar N confirmado" in next_step(case).text("cli", "c", "es")


def test_sabueso_alone_shows_the_welcome(capsys):
    assert main([]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Sabueso" in out and "Follow the trail" in out and "sabueso demo" in out


def test_cli_commands_end_with_the_next_step(tmp_path, evidence_dir, capsys):
    root = tmp_path / "case"
    assert main(["new", str(root), "-n", "T", "-i", "Tester"]) == EXIT_OK
    assert "Next step: add the first evidence item" in capsys.readouterr().out
    assert main(["-c", str(root), "evidence", "add", str(evidence_dir)]) == EXIT_OK
    assert f'sabueso -c "{root}" triage EV-001' in capsys.readouterr().out
    assert main(["-c", str(root), "info"]) == EXIT_OK
    assert "Next step: analyse EV-001" in capsys.readouterr().out


def test_web_shows_the_next_step(tmp_path, evidence_dir):
    from sabueso.web import create_app

    with Case.create(tmp_path / "case", "T", "Tester") as case:
        case.add_evidence(evidence_dir)
    client = create_app(tmp_path).test_client()
    page = client.get("/c/case/?lang=en").get_data(as_text=True)
    assert 'class="next-step"' in page and "has not been analysed yet" in page and "#case-evidence" in page
    index = client.get("/?lang=en").get_data(as_text=True)
    assert "Next step" in index and ">Analyse</a>" in index and "Follow the trail" in index
