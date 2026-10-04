from __future__ import annotations

import sqlite3

from forense.cli import EXIT_ERROR, EXIT_INTEGRITY, EXIT_OK, main


def test_full_workflow_in_spanish(tmp_path, evidence_dir, capsys):
    case = str(tmp_path / "caso")
    assert main(["nuevo", case, "-n", "Caso CLI", "-i", "Ana", "-L", "es"]) == EXIT_OK
    assert "creado" in capsys.readouterr().out
    assert main(["-c", case, "evidencia", "agregar", str(evidence_dir), "--descripcion", "carpeta", "-L", "es"]) == EXIT_OK
    assert "EV-001" in capsys.readouterr().out
    assert main(["-c", case, "analizar", "inventory", "EV-001", "-o", "hashes=md5", "-L", "es"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Análisis #1 (inventory): completado" in out
    assert main(["-c", case, "-L", "es", "verificar"]) == EXIT_OK
    assert "Integridad verificada" in capsys.readouterr().out
    assert main(["-c", case, "informe", "-L", "es"]) == EXIT_OK
    assert "Informe generado" in capsys.readouterr().out
    assert any(p.name.endswith("_es.html") for p in (tmp_path / "caso" / "reports").iterdir())


def test_english_commands_options_after_command(tmp_path, evidence_dir, capsys):
    case = str(tmp_path / "case")
    assert main(["new", case, "--name", "CLI case", "--investigator", "Bob"]) == EXIT_OK
    assert main(["evidence", "add", str(evidence_dir), "-c", case, "--copy"]) == EXIT_OK
    assert main(["triage", "EV-001", "--case", case, "--analyst", "Eve", "--lang", "en"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "inventory" in out and "completed" in out
    assert main(["analyses", "-c", case]) == EXIT_OK
    assert "Eve" in capsys.readouterr().out
    assert main(["show", "1", "-c", case, "--limit", "1"]) == EXIT_OK
    assert "Showing 1 of 2." in capsys.readouterr().out
    assert main(["timeline", "-c", case, "--search", "a.txt"]) == EXIT_OK
    assert "a.txt" in capsys.readouterr().out
    export = tmp_path / "findings.json"
    assert main(["export", "findings", "-o", str(export), "-c", case]) == EXIT_OK
    assert export.exists()
    assert main(["custody", "--verify", "-c", case]) == EXIT_OK
    assert "intact" in capsys.readouterr().out


def test_verify_reports_tampering(tmp_path, evidence_dir, capsys):
    case = str(tmp_path / "case")
    main(["new", case, "-n", "x", "-i", "y"])
    main(["evidence", "add", str(evidence_dir), "-c", case])
    (evidence_dir / "a.txt").write_text("changed", encoding="utf-8")
    capsys.readouterr()
    assert main(["verify", "-c", case]) == EXIT_INTEGRITY
    assert "[FAIL] Evidence EV-001" in capsys.readouterr().out

    db = sqlite3.connect(tmp_path / "case" / "forense.db")
    db.execute("UPDATE custody SET actor = 'someone else' WHERE seq = 1")
    db.commit()
    db.close()
    assert main(["custody", "--verify", "-c", case]) == EXIT_INTEGRITY


def test_errors_are_reported_not_raised(tmp_path, capsys):
    assert main(["info", "-c", str(tmp_path / "missing")]) == EXIT_ERROR
    assert "No case found" in capsys.readouterr().err
    assert main(["info", "-c", str(tmp_path / "missing"), "-L", "es"]) == EXIT_ERROR
    assert "No hay ningún caso" in capsys.readouterr().err


def test_modules_listing_and_demo(tmp_path, capsys):
    assert main(["modulos", "-L", "es"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Registros de eventos (EVTX)" in out and "-o hash_list=" in out
    assert main(["demo", str(tmp_path / "demo"), "-a", "Tester"]) == EXIT_OK
    assert "Demo case analysed" in capsys.readouterr().out
    assert main(["findings", "-c", str(tmp_path / "demo" / "case_demo"), "--min-severity", "critical"]) == EXIT_OK
    assert "IFEO debugger for sethc.exe" in capsys.readouterr().out
