from __future__ import annotations

import csv
import json

import pytest

from forense.cli import EXIT_OK, main
from forense.core.case import Case
from forense.core.execution import build_overview, executable_of, execution_overview, normalize_path
from forense.report import generate_report
from forense.web import create_app


def test_paths_from_every_source_are_normalised():
    same = {
        "\\VOLUME{01d7a1b2c3d4e5f6-1234abcd}\\USERS\\PUBLIC\\TOOLS\\RCLONE.EXE",
        "\\Device\\HarddiskVolume3\\Users\\Public\\Tools\\rclone.exe",
        "C:\\Users\\Public\\Tools\\rclone.exe",
        "c:/users/public/tools/rclone.exe",
    }
    assert {normalize_path(p) for p in same} == {"\\users\\public\\tools\\rclone.exe"}
    assert normalize_path("%ProgramFiles%\\7-Zip\\7zG.exe") == "\\program files\\7-zip\\7zg.exe"
    assert normalize_path("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe") == "\\windows\\system32\\cmd.exe"
    assert normalize_path("\\SystemRoot\\System32\\smss.exe") == "\\windows\\system32\\smss.exe"
    assert executable_of('"C:\\Program Files\\App\\app.exe" --x') == "C:\\Program Files\\App\\app.exe"
    assert executable_of("powershell -enc AAA\\1") == "powershell.exe" and executable_of("") == ""


def test_overview_merges_sources():
    rows = [
        ("prefetch", json.dumps({"path": "\\VOLUME{x}\\USERS\\BOB\\DOWNLOADS\\TOOL.EXE", "run_count": 3,
                                 "last_run": "2026-01-03T00:00:00.000000Z",
                                 "previous_runs": ["2026-01-01T00:00:00.000000Z"]}), "EV-1"),
        ("bam", json.dumps({"path": "\\Device\\HarddiskVolume2\\Users\\Bob\\Downloads\\tool.exe",
                            "last_execution": "2026-01-04T00:00:00.000000Z", "sid": "S-1-5-21-1"}), "EV-1"),
        ("amcache_file", json.dumps({"path": "c:\\users\\bob\\downloads\\tool.exe", "sha1": "ab" * 20,
                                     "key_last_written": "2026-01-01T00:00:00.000000Z"}), "EV-1"),
        ("memory_process", json.dumps({"name": "tool.exe", "path": "", "created": "2026-01-05T00:00:00.000000Z",
                                       "cmdline": "tool.exe --exfil"}), "EV-2"),
        ("event", json.dumps({"event_id": 4688, "channel": "Security", "timestamp": "2026-01-02T00:00:00.000000Z",
                              "data": {"NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                                       "SubjectUserName": "bob", "CommandLine": "cmd /c whoami"}}), "EV-3"),
        ("event", json.dumps({"event_id": 4624, "data": {}}), "EV-3"),
        ("run_mru", json.dumps({"command": "mimikatz\\1", "user": "bob"}), "EV-1"),
        ("shimcache", json.dumps({"path": "C:\\Users\\Public\\scvhost.exe", "last_modified": "2020-01-01"}), "EV-1"),
        ("userassist", json.dumps({"program": "Microsoft.Windows.Explorer.lnk"}), "EV-1"),
        ("web_visit", json.dumps({"url": "x"}), "EV-1"),
    ]
    programs = {p.name.lower(): p for p in build_overview(rows)}
    tool = programs["tool.exe"]
    assert tool.path == "c:\\users\\bob\\downloads\\tool.exe" and set(tool.sources) == {"prefetch", "bam", "amcache",
                                                                                       "memory"}
    assert (tool.first, tool.last, tool.run_count) == ("2026-01-01T00:00:00.000000Z", "2026-01-05T00:00:00.000000Z", 3)
    assert tool.users == {"S-1-5-21-1"} and tool.sha1 == {"ab" * 20} and tool.evidence == {"EV-1", "EV-2"}
    assert tool.command_lines == ["tool.exe --exfil"]
    assert programs["cmd.exe"].command_lines == ["cmd /c whoami"] and programs["cmd.exe"].users == {"bob"}
    assert programs["mimikatz.exe"].flags == ["attack_tool"]
    assert programs["scvhost.exe"].flags == ["lookalike", "suspicious_location"]
    assert programs["scvhost.exe"].first is None  # ShimCache only proves presence
    assert "microsoft.windows.explorer.lnk" not in programs
    ordered = build_overview(rows)
    assert all(p.flags for p in ordered[:2]) and not ordered[-1].flags


@pytest.fixture(scope="module")
def demo_case(tmp_path_factory):
    root = tmp_path_factory.mktemp("exec")
    assert main(["demo", str(root), "-a", "Tester"]) == EXIT_OK
    return root / "case_demo"


def test_demo_execution_overview(demo_case, capsys, tmp_path):
    with Case.open(demo_case) as case:
        programs = {(p.name.lower(), p.path.lower()): p for p in execution_overview(case)}
        fake = programs[("svchost.exe", "c:\\users\\public\\svchost.exe")]
        assert {"prefetch", "bam", "amcache", "shimcache", "userassist", "memory"} <= set(fake.sources)
        assert fake.flags == ["suspicious_location"]
        assert ("svchost.exe", "c:\\windows\\system32\\svchost.exe") in programs  # the real one is another row
        assert [p.name for p in execution_overview(case, search="rclone")] == ["rclone.exe"]
        assert all(p.flags for p in execution_overview(case, suspicious=True))
    capsys.readouterr()
    assert main(["-c", str(demo_case), "ejecucion", "--sospechosos", "-L", "es"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "mimikatz.exe" in out and "herramienta ofensiva" in out and "EXCEL.EXE" not in out
    target = tmp_path / "execution.csv"
    assert main(["-c", str(demo_case), "export", "execution", "-o", str(target)]) == EXIT_OK
    with open(target, encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    assert any(r["Program"] == "rclone.exe" and "offensive tool" in r["Flags"] for r in rows)


def test_execution_in_web_and_report(demo_case):
    app = create_app(demo_case.parent)
    client = app.test_client()
    page = client.get("/c/case_demo/execution?lang=en&suspicious=1").get_data(as_text=True)
    assert "rclone.exe" in page and "offensive tool" in page and "EXCEL.EXE" not in page
    with Case.open(demo_case) as case:
        html = generate_report(case, "es").read_text(encoding="utf-8")
    assert "Ejecución (" in html and "mimikatz.exe" in html and "<h2>5. Ejecución (" in html
