"""MITRE ATT&CK mapping, incident storyline, STIX export, case overview and charts."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

import pytest

from forense.charts import Bucket, activity_chart, bucketize, count_color, ink_on, nice_ticks, severity_bar, tactic_bars
from forense.cli import EXIT_OK, main
from forense.core.attack import TACTICS, TECHNIQUES, attack_matrix, draft_summary, storyline, techniques_for
from forense.core.case import Case
from forense.core.overview import case_overview
from forense.core.stix import build_bundle
from forense.web import create_app


def _finding(code, severity="high", timestamp="2024-03-01T10:00:00.000000Z", fid=1, review=None, **params):
    return {"id": fid, "code": code, "severity": severity, "timestamp": timestamp, "params": params,
            "review": {"status": review} if review else None, "evidence_id": "EV-001"}


@pytest.fixture(scope="module")
def demo_case(tmp_path_factory):
    root = tmp_path_factory.mktemp("attack")
    assert main(["demo", str(root), "-a", "Tester"]) == EXIT_OK
    return root / "case_demo"


# -- mapping ------------------------------------------------------------------------------------
def test_techniques_from_codes_tools_and_sigma_tags():
    assert "T1070.004" in techniques_for(_finding("recyclebin.deleted_executable"))
    assert "T1003" in techniques_for(_finding("prefetch.attack_tool", program="MIMIKATZ.EXE"))
    assert "T1219" in techniques_for(_finding("prefetch.attack_tool", program="anydesk.exe"))
    assert "T1546.008" in techniques_for(_finding("registry.ifeo_debugger", program="sethc.exe"))
    assert "T1546.008" not in techniques_for(_finding("registry.ifeo_debugger", program="notepad.exe"))
    assert techniques_for(_finding("sigma.match", techniques="t1059.001, T1003")) == ["T1059.001", "T1003"]
    assert techniques_for(_finding("inventory.nothing_to_see")) == []


def test_every_mapped_technique_has_a_known_tactic():
    tactics = {name for name, _ in TACTICS}
    for technique, (name, technique_tactics) in TECHNIQUES.items():
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", technique) and name
        assert set(technique_tactics) <= tactics, technique


def test_matrix_filters_noise_and_false_positives():
    findings = [
        _finding("prefetch.attack_tool", "high", fid=1, program="mimikatz.exe"),
        _finding("recyclebin.deleted_executable", "low", fid=2),  # below the threshold
        _finding("recyclebin.deleted_executable", "low", fid=3, review="confirmed"),  # confirmed always counts
        _finding("psreadline.suspicious_command", "high", fid=4, review="false_positive", command="psexec \\\\x"),
    ]
    matrix = attack_matrix(findings)
    assert [h.technique for h in matrix["credential-access"]] == ["T1003"]
    assert [f["id"] for f in matrix["defense-evasion"][0].findings] == [3]
    assert "lateral-movement" not in matrix
    assert "lateral-movement" in attack_matrix(findings, include_false_positives=True)
    assert len(attack_matrix(findings, min_severity="low")["defense-evasion"][0].findings) == 2


def test_storyline_and_draft_summary_follow_the_kill_chain():
    findings = [
        _finding("prefetch.attack_tool", "critical", "2024-03-01T12:00:00Z", 1, program="mimikatz.exe"),
        _finding("registry.suspicious_autorun", "high", "2024-03-01T11:00:00Z", 2, value="C:\\Users\\Public\\a.exe"),
    ]
    phases = storyline(findings)
    order = {name: i for i, (name, _) in enumerate(TACTICS)}
    assert [p.tactic for p in phases] == sorted((p.tactic for p in phases), key=order.get)
    text = draft_summary(findings)
    assert "2024-03-01" in text and "(#1)" in text and "(#2)" in text
    assert text.splitlines()[-1]  # the review disclaimer closes the draft
    assert draft_summary([]) != "" and "(#" not in draft_summary([])


# -- demo case: matrix, STIX, CLI and web ----------------------------------------------------------
def test_demo_case_covers_the_attack(demo_case):
    with Case.open(demo_case) as case:
        matrix = attack_matrix(case.findings())
    assert {"execution", "persistence", "defense-evasion", "credential-access", "lateral-movement",
            "command-and-control", "exfiltration"} <= set(matrix)
    techniques = {h.technique for hits in matrix.values() for h in hits}
    assert {"T1003", "T1547.001", "T1053.005", "T1567.002", "T1070.004"} <= techniques


def test_stix_bundle(demo_case):
    with Case.open(demo_case) as case:
        bundle = build_bundle(case)
        again = build_bundle(case)
    objects = bundle["objects"]
    assert bundle["type"] == "bundle" and all(o["spec_version"] == "2.1" for o in objects)
    assert len({o["id"] for o in objects}) == len(objects)
    patterns = [o["pattern"] for o in objects if o["type"] == "indicator"]
    assert "[ipv4-addr:value = '198.51.100.23']" in patterns
    assert any(p.startswith("[file:hashes.'SHA-256'") for p in patterns)
    assert all(re.fullmatch(r"\[[a-z0-9-]+:[a-z_.'A-Z0-9-]+ = '.+'\]", p) for p in patterns)
    assert not any("7-zip" in p or "microsoft.com" in p for p in patterns)  # legitimate downloads are left out
    ids = lambda b: sorted(o["id"] for o in b["objects"] if o["type"] in ("indicator", "attack-pattern"))  # noqa: E731
    assert ids(bundle) == ids(again)  # deterministic identifiers
    report = objects[-1]
    assert report["type"] == "report" and set(report["object_refs"]) <= {o["id"] for o in objects}
    assert any(o["type"] == "attack-pattern" and o["external_references"][0]["external_id"] == "T1003"
               for o in objects)


def test_cli_attack_and_stix_export(demo_case, tmp_path, capsys):
    capsys.readouterr()
    assert main(["-c", str(demo_case), "mitre", "-L", "es"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "T1003" in out and "Acceso a credenciales" in out
    assert main(["-c", str(demo_case), "attack", "--summary"]) == EXIT_OK
    assert "draft" in capsys.readouterr().out.lower()
    target = tmp_path / "iocs.json"
    assert main(["-c", str(demo_case), "export", "stix", "-o", str(target)]) == EXIT_OK
    assert json.loads(target.read_text(encoding="utf-8"))["type"] == "bundle"
    with Case.open(demo_case) as case:
        assert case.custody.verify() == []


def test_web_dashboard_and_attack_pages(demo_case):
    client = create_app(demo_case.parent).test_client()
    dashboard = client.get(f"/c/{demo_case.name}/").get_data(as_text=True)
    assert "viz-activity" in dashboard and "viz-severity" in dashboard and "viz-hbars" in dashboard
    page = client.get(f"/c/{demo_case.name}/attack?lang=es").get_data(as_text=True)
    assert "T1003" in page and "attack.mitre.org/techniques/T1003/" in page and "Exfiltración" in page
    findings = client.get(f"/c/{demo_case.name}/findings?technique=T1003").get_data(as_text=True)
    assert "T1003" in findings


# -- overview and charts -----------------------------------------------------------------------------
def test_case_overview(demo_case):
    with Case.open(demo_case) as case:
        overview = case_overview(case)
    assert overview["window"] is not None and overview["buckets"]
    assert sum(overview["severity_counts"].values()) == len(overview["findings"])
    assert [name for name, _ in overview["tactic_rows"]] == [name for name, _ in TACTICS]


def test_bucketize_and_ticks():
    start = datetime(2024, 3, 1, tzinfo=timezone.utc)
    end = datetime(2024, 3, 2, tzinfo=timezone.utc)
    rows = [("2024-03-01T10:00:00Z", 5, 1), ("2024-03-01T10:00:00Z", 2, 0), ("garbage", 9, 9),
            ("2023-01-01T00:00:00Z", 7, 0)]
    buckets, unit = bucketize(rows, start, end)
    assert unit == "hour" and len(buckets) == 24
    assert (buckets[10].count, buckets[10].flagged) == (7, 1) and sum(b.count for b in buckets) == 7
    assert nice_ticks(0) == [0, 1] and nice_ticks(7)[-1] >= 7 and nice_ticks(1234)[:2] == [0, 500]
    assert bucketize([], start, start + (end - start) * 60)[1] in ("day", "week")


def test_charts_render_accessible_svg():
    start = datetime(2024, 3, 1, tzinfo=timezone.utc)
    labels = {"title": "Activity", "events": "events", "flagged": "flagged", "findings": "Findings"}
    buckets = [Bucket(start.replace(hour=h), h, 1 if h == 5 else 0) for h in range(24)]
    svg = str(activity_chart(buckets, "hour", [{"timestamp": "2024-03-01T05:30:00Z", "severity": "high",
                                                  "label": "<script>"}], labels, link="/c/x/timeline"))
    assert svg.startswith("<svg") and "<title>" in svg and "viz-bar-flagged" in svg and "viz-sev-high" in svg
    assert "<script>" not in svg and "&lt;script&gt;" in svg
    assert "from=2024-03-01T05:00&amp;to=2024-03-01T06:00" in svg
    sev = {s: s.title() for s in ("info", "low", "medium", "high", "critical")} | {"title": "Severity"}
    bar = str(severity_bar({"high": 3, "low": 1}, sev))
    assert bar.index("viz-sev-high") < bar.index("viz-sev-low") and "75%" in bar
    assert str(severity_bar({}, sev)) == ""
    assert "viz-hbar" in str(tactic_bars([("Execution", 2), ("Impact", 0)], {"title": "t", "techniques": "tech"}))
    assert count_color(0, 5) == "" and count_color(5, 5) != count_color(1, 5)
    assert ink_on("#ffffff") == "#0b0b0b" and ink_on("#184f95") == "#ffffff"
