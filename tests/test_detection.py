"""Sigma engine and YARA scanning."""

from __future__ import annotations

import io
import shutil
import zipfile
from pathlib import Path

import pytest

from forense.cli import EXIT_OK, main
from forense.modules import get_module
from forense.modules.base import AnalysisContext, ResultSink
from forense.parsers.evtx import WinEvent
from forense.sigma import BUILTIN_RULES, SigmaRuleSet
from forense.sigma.download import extract_windows_rules
from forense.sigma.engine import SigmaError, _base64offset, compile_rule

DATA = Path(__file__).parent / "data"


def rule(detection: dict, logsource: dict | None = None, level: str = "high"):
    return compile_rule({"title": "t", "id": "x", "level": level, "logsource": logsource or {"service": "security"},
                         "detection": detection})


@pytest.mark.parametrize("detection, event, expected", [
    ({"s": {"Image|endswith": "\\cmd.exe"}, "condition": "s"}, {"Image": "C:\\Windows\\System32\\CMD.EXE"}, True),
    ({"s": {"Image|endswith": "\\cmd.exe"}, "condition": "s"}, {"Image": "C:\\cmd.exe.bak"}, False),
    ({"s": {"CommandLine|contains|all": ["-enc", "hidden"]}, "condition": "s"}, {"CommandLine": "ps -w hidden -enc AA"}, True),
    ({"s": {"CommandLine|contains|all": ["-enc", "hidden"]}, "condition": "s"}, {"CommandLine": "ps -enc AA"}, False),
    ({"s": {"CommandLine|contains|windash": " -decode "}, "condition": "s"}, {"CommandLine": "certutil /decode a b"}, True),
    ({"s": {"Path": "C:\\Users\\\\*\\AppData\\\\*.exe"}, "condition": "s"}, {"Path": "c:\\users\\bob\\appdata\\x.exe"}, True),
    ({"s": {"Cmd|contains": "\\\\\\*.exe"}, "condition": "s"}, {"Cmd": "dir C:\\*.exe /s"}, True),
    ({"s": {"Cmd|contains": "\\\\\\*.exe"}, "condition": "s"}, {"Cmd": "dir C:\\a.exe"}, False),
    ({"s": {"Name": "literal\\*star"}, "condition": "s"}, {"Name": "literal*star"}, True),
    ({"s": {"Name": "literal\\*star"}, "condition": "s"}, {"Name": "literalXstar"}, False),
    ({"s": {"Ip|cidr": "10.0.0.0/8"}, "condition": "s"}, {"Ip": "10.1.2.3"}, True),
    ({"s": {"Ip|cidr": "10.0.0.0/8"}, "condition": "s"}, {"Ip": "192.168.1.1"}, False),
    ({"s": {"Cmd|re": "^powershell.*-e\\s"}, "condition": "s"}, {"Cmd": "PowerShell -e AAA"}, False),
    ({"s": {"Cmd|re|i": "^powershell.*-e\\s"}, "condition": "s"}, {"Cmd": "PowerShell -e AAA"}, True),
    ({"s": {"Cmd|base64offset|contains": "http"}, "condition": "s"}, {"Cmd": "x aHR0cDovL2E= y"}, True),
    ({"s": {"Field": None}, "condition": "s"}, {"Other": "1"}, True),
    ({"s": {"Field|exists": True}, "condition": "s"}, {"Field": "v"}, True),
    ({"s": {"Count|gte": 5}, "condition": "s"}, {"Count": "7"}, True),
    ({"s": {"A|fieldref": "B"}, "condition": "s"}, {"A": "x", "B": "X"}, True),
    ({"s": {"EventID": 4625}, "f": {"User|endswith": "$"}, "condition": "s and not f"}, {"EventID": 4625, "User": "bob"}, True),
    ({"s": {"EventID": 4625}, "f": {"User|endswith": "$"}, "condition": "s and not f"}, {"EventID": 4625, "User": "PC$"}, False),
    ({"sel_a": {"A": 1}, "sel_b": {"B": 2}, "condition": "1 of sel_*"}, {"B": 2}, True),
    ({"sel_a": {"A": 1}, "sel_b": {"B": 2}, "condition": "all of sel_*"}, {"B": 2}, False),
    ({"sel_a": {"A": 1}, "sel_b": {"B": 2}, "condition": "all of them"}, {"A": 1, "B": 2}, True),
    ({"a": {"A": 1}, "b": {"B": 2}, "c": {"C": 3}, "condition": "a and (b or c)"}, {"A": 1, "C": 3}, True),
    ({"k": ["mimikatz", "sekurlsa::"], "condition": "k"}, {"Payload": "invoke sekurlsa::logonpasswords"}, True),
    ({"s": [{"A": 1}, {"B": 2}], "condition": "s"}, {"B": 2}, True),
])
def test_sigma_semantics(detection, event, expected):
    assert rule(detection).matches(event) is expected


def test_sigma_errors_and_mapping():
    with pytest.raises(SigmaError):
        rule({"s": {"A": 1}, "condition": "s | count() > 5"})
    with pytest.raises(SigmaError):
        rule({"s": {"A": 1}, "condition": "missing"})
    with pytest.raises(SigmaError):
        rule({"s": {"A": 1}, "condition": "s"}, {"product": "linux", "category": "process_creation"})
    assert _base64offset(b"http") == ["aHR0c", "h0dH", "odHRw"]
    proc = compile_rule({"title": "p", "level": "high", "logsource": {"category": "process_creation", "product": "windows"},
                         "detection": {"s": {"ParentImage|endswith": "\\winword.exe", "Image|endswith": "\\cmd.exe"},
                                       "condition": "s"}})
    ruleset = SigmaRuleSet([proc])
    sysmon = {"ParentImage": "C:\\Office\\WINWORD.EXE", "Image": "C:\\Windows\\cmd.exe"}
    security = {"ParentProcessName": "C:\\Office\\WINWORD.EXE", "NewProcessName": "C:\\Windows\\cmd.exe"}
    assert ruleset.match("Microsoft-Windows-Sysmon/Operational", 1, sysmon) == [proc]
    assert ruleset.match("Security", 4688, security) == [proc]  # Sysmon field names translated for 4688
    assert ruleset.match("Security", 4624, security) == []


def test_builtin_rules_load_and_cli(capsys):
    ruleset, errors = SigmaRuleSet.load([BUILTIN_RULES])
    assert errors == [] and len(ruleset.rules) >= 15
    assert len({r.id for r in ruleset.rules}) == len(ruleset.rules)
    assert main(["sigma", "check", str(BUILTIN_RULES)]) == EXIT_OK
    assert "unsupported" in capsys.readouterr().out


def test_sigma_download_extraction(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("sigma-master/rules/windows/builtin/security/a.yml", "title: a")
        archive.writestr("sigma-master/rules/linux/b.yml", "title: b")
        archive.writestr("sigma-master/rules/windows/../../evil.yml", "title: evil")
    assert extract_windows_rules(buffer.getvalue(), tmp_path / "rules") == 1
    assert (tmp_path / "rules" / "builtin" / "security" / "a.yml").exists() and not (tmp_path / "evil.yml").exists()


def _event(event_id: int, channel: str = "Security", **data) -> WinEvent:
    return WinEvent("2026-09-14T03:00:00Z", event_id, "prov", channel, "DC01", 7, 0, "", data)


def test_evtx_module_raises_sigma_findings(tmp_path):
    from forense.modules.windows.evtx import EvtxModule, _State

    module = EvtxModule()
    ctx = AnalysisContext(tmp_path, tmp_path, module.parse_options({}), ResultSink(), module="evtx")
    state = _State(10)
    state.sigma = module._load_sigma(ctx)
    module._process(ctx, state, _event(4624, TargetUserName="admin", LogonType=9, LogonProcessName="seclogo",
                                       AuthenticationPackageName="Negotiate"), "s.evtx")
    module._process(ctx, state, _event(1, "Microsoft-Windows-Sysmon/Operational", ParentImage="C:\\x\\WINWORD.EXE",
                                       Image="C:\\Windows\\System32\\cmd.exe", CommandLine="cmd /c whoami /all"), "s.evtx")
    ctx.flush()
    titles = {f["params"]["title"]: f for f in ctx.sink.findings if f["code"] == "sigma.match"}
    assert "Logon with new credentials through seclogo (pass-the-hash pattern)" in titles
    office = titles["Office application spawning a shell or script host"]
    assert office["severity"] == "high" and "T1204.002" in office["params"]["techniques"]
    assert "Account and domain discovery commands" not in titles  # low level, below the default minimum
    assert any(e["type"] == "sigma_match" for e in ctx.sink.events)


def test_evtx_module_with_external_rules_and_level(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "user.yml").write_text(
        "title: User created\nid: 1\nlevel: low\nlogsource:\n  product: windows\n  service: security\n"
        "detection:\n  s:\n    EventID: 4720\n  condition: s\n", encoding="utf-8")
    (rules / "broken.yml").write_text("title: x\ndetection: {condition: missing}\nlogsource: {service: security}\n",
                                      encoding="utf-8")
    shutil.copy(DATA / "new-user-security.evtx", tmp_path / "s.evtx")
    sink = ResultSink()
    ctx = get_module("evtx").run(tmp_path / "s.evtx", tmp_path / "out", {"sigma": "no", "sigma_rules": str(rules),
                                                                        "sigma_min_level": "low"}, sink=sink)
    assert ctx.summary["sigma_matches"] == {"User created": 1} and ctx.summary["sigma_rules_skipped"] == 1


def test_yara_module(demo, tmp_path):
    sink = ResultSink()
    ctx = get_module("yara").run(demo["triage"], tmp_path / "out", {"rules": str(demo["yara"])}, sink=sink)
    matches = [data for kind, data in sink.records if kind == "yara_match"]
    assert [m["file"] for m in matches] == ["C/Users/Public/svchost.exe"]
    assert matches[0]["strings"] == ["$marker", "$mz"] and matches[0]["offsets"]["$mz"] == [0]
    assert len(matches[0]["offsets"]["$marker"]) == 10  # capped per string
    assert sink.findings[0]["severity"] == "critical" and ctx.summary["rule_files"] == 1
    bad = tmp_path / "bad.yar"
    bad.write_text("rule broken { condition: nope }", encoding="utf-8")
    with pytest.raises(Exception, match="bad.yar"):
        get_module("yara").run(demo["triage"], tmp_path / "out2", {"rules": str(bad)})
