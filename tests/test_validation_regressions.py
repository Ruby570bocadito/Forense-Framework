"""Regressions found by validating against public cases with a known answer (see docs/VALIDACION.md).

* NIST CFReDS "Hacking Case" (Windows XP disk): profiles under Documents and Settings were not extracted,
  the placeholder IFEO key of XP, files unzipped by Explorer and registry .LOG files were reported as
  suspicious, offensive tools of the case were not recognised and iexplore.exe looked like explorer.exe.
* EVTX-ATTACK-SAMPLES with SigmaHQ rules: techniques missing from the built-in ATT&CK table had no tactic,
  and the rule pack was slow to load and to evaluate.
"""

from __future__ import annotations

import pytest

from sabueso.core.attack import attack_matrix, technique_info, techniques_for
from sabueso.core.heuristics import installed_tool, lookalike_of, tool_category
from sabueso.core.signatures import check_extension
from sabueso.image import TRIAGE_PATTERNS, _matches
from sabueso.modules.windows.mft import timestomp_severity
from sabueso.modules.windows.registry import _default_ifeo
from sabueso.sigma import SigmaRuleSet
from sabueso.sigma.engine import compile_rule


@pytest.mark.parametrize("path", [
    "Documents and Settings/Mr. Evil/NTUSER.DAT",
    "Documents and Settings/Mr. Evil/Local Settings/Application Data/Microsoft/Windows/UsrClass.dat",
    "Documents and Settings/Mr. Evil/Recent/interception.lnk",
    "RECYCLER/S-1-5-21-2000478354-688789844-1708537768-1003/INFO2",
])
def test_triage_profile_covers_windows_xp(path):
    segments = tuple(path.split("/"))
    assert any(_matches(segments, tuple(p.split("/"))) for p in TRIAGE_PATTERNS)


def test_placeholder_ifeo_key_of_windows_xp_is_not_a_backdoor():
    assert _default_ifeo("Your Image File Name Here without a path", "ntsd -d")
    assert not _default_ifeo("sethc.exe", "cmd.exe")
    assert not _default_ifeo("Your Image File Name Here without a path", "C:\\evil.exe")


def test_files_unzipped_by_explorer_are_a_weak_timestomping_sign():
    unzipped = "\\Documents and Settings\\Mr. Evil\\Local Settings\\Temp\\Temporary Directory 1 for x.zip\\Setup.exe"
    assert timestomp_severity(unzipped) == "low"
    assert timestomp_severity("\\Users\\bob\\Desktop\\Setup.exe") == "high"


@pytest.mark.parametrize("name", ["system.LOG", "SAM.LOG1", "NTUSER.DAT.LOG2"])
def test_registry_transaction_logs_are_not_disguised_files(tmp_path, name):
    path = tmp_path / name
    path.write_bytes(b"regf" + bytes(60))
    assert check_extension(path, path.read_bytes())[1] is None


@pytest.mark.parametrize("display_name, tool", [
    ("Cain & Abel v2.5 beta45", "cain"), ("Ethereal 0.10.6", "ethereal"), ("Look@LAN 2.50 Build 29", "lookatlan"),
    ("Network Stumbler 0.4.0 (remove only)", "netstumbler"), ("123 Write All Stored Passwords", "123wasp"),
    ("Microsoft Office Professional", None), ("Mozilla Firefox", None),
])
def test_installed_offensive_tools(display_name, tool):
    assert installed_tool(display_name) == tool


def test_classic_offensive_tools_and_their_techniques():
    for exe in ("cain.exe", "ethereal.exe", "netstumbler.exe", "lookatlan.exe"):
        assert tool_category(exe) == "attack_tool"
    finding = {"code": "registry.installed_attack_tool", "params": {"program": "Cain & Abel v2.5", "tool": "cain"}}
    assert {"T1003", "T1040"} <= set(techniques_for(finding))


@pytest.mark.parametrize("name", ["iexplore.exe", "tasklist.exe", "dashost.exe", "synchost.exe"])
def test_genuine_windows_binaries_are_not_lookalikes(name):
    assert lookalike_of(name) is None


def test_lookalikes_are_still_reported():
    assert lookalike_of("scvhost.exe") == "svchost.exe"


def test_sigma_tactic_tags_place_unknown_techniques():
    finding = {"code": "sigma.match", "severity": "high", "timestamp": "2020-01-01T00:00:00Z",
               "params": {"techniques": "T1218.011", "tactics": "defense-evasion"}}
    assert technique_info("T1218.011", finding)[1] == ("defense-evasion",)
    assert "defense-evasion" in attack_matrix([finding])


def _rule(detection: dict, logsource: dict | None = None):
    return compile_rule({"title": "t", "id": "x", "level": "high",
                         "logsource": logsource or {"service": "security"}, "detection": detection})


@pytest.mark.parametrize("detection, event", [
    ({"sel_img": {"Image|endswith": "\\cmd.exe"}, "sel_cli": {"CommandLine|contains": ["/c", "/k"]},
      "condition": "all of sel_*"}, {"Image": "C:\\Windows\\CMD.EXE", "CommandLine": "cmd /C whoami"}),
    ({"sel_img": {"Image|endswith": "\\cmd.exe"}, "sel_cli": {"CommandLine|contains": ["/c", "/k"]},
      "condition": "all of sel_*"}, {"Image": "C:\\Windows\\cmd.exe", "CommandLine": "cmd"}),
    ({"a": [{"Image|endswith": "\\rundll32.exe"}, {"OriginalFileName": "RUNDLL32.EXE"}], "condition": "1 of a*"},
     {"OriginalFileName": "RUNDLL32.EXE", "Image": "C:\\x\\renamed.exe"}),
    ({"s": {"Cmd|contains|cased": "Invoke"}, "condition": "s"}, {"Cmd": "invoke-thing"}),
    ({"s": {"Cmd|contains": "kelvin"}, "condition": "s"}, {"Cmd": "\u212aelvin"}),  # Unicode case folding
    ({"s": {"Cmd|contains": "lit\\*eral"}, "condition": "s"}, {"Cmd": "a lit*eral b"}),
    ({"s": {"Cmd|re": "who.mi"}, "f": {"User": "x"}, "condition": "s and not f"}, {"Cmd": "whoami", "User": "y"}),
])
def test_sigma_prefilter_never_changes_the_result(detection, event):
    rule = _rule(detection)
    assert rule.matches(event) is rule._condition_matches(event)


def test_sigma_required_event_ids_index_the_rule():
    rule = _rule({"s": {"EventID": [4624, 4625]}, "f": {"LogonType": 3}, "condition": "s and not f"})
    assert rule.required_event_ids == (4624, 4625)
    ruleset = SigmaRuleSet([rule])
    assert ruleset.match("Security", 4625, {"EventID": 4625, "LogonType": 2}) == [rule]
    assert ruleset.match("Security", 4688, {"EventID": 4688, "LogonType": 2}) == []
    either = _rule({"s": {"EventID": 4624}, "t": {"EventID": 4688}, "condition": "s or t"})
    assert either.required_event_ids == ()


def test_sigma_rule_pack_is_loaded_once(tmp_path):
    (tmp_path / "r.yml").write_text("title: t\nid: x\nlevel: high\nlogsource: {service: security}\n"
                                    "detection: {s: {EventID: 1102}, condition: s}\n", encoding="utf-8")
    first, _ = SigmaRuleSet.load([tmp_path])
    assert SigmaRuleSet.load([tmp_path])[0] is first
    (tmp_path / "r.yml").write_text("title: t2\nid: y\nlevel: high\nlogsource: {service: security}\n"
                                    "detection: {s: {EventID: 104}, condition: s}\n", encoding="utf-8")
    second, _ = SigmaRuleSet.load([tmp_path])
    assert second is not first and second.rules[0].title == "t2"


def test_files_extracted_from_an_image_keep_their_original_times(tmp_path):
    """The copies' creation/change times are the extraction's: the timeline must use the image's (NIST case)."""
    import json

    from sabueso.modules import get_module

    extracted = tmp_path / "analysis" / "extracted"
    (extracted / "C" / "Users").mkdir(parents=True)
    (extracted / "C" / "Users" / "notes.txt").write_text("x", encoding="utf-8")
    original = {"mtime": "2004-08-20T15:04:52.000000Z", "atime": "2004-08-21T10:00:00.000000Z",
                "ctime": "2004-08-20T15:04:52.000000Z", "crtime": "2004-08-19T23:03:54.000000Z"}
    (tmp_path / "analysis" / "extraction_times.json").write_text(json.dumps({"C/Users/notes.txt": original}),
                                                                 encoding="utf-8")
    ctx = get_module("inventory").run(extracted, tmp_path / "out")
    record = next(data for kind, data in ctx.sink.records if kind == "file")
    assert {key: record[key] for key in original} == original
    assert all(event["timestamp"] < "2005" for event in ctx.sink.events)
    # a folder inside the extraction finds the manifest too, with paths relative to itself
    from sabueso.core.utils import original_times
    assert original_times(extracted / "C") == {"Users/notes.txt": original}
