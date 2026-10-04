"""Configuration file, playbooks, `forense auto` and the watched drop folder."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest

from forense.automation import BUILTIN_PLAYBOOKS, STATE_FILE, auto, load_playbook, module_options, watch
from forense.cli import EXIT_OK, main
from forense.core.case import Case
from forense.core.config import DEFAULTS, Config, load_config, set_config, write_template
from forense.core.errors import ForenseError
from forense.web import create_app


@pytest.fixture(autouse=True)
def _reset_config(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSE_CONFIG", str(tmp_path / "no-config.yaml"))  # never the examiner's own file
    set_config(None)
    yield
    set_config(None)


def _config(tmp_path: Path, **extra) -> Config:
    path = tmp_path / "config.yaml"
    path.write_text(json.dumps(extra), encoding="utf-8")  # JSON is valid YAML
    return load_config(path)


# -- configuration ----------------------------------------------------------------------------------
def test_config_defaults_merge_and_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("INTEL", str(tmp_path))
    config = _config(tmp_path, analyst="Ana", intel={"hash_lists": ["$INTEL/bad.txt"]})
    assert config.loaded and config.value("analyst") == "Ana"
    assert config.value("intel.sigma_min_level") == DEFAULTS["intel"]["sigma_min_level"]  # merged, not replaced
    assert config.paths("intel.hash_lists") == [tmp_path / "bad.txt"]
    assert config.value("intel.missing.deep", "x") == "x" and config.paths("intel.watchlists") == []
    assert not load_config(tmp_path / "absent.yaml").loaded


def test_config_errors_and_template(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("analyst: [unclosed", encoding="utf-8")
    with pytest.raises(ForenseError) as info:
        load_config(bad)
    assert info.value.code == "error.config_invalid"
    bad.write_text("- a list\n- not a mapping\n", encoding="utf-8")
    with pytest.raises(ForenseError):
        load_config(bad)
    path = write_template(tmp_path / "sub" / "config.yaml")
    assert load_config(path).value("web.port") == 8765
    with pytest.raises(ForenseError):
        write_template(path)
    write_template(path, overwrite=True)


def test_cli_config_and_analyst_default(tmp_path, capsys):
    path = tmp_path / "forense.yaml"
    assert main(["config", "init", str(path)]) == EXIT_OK
    path.write_text(path.read_text(encoding="utf-8").replace('analyst: ""', 'analyst: "Config Analyst"'),
                    encoding="utf-8")
    assert main(["--config", str(path), "config", "show"]) == EXIT_OK
    assert "Config Analyst" in capsys.readouterr().out
    case = tmp_path / "case"
    assert main(["--config", str(path), "new", str(case), "-n", "Cfg", "-i", "Ana"]) == EXIT_OK
    with Case.open(case) as opened:
        opened.add_evidence(tmp_path / "forense.yaml", actor=None)
    assert main(["--config", str(path), "-c", str(case), "analyze", "inventory", "EV-001"]) == EXIT_OK
    with Case.open(case) as opened:
        assert opened.analyses()[0].actor == "Config Analyst"


# -- playbooks ---------------------------------------------------------------------------------------
def test_playbooks(tmp_path):
    assert load_playbook("full") == BUILTIN_PLAYBOOKS["full"]
    custom = tmp_path / "pb.yaml"
    custom.write_text("steps:\n  - modules: {inventory: {hashes: md5}}\n  - report\n", encoding="utf-8")
    assert load_playbook(str(custom))[0] == {"modules": {"inventory": {"hashes": "md5"}}}
    for content in ("steps: []\n", "nothing: here\n", "steps: [\n"):
        custom.write_text(content, encoding="utf-8")
        with pytest.raises(ForenseError):
            load_playbook(str(custom))
    with pytest.raises(ForenseError) as info:
        load_playbook("no-such-playbook")
    assert info.value.code == "error.playbook_unknown"


def test_module_options_from_config(tmp_path):
    (tmp_path / "sigma").mkdir()
    config = _config(tmp_path, image={"vss": True}, intel={"sigma_rules": str(tmp_path / "sigma"),
                                                             "sigma_min_level": "high"},
                     memory={"symbols": str(tmp_path / "missing"), "offline": True})
    options = module_options(config)
    assert options["image"] == {"vss": True} and options["evtx"]["sigma_min_level"] == "high"
    assert options["memory"] == {"offline": True}  # a missing symbols folder is not passed on


def test_auto_full_playbook_with_intelligence(tmp_path, demo):
    config = _config(tmp_path, analyst="Robot", organization="CERT",
                     intel={"hash_lists": [str(demo["hashes"])], "watchlists": [str(demo["watchlist"])],
                            "yara_rules": [str(demo["yara"])]}, report={"languages": ["es", "en"]})
    messages = []
    result = auto([demo["triage"]], new_case=tmp_path / "auto_case", playbook="full", config=config,
                  progress=messages.append)
    assert all(step.status in ("ok", "completed") for step in result.steps), result.steps
    assert {p.suffix for p in result.reports} == {".html"} and len(result.reports) == 2
    assert {re.sub(r"_.*", "", p.name) for p in result.exports} == {"findings", "timeline", "execution", "iocs"}
    assert any(m.startswith("Step") or "triage" in m for m in messages)
    with Case.open(result.case_path) as case:
        assert case.info["organization"] == "CERT" and case.info["investigator"] == "Robot"
        modules = {a.module for a in case.analyses()}
        assert {"registry", "prefetch", "hashset", "ioc", "yara"} <= modules
        codes = {f["code"] for f in case.findings()}
        assert {"hashset.match", "ioc.watchlist_match", "yara.match"} <= codes
        assert case.custody.verify() == []
    stix = next(p for p in result.exports if p.name.startswith("iocs"))
    assert json.loads(stix.read_text(encoding="utf-8"))["type"] == "bundle"


def test_auto_into_an_existing_case_with_a_custom_playbook(case, evidence_dir, tmp_path):
    playbook = tmp_path / "pb.yaml"
    playbook.write_text("steps:\n  - modules: {inventory: {}}\n  - intel\n  - export: [findings]\n",
                        encoding="utf-8")
    result = auto([evidence_dir], case_dir=case.root, playbook=str(playbook), config=_config(tmp_path))
    assert [s.status for s in result.steps] == ["completed", "skipped", "ok"]
    assert result.exports and result.exports[0].parent == case.root / "exports"


def test_unknown_step_is_reported_not_raised(case, evidence_dir, tmp_path):
    playbook = tmp_path / "pb.yaml"
    playbook.write_text("steps: [explode, report]\n", encoding="utf-8")
    result = auto([evidence_dir], case_dir=case.root, playbook=str(playbook), config=_config(tmp_path))
    assert [s.status for s in result.steps] == ["failed", "ok"]


def test_cli_auto(tmp_path, demo, capsys):
    target = tmp_path / "cli_case"
    assert main(["auto", str(demo["triage"]), "--new", str(target), "-p", "quick", "-i", "Ana"]) == EXIT_OK
    out = capsys.readouterr().out
    assert str(target) in out and "report_" in out
    assert Case.is_case(target)


# -- watched folder ----------------------------------------------------------------------------------
def test_watch_processes_each_item_once(tmp_path, evidence_dir):
    inbox, workspace = tmp_path / "inbox", tmp_path / "cases"
    inbox.mkdir()
    (inbox / "first.txt").write_text("one", encoding="utf-8")
    (inbox / "copying.part").write_text("partial", encoding="utf-8")
    (inbox / ".hidden").write_text("x", encoding="utf-8")
    config = _config(tmp_path)
    results = watch(inbox, workspace, playbook="triage", once=True, config=config)
    assert len(results) == 1 and Case.is_case(results[0].case_path)
    state = json.loads((workspace / STATE_FILE).read_text(encoding="utf-8"))
    assert [v["status"] for v in state.values()] == ["ok"]
    assert watch(inbox, workspace, playbook="triage", once=True, config=config) == []  # already processed
    (inbox / "second.txt").write_text("two", encoding="utf-8")
    assert len(watch(inbox, workspace, playbook="triage", once=True, config=config)) == 1


def test_watch_waits_for_stable_items_and_survives_failures(tmp_path):
    inbox, workspace = tmp_path / "inbox", tmp_path / "cases"
    inbox.mkdir()
    (inbox / "evidence.txt").write_text("data", encoding="utf-8")
    polls = []

    def stop() -> bool:
        polls.append(1)
        return len(polls) >= 2

    results = watch(inbox, workspace, playbook="no-such-playbook", interval=0.01, config=_config(tmp_path),
                    stop=stop)
    assert results == []  # first poll only records the size; the second fails on the playbook
    state = json.loads((workspace / STATE_FILE).read_text(encoding="utf-8"))
    assert [v["status"] for v in state.values()] == ["failed"]


def test_cli_watch_once(tmp_path, capsys):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "a.txt").write_text("a", encoding="utf-8")
    assert main(["vigilar", str(inbox), "-w", str(tmp_path / "ws"), "--una-vez", "-p", "triage"]) == EXIT_OK
    assert len([p for p in (tmp_path / "ws").iterdir() if p.is_dir()]) == 1


# -- web ----------------------------------------------------------------------------------------------
def test_web_automatic_analysis(tmp_path, evidence_dir):
    with Case.create(tmp_path / "ws" / "case1", "Web", "Wendy") as case:
        case.add_evidence(evidence_dir)
    client = create_app(tmp_path / "ws").test_client()
    page = client.get("/c/case1/").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    assert client.post("/c/case1/auto", data={"csrf_token": token, "evidence": "EV-001",
                                              "playbook": "triage"}).status_code == 302
    for _ in range(200):
        jobs = client.get("/api/jobs?case=case1").get_json()
        if jobs and jobs[0]["status"] in ("done", "failed"):
            break
        time.sleep(0.05)
    assert jobs[0]["status"] == "done", jobs
    assert client.get("/c/case1/reports").get_data(as_text=True).count("report_") >= 1
