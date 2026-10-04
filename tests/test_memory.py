from __future__ import annotations

import json
import textwrap

import pytest

from forense.core.errors import ModuleError
from forense.modules.base import ResultSink, get_module
from forense.modules.windows import memory as memory_module
from forense.modules.windows.memory import _external, _lookalike
from forense.parsers.volatility import find_outputs, parse_output


def run(target, out, **options):
    sink = ResultSink()
    ctx = get_module("memory").run(target, out, options, sink=sink)
    return ctx, sink


def by_code(sink: ResultSink) -> dict[str, list[dict]]:
    codes: dict[str, list[dict]] = {}
    for finding in sink.findings:
        codes.setdefault(finding["code"], []).append(finding)
    return codes


def test_imported_volatility_outputs(demo, tmp_path):
    assert set(find_outputs(demo["memory"])) == {"info", "pslist", "psscan", "pstree", "cmdline", "netscan",
                                                 "malfind", "svcscan"}
    ctx, sink = run(demo["memory"], tmp_path / "out")
    assert ctx.summary["source"] == "Imported Volatility 3 JSON outputs" and set(ctx.summary["plugins"].values()) == {"ok"}
    assert ctx.summary["processes"] == 22 and ctx.summary["hidden_processes"] == 1
    assert ctx.summary["system"]["NtBuildLab"].startswith("19041")
    findings = by_code(sink)
    assert findings["memory.hidden_process"][0]["params"]["process"] == "scvhost.exe (PID 7660)"
    assert findings["memory.lookalike_name"][0]["params"]["imitates"] == "svchost.exe"
    assert findings["memory.masquerading"][0]["params"]["path"] == "C:\\Users\\Public\\svchost.exe"
    assert findings["memory.unexpected_parent"][0]["params"]["parent"] == "powershell.exe (PID 6012)"
    assert {f["params"]["process"] for f in findings["memory.attack_tool"]} == {"mimikatz.exe (PID 7012)",
                                                                                "rclone.exe (PID 7344)"}
    connection = findings["memory.suspicious_connection"]
    assert len(connection) == 1 and connection[0]["params"]["remote"] == "198.51.100.23:443"
    injected = {f["params"]["process"]: f["severity"] for f in findings["memory.injected_code"]}
    assert injected == {"explorer.exe (PID 3964)": "high", "MsMpEng.exe (PID 2040)": "low"}
    assert findings["memory.suspicious_service"][0]["params"]["service"] == "WinUpdateSvc"
    assert findings["memory.suspicious_location"][0]["params"]["process"] == "wupd.exe (PID 6400)"
    assert "memory.duplicate_system_process" not in findings and "memory.suspicious_child" not in findings

    processes = {d["pid"]: d for kind, d in sink.records if kind == "memory_process"}
    assert processes[6248]["parent"] == "powershell.exe" and processes[6248]["cmdline"].endswith("--silent")
    assert processes[7012]["exited"] and not processes[7012]["in_pslist"] and processes[7012]["in_psscan"]
    assert processes[5120]["name"] == "EXCEL.EXE"
    assert {e["type"] for e in sink.events} == {"memory_process_start", "memory_process_exit", "memory_connection"}


def test_running_volatility(demo, tmp_path):
    log = tmp_path / "calls.txt"
    fake = tmp_path / "vol.py"
    fake.write_text(textwrap.dedent(f"""
        import pathlib, sys
        args = sys.argv[1:]
        with open({str(log)!r}, "a", encoding="utf-8") as fh:
            fh.write(" ".join(args) + "\\n")
        plugin = args[-1]
        if plugin == "windows.malware.malfind.Malfind":
            sys.stderr.write("vol: error: argument PLUGIN: invalid choice: " + plugin + "\\n")
            sys.exit(2)
        if plugin.endswith("NetScan"):
            sys.stderr.write("Volatility 3 Framework 2.7\\n")
            print("Unsatisfied requirement plugins.NetScan.kernel.symbol_table_name")
            sys.exit(1)
        short = plugin.split(".")[-2]
        source = next(pathlib.Path({str(demo["memory"])!r}).glob("*.windows." + short + ".json"))
        print("Volatility 3 Framework 2.7")
        print(source.read_text(encoding="utf-8"))
    """), encoding="utf-8")
    image = tmp_path / "WS.raw"
    image.write_bytes(b"\0" * 4096)
    symbols = tmp_path / "symbols"
    symbols.mkdir()
    ctx, sink = run(image, tmp_path / "out", vol_path=str(fake), symbols=str(symbols), offline=True,
                    plugins="pslist,psscan,cmdline,netscan,malfind")
    assert ctx.summary["source"] == "Volatility 3 run on the dump" and ctx.summary["image"] == "WS.raw"
    assert ctx.summary["plugins"] == {"pslist": "ok", "psscan": "ok", "cmdline": "ok", "netscan": "failed",
                                      "malfind": "ok"}
    assert ctx.errors[0]["path"] == "netscan" and "Unsatisfied requirement" in ctx.errors[0]["error"]
    assert ctx.artifacts == ["volatility"] and (tmp_path / "out" / "volatility" / "pslist.json").exists()
    calls = log.read_text(encoding="utf-8").splitlines()
    assert len(calls) == 6 and all(f"-f {image}" in c and "--offline" in c and "-r json" in c for c in calls)
    assert calls[-1].endswith("windows.malfind.Malfind")
    assert "memory.hidden_process" in by_code(sink) and "memory.suspicious_connection" not in by_code(sink)


def test_errors(tmp_path, monkeypatch):
    image = tmp_path / "mem.raw"
    image.write_bytes(b"\0" * 1024)
    with pytest.raises(ModuleError, match="Unknown plugins: dlllist"):
        run(image, tmp_path / "a", plugins="pslist,dlllist")
    monkeypatch.setattr(memory_module, "volatility_command", lambda path=None: None)
    with pytest.raises(ModuleError, match="Volatility 3 is not installed"):
        run(image, tmp_path / "b")
    (tmp_path / "empty").mkdir()
    with pytest.raises(ModuleError, match="No memory dump"):
        run(tmp_path / "empty", tmp_path / "c")


def test_output_parsing_and_heuristics():
    tree = '[{"PID": 4, "__children": [{"PID": 88, "__children": [{"PID": 99, "__children": []}]}]}]'
    rows = parse_output("Volatility 3 Framework 2.7\n" + tree)
    assert [(r["PID"], r["__depth"]) for r in rows] == [(4, 0), (88, 1), (99, 2)]
    assert parse_output('{"PID": 1}\n{"PID": 2}\n') == [{"PID": 1, "__depth": 0}, {"PID": 2, "__depth": 0}]
    assert json.loads("[]") == parse_output("[]")
    assert _lookalike("scvhost.exe") == "svchost.exe" and _lookalike("lsas.exe") == "lsass.exe"
    assert _lookalike("svchost.exe") is None and _lookalike("notepad.exe") is None
    assert _external("198.51.100.23") and _external("8.8.8.8") and _external("::ffff:8.8.8.8")
    assert not any(_external(a) for a in ("10.1.2.3", "192.168.1.5", "127.0.0.1", "fe80::1", "*", "0.0.0.0"))


def test_parent_and_duplicate_rules(tmp_path):
    folder = tmp_path / "vol"
    folder.mkdir()

    def proc(pid, ppid, name, minute, path=""):
        return {"PID": pid, "PPID": ppid, "ImageFileName": name, "CreateTime": f"2026-01-01T10:{minute:02d}:00+00:00",
                "ExitTime": None, "Threads": 3, "Path": path, "Cmd": path, "__children": []}
    processes = [proc(500, 400, "wininit.exe", 0), proc(600, 500, "lsass.exe", 1, "C:\\Windows\\System32\\lsass.exe"),
                 proc(700, 1, "lsass.exe", 2, "C:\\Windows\\System32\\lsass.exe"), proc(800, 900, "winword.exe", 3),
                 proc(810, 800, "powershell.exe", 4, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")]
    (folder / "pstree.json").write_text(json.dumps(processes), encoding="utf-8")
    _, sink = run(folder, tmp_path / "out", plugins="pstree")
    findings = by_code(sink)
    assert findings["memory.duplicate_system_process"][0]["params"]["pids"] == "600, 700"
    assert findings["memory.suspicious_child"][0]["params"]["parent"] == "winword.exe (PID 800)"
    assert "memory.unexpected_parent" not in findings  # PPID 1 does not exist: no parent to judge
