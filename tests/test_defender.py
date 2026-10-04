"""Microsoft Defender support logs (MPLog) and detection history."""

from __future__ import annotations

from forense.core.attack import techniques_for
from forense.modules.base import ResultSink, get_module
from forense.parsers.defender import decode_text, parse_detection_history, parse_mplog

LOG = (
    "2026-09-14T03:06:10.512Z DETECTION_ADD#1 HackTool:Win32/Mimikatz!pz file:C:\\Tools\\mimikatz.exe PidTid: 5208\r\n"
    "2026-09-14T03:06:10.600Z DETECTIONEVENT MPSOURCE_REALTIME HackTool:Win32/Mimikatz!pz file:C:\\Tools\\mimikatz.exe;\r\n"
    "2026-09-14T03:06:10.700Z DETECTIONEVENT MPSOURCE_REALTIME HackTool:Win32/Mimikatz!pz file:C:\\Tools\\mimikatz.exe;\r\n"
    "2026-09-14T02:35:03.100Z SDN:Issuing SDN query for \\Device\\HarddiskVolume3\\x.exe (\\Device\\HarddiskVolume3\\x.exe)"
    " (sha1=" + "a" * 40 + ", sha2=" + "b" * 64 + ")\r\n"
    "2026-09-14T04:12:00.001Z ProcessImageName: rclone.exe, Pid: 7344, TotalTime: 1532, Count: 412, MaxTime: 88, "
    "MaxTimeFile: \\Device\\HarddiskVolume3\\Users\\maria\\a.zip->(ZIP), EstimatedImpact: 37%\r\n"
    "not a log line\r\n2026-09-14T04:13:00Z Engine: something else\r\n"
)


def test_parse_mplog():
    entries = list(parse_mplog(LOG))
    kinds = [e.kind for e in entries]
    assert kinds == ["detection", "detection", "file", "process"]  # the repeated DETECTIONEVENT line counts once
    assert entries[0].data["threat"] == "HackTool:Win32/Mimikatz!pz" and entries[0].data["action"] == "add"
    assert entries[1].data["source"] == "realtime" and entries[1].data["resource"] == "C:\\Tools\\mimikatz.exe"
    assert entries[2].data["sha256"] == "b" * 64
    assert entries[3].data == {"name": "rclone.exe", "pid": 7344, "count": 412, "total_ms": 1532,
                               "impact_percent": 37, "slowest_file": "\\Device\\HarddiskVolume3\\Users\\maria\\a.zip"}


def test_decode_text_handles_utf16_with_and_without_bom():
    assert decode_text("\ufeff" .encode("utf-16-le") + LOG.encode("utf-16-le")).lstrip("\ufeff") == LOG
    assert decode_text(LOG.encode("utf-16-le")) == LOG
    assert decode_text(LOG.encode("utf-8")) == LOG


def test_detection_history():
    def wide(text: str) -> bytes:
        return text.encode("utf-16-le") + b"\x00\x00\x07\x00"

    blob = b"\x08\x00" + wide("Magic.Version:1.2") + wide("Trojan:Win32/Wacatac.B!ml") + \
        wide("file:_C:\\Users\\ana\\Downloads\\invoice.exe") + wide("PC01\\ana") + wide("C:\\Program Files\\x\\y.exe")
    detection = parse_detection_history(blob)
    assert detection.threat == "Trojan:Win32/Wacatac.B!ml" and detection.user == "PC01\\ana"
    assert detection.resources == [("file", "C:\\Users\\ana\\Downloads\\invoice.exe")]
    assert detection.process == "C:\\Program Files\\x\\y.exe"
    assert parse_detection_history(b"\x00" * 100 + wide("nothing interesting")) is None


def test_defender_module_on_the_demo(demo, tmp_path):
    sink = ResultSink()
    ctx = get_module("defender").run(demo["triage"], tmp_path / "out", {}, sink=sink)
    assert ctx.summary["mplog_files"] == 1 and ctx.summary["detection_history"] == 1
    findings = {f["code"]: f for f in sink.findings}
    detection = findings["defender.detection"]
    assert detection["severity"] == "high" and detection["params"]["threat"] == "HackTool:Win32/Mimikatz!pz"
    assert "T1003" in techniques_for(detection)
    tools = {f["params"]["program"] for f in sink.findings if f["code"] == "defender.attack_tool"}
    assert tools == {"mimikatz.exe", "rclone.exe"}
    mimikatz = next(f for f in sink.findings if f["params"].get("program") == "mimikatz.exe")
    assert mimikatz["params"]["file"].lower().endswith("\\windows\\system32\\lsass.exe")
    artifacts = {a for a, _ in sink.records}
    assert {"defender_process", "defender_file", "defender_detection", "defender_detection_history"} <= artifacts
    assert any(e["type"] == "defender_detection" for e in sink.events)
    assert sum(1 for f in sink.findings if f["code"] == "defender.detection") == 1  # MPLog + history: one finding
