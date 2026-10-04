from __future__ import annotations

import base64
import gzip
import json
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from forense.core.errors import ModuleError
from forense.core.timezone import WindowsTimeZone
from forense.demo.builders import HiveBuilder
from forense.image import Extractor, _stream_dest, filesystems, open_image
from forense.modules.base import ResultSink, get_module
from forense.modules.windows.psreadline import parse_history
from forense.modules.windows.setupapi import classify, parse_log
from forense.modules.windows.tasks import parse_task
from forense.modules.windows.wintimeline import application, clipboard_text
from forense.modules.windows.wmi import scan_repository
from forense.parsers.usnjrnl import FILE_CREATE, FILE_DELETE, build_record, iter_records

DATA = Path(__file__).parent / "data"
T = datetime(2026, 9, 14, 3, 0, tzinfo=timezone.utc)
REG_DWORD, REG_BINARY = 4, 3


def run(module: str, target: Path, out: Path, **options):
    sink = ResultSink()
    ctx = get_module(module).run(target, out / f"out_{module}", options, sink=sink)
    return ctx, sink


def codes(sink: ResultSink) -> dict[str, list[dict]]:
    found: dict[str, list[dict]] = {}
    for finding in sink.findings:
        found.setdefault(finding["code"], []).append(finding)
    return found


# -- scheduled tasks ----------------------------------------------------------------------
def test_scheduled_tasks(demo, tmp_path):
    ctx, sink = run("tasks", demo["triage"], tmp_path)
    assert ctx.summary == {"tasks": 2, "hidden_tasks": 1}
    [finding] = codes(sink)["tasks.suspicious_task"]
    assert finding["params"]["task"] == "\\WinUpdateCheck" and finding["params"]["user"] == "SYSTEM"
    assert {"hidden_window", "execution_policy_bypass", "hidden_task", "runs_as_system"} <= set(
        finding["params"]["reasons"].split(", "))
    task = next(d for k, d in sink.records if d["name"] == "\\WinUpdateCheck")
    assert task["triggers"].startswith("BootTrigger; TimeTrigger 2026-09-14T04:55:00 (every PT1H)")
    with pytest.raises(ValueError):
        parse_task(b'<?xml version="1.0"?><!DOCTYPE t [<!ENTITY a "x">]><Task>&a;</Task>')
    with pytest.raises(ValueError):
        parse_task(b"<NotATask/>")


# -- PowerShell history ---------------------------------------------------------------------
def test_psreadline_history(demo, tmp_path):
    assert parse_history("a\nb `\n  c\n\nd `") == [(1, "a"), (2, "b \n  c"), (5, "d")]
    ctx, sink = run("psreadline", demo["triage"], tmp_path)
    assert ctx.summary == {"commands_per_user": {"maria": 7}, "suspicious_commands": 3}
    rules = [f["params"]["rules"] for f in codes(sink)["psreadline.suspicious_command"]]
    assert rules == ["download_cradle, invoke_expression", "defender_tampering", "tool:rclone"]
    commands = [d["command"] for k, d in sink.records]
    assert "C:\\Users\\maria\\Desktop\\clientes_2026.zip" in commands[4] and commands[4].count("\n") == 1
    [event] = sink.events
    assert event["type"] == "powershell_history" and "last: Get-Process" in event["details"]


# -- Windows Timeline -----------------------------------------------------------------------
def test_windows_timeline(demo, tmp_path):
    ctx, sink = run("wintimeline", demo["triage"], tmp_path)
    assert ctx.summary == {"activities": {"open": 2, "in_focus": 2, "clipboard": 1}, "clipboard_items": 1}
    records = [d for _, d in sink.records]
    assert records[0]["application"] == "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"
    assert records[1]["focus_seconds"] == 900
    clip = next(r for r in records if r["type"] == "clipboard")
    assert clip["clipboard"].startswith("powershell -nop -w hidden -enc")
    assert list(codes(sink)) == ["wintimeline.suspicious_clipboard"]
    assert application('[{"application":"Microsoft.Windows.Explorer","platform":"afs_crossplatform"}]') \
        == "Microsoft.Windows.Explorer"
    assert application('[{"application":"C:\\\\Users\\\\Public\\\\mimikatz.exe","platform":"x_exe_path"}]') \
        == "C:\\Users\\Public\\mimikatz.exe"
    text = json.dumps([{"content": base64.b64encode("contraseña".encode()).decode(), "formatName": "Text"}])
    assert clipboard_text(text) == "contraseña" and clipboard_text("not json") == ""


# -- setupapi and time zones ---------------------------------------------------------------
def _system_hive(path: Path, with_rules: bool = True) -> Path:
    hive = HiveBuilder()
    hive.value("Select", "Current", REG_DWORD, 1)
    tzi = "ControlSet001\\Control\\TimeZoneInformation"
    hive.value(tzi, "TimeZoneKeyName", 1, "Romance Standard Time")
    hive.value(tzi, "ActiveTimeBias", REG_DWORD, 0xFFFFFF88)
    if with_rules:
        hive.value(tzi, "Bias", REG_DWORD, 0xFFFFFFC4)
        hive.value(tzi, "StandardBias", REG_DWORD, 0)
        hive.value(tzi, "DaylightBias", REG_DWORD, 0xFFFFFFC4)
        hive.value(tzi, "StandardStart", REG_BINARY, struct.pack("<8H", 0, 10, 0, 5, 3, 0, 0, 0))
        hive.value(tzi, "DaylightStart", REG_BINARY, struct.pack("<8H", 0, 3, 0, 5, 2, 0, 0, 0))
    path.parent.mkdir(parents=True, exist_ok=True)
    return hive.save(path)


def test_time_zone_rules(tmp_path):
    evidence = tmp_path / "ev"
    _system_hive(evidence / "C/Windows/System32/config/SYSTEM")
    zone = WindowsTimeZone.from_evidence(evidence)
    assert zone.name == "Romance Standard Time"
    assert zone.to_utc(datetime(2026, 7, 1, 12, 0)) == datetime(2026, 7, 1, 10, 0, tzinfo=timezone.utc)
    assert zone.to_utc(datetime(2026, 1, 15, 12, 0)) == datetime(2026, 1, 15, 11, 0, tzinfo=timezone.utc)
    assert zone.is_dst(datetime(2026, 3, 29, 2, 30)) and not zone.is_dst(datetime(2026, 3, 28, 12, 0))
    assert not zone.is_dst(datetime(2026, 10, 25, 3, 0))  # last Sunday of October
    southern = WindowsTimeZone("AUS Eastern", -600, 0, -60, (4, 0, 1, 3, 0), (10, 0, 1, 2, 0))
    assert southern.is_dst(datetime(2026, 1, 10)) and not southern.is_dst(datetime(2026, 7, 10))
    _system_hive(tmp_path / "old/config/SYSTEM", with_rules=False)
    fallback = WindowsTimeZone.from_evidence(tmp_path / "old")
    assert fallback.bias == -120 and fallback.to_utc(datetime(2026, 1, 1, 12)).hour == 10


def test_setupapi(demo, tmp_path):
    ctx, sink = run("setupapi", demo["triage"], tmp_path)
    assert ctx.summary["time_conversion"] == "Romance Standard Time"
    usb = next(d for _, d in sink.records if d["class"] == "usb_storage")
    assert (usb["vendor"], usb["product"], usb["serial"]) == ("Kingston", "DataTraveler 3.0", "60A44C3FAE2BE2B0E9160123")
    assert usb["first_install"] == "2026-09-14T03:40:00.123000Z" and usb["local_time"] == "2026-09-14 05:40:00"
    assert len(codes(sink)["setupapi.external_storage"]) == 1  # the WPD entry of the same drive is not repeated

    log = tmp_path / "solo" / "setupapi.dev.log"
    log.parent.mkdir()
    log.write_text(">>>  [Device Install (Hardware initiated) - USB\\VID_0781&PID_5583\\4C530001\n"
                   ">>>  [Device Install (Hardware initiated) - USB\\VID_0781&PID_5583\\4C530001]\n"
                   ">>>  Section start 2026/01/10 10:00:00.000\n<<<  [Exit status: SUCCESS]\n", encoding="utf-8")
    ctx, sink = run("setupapi", log.parent, tmp_path, utc_offset="-05:00")
    [(_, record)] = sink.records
    assert record["first_install"] == "2026-01-10T15:00:00.000000Z" and record["vendor"] == "VID_0781"
    with pytest.raises(ModuleError):
        run("setupapi", log.parent, tmp_path / "x", utc_offset="Madrid")
    assert classify("SCSI\\Disk&Ven_NVMe")["class"] == "disk" and parse_log("garbage\n") == []


# -- WMI -------------------------------------------------------------------------------------
def test_wmi_persistence(demo, tmp_path):
    ctx, sink = run("wmi", demo["triage"], tmp_path)
    assert ctx.summary == {"subscriptions": 2, "non_default": 1}
    [finding] = codes(sink)["wmi.persistence"]
    assert finding["severity"] == "high" and finding["params"]["filter"] == "WinUpdFilter"
    assert finding["params"]["action"].endswith("-file C:\\Users\\Public\\sync.ps1")
    assert finding["params"]["query"].startswith("SELECT * FROM __InstanceModificationEvent WITHIN 60")
    data = b'xx\x00ActiveScriptEventConsumer.Name="Up"\x00\x00__EventFilter.Name="F"\x00junk'
    [binding] = scan_repository(data)
    assert binding["consumer_type"] == "ActiveScriptEventConsumer" and binding["action"] == ""


# -- USN journal ---------------------------------------------------------------------------------
def test_usn_journal_demo(demo, tmp_path):
    ctx, sink = run("usnjrnl", demo["triage"], tmp_path)
    journal = ctx.summary["journals"]["C/$Extend/$J"]
    assert journal["records"] == 12 and journal["paths"] == "mft" and journal["deleted"] == 4
    found = codes(sink)
    assert [f["params"]["path"] for f in found["usnjrnl.attack_tool"]] == ["\\Users\\Public\\Tools\\mimikatz.exe",
                                                                          "\\Users\\Public\\Tools\\rclone.exe"]
    assert {f["params"]["path"] for f in found["usnjrnl.executable_created_deleted"]} == {
        "\\Users\\Public\\Tools\\mimikatz.exe", "\\Users\\Public\\sync.ps1"}
    assert found["usnjrnl.prefetch_deleted"][0]["params"]["count"] == 1
    deleted = [e for e in sink.events if e["type"] == "usn_file_deleted"]
    assert deleted[0]["details"] == "\\Users\\Public\\Tools\\mimikatz.exe"


def test_usn_parser_and_ransomware_patterns(tmp_path):
    blob = bytearray(b"\x00" * 4096 + b"\xff" * 16)  # sparse area, then garbage to resynchronise on
    usn = 1000
    for i in range(30):
        ext = (".docx", ".xlsx", ".pdf", ".jpg")[i % 4]
        blob += build_record(f"doc{i}{ext}", 100 + i, 50, 0x1000, T + timedelta(seconds=i), usn)
        blob += build_record(f"doc{i}{ext}.lockbit", 100 + i, 50, 0x2000 | 0x80000000, T + timedelta(seconds=i), usn)
    for i in range(15):
        blob += build_record(f"tmp{i}.dat", 500 + i, 50, FILE_DELETE | 0x80000000, T + timedelta(minutes=1), usn)
    records = list(iter_records(bytes(blob)))
    assert len(records) == 75 and records[0].name == "doc0.docx" and records[0].reasons == ["RENAME_OLD_NAME"]
    journal = tmp_path / "ev" / "$J"
    journal.parent.mkdir()
    journal.write_bytes(bytes(blob))
    ctx, sink = run("usnjrnl", journal.parent, tmp_path, rename_threshold=20, delete_threshold=10)
    found = codes(sink)
    rename = found["usnjrnl.mass_rename"][0]
    assert rename["severity"] == "critical" and rename["params"]["extension"] == ".lockbit"
    assert rename["params"]["count"] == 30 and rename["params"]["extensions"] == 4
    assert found["usnjrnl.mass_deletion"][0]["params"]["count"] == 15
    assert ctx.summary["journals"]["$J"]["paths"] == "names_only"
    renamed = next(e for e in sink.events if e["type"] == "usn_file_renamed")
    assert renamed["details"] == "doc0.docx → doc0.docx.lockbit"
    assert list(iter_records(build_record("a.txt", 1, 5, FILE_CREATE, T, 1)[:40])) == []


# -- alternate data streams in images -----------------------------------------------------------
def test_alternate_data_streams_are_extracted(tmp_path):
    raw = tmp_path / "ads.ntfs"
    raw.write_bytes(gzip.decompress((DATA / "ads.ntfs.gz").read_bytes()))
    img, _ = open_image(raw)
    [(_, fs)] = list(filesystems(img))
    patterns = ("Users/Public/journal.bin:$J", "Users/*/Downloads/*.exe:Zone.Identifier", "Users/*/Downloads/*.exe")
    files = {f.source: f for f in Extractor(fs, tmp_path / "out", patterns).run()}
    assert set(files) == {"/Users/Public/Downloads/tool.exe", "/Users/Public/Downloads/tool.exe:Zone.Identifier",
                          "/Users/Public/journal.bin:$J"}
    zone = files["/Users/Public/Downloads/tool.exe:Zone.Identifier"]
    assert zone.dest.name == "tool.exe_Zone.Identifier" and b"HostUrl=http://update-cdn.example" in zone.dest.read_bytes()
    journal = files["/Users/Public/journal.bin:$J"]
    assert journal.size == 4096 and journal.dest.read_bytes() == b"USNDATA!" * 512  # 2 MiB sparse run skipped
    assert _stream_dest(("$Extend", "$UsnJrnl"), "$J") == ("$Extend", "$J")
