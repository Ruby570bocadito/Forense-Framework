"""Prefetch, SRUM, ShellBags and jump lists (real samples where licensing allows)."""

from __future__ import annotations

import gzip
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from forense.demo import builders as b
from forense.modules import get_module
from forense.modules.base import ResultSink
from forense.modules.windows.mft import timestomp_severity
from forense.parsers.jumplist import parse_destlist
from forense.parsers.shellitems import fat_datetime, join_path, parse_shell_item

DATA = Path(__file__).parent / "data"
T = datetime(2026, 9, 14, 2, 36, tzinfo=timezone.utc)


def run(module: str, target: Path, out: Path, **options):
    sink = ResultSink()
    ctx = get_module(module).run(target, out / f"out_{module}", options, sink=sink)
    return ctx, sink


def records(sink: ResultSink, artifact: str) -> list[dict]:
    return [data for kind, data in sink.records if kind == artifact]


# -- Prefetch -------------------------------------------------------------------------
def test_prefetch_real_samples_all_formats(tmp_path):
    ctx, sink = run("prefetch", DATA / "prefetch", tmp_path)
    assert ctx.summary["format_versions"] == {"17": 1, "23": 1, "30": 1}  # XP, 7 and compressed Windows 10
    by_exe = {r["executable"]: r for r in records(sink, "prefetch")}
    assert by_exe["PING.EXE"]["run_count"] == 14 and by_exe["PING.EXE"]["last_run"] == "2012-04-06T19:00:55.932955Z"
    assert by_exe["NOTEPAD.EXE"]["path"] == "\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE"
    assert len(by_exe["NOTEPAD.EXE"]["previous_runs"]) == 1  # Windows 10 keeps up to 8 run times
    assert by_exe["CMD.EXE"]["volumes"][0]["serial"] == "24CB074B"
    assert {e["type"] for e in sink.events} == {"program_executed"} and not sink.findings


def test_prefetch_detections(tmp_path):
    folder = tmp_path / "Prefetch"
    folder.mkdir()
    vol = "\\DEVICE\\HARDDISKVOLUME3"
    for exe, path in (("MIMIKATZ.EXE", "\\USERS\\PUBLIC\\MIMIKATZ.EXE"), ("ANYDESK.EXE", "\\PROGRAM FILES\\ANYDESK.EXE"),
                      ("UPDATE.EXE", "\\USERS\\BOB\\APPDATA\\LOCAL\\TEMP\\UPDATE.EXE")):
        (folder / f"{exe}-00000001.pf").write_bytes(b.build_prefetch_v23(exe, 1, 2, T, [vol + path]))
    _, sink = run("prefetch", folder, tmp_path)
    found = {f["code"]: f for f in sink.findings}
    assert found["prefetch.attack_tool"]["severity"] == "high"
    assert found["prefetch.remote_access"]["severity"] == "medium"
    assert found["prefetch.suspicious_execution"]["params"]["path"] == "\\USERS\\BOB\\APPDATA\\LOCAL\\TEMP\\UPDATE.EXE"


# -- SRUM ---------------------------------------------------------------------------
def test_srum_real_database(tmp_path):
    srudb = tmp_path / "SRUDB.dat"
    with gzip.open(DATA / "SRUDB.dat.gz") as src, open(srudb, "wb") as dst:
        shutil.copyfileobj(src, dst)
    ctx, sink = run("srum", srudb, tmp_path, upload_threshold_mb="80")
    network = records(sink, "srum_network")
    assert len(network) == 1840 and len(records(sink, "srum_connectivity")) == 260
    first = network[0]
    assert first["application"] == "DiagTrack" and first["user"] == "S-1-5-18"
    assert first["timestamp"] == "2017-11-05T11:32:00.000000Z" and first["bytes_sent"] == 2076
    ssh = next(f for f in sink.findings if "ssh.exe" in f["params"]["app"])
    assert ssh["code"] == "srum.large_upload" and ssh["params"]["sent"] == "87.5 MiB"
    assert ctx.summary["applications_with_traffic"] == 62


# -- ShellBags ------------------------------------------------------------------------
def test_shell_items():
    entry = parse_shell_item(b.shell_file_entry("Informes 2026", T, T, T, mft_entry=1234, mft_sequence=7))
    assert (entry.kind, entry.name, entry.mft_entry, entry.mft_sequence) == ("directory", "Informes 2026", 1234, 7)
    assert entry.modified == entry.created == T  # FAT times have 2 s resolution
    assert parse_shell_item(b.shell_root("20d04fe0-3aea-1069-a2d8-08002b30309d")).name == "This PC"
    assert parse_shell_item(b.shell_volume("E:\\")).name == "E:"
    assert parse_shell_item(b.shell_network("\\\\srv\\share")).name == "\\\\srv\\share"
    assert parse_shell_item(b"\x05\x00\x99\x00\x00").name == "[0x99]"
    assert fat_datetime(b"\x00\x00\x00\x00") is None
    volume = parse_shell_item(b.shell_volume("C:\\"))
    assert join_path(join_path("This PC", volume), entry) == "C:\\Informes 2026"


def test_shellbags_module_on_demo(demo, tmp_path):
    _, sink = run("shellbags", demo["triage"], tmp_path)
    paths = {r["path"]: r for r in records(sink, "shellbag")}
    assert paths["E:\\clientes"]["mft_entry"] == 41 and paths["E:\\clientes"]["last_interacted"]
    assert "C:\\Users\\Public\\Tools" in paths
    assert [f["params"]["path"] for f in sink.findings] == ["\\\\192.0.2.20\\C$"]
    assert any(e["type"] == "folder_accessed" and "E:\\clientes" in e["details"] for e in sink.events)


# -- Jump lists ---------------------------------------------------------------------------
def test_jump_lists_real_samples(tmp_path):
    ctx, sink = run("jumplists", DATA / "jumplists", tmp_path)
    entries = records(sink, "jumplist_entry")
    explorer = [e for e in entries if e["application"] == "Windows Explorer (7)"]
    assert len(explorer) == 7 and explorer[0]["target_path"] == "C:\\Users\\bperry\\Downloads"
    assert explorer[0]["last_access"] == "2015-08-29T15:32:44.034300Z" and explorer[0]["hostname"] == "student-pc1"
    custom = [e for e in entries if e["kind"] == "custom"]
    assert custom and custom[0]["target_path"] == "C:\\Windows\\System32\\GettingStarted.exe"
    assert ctx.summary["jump_lists"] == 2


def test_destlist_version_3():
    path = "C:\\x.txt"
    entry = bytearray(130)
    entry[72:80] = b"host-01\x00"
    entry[88:92] = (5).to_bytes(4, "little")
    entry[100:108] = b.to_filetime(T).to_bytes(8, "little")
    entry[108:112] = (0xFFFFFFFF).to_bytes(4, "little")
    entry[116:120] = (9).to_bytes(4, "little")
    entry[128:130] = len(path).to_bytes(2, "little")
    data = (3).to_bytes(4, "little") + (1).to_bytes(4, "little") + bytes(24) + bytes(entry) + path.encode("utf-16-le")
    version, entries = parse_destlist(data + bytes(4))
    assert version == 3 and entries[0].path == path and entries[0].access_count == 9
    assert entries[0].hostname == "host-01" and not entries[0].pinned and entries[0].last_modified == T


# -- $MFT timestomping noise control -------------------------------------------------------
@pytest.mark.parametrize("path, severity", [
    ("\\WINDOWS\\system32\\bootvid.dll", None), ("\\Program Files\\App\\a.exe", None), ("\\ntldr", None),
    ("\\Windows\\Temp\\x.exe", "high"), ("\\Users\\Public\\svchost.exe", "high"),
    ("\\Users\\bob\\Documents\\a.docx", "medium"),
])
def test_timestomp_severity(path, severity):
    assert timestomp_severity(path) == severity
