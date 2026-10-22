from __future__ import annotations

import hashlib
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from forense.core.errors import ModuleError
from forense.demo import MALWARE
from forense.demo import builders as b
from forense.modules import available_modules, get_module
from forense.modules.base import AnalysisContext, ResultSink
from forense.parsers.evtx import WinEvent

DATA = Path(__file__).parent / "data"
_T0 = datetime(2026, 9, 14, 2, 10, tzinfo=timezone.utc)


def run(module: str, target: Path, tmp_path: Path, **options):
    sink = ResultSink()
    ctx = get_module(module).run(target, tmp_path / f"out_{module}", options, sink=sink)
    return ctx, sink


def records(sink: ResultSink, artifact: str) -> list[dict]:
    return [data for kind, data in sink.records if kind == artifact]


def codes(sink: ResultSink) -> dict[str, list[dict]]:
    found: dict[str, list[dict]] = {}
    for finding in sink.findings:
        found.setdefault(finding["code"], []).append(finding)
    return found


def test_registry_module(demo, tmp_path):
    ctx, sink = run("registry", demo["triage"], tmp_path)
    found = codes(sink)
    assert found["registry.ifeo_debugger"][0]["severity"] == "critical"
    assert found["registry.suspicious_autorun"][0]["params"]["name"] == "Updater"
    assert found["registry.suspicious_service"][0]["params"]["service"] == "WinUpdateSvc"
    assert "registry.suspicious_runmru" in found and "registry.password_not_required" in found
    assert ctx.summary["system"]["computer_name"] == "WS-CONTAB01"
    assert ctx.summary["system"]["utc_offset_minutes"] == 120
    assert ctx.summary["os"]["product_name"] == "Windows 11 Pro"
    usb = records(sink, "usb_device")[0]
    assert usb["vendor"] == "Kingston" and usb["serial"] == "60A44C3FAE2BE2B0E9160123"
    assert usb["first_install"].startswith("2026-09-14T03:40")
    users = {r["username"]: r for r in records(sink, "user_account")}
    assert users["soporte"]["rid"] == 1002 and users["Invitado"]["disabled"]
    assert any("svchost.exe" in r["program"] for r in records(sink, "userassist"))
    assert records(sink, "amcache_file")[0]["sha1"] == hashlib.sha1(MALWARE).hexdigest()
    assert [r["command"] for r in records(sink, "run_mru")][1] == "excel"
    assert {e["type"] for e in sink.events} >= {"program_executed", "usb_first_connected", "account_created"}


def test_lnk_module(demo, tmp_path):
    ctx, sink = run("lnk", demo["triage"], tmp_path)
    found = codes(sink)
    assert found["lnk.startup_item"][0]["severity"] == "high"
    assert found["lnk.removable_media"][0]["params"]["serial"] == "6A2F-11C0"
    targets = {r["target_path"] for r in records(sink, "shell_link")}
    assert "\\\\192.0.2.10\\finanzas\\presupuesto_2027.docx" in targets
    assert ctx.summary["links"] == 3


def test_recyclebin_module(demo, tmp_path):
    ctx, sink = run("recyclebin", demo["triage"], tmp_path)
    items = {r["original_path"]: r for r in records(sink, "deleted_file")}
    assert items["C:\\Users\\maria\\Desktop\\clientes_2026.zip"]["content_present"]
    assert not items["C:\\Users\\Public\\sync.ps1"]["content_present"]
    assert set(codes(sink)) == {"recyclebin.deleted_archive", "recyclebin.deleted_executable"}
    assert ctx.summary["deleted_items"] == 2


def test_browsers_module(demo, tmp_path):
    ctx, sink = run("browsers", demo["triage"], tmp_path)
    visits = records(sink, "web_visit")
    assert {v["browser"] for v in visits} == {"Chrome", "Firefox"}
    downloads = {d["saved_to"]: d for d in records(sink, "web_download")}
    assert downloads["C:\\Users\\maria\\Downloads\\Factura_0914.pdf.exe"]["url"].endswith("Factura_0914.pdf.exe")
    found = codes(sink)
    assert len(found["browser.executable_download"]) == 2
    assert {f["params"]["domain"] for f in found["browser.suspicious_domain"]} == {"pastebin.com", "transfer.sh"}
    # the evidence database must not have been modified or accompanied by journal files
    history = next(demo["triage"].rglob("History"))
    assert not history.with_name("History-wal").exists() and not history.with_name("History-journal").exists()


def test_mft_module(demo, tmp_path):
    ctx, sink = run("mft", demo["triage"], tmp_path)
    entries = {r["path"]: r for r in records(sink, "mft_entry")}
    assert entries["\\Users\\Public\\svchost.exe"]["host_url"] == "http://update-cdn.example/dl/svchost.exe"
    assert not entries["\\Users\\maria\\clientes_2026.zip"]["in_use"]
    # the mailbox archive is so fragmented that its $DATA and its ADS live in an extension record
    pst = entries["\\Users\\maria\\Downloads\\backup_correo.pst"]
    assert pst["size"] == 2_147_483_648 and pst["ads"] == "Zone.Identifier"
    assert pst["host_url"] == "http://update-cdn.example/dl/backup_correo.pst"
    assert sum(s.get("extension_records", 0) for s in ctx.summary["mft_files"].values()) == 1
    found = codes(sink)
    assert found["mft.timestomping"][0]["params"]["path"] == "\\Users\\Public\\svchost.exe"
    assert len(found["mft.downloaded_executable"]) == 2
    _, sink_no_deleted = run("mft", demo["triage"], tmp_path, include_deleted="no", timeline="none")
    assert all(r["in_use"] for _, r in sink_no_deleted.records) and not sink_no_deleted.events


def test_notifications_module(demo, tmp_path):
    ctx, sink = run("notifications", demo["triage"], tmp_path)
    rows = records(sink, "notification")
    assert len(rows) == 4 and all(r["user"] == "maria" for r in rows)
    by_app = {r["app"]: r for r in rows}
    invoice = by_app["Microsoft.OutlookForWindows_8wekyb3d8bbwe!Microsoft.OutlookForWindows"]
    assert invoice["title"] == "Factura septiembre" and "Factura_0914.pdf" in invoice["body"]
    assert invoice["type"] == "toast" and invoice["arrival"].startswith("2026-09-14T02:02")
    defender = by_app["Windows.Defender_8wekyb3d8bbwe!WindowsDefender"]
    assert defender["title"] == "Acción recomendada"
    assert ctx.summary["notifications"] == 4
    assert ctx.summary["per_app"]["MicrosoftTeams_8wekyb3d8bbwe!Microsoft.Teams"] == 1
    assert any(e["type"] == "notification" for e in sink.events)


def test_notifications_tolerates_corruption(tmp_path):
    db = tmp_path / "wpndatabase.db"
    b.build_wpndatabase(db, [("App.example!App", "Título", "Cuerpo", _T0, _T0)])
    good = db.read_bytes()
    db.write_bytes(good[: len(good) // 3])  # truncated real SQLite: header intact, tables lost
    ctx, sink = run("notifications", db, tmp_path)
    assert sink.records == [] and len(ctx.errors) == 1
    db.write_bytes(b"not a sqlite database at all")
    ctx, sink = run("notifications", db, tmp_path)
    assert sink.records == [] and ctx.errors == []  # rejected by the discovery predicate
    db.unlink()
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE Other (x INTEGER)")
    conn.commit()
    conn.close()
    ctx, sink = run("notifications", db, tmp_path)
    assert sink.records == [] and len(ctx.errors) == 1  # SQLite without the expected tables


def test_notifications_payload_variants(tmp_path):
    db = tmp_path / "wpndatabase.db"
    b.build_wpndatabase(db, [("A.example!A", "Uno & dos", "Cuerpo", _T0, _T0)])
    conn = sqlite3.connect(db)
    utf8 = b'<toast><binding template="ToastGeneric"><text id="1">UTF8</text><text id="2">dos</text></binding></toast>'
    conn.execute("INSERT INTO Notification (Type, Payload, ArrivalTime, ExpiryTime, PrimaryId, HandlerId) "
                 "VALUES (1,?,1,0,'A.example!A','x')", (utf8,))  # tiny non-zero FILETIME: 1601
    conn.execute("INSERT INTO Notification (Type, Payload, ArrivalTime, ExpiryTime, PrimaryId, HandlerId) "
                 "VALUES (3,?,2,0,'A.example!A','x')", (b"\x00\x01\x02 binary noise",))
    conn.commit()
    conn.close()
    ctx, sink = run("notifications", db, tmp_path)
    rows = records(sink, "notification")
    assert len(rows) == 3  # ORDER BY ArrivalTime: 1 < 2 < the built toast
    assert rows[0]["title"] == "UTF8" and rows[0]["body"] == "dos"
    assert rows[1]["title"] == "" and rows[1]["body"] == "" and rows[1]["type"] == "3"
    assert rows[2]["title"] == "Uno & dos" and rows[2]["body"] == "Cuerpo"  # escaped XML decoded once
    assert rows[0]["arrival"].startswith("1601") and rows[2]["arrival"].startswith("2026")
    assert len([e for e in sink.events if e["type"] == "notification"]) == 3


def test_rdp_cache_module(demo, tmp_path):
    ctx, sink = run("rdp_cache", demo["triage"], tmp_path)
    rows = records(sink, "rdp_tile")
    assert len(rows) == 4 and all(r["file"].endswith("Cache0001.bin") for r in rows)
    assert [r["width"] for r in rows] == [64, 64, 96, 64] and rows[2]["bpp"] == 32
    assert all(len(r["key"]) == 16 for r in rows) and rows[0]["offset"] == 12
    found = codes(sink)
    assert found["rdp_cache.historic_activity"][0]["severity"] == "low"
    assert found["rdp_cache.historic_activity"][0]["params"]["tiles"] == 4
    assert len(ctx.artifacts) == 4 and all(a.endswith(".bmp") for a in ctx.artifacts)
    bmp = ctx.output_dir / ctx.artifacts[0]
    assert bmp.read_bytes()[:2] == b"BM" and bmp.stat().st_size > 14 + 40
    assert ctx.summary["tiles"] == 4 and list(ctx.summary["cache_files"]) == ["C/Users/maria/AppData/Local/"
                                                                             "Microsoft/Terminal Server Client/"
                                                                             "Cache/Cache0001.bin"]


def test_rdp_cache_tolerates_corruption(tmp_path):
    db = tmp_path / "Cache0001.bin"
    b.build_rdp_cache(db, [(64, 64, 16), (64, 64, 16), (64, 64, 16)])
    good = db.read_bytes()
    tile = 8 + 4 + 40 + (((64 * 16 + 31) // 32) * 4) * 64
    db.write_bytes(good[:12 + tile + tile // 2])  # second tile cut in half: only the first survives
    ctx, sink = run("rdp_cache", db, tmp_path)
    assert len(records(sink, "rdp_tile")) == 1 and ctx.summary["tiles"] == 1 and not ctx.errors
    db.write_bytes(b"Cache0001.bin header" + bytes(12) + b"\xff" * 300)  # header + garbage: no valid tile
    ctx, sink = run("rdp_cache", db, tmp_path)
    assert sink.records == [] and sink.findings == [] and not ctx.errors
    db.write_bytes(b"\x00" * 12)  # empty container: no tiles either
    ctx, sink = run("rdp_cache", db, tmp_path)
    assert sink.records == [] and ctx.summary["tiles"] == 0


def test_logfile_module(demo, tmp_path):
    ctx, sink = run("logfile", demo["triage"], tmp_path)
    rows = records(sink, "logfile_entry")
    created = next(r for r in rows if r["operation"] == "initialize_file_record_segment")
    assert created["record"] == 70 and created["parent_record"] == 65 and created["name"] == "svchost.exe"
    added = next(r for r in rows if r["operation"] == "index_entry_add")
    assert added["name"] == "mimikatz.exe" and added["record"] == 74 and added["parent_record"] == 73
    assert added["lsn"] < next(r for r in rows if r["operation"] == "index_entry_delete")["lsn"]
    # the mapping pairs update rides on the open attribute table: the 0x1C record before it
    # opened the $DATA stream of svchost.exe (record 70)
    mapping = next(r for r in rows if r["operation"] == "update_mapping_pairs")
    assert mapping["record"] == 70 and mapping["name"] == "svchost.exe" and mapping["attribute"] == "$DATA"
    assert all(r["attribute"] == "" for r in rows if r["operation"] != "update_mapping_pairs")
    stats = ctx.summary["logfile_files"]
    assert sum(s["records"] for s in stats.values()) == 5
    assert sum(s["named"] for s in stats.values()) == 3  # operations carrying the name in their own data
    assert sum(s["contextual"] for s in stats.values()) == 1  # the mapping pairs update, named via the table


def test_inventory_module(demo, tmp_path):
    ctx, sink = run("inventory", demo["triage"], tmp_path, hashes="md5,sha256")
    files = {r["path"]: r for r in records(sink, "file")}
    assert files["C/Users/Public/svchost.exe"]["sha256"] == hashlib.sha256(MALWARE).hexdigest()
    mismatches = codes(sink)["file.content_mismatch"]
    assert [f["params"]["path"] for f in mismatches] == ["C/Users/maria/Pictures/vacaciones.jpg"]
    assert "file.missing_signature" not in codes(sink)  # $I files are not reported
    assert (tmp_path / "out_inventory" / "bodyfile.txt").read_text().count("\n") == ctx.summary["files"]


def test_carving_module(tmp_path):
    thumb = b.build_jpeg(bytes(range(16, 80)))
    jpeg = b.build_jpeg(bytes(range(1, 255)) * 8, thumbnail=thumb)
    zipped = b.build_zip({"a.txt": b"hello"})
    image = tmp_path / "disk.img"
    image.write_bytes(b"\x00" * 1000 + jpeg + b"\x11" * 500 + b.build_png() + b"\x00" * 77 + b.GIF_1X1 +
                      b.build_pdf() + b"\x00" * 33 + zipped + b"\xff\xd8\xff garbage")
    ctx, sink = run("carving", image, tmp_path)
    carved = {r["type"]: r for r in records(sink, "carved_file")}
    assert set(carved) == {"jpg", "png", "gif", "pdf", "zip"}
    assert carved["jpg"]["size"] == len(jpeg)  # not truncated at the thumbnail's end marker
    assert (tmp_path / "out_carving" / carved["zip"]["name"]).read_bytes() == zipped
    assert ctx.summary["carved"] == 5
    with pytest.raises(ModuleError):
        get_module("carving").run(tmp_path, tmp_path / "x")  # directories are rejected


def test_ioc_and_hashset_modules(demo, tmp_path):
    ctx, sink = run("ioc", demo["triage"], tmp_path, watchlist=str(demo["watchlist"]), save_strings="yes")
    values = {r["value"] for r in records(sink, "ioc")}
    assert {"exfil@proton.example", "198.51.100.23", "http://update-cdn.example/dl/"} <= values
    assert {f["params"]["indicator"] for f in codes(sink)["ioc.watchlist_match"]} == \
        {"exfil@proton.example", "198.51.100.23", "update-cdn.example"}
    assert (tmp_path / "out_ioc" / "strings.tsv").exists()

    ctx, sink = run("hashset", demo["triage"], tmp_path, hash_list=str(demo["hashes"]))
    assert [r["path"] for r in records(sink, "hash_match")] == ["C/Users/Public/svchost.exe"]
    assert ctx.summary["hashes_loaded"] == {"sha256": 2}


def test_utf16_strings_and_offsets(tmp_path):
    data = b"\x00" * 10 + "visit http://evil.example/x now".encode("utf-16-le")
    (tmp_path / "blob.bin").write_bytes(data)
    _, sink = run("ioc", tmp_path / "blob.bin", tmp_path)
    url = records(sink, "ioc")[0]
    assert url["value"] == "http://evil.example/x" and url["encoding"] == "utf-16le" and url["offset"] == 22


# -- EVTX -------------------------------------------------------------------------------------
def test_evtx_module_on_real_samples(tmp_path):
    for name in ("new-user-security.evtx", "Security_short_selected.evtx"):
        shutil.copy(DATA / name, tmp_path / name)
    ctx, sink = run("evtx", tmp_path, tmp_path)
    found = codes(sink)
    assert found["evtx.user_created"][0]["params"]["user"] == "IE8Win7\\IEUser"
    group = found["evtx.privileged_group_add"][0]["params"]
    assert group["group"] == "Administrators" and group["member"] == "IE8Win7\\IEUser"  # SID resolved via 4720
    assert ctx.summary["events"] == 11 and ctx.summary["failed_logons"] == 1
    assert len(records(sink, "event")) == 11


def _event(event_id: int, ts: str, **data) -> WinEvent:
    return WinEvent(ts, event_id, "Microsoft-Windows-Security-Auditing", "Security", "DC01", 1, 0, "", data)


def test_evtx_brute_force_followed_by_success(tmp_path):
    from forense.modules.windows.evtx import EvtxModule, _State

    module = EvtxModule()
    ctx = AnalysisContext(tmp_path, tmp_path, module.parse_options({}), ResultSink(), module="evtx")
    state = _State(threshold=5)
    for i in range(6):
        module._process(ctx, state, _event(4625, f"2026-09-14T02:0{i}:00Z", TargetUserName="admin",
                                           IpAddress="203.0.113.7", LogonType="10", Status="0xc000006d"), "s.evtx")
    module._process(ctx, state, _event(4624, "2026-09-14T02:09:00Z", TargetUserName="admin", TargetDomainName="DC",
                                       IpAddress="203.0.113.7", LogonType="10"), "s.evtx")
    module._process(ctx, state, _event(1102, "2026-09-14T02:30:00Z", SubjectUserName="admin"), "s.evtx")
    module._process(ctx, state, _event(4688, "2026-09-14T02:20:00Z", SubjectUserName="admin",
                                       NewProcessName="C:\\Windows\\System32\\vssadmin.exe",
                                       CommandLine="vssadmin delete shadows /all /quiet"), "s.evtx")
    state.finish(ctx)
    ctx.flush()
    found = codes(ctx.sink)
    assert found["evtx.brute_force"][0]["params"]["count"] == 6
    assert found["evtx.brute_force_success"][0]["severity"] == "critical"
    assert "evtx.rdp_public" not in found  # 203.0.113.0/24 is a documentation range, not a public address
    assert found["evtx.log_cleared"][0]["severity"] == "high"
    assert found["evtx.suspicious_command"][0]["severity"] == "critical"
    logon = next(e for e in ctx.sink.events if e["type"] == "logon")
    assert "LogonType=10 (RemoteInteractive)" in logon["details"]


def test_every_module_is_described():
    names = [m.name for m in available_modules()]
    windows = {"evtx", "registry", "lnk", "logfile", "recyclebin", "browsers", "mft", "prefetch", "rdp_cache",
               "srum", "shellbags", "jumplists", "memory", "notifications", "tasks", "psreadline",
               "wintimeline", "setupapi", "wmi", "usnjrnl", "defender"}
    assert windows <= set(names) and {"inventory", "carving", "ioc", "hashset"} <= set(names)
    assert set(names[:len(windows)]) == windows and names[:len(windows)] == sorted(windows)  # Windows first


def _sparse(path: Path, size: int, head: bytes = b"") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(head)
        fh.truncate(size)  # logical size without materialising the bytes
    return path


def test_oversize_artifacts_never_reach_memory(tmp_path):
    """The read_capped gate: grown or hostile files cannot turn the read_bytes pattern into pressure."""
    root = tmp_path / "ev"
    _sparse(root / "Console" / "psreadline" / "me_host" / "ConsoleHost_history.txt", 64 * 1024 * 1024 + 1)
    _sparse(root / "ProgramData" / "mplog-20261023-1.log", 256 * 1024 * 1024 + 1)
    _sparse(root / "Cache0001.bin", 256 * 1024 * 1024 + 1)
    _sparse(root / "setupapi.dev.log", 256 * 1024 * 1024 + 1)
    _sparse(root / "Recent" / "huge.lnk", 16 * 1024 * 1024 + 1)
    _sparse(root / "Windows" / "System32" / "Tasks" / "evil", 1024 * 1024 + 1, head=b"<?xml")
    _sparse(root / "$Recycle.Bin" / "S-1-5-21-1000" / "$I8F4C2A1", 65537)

    for module, reported in (("psreadline", True), ("defender", True), ("rdp_cache", True),
                             ("setupapi", True), ("lnk", False), ("tasks", False), ("recyclebin", False)):
        ctx, sink = run(module, root, tmp_path)
        assert sink.records == [], module
        assert (len(ctx.errors) == 1) if reported else (ctx.errors == []), (module, ctx.errors)

    # the reported ones name the file and the limit, so the analyst knows what was refused
    ctx, _ = run("psreadline", root, tmp_path)
    assert "FileTooLarge" in ctx.errors[0]["error"] and "limit" in ctx.errors[0]["error"]
    assert "ConsoleHost_history.txt" in ctx.errors[0]["error"]
    ctx, _ = run("setupapi", root, tmp_path)
    assert "setupapi.dev.log" in ctx.errors[0]["error"]
