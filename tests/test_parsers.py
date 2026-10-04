from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest

from forense.demo import builders as b
from forense.parsers.evtx import iter_events, normalize
from forense.parsers.lnk import LnkError, find_embedded_lnks, parse_lnk
from forense.parsers.mft import MftReader, PathResolver, parse_record, parse_zone_identifier
from forense.parsers.recyclebin import RecycleBinError, parse_i_file
from forense.parsers.regf import REG_BINARY, RegistryError, RegistryHive, identify
from forense.parsers.shimcache import ShimCacheError, parse_appcompatcache

DATA = Path(__file__).parent / "data"

T = datetime(2026, 9, 14, 2, 35, 0, tzinfo=timezone.utc)


# -- registry -----------------------------------------------------------------------
def test_registry_roundtrip():
    h = b.HiveBuilder(default_time=T)
    h.value("Software\\Vendor\\App", "Name", b.REG_SZ, "Forense")
    h.value("Software\\Vendor\\App", "Count", b.REG_DWORD, 42)
    h.value("Software\\Vendor\\App", "Big", b.REG_QWORD, 2 ** 40)
    h.value("Software\\Vendor\\App", "List", b.REG_MULTI_SZ, ["a", "b"])
    h.value("Software\\Vendor\\App", "Tiny", REG_BINARY, b"\x01\x02")
    h.value("Software\\Vendor\\App", "Huge", REG_BINARY, bytes(range(256)) * 100)  # big data (db) record
    h.value("Software\\Vendor\\App", "", b.REG_SZ, "default")
    h.key("Software\\Ünïcode", T)
    hive = RegistryHive(h.build())
    assert hive.checksum_ok and not hive.dirty
    key = hive.open("software\\VENDOR\\app")
    assert key is not None and key.path == "Software\\Vendor\\App" and key.last_written == T
    assert key.get("Name") == "Forense" and key.get("Count") == 42 and key.get("Big") == 2 ** 40
    assert key.get("List") == ["a", "b"] and key.get("Tiny") == b"\x01\x02"
    assert key.get("Huge") == bytes(range(256)) * 100
    assert key.value("").data == "default"
    assert hive.open("Software\\Ünïcode") is not None
    assert hive.open("Software\\Missing") is None
    assert [k.path for k in hive.walk()][:2] == ["", "Software"]


def test_registry_identify_and_dirty():
    h = b.HiveBuilder()
    h.dirty = True
    h.value("Select", "Current", b.REG_DWORD, 1)
    h.key("ControlSet001\\Services")
    hive = RegistryHive(h.build())
    assert hive.dirty and identify(hive) == "system"
    with pytest.raises(RegistryError):
        RegistryHive(b"not a hive" * 1000)


# -- shell links ---------------------------------------------------------------------
def test_lnk_local_target_with_tracker():
    data = b.build_lnk("E:\\clientes.xlsx", T, T, T, size=1234, drive_type=2, serial=0x6A2F11C0,
                       volume_label="KINGSTON", machine_id="ws-01", mac="00:15:5d:01:02:03",
                       arguments="--open", working_dir="E:\\")
    lnk = parse_lnk(data)
    assert lnk.target_path == "E:\\clientes.xlsx" and lnk.target_size == 1234
    assert lnk.drive_type == "removable" and lnk.volume_serial == "6A2F-11C0" and lnk.volume_label == "KINGSTON"
    assert lnk.arguments == "--open" and lnk.working_dir == "E:\\"
    assert lnk.machine_id == "ws-01" and lnk.mac_address == "00:15:5d:01:02:03"
    assert lnk.target_created == T


def test_lnk_network_and_embedded():
    data = b.build_lnk("docs\\plan.docx", T, T, T, network_share="\\\\fs01\\share")
    assert parse_lnk(data).target_path == "\\\\fs01\\share\\docs\\plan.docx"
    blob = b"junk" + data + b"\x00" * 10 + b.build_lnk("C:\\a.txt", T, T, T)
    assert [lnk.target_path for _, lnk in find_embedded_lnks(blob)][-1] == "C:\\a.txt"
    with pytest.raises(LnkError):
        parse_lnk(b"not a link" * 10)


# -- recycle bin -------------------------------------------------------------------------
@pytest.mark.parametrize("version", [1, 2])
def test_recycle_bin_versions(version):
    item = parse_i_file(b.build_i_file("C:\\Users\\bob\\secret.zip", 4096, T, version))
    assert (item.version, item.original_size, item.deleted, item.original_path) == \
        (version, 4096, T, "C:\\Users\\bob\\secret.zip")
    with pytest.raises(RecycleBinError):
        parse_i_file(struct.pack("<QqQ", 9, 0, 0) + b"\x00" * 8)


# -- $MFT ---------------------------------------------------------------------------------
def _times(dt: datetime, extra: int = 0) -> tuple:
    ft = b.to_filetime(dt) + extra
    return (ft, ft, ft, ft)


def test_mft_record_fixups_timestomp_and_zone():
    stomped = b.to_filetime(datetime(2019, 1, 1, tzinfo=timezone.utc))
    raw = b.build_mft_record(40, "evil.exe", 5, si=(stomped, stomped, stomped, stomped), fn=_times(T, 1234),
                             size=4096, zone_identifier="[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=http://x.example/e\r\n")
    assert raw[510:512] == raw[48:50]  # sector tail replaced by the update sequence number
    entry = parse_record(raw, 40)
    assert entry.fixup_ok and entry.in_use and not entry.is_directory
    assert entry.name == "evil.exe" and entry.parent_record == 5 and entry.size == 64
    assert entry.ads == ["Zone.Identifier"]
    assert parse_zone_identifier(entry.zone_identifier)["HostUrl"] == "http://x.example/e"
    assert entry.timestomp_indicators == ["si_created_before_fn", "si_no_subseconds"]
    assert parse_record(b"\x00" * 1024, 1) is None


def test_mft_reader_and_paths(tmp_path):
    t = _times(T, 77)
    records = {0: b.build_mft_record(0, "$MFT", 5, si=t, fn=t),
               5: b.build_mft_record(5, ".", 5, si=t, fn=t, directory=True, sequence=5, parent_sequence=5),
               6: b.build_mft_record(6, "Users", 5, si=t, fn=t, directory=True, parent_sequence=5),
               7: b.build_mft_record(7, "a.txt", 6, si=t, fn=t),
               8: b.build_mft_record(8, "lost.txt", 99, si=t, fn=t, in_use=False)}
    path = tmp_path / "$MFT"
    path.write_bytes(b"".join(records.get(i, b"\x00" * 1024) for i in range(9)))
    resolver = PathResolver()
    with MftReader.open(path) as reader:
        entries = list(reader)
    for entry in entries:
        resolver.add(entry)
    assert [e.record for e in entries] == [0, 5, 6, 7, 8]
    assert resolver.path(7) == "\\Users\\a.txt"
    assert resolver.path(8) == "\\$OrphanFiles\\lost.txt"
    assert not entries[-1].in_use


# -- ShimCache ------------------------------------------------------------------------------
def test_shimcache_win10_and_win7():
    fmt, entries = parse_appcompatcache(b.build_shimcache_win10([("C:\\a.exe", T), ("C:\\b.exe", T)]))
    assert fmt == "windows10" and [(e.position, e.path, e.last_modified) for e in entries] == \
        [(1, "C:\\a.exe", T), (2, "C:\\b.exe", T)]

    path = "C:\\old.exe".encode("utf-16-le")
    header = struct.pack("<II", 0xBADC0FEE, 1).ljust(0x80, b"\x00")
    entry = struct.pack("<HHIQQIIQQ", len(path), len(path) + 2, 0, 0x80 + 48, b.to_filetime(T), 2, 0, 0, 0)
    fmt, entries = parse_appcompatcache(header + entry + path)
    assert fmt == "windows7" and entries[0].path == "C:\\old.exe" and entries[0].executed
    with pytest.raises(ShimCacheError):
        parse_appcompatcache(b"\x99" * 64)


# -- EVTX -------------------------------------------------------------------------------------
def test_evtx_real_samples():
    events = list(iter_events(DATA / "new-user-security.evtx"))
    assert sorted(e.event_id for e in events) == [4720, 4728, 4732, 4732]
    created = next(e for e in events if e.event_id == 4720)
    assert created.channel == "Security" and created.get("TargetUserName") == "IEUser"
    assert created.timestamp.startswith("2013-10-23T16:22:39")
    failed = [e for e in iter_events(DATA / "Security_short_selected.evtx") if e.event_id == 4625]
    assert len(failed) == 1


def test_evtx_normalize_shapes():
    event = normalize({"Event": {
        "System": {"Provider": {"#attributes": {"Name": "EventLog"}}, "EventID": {"#text": 6009},
                   "TimeCreated": {"#attributes": {"SystemTime": "2017-07-12T17:16:28.214161Z"}},
                   "EventRecordID": 1, "Channel": "System", "Computer": "PC"},
        "EventData": {"Data": {"#text": ["10.00.", "15063"]}},
        "UserData": {"LogFileCleared": {"#attributes": {"xmlns": "x"}, "SubjectUserName": "bob"}},
    }})
    assert event.event_id == 6009 and event.data["param1"] == "10.00." and event.get("SubjectUserName") == "bob"
