from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sabueso.demo import builders as b
from sabueso.parsers.evtx import iter_events, normalize
from sabueso.parsers.lnk import LnkError, find_embedded_lnks, parse_lnk
from sabueso.parsers.logfile import (
    LogFileError,
    LogRecord,
    OpenAttributes,
    attribute_display,
    attribute_name_from_data,
    attribute_type_name,
    file_name_from_content,
    file_record_from_data,
    index_entry_file_name,
    iter_records,
    open_attribute_from_data,
    open_logfile,
    operation_name,
    parse_restart,
)
from sabueso.parsers.mft import (
    MftReader,
    PathResolver,
    collect_extensions,
    merge_extensions,
    parse_attribute_list,
    parse_record,
    parse_zone_identifier,
)
from sabueso.parsers.recyclebin import RecycleBinError, parse_i_file
from sabueso.parsers.regf import REG_BINARY, RegistryError, RegistryHive, identify
from sabueso.parsers.shimcache import ShimCacheError, parse_appcompatcache

DATA = Path(__file__).parent / "data"

T = datetime(2026, 9, 14, 2, 35, 0, tzinfo=timezone.utc)


# -- registry -----------------------------------------------------------------------
def test_registry_roundtrip():
    h = b.HiveBuilder(default_time=T)
    h.value("Software\\Vendor\\App", "Name", b.REG_SZ, "Sabueso")
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
    assert key.get("Name") == "Sabueso" and key.get("Count") == 42 and key.get("Big") == 2 ** 40
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


def test_mft_attribute_list_merges_extension_records(tmp_path):
    t = _times(T, 5)
    zone = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=http://x.example/backup.pst\r\n"
    ext = b.build_mft_extension_record(41, 40, data_size=3_221_225_472, ads=[("Zone.Identifier", zone)])
    base = b.build_mft_record(40, "backup.pst", 67, si=t, fn=t,
                              attribute_list=b.build_mft_attribute_list(
                                  [(0x80, "", 41, 1), (0x80, "Zone.Identifier", 41, 1)]),
                              omit_data=True)
    path = tmp_path / "$MFT"
    blob = {0: b.build_mft_record(0, "$MFT", 5, si=t, fn=t), 40: base, 41: ext}
    path.write_bytes(b"".join(blob.get(i, b"\x00" * 1024) for i in range(42)))  # records at their MFT positions
    with MftReader.open(path) as reader:
        entries = list(reader)
    assert [e.record for e in entries] == [0, 40, 41]
    base, ext_entry = entries[1], entries[2]
    assert base.size == 0 and base.ads == [] and not base.has_unnamed_data
    assert [(a.record, a.record_sequence, a.name) for a in base.attribute_list] == [(41, 1, ""),
                                                                                    (41, 1, "Zone.Identifier")]
    assert ext_entry.size == 3_221_225_472 and ext_entry.base_record == 40 and ext_entry.base_sequence == 1
    merged = merge_extensions(base, collect_extensions(entries)[40])
    assert merged.size == 3_221_225_472  # real size of the $DATA that lives in the extension record
    assert merged.ads == ["Zone.Identifier"]
    assert parse_zone_identifier(merged.zone_identifier)["HostUrl"] == "http://x.example/backup.pst"


def test_mft_merge_rejects_stale_extension_records():
    t = _times(T)
    stale = parse_record(b.build_mft_extension_record(41, 40, data_size=999_999), 41)
    # base reused by another file: the extension stores sequence 1, the base is now sequence 5
    reused = parse_record(b.build_mft_record(40, "reused.txt", 5, si=t, fn=t, sequence=5, size=512), 40)
    assert merge_extensions(reused, [stale]).size == 64  # resident $DATA: nothing adopted
    # readable $ATTRIBUTE_LIST that no longer lists the extension record
    relisted = parse_record(b.build_mft_record(40, "moved.txt", 5, si=t, fn=t,
                                               attribute_list=b.build_mft_attribute_list([(0x80, "", 42, 1)]),
                                               size=512), 40)
    assert merge_extensions(relisted, [stale]).size == 64 and merge_extensions(relisted, [stale]).ads == []
    # unreadable $ATTRIBUTE_LIST: the header link plus matching sequences are trusted
    plain = parse_record(b.build_mft_record(40, "plain.txt", 5, si=t, fn=t, omit_data=True,
                                            attribute_list=b"\x99" * 40), 40)
    assert plain.attribute_list == [] and not plain.has_unnamed_data
    assert merge_extensions(plain, [stale]).size == 999_999


def test_mft_attribute_list_corrupt_content():
    assert parse_attribute_list(b"") == []
    assert parse_attribute_list(b"\x99" * 25) == []  # shorter than one entry
    zero = struct.pack("<IH", 0x80, 0) + b"\x00" * 30
    assert parse_attribute_list(zero) == []  # zero-length entry: stop, no infinite loop
    truncated = struct.pack("<IHBBQQH", 0x80, 40, 0, 26, 0, (1 << 48) | 41, 0) + b"\x00" * 4
    assert parse_attribute_list(truncated) == []  # entry announces more bytes than there are
    assert len(parse_attribute_list(truncated + b"\x00" * 36)) == 1  # complete: exactly one entry
    junk = parse_record(b"FILE" + bytes(range(256)) * 4, 7)  # hostile extension record: must not raise
    assert junk is None or not junk.fixup_ok
    t = _times(T)
    plain = parse_record(b.build_mft_record(40, "a.txt", 5, si=t, fn=t), 40)
    merged = merge_extensions(plain, [junk] if junk else [])
    assert merged.size == 0 and merged.ads == []


# -- $LogFile ---------------------------------------------------------------------------
def test_logfile_names_from_operations(tmp_path):
    t = _times(T)
    image = b.build_mft_record(70, "tool.exe", 65, si=t, fn=t, size=512)
    entry = b.build_logfile_index_entry(0x4A, 73, "mimikatz.exe", t)
    ops = [b.build_lfs_record(0x1A2B3C, 7, 0x02, 0x00, redo_data=image),
           b.build_lfs_record(0x1A2B50, 9, 0x0E, 0x00, redo_data=entry),
           b.build_lfs_record(0x1A2B64, 9, 0x00, 0x0F, undo_data=entry),
           b.build_lfs_record(0x1A2B78, 9, 0x13, 0x00, redo_data=b.build_file_name_value(73, "renamed.txt", t))]
    path = tmp_path / "$LogFile"
    path.write_bytes(b.build_logfile(ops))
    fh, info = open_logfile(path)
    try:
        records = list(iter_records(fh, info))
    finally:
        fh.close()
    assert info.page_size == 4096 and info.clients == 1
    assert [r.lsn for r in records] == [0x1A2B3C, 0x1A2B50, 0x1A2B64, 0x1A2B78]
    assert (records[0].redo_op, records[0].undo_op) == (0x02, 0x00)
    rec = file_record_from_data(records[0].redo_data)
    assert rec is not None and rec.fixup_ok  # the image keeps its update sequence
    assert rec.name == "tool.exe" and rec.record == 70 and rec.parent_record == 65
    assert index_entry_file_name(records[1].redo_data) == (0x4A, 73, "mimikatz.exe")
    assert index_entry_file_name(records[2].undo_data) == (0x4A, 73, "mimikatz.exe")  # deletes ride on undo
    assert file_name_from_content(records[3].redo_data) == (73, "renamed.txt")
    assert operation_name(0x02) == "initialize_file_record_segment"
    assert operation_name(0x99).startswith("unknown_")


def test_logfile_corrupt_content(tmp_path):
    with pytest.raises(LogFileError):
        parse_restart(b"\x00" * 8192)
    with pytest.raises(LogFileError):
        parse_restart(b"JUNK" * 2048)
    ops = [b.build_lfs_record(1, 1, 0x02, 0x00, redo_data=b.build_mft_record(5, "a.txt", 5, si=_times(T), fn=_times(T)))]
    good = b.build_logfile(ops)
    # restart page 0 with a broken fixup: page 1 (its copy) is used
    broken = bytearray(good)
    broken[510:512] = b"\x99\x99"
    info = parse_restart(bytes(broken))
    assert info.page_size == 4096
    # a page that is not a record page is skipped; the records survive on the next page
    hole = good[:8192] + b"\xAA" * 4096 + good[8192:]
    path = tmp_path / "$LogFile"
    path.write_bytes(hole)
    fh, info = open_logfile(path)
    try:
        records = list(iter_records(fh, info))
    finally:
        fh.close()
    assert [r.lsn for r in records] == [1]
    # a NextRecordOffset beyond the page does not go past its end
    padded = bytearray(good)
    struct.pack_into("<H", padded, 8192 + 24, 0xFFFF)
    path.write_bytes(bytes(padded))
    fh, info = open_logfile(path)
    try:
        assert [r.lsn for r in iter_records(fh, info)] == [1]
    finally:
        fh.close()


def test_logfile_open_attributes_incremental(tmp_path):
    """An OpenNonresidentAttribute (0x1C) gives the mapping pairs update that follows its context."""
    t = _times(T)
    image = b.build_mft_record(70, "tool.exe", 65, si=t, fn=t, size=512)
    ops = [
        b.build_lfs_record(0x1A2B3C, 7, 0x02, 0x00, redo_data=image),
        b.build_lfs_record(0x1A2B46, 8, 0x1C, 0x00, redo_data=b.build_open_attribute(70, 0x80),
                           undo_data="J".encode("utf-16-le"), target_attribute=0x28),
        b.build_lfs_record(0x1A2B50, 9, 0x09, 0x09, redo_data=b"\x11" * 16, target_attribute=0x28),
    ]
    path = tmp_path / "$LogFile"
    path.write_bytes(b.build_logfile(ops))
    fh, info = open_logfile(path)
    try:
        records = list(iter_records(fh, info))
    finally:
        fh.close()
    assert records[1].redo_op == 0x1C and records[2].target_attribute == 0x28
    table = OpenAttributes()
    for record in records:
        table.update(record)
    entry = table.lookup(0x28)
    assert entry is not None and entry.reference == 70 and entry.type_code == 0x80 and entry.name == "J"
    assert attribute_display(entry) == "$DATA (J)"
    assert table.lookup(0x50) is None  # an index that was never opened
    assert attribute_name_from_data(records[1].undo_data) == "J"
    assert attribute_name_from_data(b"") == ""
    assert attribute_name_from_data("\x01\x00".encode("utf-16-le")) == ""  # control bytes are not a name
    assert attribute_type_name(0x80) == "$DATA" and attribute_type_name(0x777).startswith("type_")
    # a free slot and a short blob are not entries
    assert open_attribute_from_data(b"\x00" * 0x28) is None
    assert open_attribute_from_data(b"\xFF" * 8) is None


def test_logfile_open_attribute_dumps_and_corruption():
    """Checkpoint dumps answer by byte offset; a broken 0x1C only clears the incremental table."""
    dump = b"\x00" * 0x28 + b.build_open_attribute(74, 0xA0)  # slot 0x00 free, 0x28 = $INDEX_ALLOCATION
    names = struct.pack("<HH", 0x28, 6) + "J".encode("utf-16-le") + b"\x00\x00" + struct.pack("<HH", 0, 0)
    table = OpenAttributes()
    table.update(LogRecord(1, 1, 0, 0x1D, 0x00, dump, b""))
    table.update(LogRecord(2, 1, 0, 0x1E, 0x00, names, b""))
    entry = table.lookup(0x28)
    assert entry is not None and entry.reference == 74 and entry.name == "J"  # name rides on the names dump
    assert attribute_display(entry) == "$INDEX_ALLOCATION (J)"
    assert table.lookup(0x00) is None  # the free slot is not an attribute
    assert table.lookup(0x50) is None  # beyond the dump
    # a broken OpenNonresidentAttribute invalidates the incremental entries, but the last
    # checkpoint dump remains the best known state (as in the reference restart analysis)
    table.update(LogRecord(3, 1, 0, 0x1C, 0x00, b"\xFF" * 8, b"", target_attribute=0x28))
    entry = table.lookup(0x28)
    assert entry is not None and entry.reference == 74
    # a valid 0x1C entry wins over the dump from that point on
    table.update(LogRecord(4, 1, 0, 0x1C, 0x00, b.build_open_attribute(90, 0x90), b"", target_attribute=0x28))
    entry = table.lookup(0x28)
    assert entry is not None and entry.reference == 90 and entry.name == ""  # unnamed: no dump name lookup
    # hostile names dumps never break the walk
    hostile = OpenAttributes()
    hostile.update(LogRecord(1, 1, 0, 0x1E, 0x00, struct.pack("<HH", 0x28, 0xFFFF) + b"\x01\x00", b""))
    hostile.update(LogRecord(2, 1, 0, 0x1D, 0x00, dump, b""))
    entry = hostile.lookup(0x28)
    assert entry is not None and entry.name == ""


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
