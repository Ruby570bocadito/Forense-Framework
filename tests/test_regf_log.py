from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

from forense.demo.builders import HiveBuilder
from forense.modules.base import ResultSink, get_module
from forense.parsers.regf import RegistryHive
from forense.parsers.regf_log import build_log_entry, log_files, marvin32, parse_log, recover

T = datetime(2026, 9, 14, 2, 0, tzinfo=timezone.utc)
REG_SZ = 1


def _checksum(block: bytearray) -> None:
    value = 0
    for (dword,) in struct.iter_unpack("<I", bytes(block[:508])):
        value ^= dword
    struct.pack_into("<I", block, 508, value)


def _hives() -> tuple[bytes, bytes]:
    """(hive flushed to disk, hive as it was in memory) — the second one has an extra Run key."""
    old = HiveBuilder(default_time=T)
    old.value("Microsoft\\Windows\\CurrentVersion\\Run", "OneDrive", REG_SZ, "C:\\OneDrive.exe")
    new = HiveBuilder(default_time=T)
    new.value("Microsoft\\Windows\\CurrentVersion\\Run", "OneDrive", REG_SZ, "C:\\OneDrive.exe")
    new.value("Microsoft\\Windows\\CurrentVersion\\Run", "Updater", REG_SZ, "C:\\Users\\Public\\svchost.exe")
    primary = bytearray(old.build())
    struct.pack_into("<II", primary, 4, 8, 7)  # primary 8, secondary 7: dirty
    _checksum(primary)
    return bytes(primary), new.build()


def _log_header(source: bytes, sequence: int, file_type: int) -> bytearray:
    header = bytearray(source[:512])
    struct.pack_into("<II", header, 4, sequence, sequence)
    struct.pack_into("<I", header, 28, file_type)
    _checksum(header)
    return header


def _dirty_pages(old: bytes, new: bytes, size: int) -> list[tuple[int, bytes]]:
    old_bins, new_bins = old[4096:].ljust(len(new) - 4096, b"\x00"), new[4096:]
    return [(off, new_bins[off:off + size]) for off in range(0, len(new_bins), size)
            if new_bins[off:off + size] != old_bins[off:off + size]]


def _new_format_log(primary: bytes, target: bytes) -> bytes:
    pages = _dirty_pages(primary, target, 4096)
    hbins = len(target) - 4096
    return bytes(_log_header(primary, 7, 6)) + build_log_entry(7, hbins, pages[:1]) + \
        build_log_entry(8, hbins, pages[1:])


def _old_format_log(primary: bytes, target: bytes) -> bytes:
    pages = _dirty_pages(primary, target, 512)
    hbins = len(target) - 4096
    bitmap = bytearray(hbins // 4096)
    for offset, _ in pages:
        bitmap[offset // 512 // 8] |= 1 << (offset // 512 % 8)
    data = bytes(_log_header(primary, 7, 1)) + b"DIRT" + bytes(bitmap)
    data = data.ljust((len(data) + 511) // 512 * 512, b"\x00")
    return data + b"".join(page for _, page in pages)


def test_marvin32_and_entry_validation():
    assert marvin32(b"") != marvin32(b"\x00") and marvin32(b"abc") != marvin32(b"abd")
    assert marvin32(b"registry") == marvin32(b"registry")
    entry = build_log_entry(5, 4096, [(0, b"A" * 4096)])
    header = _log_header(b"regf" + b"\x00" * 508, 5, 6)
    log = parse_log(bytes(header) + entry)
    assert log.format == "new" and [(e.sequence, len(e.pages)) for e in log.entries] == [(5, 1)]
    tampered = bytearray(entry)
    tampered[100] ^= 1
    assert parse_log(bytes(header) + bytes(tampered)).entries == []  # Hash-1 no longer matches
    bad_header = bytearray(header)
    bad_header[60] ^= 1
    assert parse_log(bytes(bad_header) + entry) is None  # base block checksum


def test_new_format_recovery(tmp_path):
    primary, target = _hives()
    with RegistryHive(primary) as hive:
        assert hive.dirty and hive.open("Microsoft\\Windows\\CurrentVersion\\Run").get("Updater") is None
    log = parse_log(_new_format_log(primary, target), "SOFTWARE.LOG1")
    result = recover(primary, [log])
    assert result.entries == 2 and result.last_sequence == 8 and result.logs == ["SOFTWARE.LOG1"]
    assert bytes(result.data[4096:]) == target[4096:]

    folder = tmp_path / "config"
    folder.mkdir()
    (folder / "SOFTWARE").write_bytes(primary)
    (folder / "SOFTWARE.LOG1").write_bytes(_new_format_log(primary, target))
    (folder / "SOFTWARE.LOG2").write_bytes(b"")
    assert log_files(folder / "SOFTWARE") == [folder / "SOFTWARE.LOG1"]
    with RegistryHive(folder / "SOFTWARE") as hive:
        assert hive.was_dirty and not hive.dirty and hive.checksum_ok
        run = hive.open("Microsoft\\Windows\\CurrentVersion\\Run")
        assert run.get("Updater") == "C:\\Users\\Public\\svchost.exe"
    with RegistryHive(folder / "SOFTWARE", recover_logs=False) as hive:
        assert hive.dirty and hive.recovery is None


def test_old_format_recovery():
    primary, target = _hives()
    log = parse_log(_old_format_log(primary, target), "SOFTWARE.LOG")
    assert log.format == "old" and log.sequence == 7
    assert bytes(recover(primary, [log]).data[4096:]) == target[4096:]
    stale = parse_log(_old_format_log(primary, target).replace(b"\x07\x00\x00\x00\x07", b"\x05\x00\x00\x00\x05", 1))
    assert stale is None or recover(primary, [stale]) is None  # older than the hive: not applied


def test_registry_module_applies_logs(tmp_path):
    primary, target = _hives()
    evidence = tmp_path / "C" / "Windows" / "System32" / "config"
    evidence.mkdir(parents=True)
    (evidence / "SOFTWARE").write_bytes(primary)
    (evidence / "SOFTWARE.LOG1").write_bytes(_new_format_log(primary, target))
    sink = ResultSink()
    ctx = get_module("registry").run(tmp_path, tmp_path / "out", sink=sink)
    assert ctx.summary["recovered_hives"] == ["C/Windows/System32/config/SOFTWARE"]
    hive = next(d for k, d in sink.records if k == "hive")
    assert hive["dirty"] and hive["recovered_from"] == "SOFTWARE.LOG1" and hive["log_entries_applied"] == 2
    autoruns = [d for k, d in sink.records if k == "autorun"]
    assert any(a.get("name") == "Updater" for a in autoruns)
    assert all(f["code"] != "registry.dirty_hive" for f in sink.findings)

    (evidence / "SOFTWARE.LOG1").unlink()
    sink = ResultSink()
    get_module("registry").run(tmp_path, tmp_path / "out2", sink=sink)
    assert [f["code"] for f in sink.findings if f["code"] == "registry.dirty_hive"] == ["registry.dirty_hive"]


def test_real_layout_helpers(tmp_path):
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(b"regf")
    (tmp_path / "ntuser.dat.LOG2").write_bytes(b"x" * 600)
    (tmp_path / "NTUSER.DAT.LOG1").write_bytes(b"x" * 10)  # too small to be a log
    assert log_files(hive) == [tmp_path / "ntuser.dat.LOG2"]
    assert log_files(Path("/nonexistent/SYSTEM")) == []
