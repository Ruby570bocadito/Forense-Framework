"""Recovery of deleted registry keys and values from free and orphaned cells."""

from __future__ import annotations

import random
import struct
from datetime import datetime, timezone

from forense.core.attack import techniques_for
from forense.demo import builders as b
from forense.i18n import t
from forense.modules.base import ResultSink, get_module
from forense.parsers.regf import BASE_BLOCK_SIZE, RegistryError, RegistryHive
from forense.parsers.regf_deleted import cells, recover_deleted

T = datetime(2026, 9, 14, 3, 0, tzinfo=timezone.utc)


def _hive() -> b.HiveBuilder:
    h = b.HiveBuilder(default_time=T)
    h.value("ControlSet001\\Services\\Spooler", "ImagePath", b.REG_EXPAND_SZ, "%SystemRoot%\\System32\\spoolsv.exe")
    h.key("ControlSet001\\Services\\PSEXESVC", T, deleted=True)
    h.value("ControlSet001\\Services\\PSEXESVC", "ImagePath", b.REG_EXPAND_SZ, "%SystemRoot%\\PSEXESVC.exe")
    h.value("ControlSet001\\Services\\PSEXESVC\\Parameters", "Big", b.REG_BINARY, bytes(range(256)) * 80)
    h.deleted_value("ControlSet001\\Services\\Spooler", "Evil", b.REG_SZ, "cmd.exe /c C:\\Users\\Public\\x.bat")
    return h


def test_deleted_keys_values_and_paths():
    with RegistryHive(_hive().build()) as hive:
        assert "ControlSet001\\Services\\PSEXESVC" not in {k.path for k in hive.walk()}
        keys, values = recover_deleted(hive)
    by_path = {k.path: k for k in keys}
    assert set(by_path) == {"ControlSet001\\Services\\PSEXESVC", "ControlSet001\\Services\\PSEXESVC\\Parameters"}
    service = by_path["ControlSet001\\Services\\PSEXESVC"]
    assert not service.partial and not service.still_present and service.last_written == T
    assert [(v.name, v.data) for v in service.values] == [("ImagePath", "%SystemRoot%\\PSEXESVC.exe")]
    big = by_path["ControlSet001\\Services\\PSEXESVC\\Parameters"].values[0]
    assert big.data == bytes(range(256)) * 80  # big data (db) records are rebuilt too
    loose = {v.name: v for v in values}
    assert loose["Evil"].data == "cmd.exe /c C:\\Users\\Public\\x.bat" and loose["Evil"].key_path == ""
    assert loose["ImagePath"].key_path == "ControlSet001\\Services\\PSEXESVC"


def test_broken_parent_chain_gives_a_partial_path():
    data = bytearray(_hive().build())
    with RegistryHive(bytes(data)) as hive:
        keys, _ = recover_deleted(hive)
    service = next(k for k in keys if k.name == "PSEXESVC")
    struct.pack_into("<I", data, BASE_BLOCK_SIZE + service.offset + 4 + 16, 0x7FFFFFF0)  # parent offset -> nowhere
    with RegistryHive(bytes(data)) as hive:
        keys, _ = recover_deleted(hive)
    paths = {k.path: k.partial for k in keys}
    assert paths == {"PSEXESVC": True, "PSEXESVC\\Parameters": True}


def test_orphaned_allocated_records_are_recovered():
    """A key still allocated but no longer linked from its parent ("healed" hive)."""
    data = bytearray(_hive().build())
    with RegistryHive(bytes(data)) as hive:
        for start, end, free in cells(hive):
            if free and data[start + 4:start + 6] in (b"nk", b"vk"):
                struct.pack_into("<i", data, start, -(end - start))  # allocated again, still unlinked
    with RegistryHive(bytes(data)) as hive:
        keys, values = recover_deleted(hive)
    assert {k.name for k in keys} == {"PSEXESVC", "Parameters"} and "Evil" in {v.name for v in values}


def test_live_hive_has_nothing_deleted():
    h = b.HiveBuilder(default_time=T)
    for i in range(50):
        h.value(f"Software\\Vendor\\App{i}", "Path", b.REG_SZ, f"C:\\Program Files\\App{i}\\app.exe")
    with RegistryHive(h.build()) as hive:
        assert recover_deleted(hive) == ([], [])


def test_corrupted_hives_never_break_recovery():
    data = _hive().build()
    rng = random.Random(4242)
    for _ in range(300):
        buf = bytearray(data)
        for _ in range(rng.randint(1, 30)):
            buf[rng.randrange(BASE_BLOCK_SIZE, len(buf))] = rng.randrange(256)
        try:
            with RegistryHive(bytes(buf), recover_logs=False) as hive:
                recover_deleted(hive)
        except RegistryError:
            pass


def test_registry_module_reports_deleted_persistence(demo, tmp_path):
    sink = ResultSink()
    module = get_module("registry")
    module.run(demo["triage"], tmp_path / "out", {}, sink=sink)
    deleted = [d for a, d in sink.records if a == "registry_deleted_key"]
    assert any(d["path"].endswith("Services\\PSEXESVC") and not d["partial_path"] for d in deleted)
    codes = {f["code"]: f for f in sink.findings}
    assert codes["registry.deleted_service"]["severity"] == "high"
    value = codes["registry.deleted_suspicious_value"]
    assert value["params"]["name"] == "OneDriveSync" and "sync.ps1" in value["params"]["data"]
    assert {"T1070.009", "T1543.003"} <= set(techniques_for(codes["registry.deleted_service"]))
    assert any(e["type"] == "registry_key_deleted" for e in sink.events)
    # findings render in both languages even with a parameter named "key"
    assert "OneDriveSync" in t("finding.registry.deleted_suspicious_value.title", "es", **value["params"])
    sink_off = ResultSink()
    module.run(demo["triage"], tmp_path / "out2", {"deleted": "no"}, sink=sink_off)
    assert not [a for a, _ in sink_off.records if a.startswith("registry_deleted")]
