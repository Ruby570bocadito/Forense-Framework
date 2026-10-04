from __future__ import annotations

import gzip
import json
import os
from pathlib import Path

import pytest
import pytsk3

from forense.cli import EXIT_OK, main
from forense.core.case import Case
from forense.core.errors import ForenseError
from forense.image import filesystems, find_image, is_disk_image, open_image, shadow_copies
from forense.modules.base import ResultSink, get_module, mask_secret

DATA = Path(__file__).parent / "data"  # VHDX, VMDK, QCOW2 and VSS samples come from dfvfs (Apache-2.0)
EXTERNAL = Path(os.environ.get("FORENSE_TEST_DATA", "/nonexistent"))  # optional dfvfs test_data checkout


def unpack(tmp_path: Path, *names: str) -> Path:
    for name in names:
        (tmp_path / name).write_bytes(gzip.decompress((DATA / f"{name}.gz").read_bytes()))
    return tmp_path / names[0]


def root_names(fs) -> list[str]:
    return sorted(e.info.name.name.decode() for e in fs.open_dir("/")
                  if e.info.name.name not in (b".", b"..") and not e.info.name.name.startswith(b"$"))


def test_differencing_vhdx_uses_its_parent(tmp_path):
    child = unpack(tmp_path, "ntfs-differential.vhdx", "ntfs-parent.vhdx")
    assert is_disk_image(child) and find_image(tmp_path) == child
    img, info = open_image(child)
    assert info.format == "vhdx" and info.segments == ["ntfs-differential.vhdx", "ntfs-parent.vhdx"]
    assert info.headers == {"disk_type": "differencing"} and info.size == 4 * 1024 * 1024
    [(partition, fs)] = list(filesystems(img))
    assert partition.filesystem == "ntfs" and partition.offset == 65536
    (tmp_path / "ntfs-parent.vhdx").unlink()
    with pytest.raises(ForenseError, match="parent"):
        open_image(child)


def test_vmdk_and_qcow2(tmp_path):
    img, info = open_image(unpack(tmp_path, "ext2.vmdk"))
    [(partition, fs)] = list(filesystems(img))
    assert info.format == "vmdk" and partition.filesystem == "ext2" and "passwords.txt" in root_names(fs)
    img, info = open_image(unpack(tmp_path, "windows_volume.qcow2"))
    [(partition, fs)] = list(filesystems(img))
    assert info.format == "qcow2" and partition.filesystem == "ntfs"


def test_volume_shadow_copies(tmp_path):
    img, _ = open_image(unpack(tmp_path, "vss.raw"))
    [(partition, fs)] = list(filesystems(img))
    assert {"vss1", "vss2"} <= set(root_names(fs))
    copies = shadow_copies(partition)
    assert [(c.index, c.created) for c in copies] == [(1, "2021-05-01T17:40:03.223030Z"),
                                                     (2, "2021-05-01T17:41:28.224986Z")]
    first, second = (pytsk3.FS_Info(c.img) for c in copies)
    assert "vss1" not in root_names(first) and "vss1" in root_names(second) and "vss2" not in root_names(second)


def test_image_module_extracts_only_changed_files_from_shadow_copies(tmp_path):
    image = unpack(tmp_path, "vss.raw")
    sink = ResultSink()
    ctx = get_module("image").run(image, tmp_path / "out", {"vss": "yes", "patterns": "vss*,a_directory/**"},
                                  sink=sink)
    assert ctx.summary["shadow_copies"] == 2 and ctx.summary["volumes"][0]["shadow_copies"] == 2
    files = {(r["volume"], r["path"]) for k, r in sink.records if k == "extracted_file"}
    assert files == {("C", "/vss1"), ("C", "/vss2"), ("C", "/a_directory/a_file"), ("C", "/a_directory/another_file")}
    assert not (tmp_path / "out" / "extracted" / "C_vss1").exists()  # identical to the live volume: removed
    events = [e for e in sink.events if e["type"] == "shadow_copy_created"]
    assert [e["timestamp"] for e in events] == ["2021-05-01T17:40:03.223030Z", "2021-05-01T17:41:28.224986Z"]


def test_secret_options_are_never_stored(tmp_path):
    image = unpack(tmp_path, "vss.raw")
    with Case.create(tmp_path / "case", "Secrets", "Tester") as case:
        evidence = case.add_evidence(image)
        analysis = case.run_analysis("image", evidence.id, {"bitlocker_recovery": "111111-222222-333333",
                                                            "patterns": "vss1"})
        stored = analysis.options["bitlocker_recovery"]
        assert stored == mask_secret("111111-222222-333333") and "111111" not in stored
        dump = json.dumps([e.details for e in case.custody.entries()])
        assert "111111-222222" not in dump and stored in dump
        assert all(case.verify_results(a.id) for a in case.analyses())


def test_cli_image_options(tmp_path, capsys, monkeypatch):
    image = unpack(tmp_path, "vss.raw")
    case = str(tmp_path / "case")
    assert main(["new", case, "-n", "VSS", "-i", "Ana"]) == EXIT_OK
    assert main(["-c", case, "evidence", "add", str(image)]) == EXIT_OK
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "not-the-key")
    assert main(["-c", case, "image", "EV-001", "--vss", "-p", "vss*", "--bitlocker-password", "-"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Shadow copies: 2" in out and "Derived evidence EV-002 registered with 2 extracted file(s)." in out
    with Case.open(Path(case)) as opened:
        assert opened.analyses()[0].options["bitlocker_password"] == mask_secret("not-the-key")


@pytest.mark.skipif(not (EXTERNAL / "bdetogo.raw").exists(), reason="BitLocker sample not available")
def test_bitlocker_to_go(tmp_path):  # pragma: no cover - needs FORENSE_TEST_DATA=<dfvfs>/test_data
    image = EXTERNAL / "bdetogo.raw"
    sink = ResultSink()
    ctx = get_module("image").run(image, tmp_path / "locked", {}, sink=sink)
    assert [f["code"] for f in sink.findings] == ["image.bitlocker_locked"]
    sink = ResultSink()
    ctx = get_module("image").run(image, tmp_path / "open", {"bitlocker_password": "bde-TEST", "all_files": "yes"},
                                  sink=sink)
    assert ctx.summary["volumes"][0]["encryption"] == "bitlocker" and ctx.summary["files_extracted"] > 0
