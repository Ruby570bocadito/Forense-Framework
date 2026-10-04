from __future__ import annotations

import csv
import json
import sqlite3
import struct
from pathlib import Path

import pytest

from forense.cli import EXIT_OK, main
from forense.collector import collect
from forense.core.case import Case, CaseError
from forense.core.errors import ForenseError
from forense.image import Extractor, ImageInfo, filesystems, is_disk_image, open_image, verify_media
from forense.modules.base import ResultSink, get_module

DATA = Path(__file__).parent / "data"
E01 = DATA / "ntfs.E01"
MEDIA_MD5 = "e3ecd5a814f2395fe54cc665cdf68af5"


@pytest.fixture(scope="module")
def media(tmp_path_factory) -> bytes:
    """The raw NTFS volume stored in the E01 (24 MiB)."""
    img, info = open_image(E01)
    return img.read(0, info.size)


def _mbr_disk(path, volume: bytes, start_sector: int = 2048) -> None:
    entry = struct.pack("<B3sB3sII", 0, b"\x00" * 3, 0x07, b"\x00" * 3, start_sector, len(volume) // 512)
    mbr = bytearray(512)
    mbr[446:462] = entry
    mbr[510:512] = b"\x55\xaa"
    with open(path, "wb") as fh:
        fh.write(mbr + b"\x00" * (start_sector * 512 - 512) + volume)


def test_open_e01_reads_acquisition_metadata_and_verifies():
    assert is_disk_image(E01)
    img, info = open_image(E01)
    assert info.format == "ewf" and info.size == 24 * 1024 * 1024 and info.segments == ["ntfs.E01"]
    assert info.stored_hashes["md5"] == MEDIA_MD5
    assert info.headers["case_number"] == "CASE-TEST"
    result = verify_media(img, info)
    assert result["match"] is True and result["computed"]["md5"] == MEDIA_MD5

    tampered = ImageInfo(info.path, info.format, info.size, stored_hashes={"md5": "0" * 32})
    assert verify_media(img, tampered)["match"] is False


def test_extractor_copies_triage_files_with_hashes(tmp_path):
    img, _ = open_image(E01)
    [(partition, fs)] = list(filesystems(img))
    assert partition.filesystem == "ntfs"
    files = {f.source: f for f in Extractor(fs, tmp_path, ("Windows/System32/config/*", "Users/*/NTUSER.DAT")).run()}
    assert set(files) == {"/Windows/System32/config/SAM", "/Windows/System32/config/SOFTWARE",
                          "/Windows/System32/config/SYSTEM", "/Users/maria/NTUSER.DAT"}
    system = files["/Windows/System32/config/SYSTEM"]
    assert system.dest == tmp_path / "Windows" / "System32" / "config" / "SYSTEM"
    assert system.dest.read_bytes()[:4] == b"regf" and system.size == system.dest.stat().st_size
    assert system.mtime and system.inode > 0


def test_partitioned_and_split_raw_images(tmp_path, media):
    disk = tmp_path / "disk.dd"
    _mbr_disk(disk, media)
    img, info = open_image(disk)
    [(partition, fs)] = list(filesystems(img))
    assert info.format == "raw" and partition.offset == 2048 * 512 and partition.filesystem == "ntfs"

    data = disk.read_bytes()
    half = len(data) // 2
    (tmp_path / "split.001").write_bytes(data[:half])
    (tmp_path / "split.002").write_bytes(data[half:])
    img, info = open_image(tmp_path / "split.001")
    assert info.segments == ["split.001", "split.002"] and info.size == len(data)
    [(partition, fs)] = list(filesystems(img))
    files = Extractor(fs, tmp_path / "out", ("Windows/Prefetch/*.pf",)).run()
    assert len(files) == 4


def test_image_module_records_and_options(tmp_path):
    sink = ResultSink()
    ctx = get_module("image").run(E01, tmp_path / "out", {"verify": "yes", "patterns": "Windows/Prefetch/*.pf"},
                                  sink=sink)
    assert ctx.summary["verification"]["match"] is True and ctx.summary["files_extracted"] == 4
    kinds = [kind for kind, _ in sink.records]
    assert kinds.count("image_info") == 1 and kinds.count("image_partition") == 1 and kinds.count("extracted_file") == 4
    assert (tmp_path / "out" / "extracted" / "C" / "Windows" / "Prefetch").is_dir()
    assert ctx.artifacts == ["extracted"]


def test_triage_of_an_image_extracts_derived_evidence(case):
    image = case.add_evidence(E01, "laptop", copy=True)
    results = {module: analysis for module, analysis, _ in case.triage(image.id)}
    assert results["image"].summary["files_extracted"] == 20
    assert {"registry", "prefetch", "evtx", "browsers", "lnk", "mft"} <= {m for m, a in results.items() if a}

    derived = case.evidence_list()[-1]
    assert derived.derived_from == image.id and derived.kind == "directory" and derived.file_count == 20
    assert results["registry"].evidence_id == derived.id
    codes = {f["code"] for f in case.findings()}
    assert {"registry.ifeo_debugger", "prefetch.attack_tool"} <= codes
    assert "evidence_derived" in [e.action for e in case.custody.entries()]
    assert case.custody.verify() == []
    assert case.verify_evidence(derived.id).ok
    assert all(case.verify_results(a.id) for a in case.analyses())


def test_evidence_inside_the_case_is_still_rejected(case):
    (case.root / "analyses" / "x").mkdir(parents=True)
    with pytest.raises(CaseError):
        case.add_evidence(case.root / "analyses" / "x")


def test_old_cases_are_migrated(tmp_path):
    if sqlite3.sqlite_version_info < (3, 35):
        pytest.skip("DROP COLUMN needs SQLite 3.35")
    with Case.create(tmp_path / "old", "Old", "Tester") as case:
        case.conn.execute("ALTER TABLE evidence DROP COLUMN derived_from")
    with Case.open(tmp_path / "old") as case:
        columns = [r[1] for r in case.conn.execute("PRAGMA table_info(evidence)")]
        assert "derived_from" in columns


def test_collector_from_an_image(tmp_path):
    dest = tmp_path / "collection"
    result = collect(dest, str(E01))
    assert result["files"] == 20 and result["errors"] == [] and result["source"] == str(E01)
    assert (dest / "C" / "Windows" / "System32" / "config" / "SYSTEM").exists()
    with open(dest / "manifest.csv", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert {r["path"] for r in rows} >= {"C/Windows/System32/config/SAM", "C/$MFT"}
    description = json.loads((dest / "collection.json").read_text(encoding="utf-8"))
    assert description["manifest_sha256"] == result["manifest_sha256"]
    with pytest.raises(ForenseError):
        collect(dest, str(E01))


def test_cli_image_and_collect(tmp_path, capsys):
    case = str(tmp_path / "case")
    assert main(["new", case, "-n", "Images", "-i", "Ana"]) == EXIT_OK
    assert main(["-c", case, "evidence", "add", str(E01)]) == EXIT_OK
    assert main(["-c", case, "imagen", "EV-001", "--verificar", "-p", "Windows/Prefetch/*", "--triaje"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Derived evidence EV-002 registered with 4 extracted file(s)." in out
    assert "prefetch" in out and "MIMIKATZ.EXE" in out
    assert main(["collect", str(tmp_path / "col"), "--source", str(E01), "--add-to-case", "-c", case]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Collection finished: 20 file(s)" in out and "EV-003" in out
