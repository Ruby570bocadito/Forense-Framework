from __future__ import annotations

import json
import os
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from forense.core.case import Case
from forense.core.custody import GENESIS
from forense.core.errors import CaseError, ModuleError
from forense.core.hashing import hash_bytes, hash_file, hash_tree
from forense.core.heuristics import autostart_suspicion, is_suspicious_location, suspicious_command_rules
from forense.core.signatures import check_extension
from forense.core.utils import filetime_to_dt, find_files, normalize_ts, parse_datetime, webkit_to_dt
from forense.demo.builders import build_png, build_zip, to_filetime


# -- utilities ---------------------------------------------------------------------
def test_hashes_of_known_input(tmp_path):
    path = tmp_path / "abc"
    path.write_bytes(b"abc")
    assert hash_file(path) == hash_bytes(b"abc") == {
        "md5": "900150983cd24fb0d6963f7d28e17f72",
        "sha1": "a9993e364706816aba3e25717850c26c9cd0d89d",
        "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    }


def test_tree_hash_changes_with_content_and_names(evidence_dir):
    first = hash_tree(evidence_dir)
    assert first.file_count == 2 and first.total_size == 305
    (evidence_dir / "a.txt").write_text("alpha!", encoding="utf-8")
    assert hash_tree(evidence_dir).hashes != first.hashes
    (evidence_dir / "a.txt").write_text("alpha", encoding="utf-8")
    assert hash_tree(evidence_dir).hashes == first.hashes
    (evidence_dir / "a.txt").rename(evidence_dir / "renamed.txt")
    assert hash_tree(evidence_dir).hashes != first.hashes


def test_time_conversions():
    when = datetime(2026, 9, 14, 2, 35, 0, 123456, tzinfo=timezone.utc)
    assert filetime_to_dt(to_filetime(when)) == when
    assert filetime_to_dt(0) is None
    assert webkit_to_dt(to_filetime(when) // 10) == when
    assert normalize_ts("2016-06-29T15:24:34.3460005Z") == "2016-06-29T15:24:34.346000Z"
    assert normalize_ts("2026-09-14") == "2026-09-14T00:00:00.000000Z"
    assert normalize_ts("2026-09-14 04:00:00+02:00") == "2026-09-14T02:00:00.000000Z"
    assert normalize_ts("2026-09-14T04:00:00.5+02:00") == "2026-09-14T02:00:00.500000Z"
    assert normalize_ts("2026-09-14T04:00:00.1234567-01:30") == "2026-09-14T05:30:00.123456Z"
    assert parse_datetime("2026-01-02T03:04:05Z").tzinfo is not None


def test_signatures_detect_disguised_files(tmp_path):
    jpg = tmp_path / "holiday.jpg"
    jpg.write_bytes(build_zip({"x.txt": b"x"}))
    signature, reason = check_extension(jpg, jpg.read_bytes()[:64])
    assert signature.name == "ZIP" and reason == "content_mismatch"
    png = tmp_path / "logo.png"
    png.write_bytes(build_png())
    signature, reason = check_extension(png, png.read_bytes()[:64])
    assert signature.name == "PNG" and reason is None
    fake = tmp_path / "report.pdf"
    fake.write_text("not a pdf")
    assert check_extension(fake, b"not a pdf")[1] == "missing_signature"
    system = tmp_path / "SYSTEM"
    assert check_extension(system, b"regf" + b"\x00" * 60)[1] is None


def test_command_heuristics():
    assert "powershell_encoded" in suspicious_command_rules(
        "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA")
    assert "shadow_copy_deletion" in suspicious_command_rules("vssadmin.exe Delete Shadows /All /Quiet")
    assert suspicious_command_rules("C:\\Program Files\\App\\app.exe /background") == []
    assert is_suspicious_location(r"C:\Users\bob\AppData\Local\Temp\x.exe")
    assert not is_suspicious_location(r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe")
    assert "script_interpreter" in autostart_suspicion("%COMSPEC% /c start evil.bat")


# -- case and evidence ------------------------------------------------------------------
def test_case_lifecycle(tmp_path):
    with Case.create(tmp_path / "c", "Name", "Investigator") as case:
        info = case.info
        assert info["id"].startswith("CASE-") and info["investigator"] == "Investigator"
    with pytest.raises(CaseError):
        Case.create(tmp_path / "c", "Again", "x")
    with pytest.raises(CaseError):
        Case.open(tmp_path / "missing")
    with Case.open(tmp_path / "c") as case:
        assert [e.action for e in case.custody.entries()] == ["case_created"]


def test_add_and_verify_evidence(case, evidence_dir):
    evidence = case.add_evidence(evidence_dir, "folder", actor="Alice")
    assert evidence.id == "EV-001" and evidence.kind == "directory" and evidence.file_count == 2
    assert case.verify_evidence("ev-001").ok
    (evidence_dir / "a.txt").write_text("tampered", encoding="utf-8")
    result = case.verify_evidence("EV-001")
    assert not result.ok and result.error is None
    actions = [(e.action, e.actor) for e in case.custody.entries()]
    assert ("evidence_added", "Alice") in actions
    assert case.last_verifications()["EV-001"]["result"] == "mismatch"


def test_copied_evidence_is_read_only_and_verified(case, evidence_dir):
    evidence = case.add_evidence(evidence_dir / "a.txt", copy=True)
    assert evidence.copied and evidence.path != evidence.source
    assert Path(evidence.path) == Path("evidence") / evidence.id / "a.txt"  # stored relative to the case
    assert case.root in case.disk_path(evidence.path).parents
    if os.name != "nt":
        assert not os.access(case.disk_path(evidence.path), os.W_OK) or os.geteuid() == 0
    assert case.verify_evidence(evidence.id).ok


def test_external_evidence_keeps_its_absolute_path(case, evidence_dir):
    evidence = case.add_evidence(evidence_dir / "a.txt")  # no copy: the file lives outside the case
    assert Path(evidence.path).is_absolute() and Path(evidence.path) == evidence_dir / "a.txt"
    assert case.verify_evidence(evidence.id).ok


def test_copied_case_verifies_itself_not_the_original(tmp_path, evidence_dir):
    """A copied case verifies the files registered in ITS folder: tampering the copy fails (H-007)."""
    with Case.create(tmp_path / "c1", "C1", "Tester") as case:
        case.add_evidence(evidence_dir / "a.txt", copy=True)
    shutil.copytree(tmp_path / "c1", tmp_path / "c1-copy")
    tampered = tmp_path / "c1-copy" / "evidence" / "EV-001" / "a.txt"
    os.chmod(tampered, 0o644)
    tampered.write_text("tampered", encoding="utf-8")
    with Case.open(tmp_path / "c1-copy") as copy:
        result = copy.verify_evidence("EV-001")
        assert not result.ok and result.error is None  # the copy's own file was checked
    with Case.open(tmp_path / "c1") as original:
        assert original.verify_evidence("EV-001").ok  # the original is untouched


def test_moved_case_still_verifies(tmp_path, evidence_dir):
    with Case.create(tmp_path / "c1", "C1", "Tester") as case:
        case.add_evidence(evidence_dir / "a.txt", copy=True)
    (tmp_path / "c1").rename(tmp_path / "c1-moved")
    with Case.open(tmp_path / "c1-moved") as case:
        assert case.verify_evidence("EV-001").ok


def test_legacy_absolute_paths_are_re_based(tmp_path, evidence_dir):
    """Cases registered before relative storage verify in place, and re-base once moved (H-007)."""
    with Case.create(tmp_path / "c1", "C1", "Tester") as case:
        case.add_evidence(evidence_dir / "a.txt", copy=True)
        legacy = str(case.root / "evidence" / "EV-001" / "a.txt")  # the absolute path old cases stored
        db = sqlite3.connect(case.root / "forense.db")
        db.execute("UPDATE evidence SET path = ? WHERE id = 'EV-001'", (legacy,))
        db.commit()
        db.close()
    shutil.copytree(tmp_path / "c1", tmp_path / "c1-copy")
    with Case.open(tmp_path / "c1-copy") as copy:
        assert copy.verify_evidence("EV-001").ok  # re-based to the copy's own file
        tampered = copy.root / "evidence" / "EV-001" / "a.txt"
        os.chmod(tampered, 0o644)
        tampered.write_text("tampered", encoding="utf-8")
        assert not copy.verify_evidence("EV-001").ok
        entry = [e for e in copy.custody.entries() if e.action == "evidence_verified"][-1]
        assert entry.details.get("path") == str(tampered)  # the custody chain notes the re-based location
    with Case.open(tmp_path / "c1") as original:
        assert original.verify_evidence("EV-001").ok  # the original location still verifies in place


def test_evidence_errors(case, tmp_path):
    with pytest.raises(CaseError):
        case.add_evidence(tmp_path / "nope")
    with pytest.raises(CaseError):
        case.add_evidence(case.root / "reports")
    with pytest.raises(CaseError):
        case.get_evidence("EV-999")


# -- custody -------------------------------------------------------------------------------
def test_custody_chain_detects_tampering(case):
    case.custody.append("export_created", "Bob", {"file": "x.csv"})
    entries = case.custody.entries()
    assert entries[0].prev_hash == GENESIS and entries[1].prev_hash == entries[0].hash
    assert case.custody.verify() == []

    db = sqlite3.connect(case.root / "forense.db")
    db.execute("UPDATE custody SET actor = 'Mallory' WHERE seq = 2")
    db.commit()
    db.close()
    assert [p.code for p in case.custody.verify()] == ["custody.problem.altered"]


def test_custody_detects_deleted_entry(case):
    for i in range(3):
        case.custody.append("export_created", "Bob", {"n": i})
    db = sqlite3.connect(case.root / "forense.db")
    db.execute("DELETE FROM custody WHERE seq = 2")
    db.commit()
    db.close()
    codes = {p.code for p in case.custody.verify()}
    assert {"custody.problem.sequence_gap", "custody.problem.broken_link"} <= codes


# -- analyses ------------------------------------------------------------------------------
def test_analysis_results_hash_and_tampering(case, evidence_dir):
    evidence = case.add_evidence(evidence_dir)
    analysis = case.run_analysis("inventory", evidence.id, {"hashes": "md5,sha256"})
    assert analysis.status == "completed" and analysis.record_count == 2
    assert case.verify_results(analysis.id)
    db = sqlite3.connect(case.root / "forense.db")
    db.execute("UPDATE records SET data = replace(data, 'a.txt', 'z.txt') WHERE analysis_id = ?", (analysis.id,))
    db.commit()
    db.close()
    assert not case.verify_results(analysis.id)


def test_analysis_option_validation(case, evidence_dir):
    evidence = case.add_evidence(evidence_dir)
    with pytest.raises(ModuleError):
        case.run_analysis("inventory", evidence.id, {"bogus": "1"})
    with pytest.raises(ModuleError):
        case.run_analysis("hashset", evidence.id)  # hash_list is required
    with pytest.raises(ModuleError):
        case.run_analysis("carving", evidence.id)  # needs a file
    with pytest.raises(ModuleError):
        case.run_analysis("does-not-exist", evidence.id)


def test_failed_analysis_is_recorded(case, evidence_dir, monkeypatch):
    from forense.modules.generic.inventory import InventoryModule

    evidence = case.add_evidence(evidence_dir)

    def boom(self, ctx):
        raise RuntimeError("boom")

    monkeypatch.setattr(InventoryModule, "analyze", boom)
    with pytest.raises(RuntimeError):
        case.run_analysis("inventory", evidence.id)
    analysis = case.analyses()[-1]
    assert analysis.status == "failed" and "boom" in analysis.errors[0]["error"]
    assert case.custody.entries()[-1].action == "analysis_failed"


def test_delete_analysis_is_logged(case, evidence_dir):
    evidence = case.add_evidence(evidence_dir)
    analysis = case.run_analysis("inventory", evidence.id)
    case.delete_analysis(analysis.id, "Carol")
    assert case.analyses() == []
    last = case.custody.entries()[-1]
    assert last.action == "analysis_deleted" and last.actor == "Carol"
    assert last.details["results_sha256"] == analysis.results_sha256


def test_triage_runs_applicable_modules(case, demo):
    evidence = case.add_evidence(demo["triage"])
    results = {module: (analysis, error) for module, analysis, error in case.triage(evidence.id)}
    assert results["evtx"] == (None, "triage.no_artifacts")
    for module in ("registry", "lnk", "recyclebin", "browsers", "mft", "notifications", "inventory"):
        assert results[module][0] is not None and results[module][0].status == "completed", module
    stats = case.stats()
    assert stats["findings_by_severity"].get("critical") == 1
    assert stats["events"] > 50
    page = case.events(start="2026-09-14T02:00:00", end="2026-09-14T03:00:00", search="svchost")
    assert page.total >= 3 and all("svchost" in (e["details"] + e["path"]).lower() for e in page.rows)


def test_find_files_applies_the_predicate_to_loose_files(tmp_path):
    hit = tmp_path / "ConsoleHost_history.txt"
    noise = tmp_path / "SYSTEM-basura"
    hit.write_text("whoami", encoding="utf-8")
    noise.write_bytes(b"\x00\x01")
    predicate = lambda p: p.name.lower().endswith("_history.txt")  # noqa: E731 - test-local identity
    assert find_files(noise, predicate) == []
    assert find_files(hit, predicate) == [hit]
    assert find_files(tmp_path, predicate) == [hit]


def test_triage_of_random_bytes_fabricates_nothing(case, tmp_path):
    """Random bytes carrying a bare 3-letter tool name must not yield a HIGH finding (H-004)."""
    blob = os.urandom(200_000)
    cut = len(blob) // 2
    (tmp_path / "SYSTEM-basura").write_bytes(blob[:cut] + b"\x00 cme \xff" + blob[cut:])
    evidence = case.add_evidence(tmp_path / "SYSTEM-basura")
    case.triage(evidence.id)
    assert case.findings() == []


def test_psreadline_short_tool_names_need_the_exe_suffix(case, tmp_path):
    folder = tmp_path / "psreadline"
    folder.mkdir()
    history = folder / "ConsoleHost_history.txt"
    history.write_text("cme 10.0.0.5\ncme.exe 10.0.0.5\nmimikatz 10.0.0.5\n", encoding="utf-8")
    evidence = case.add_evidence(history)
    case.triage(evidence.id)
    rules = sorted(f["params"]["rules"] for f in case.findings() if f["code"] == "psreadline.suspicious_command")
    # one finding per line: the bare "cme" is not a signal, "cme.exe" is, and mimikatz keeps its heuristic
    assert rules == ["credential_dumping, tool:mimikatz", "tool:cme"]


def test_exports_are_logged(case, evidence_dir, tmp_path):
    from forense.core import exports

    evidence = case.add_evidence(evidence_dir)
    analysis = case.run_analysis("inventory", evidence.id)
    csv_path = exports.export_analysis(case, analysis.id, tmp_path / "a.csv")
    assert csv_path.read_text(encoding="utf-8-sig").splitlines()[0].startswith("Artifact,Path")
    json_path = exports.export_timeline(case, tmp_path / "t.json", "json")
    assert len(json.loads(json_path.read_text(encoding="utf-8"))) == analysis.event_count
    exports.export_custody(case, tmp_path / "c.json")
    assert [e.action for e in case.custody.entries()][-3:] == ["export_created"] * 3


def test_csv_export_neutralises_spreadsheet_formulas(tmp_path):
    import csv

    from forense.core.utils import write_csv

    path = tmp_path / "x.csv"
    write_csv(path, [{"title": '=HYPERLINK("http://x")', "number": "-5", "cmd": "-enc AAAA", "plain": "ok"}])
    with open(path, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.reader(fh))
    assert rows[1] == ["'=HYPERLINK(\"http://x\")", "-5", "'-enc AAAA", "ok"]


def test_user_from_path_uses_the_innermost_profile():
    from pathlib import PureWindowsPath

    from forense.core.utils import user_from_path

    path = PureWindowsPath("C:/Users/analyst/cases/ev/C/Users/maria/AppData/Roaming/x.txt")
    assert user_from_path(path) == "maria"
    assert user_from_path(PureWindowsPath("C:/Users/bob/Documents/Users/notes.txt")) == "bob"
    assert user_from_path(PureWindowsPath("C:/Documents and Settings/ana/NTUSER.DAT")) == "ana"
    assert user_from_path(PureWindowsPath("C:/Windows/System32/config/SYSTEM")) == ""
