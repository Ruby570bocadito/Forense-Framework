"""Regression tests for robustness fixes: crafted evidence, hostile names and unusual input."""

from __future__ import annotations

import base64
import json
import random
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from forense.cli import EXIT_ERROR, EXIT_OK, main
from forense.core.case import Case, CaseError
from forense.core.utils import range_end, stamped_path, ts_to_iso
from forense.demo import builders as b
from forense.image import Extractor, evidence_kind, safe_name
from forense.modules.base import AnalysisContext, ResultSink, clean, mask_secret
from forense.parsers.regf import REG_BINARY, RegistryError, RegistryHive
from forense.sigma.engine import _value_matcher
from forense.web import create_app

T = datetime(2024, 3, 1, 10, 0, tzinfo=timezone.utc)


# -- file names taken from evidence -------------------------------------------------------------
@pytest.mark.parametrize("name, expected", [
    ("..", "_"), (".", "_"), ("", "_"), ("a/b\\c", "a_b_c"), ("evil.exe. . ", "evil.exe"),
    ("CON", "_CON"), ("nul.txt", "_nul.txt"), ("COM1.log", "_COM1.log"), ("con-tent.txt", "con-tent.txt"),
    ("a:stream", "a_stream"), ("tab\there", "tab_here"), ("ok name.txt", "ok name.txt"),
])
def test_safe_name(name, expected):
    assert safe_name(name) == expected


def test_safe_name_shortens_long_names_keeping_the_extension():
    name = "x" * 300 + ".evtx"
    short = safe_name(name)
    assert len(short.encode()) <= 200 and short.endswith(".evtx") and short != safe_name("y" * 300 + ".evtx")


def test_extractor_targets_stay_inside_the_destination(tmp_path):
    errors = []
    extractor = Extractor(None, tmp_path / "out", on_error=lambda source, exc: errors.append(source))
    first = extractor._target(("..", "..", "Windows", "evil.dll"), "/x")
    assert first is not None and (tmp_path / "out") in first.parents and ".." not in first.parts
    # names that sanitise to the same file (or differ only in case) do not overwrite each other
    a = extractor._target(("Users", "a:b"), "/a")
    c = extractor._target(("Users", "a_b"), "/b")
    d = extractor._target(("users", "A_B"), "/c")
    assert len({a, c, d}) == 3 and errors == []


# -- case guards ----------------------------------------------------------------------------------
def test_evidence_that_contains_the_case_is_rejected(tmp_path):
    with Case.create(tmp_path / "work" / "case", "Nested", "Tester") as case:
        with pytest.raises(CaseError) as info:
            case.add_evidence(tmp_path / "work")
        assert info.value.code == "error.evidence_contains_case"
        assert case.evidence_list() == []


def test_analysis_with_derived_evidence_cannot_be_deleted(case, tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "a.txt").write_text("a", encoding="utf-8")
    evidence = case.add_evidence(source)
    analysis = case.run_analysis("inventory", evidence.id)
    output = case.root / analysis.output_dir / "extracted"
    output.mkdir(parents=True)
    (output / "b.txt").write_text("b", encoding="utf-8")
    derived = case.add_evidence(output, derived_from=evidence.id, analysis_id=analysis.id)
    with pytest.raises(CaseError) as info:
        case.delete_analysis(analysis.id)
    assert info.value.code == "error.analysis_has_derived" and derived.id in info.value.message()


def test_running_analysis_cannot_be_deleted(case, evidence_dir):
    evidence = case.add_evidence(evidence_dir)
    analysis = case.run_analysis("inventory", evidence.id)
    case.conn.execute("UPDATE analyses SET status = 'running' WHERE id = ?", (analysis.id,))
    with pytest.raises(CaseError) as info:
        case.delete_analysis(analysis.id)
    assert info.value.code == "error.analysis_running"


def test_evidence_ids_are_sequential_and_copies_are_staged(case, evidence_dir):
    first = case.add_evidence(evidence_dir, copy=True)
    second = case.add_evidence(evidence_dir / "a.txt", copy=True)
    assert (first.id, second.id) == ("EV-001", "EV-002")
    assert not list((case.root / "evidence").glob(".incoming-*"))
    assert case.verify_evidence(first.id).ok and case.verify_evidence(second.id).ok


def test_secret_fingerprints_are_salted_per_case(tmp_path):
    with Case.create(tmp_path / "a", "A", "Tester") as a, Case.create(tmp_path / "b", "B", "Tester") as c:
        salt_a, salt_b = a._secret_salt(), c._secret_salt()
        assert salt_a == a._secret_salt() and salt_a != salt_b
        assert mask_secret("key", salt_a) != mask_secret("key", salt_b)
        assert mask_secret("key", salt_a).startswith("*** (pbkdf2:") and mask_secret("") is None


# -- text that cannot be stored as UTF-8 ------------------------------------------------------------
def test_clean_escapes_undecodable_file_names(tmp_path):
    name = b"caf\xe9.txt".decode("utf-8", "surrogateescape")
    assert clean(name) == "caf\\xe9.txt"
    assert clean({"path": [name, 1]}) == {"path": ["caf\\xe9.txt", 1]}
    sink = ResultSink()
    ctx = AnalysisContext(tmp_path, tmp_path, {}, sink, module="inventory")
    ctx.record("file", {"name": name})
    ctx.event(T, "file_modified", name, path=name)
    ctx.flush()
    json.dumps([sink.records, sink.events], ensure_ascii=False).encode("utf-8")


# -- dates -------------------------------------------------------------------------------------------
def test_range_end_includes_the_whole_day():
    assert range_end("2024-03-01") == "2024-03-01T23:59:59.999999Z"
    assert range_end("2024-03-01T10:00:00") == "2024-03-01T10:00:00.000000Z"
    assert range_end(None) is None


def test_out_of_range_timestamps_are_none():
    assert ts_to_iso(1e20) is None and ts_to_iso(float("nan")) is None
    assert ts_to_iso(0) == "1970-01-01T00:00:00.000000Z"


def test_stamped_paths_do_not_collide(tmp_path):
    first = stamped_path(tmp_path, "findings", ".csv")
    first.write_text("x")
    second = stamped_path(tmp_path, "findings", ".csv")
    assert second != first and second.name.startswith("findings_") and second.suffix == ".csv"


def test_cli_timeline_to_date_is_inclusive_and_bad_dates_are_reported(tmp_path, evidence_dir, capsys):
    case = str(tmp_path / "case")
    assert main(["new", case, "-n", "Dates", "-i", "Ana"]) == EXIT_OK
    with Case.open(Path(case)) as opened:
        evidence = opened.add_evidence(evidence_dir)
        sink_analysis = opened.run_analysis("inventory", evidence.id)
        assert sink_analysis.status == "completed"
        opened.conn.execute("UPDATE events SET timestamp = '2024-03-01T18:30:00.000000Z'")
        opened.conn.commit()
    capsys.readouterr()
    assert main(["-c", case, "timeline", "--to", "2024-03-01"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "2024-03-01 18:30" in out
    assert main(["-c", case, "timeline", "--from", "yesterday-ish"]) == EXIT_ERROR
    assert "Invalid date" in capsys.readouterr().err


def test_cli_reports_a_damaged_case_database(tmp_path, capsys):
    case = tmp_path / "case"
    assert main(["new", str(case), "-n", "Broken", "-i", "Ana"]) == EXIT_OK
    (case / "forense.db").write_bytes(b"this is not a database" * 100)
    capsys.readouterr()
    assert main(["-c", str(case), "info"]) == EXIT_ERROR
    assert "damaged" in capsys.readouterr().err


# -- crafted registry hives ----------------------------------------------------------------------
def test_corrupted_hives_only_raise_registry_errors():
    h = b.HiveBuilder(default_time=T)
    for i in range(12):
        h.value(f"Software\\Vendor{i % 3}\\App{i}", "Name", b.REG_SZ, "x" * i)
        h.value(f"Software\\Vendor{i % 3}\\App{i}", "Big", REG_BINARY, bytes(range(256)) * (i * 10))
        h.value(f"Software\\Vendor{i % 3}\\App{i}", "List", b.REG_MULTI_SZ, ["a", "b" * i])
    data = h.build()
    rng = random.Random(978)
    for _ in range(400):
        buf = bytearray(data)
        for _ in range(rng.randint(1, 40)):
            buf[rng.randrange(4096, len(buf))] = rng.randrange(256)
        if rng.random() < 0.2:
            buf = buf[:rng.randrange(4096, len(buf))]
        try:
            hive = RegistryHive(bytes(buf), recover_logs=False)
            for key in hive.walk():
                for value in key.values():
                    try:
                        _ = value.data
                    except RegistryError:
                        pass
        except RegistryError:
            pass


# -- evidence classification -------------------------------------------------------------------------
def test_evidence_kind_is_strict(tmp_path):
    raw = tmp_path / "notes.raw"
    raw.write_bytes(b"plain text, not a disk" * 100)
    assert evidence_kind(raw) == "file"
    folder = tmp_path / "exports"
    folder.mkdir()
    (folder / "pslist.json").write_text('[{"PID": 4, "ImageFileName": "System"}]', encoding="utf-8")
    (folder / "netscan.json").write_text('[{"PID": 4, "Proto": "TCPv4"}]', encoding="utf-8")
    assert evidence_kind(folder) == "volatility"
    other = tmp_path / "reports"
    (other / "deep").mkdir(parents=True)
    (other / "deep" / "pslist.json").write_text('[{"PID": 4}]', encoding="utf-8")
    (other / "deep" / "netscan.json").write_text('[{"PID": 4}]', encoding="utf-8")
    (other / "malfind.json").write_text('{"not": "volatility"}', encoding="utf-8")
    assert evidence_kind(other) == "directory"


# -- Sigma wildcards ----------------------------------------------------------------------------
FLAGS = re.DOTALL | re.IGNORECASE


@pytest.mark.parametrize("pattern, mode, text, expected", [
    ("*\\\\cmd.exe", "endswith", "C:\\Windows\\System32\\CMD.EXE", True),
    ("cmd.exe", "endswith", "C:\\cmdXexe.bak", False),
    ("powershell*-enc*", "contains", "x powershell.exe -nop -enc AAA", True),
    ("powershell*-enc", "contains", "x -enc powershell.exe", False),
    ("C:\\\\Windows\\\\*", "startswith", "c:\\windows\\temp\\a", True),
    ("C:\\\\Windows\\\\*", "startswith", "d:\\c:\\windows\\temp", False),
    ("a?c", "exact", "ABC", True), ("a?c", "exact", "abcd", False),
    ("**", "exact", "anything", True), ("a*b", "exact", "aXXbc", False),
    ("ab*ba", "exact", "aba", False), ("ab*ba", "exact", "abba", True),
    ("lit\\*star", "contains", "a lit*star b", True), ("lit\\*star", "contains", "litXstar", False),
    ("", "exact", "", True), ("", "exact", "x", False),
])
def test_sigma_wildcards(pattern, mode, text, expected):
    assert _value_matcher(pattern, mode, FLAGS)(text) is expected


def test_sigma_wildcards_do_not_backtrack():
    matcher = _value_matcher("*a*a*a*a*a*b*", "contains", FLAGS)
    started = time.perf_counter()
    assert matcher("a" * 200_000) is False
    assert time.perf_counter() - started < 2


# -- web input -------------------------------------------------------------------------------------
@pytest.fixture
def web(tmp_path, evidence_dir):
    with Case.create(tmp_path / "ws" / "case1", "Web case", "Wendy") as case:
        case.run_analysis("inventory", case.add_evidence(evidence_dir).id)
    return tmp_path / "ws"


def test_non_ascii_password_does_not_crash(web):
    client = create_app(web, password="contraseña").test_client()
    wrong = base64.b64encode("any:señal".encode()).decode()
    right = base64.b64encode("any:contraseña".encode()).decode()
    assert client.get("/", headers={"Authorization": f"Basic {wrong}"}).status_code == 401
    assert client.get("/", headers={"Authorization": f"Basic {right}"}).status_code == 200


@pytest.mark.parametrize("url", ["/c/case1/timeline?from=99999-99-99&to=2024-13-45", "/c/case1/timeline?page=" + "9" * 40,
                                 "/c/case1/analyses/" + "9" * 30, "/c/case1/timeline?to=2024-03-01"])
def test_hostile_query_strings_are_not_server_errors(web, url):
    client = create_app(web).test_client()
    assert client.get(url).status_code in (200, 302, 404)


def test_unicode_digit_exports_are_404(web):
    client = create_app(web).test_client()
    page = client.get("/c/case1/analyses").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    assert client.post("/c/case1/export/\u0663", data={"csrf_token": token}).status_code == 404
    assert client.post("/c/case1/export/" + "1" * 40, data={"csrf_token": token}).status_code == 404
