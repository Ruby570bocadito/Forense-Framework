"""Cross-case correlation: index of observables per case, cache and shared items."""

from __future__ import annotations

import json
import shutil

import pytest

from forense.cli import EXIT_OK, main
from forense.core import correlation
from forense.core.case import Case
from forense.core.correlation import CACHE_DIR, correlate, index_case, workspace_indexes
from forense.web import create_app


@pytest.fixture(scope="module")
def workspace(tmp_path_factory):
    root = tmp_path_factory.mktemp("corr")
    assert main(["demo", str(root / "lab"), "-a", "Tester"]) == EXIT_OK
    ws = root / "ws"
    ws.mkdir()
    shutil.copytree(root / "lab" / "case_demo", ws / "case_a")
    shutil.copytree(root / "lab" / "case_demo", ws / "case_b")
    with Case.create(ws / "case_c", "Unrelated", "Tester"):
        pass
    (ws / "broken").mkdir()
    (ws / "broken" / "forense.db").write_bytes(b"not a database" * 100)
    return ws


def test_index_of_a_case(workspace):
    index = index_case(workspace / "case_a", workspace, cache=False)
    found = {(k, v): o for (k, v), o in index.observations.items()}
    assert ("usb", "60A44C3FAE2BE2B0E9160123") in found
    assert found[("ip", "198.51.100.23")].ioc and "memory_connection" in found[("ip", "198.51.100.23")].sources
    assert ("host", "ws-contab01") in found and ("account", "contoso\\administrador") in found
    assert ("ip", "192.0.2.10") in found  # UNC path typed in Explorer
    assert not any(k == "ip" and v.startswith("127.") for k, v in found)


def test_shared_observables_between_cases(workspace):
    indexes = workspace_indexes(workspace)
    assert {i.slug for i in indexes} == {"case_a", "case_b", "case_c"}  # the broken case is skipped
    shared = correlate(indexes)
    keys = {(s.kind, s.value) for s in shared}
    assert {("usb", "60A44C3FAE2BE2B0E9160123"), ("ip", "198.51.100.23"), ("host", "ws-contab01")} <= keys
    assert all(len(s.cases) == 2 for s in shared)
    assert shared[0].ioc  # indicators of compromise first
    assert correlate(indexes, kinds=["usb"]) and all(s.kind == "usb" for s in correlate(indexes, kinds=["usb"]))
    assert correlate(indexes, min_cases=3) == []
    assert correlate(indexes, focus="case_c") == []


def test_index_cache_follows_the_chain_of_custody(workspace, monkeypatch):
    workspace_indexes(workspace)
    cache = workspace / CACHE_DIR / "case_a.json"
    assert cache.is_file()

    def fail(case):
        raise AssertionError("the cached index should be used")

    monkeypatch.setattr(correlation, "build_index", fail)
    assert index_case(workspace / "case_a", workspace).observations
    assert index_case(workspace / "case_b", workspace, build=False) is not None
    with Case.open(workspace / "case_a") as case:
        case.review_finding(case.findings()[0]["id"], "confirmed", "seen elsewhere", "Tester")
    with pytest.raises(AssertionError):
        index_case(workspace / "case_a", workspace)  # custody changed: rebuilt
    assert index_case(workspace / "case_a", workspace, build=False) is None


def test_cli_correlate(workspace, capsys):
    capsys.readouterr()
    assert main(["correlacionar", "-w", str(workspace), "--json", "--tipo", "usb"]) == EXIT_OK
    rows = json.loads(capsys.readouterr().out)
    assert rows and rows[0]["type"] == "usb" and {c["case"] for c in rows[0]["cases"]} == {"case_a", "case_b"}
    assert main(["-c", str(workspace / "case_b"), "correlate", "-L", "es"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "casos indexados" in out and "198.51.100.23" in out and "Dispositivo USB" in out


def test_web_correlation(workspace):
    client = create_app(workspace).test_client()
    page = client.get("/correlation?lang=en").get_data(as_text=True)
    assert "60A44C3FAE2BE2B0E9160123" in page and "/c/case_a/" in page and "/c/case_b/" in page
    assert "USB device" in client.get("/correlation?type=usb").get_data(as_text=True)
    assert 'href="/correlation"' in client.get("/").get_data(as_text=True)
    dashboard = client.get("/c/case_a/").get_data(as_text=True)
    assert "Seen in other cases" in dashboard and "198.51.100.23" in dashboard
    assert "Seen in other cases" not in client.get("/c/case_c/").get_data(as_text=True)
