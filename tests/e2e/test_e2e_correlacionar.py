"""E2E: ``sabueso correlacionar`` finds shared observables between cases.

Two cases that analyse the same EVTX must share at least the remote-logon
observables (IP, host, account) extracted from it; the JSON output is
machine-readable and the ``--type`` filter narrows the result.
"""

from __future__ import annotations

import json

from _cli import run

EVTX = "tests/data/Security_short_selected.evtx"


def _case_with_evtx(ws, name: str) -> str:
    case_dir = ws / name
    proc = run("new", str(case_dir), "-n", name, "-i", "e2e")
    assert proc.returncode == 0, proc.stderr
    proc = run("-c", str(case_dir), "evidencia", "agregar", EVTX, "-d", "shared security log")
    assert proc.returncode == 0, proc.stderr
    proc = run("-c", str(case_dir), "analizar", "evtx", "EV-001")
    assert proc.returncode == 0, proc.stderr
    return case_dir.name


def test_correlacionar_shares_observables(tmp_path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    slug_a = _case_with_evtx(ws, "caso-a")
    slug_b = _case_with_evtx(ws, "caso-b")

    proc = run("correlacionar", "-w", str(ws), "--json")
    assert proc.returncode == 0, proc.stderr
    shared = json.loads(proc.stdout)
    assert isinstance(shared, list) and len(shared) >= 1, proc.stdout
    for obs in shared:
        assert {"type", "value", "cases"} <= set(obs), obs
        case_ids = {entry["case"] for entry in obs["cases"]}
        assert {slug_a, slug_b} <= case_ids, obs

    # The --type filter narrows to one kind and stays valid JSON.
    proc = run("correlacionar", "-w", str(ws), "--json", "--type", "account")
    assert proc.returncode == 0, proc.stderr
    filtered = json.loads(proc.stdout)
    assert all(obs["type"] == "account" for obs in filtered), filtered
