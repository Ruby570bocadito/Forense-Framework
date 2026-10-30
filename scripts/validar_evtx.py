"""Validate the ``evtx`` module against public attack samples with a known answer.

Each sample of EVTX-ATTACK-SAMPLES (https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) lives in a folder named
after the ATT&CK tactic it reproduces, so every file is an attack that *should* produce at least one finding.
The script runs the module on each file (read-only, nothing is written next to the samples) and reports:

* detection: files with at least one finding of severity medium or higher;
* tactic match: files where a finding maps to the tactic of the folder;
* errors: files the parser could not read.

    python scripts/validar_evtx.py RUTA/EVTX-ATTACK-SAMPLES [--sigma DIR] [--csv salida.csv] [--json salida.json]
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

from sabueso.core.attack import technique_info, techniques_for
from sabueso.modules import get_module
from sabueso.modules.base import SEVERITY_RANK

TACTIC_FOLDERS = {
    "Command and Control": "command-and-control", "Credential Access": "credential-access",
    "Defense Evasion": "defense-evasion", "Discovery": "discovery", "Execution": "execution",
    "Lateral Movement": "lateral-movement", "Persistence": "persistence",
    "Privilege Escalation": "privilege-escalation",
}
MEDIUM = SEVERITY_RANK["medium"]


def tactics_of(finding: dict) -> set[str]:
    return {tactic for tech in techniques_for(finding) for tactic in technique_info(tech, finding)[1]}


def evaluate(path: Path, options: dict) -> dict:
    module = get_module("evtx")
    with tempfile.TemporaryDirectory() as out:
        ctx = module.run(path, Path(out), options)
    findings = ctx.sink.findings
    relevant = [f for f in findings if SEVERITY_RANK[f["severity"]] >= MEDIUM]
    return {
        "events": len(ctx.sink.events),
        "findings": len(findings),
        "relevant": len(relevant),
        "codes": sorted({f["code"] for f in relevant}),
        "tactics": sorted(set().union(*(tactics_of(f) for f in relevant)) if relevant else set()),
        # unsupported rules of an external pack are reported once per run, not as errors of the log
        "errors": [e["error"] for e in ctx.errors if not e["error"].startswith("Sigma:")],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--sigma", help="carpeta de reglas Sigma externas (p. ej. las de SigmaHQ)")
    parser.add_argument("--csv", type=Path, help="detalle por archivo en CSV")
    parser.add_argument("--json", type=Path, help="resumen en JSON")
    args = parser.parse_args(argv)
    options = {"sigma_rules": args.sigma} if args.sigma else {}

    rows, per_tactic = [], defaultdict(Counter)
    for folder, tactic in TACTIC_FOLDERS.items():
        for path in sorted((args.dataset / folder).glob("*.evtx")):
            try:
                result = evaluate(path, options)
            except Exception as exc:  # noqa: BLE001 - a crash is a validation result, not a reason to stop
                result = {"events": 0, "findings": 0, "relevant": 0, "codes": [], "tactics": [],
                          "errors": [f"CRASH {type(exc).__name__}: {exc}"]}
            row = {"tactic": tactic, "file": path.name, **result,
                   "detected": result["relevant"] > 0, "tactic_match": tactic in result["tactics"]}
            rows.append(row)
            stats = per_tactic[tactic]
            stats["files"] += 1
            stats["detected"] += row["detected"]
            stats["tactic_match"] += row["tactic_match"]
            stats["errors"] += bool(result["errors"])
            stats["crashes"] += any(e.startswith("CRASH") for e in result["errors"])

    total = sum(per_tactic.values(), Counter())
    print(f"{'Táctica':<22} {'Archivos':>8} {'Detectados':>11} {'Táctica OK':>11} {'Errores':>8}")
    for tactic, stats in [*per_tactic.items(), ("TOTAL", total)]:
        pct = 100 * stats["detected"] / stats["files"] if stats["files"] else 0
        match = 100 * stats["tactic_match"] / stats["files"] if stats["files"] else 0
        print(f"{tactic:<22} {stats['files']:>8} {stats['detected']:>5} {pct:4.0f} % {stats['tactic_match']:>5} "
              f"{match:4.0f} % {stats['errors']:>8}")
    if args.csv:
        with args.csv.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
            writer.writeheader()
            for row in rows:
                writer.writerow({k: "; ".join(v) if isinstance(v, list) else v for k, v in row.items()})
    if args.json:
        args.json.write_text(json.dumps({"per_tactic": per_tactic, "total": total}, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
