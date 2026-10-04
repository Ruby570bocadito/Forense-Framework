"""Case overview for the dashboard and the report: activity, severity, ATT&CK and review figures."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from forense.charts import Bucket, bucketize
from forense.core.attack import TACTICS, attack_matrix
from forense.core.case import Case

FOCUS_SEVERITIES = ("medium", "high", "critical")


def _parse(stamp: Optional[str]) -> Optional[datetime]:
    if not stamp:
        return None
    try:
        value = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def focus_window(case: Case, findings: list[dict]) -> Optional[tuple[datetime, datetime]]:
    """The period of the incident: span of the relevant findings, or of the events (1st-99th percentile)."""
    times = sorted(t for t in (_parse(f.get("timestamp")) for f in findings
                               if f["severity"] in FOCUS_SEVERITIES
                               and (f.get("review") or {}).get("status") != "false_positive") if t)
    if len(times) >= 2:
        start, end = times[0], times[-1]
    else:
        total = case.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        if not total:
            return None
        pick = case.conn.execute("SELECT timestamp FROM events ORDER BY timestamp LIMIT 1 OFFSET ?",
                                 (int(total * 0.01),)).fetchone()[0]
        last = case.conn.execute("SELECT timestamp FROM events ORDER BY timestamp LIMIT 1 OFFSET ?",
                                 (max(0, int(total * 0.99) - 1),)).fetchone()[0]
        start, end = _parse(pick), _parse(last)
        if times:
            start, end = min(start, times[0]), max(end, times[0])
    pad = max((end - start) * 0.08, timedelta(minutes=30))
    return start - pad, end + pad


def activity(case: Case, start: datetime, end: datetime) -> tuple[list[Bucket], str]:
    rows = case.conn.execute(
        "SELECT substr(timestamp, 1, 13) || ':00:00Z', COUNT(*), "
        "SUM(CASE WHEN severity IN ('medium', 'high', 'critical') THEN 1 ELSE 0 END) FROM events "
        "WHERE timestamp >= ? AND timestamp <= ? GROUP BY substr(timestamp, 1, 13)",
        (start.strftime("%Y-%m-%dT%H:%M:%S"), end.strftime("%Y-%m-%dT%H:%M:%S.999999Z"))).fetchall()
    return bucketize([(r[0], r[1], r[2] or 0) for r in rows], start, end)


def case_overview(case: Case) -> dict:
    findings = case.findings()
    matrix = attack_matrix(findings)
    window = focus_window(case, findings)
    buckets, unit = activity(case, *window) if window else ([], "hour")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {
        "findings": findings, "matrix": matrix, "window": window, "buckets": buckets, "unit": unit,
        "severity_counts": counts,
        "tactic_rows": [(name, len(matrix.get(name, []))) for name, _ in TACTICS],
        "techniques": len({h.technique for hits in matrix.values() for h in hits}),
        "tactics": len(matrix),
    }
