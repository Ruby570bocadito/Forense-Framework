"""Search everything in a case at once: findings, timeline, analysis records, programs and evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from forense.core.case import Case, json_like


@dataclass
class SearchResults:
    query: str
    findings: list[dict] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    events_total: int = 0
    records: list[dict] = field(default_factory=list)  # per analysis and artifact: count and a sample
    programs: list = field(default_factory=list)
    evidence: list = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.findings) + self.events_total + sum(r["count"] for r in self.records) + \
            len(self.programs) + len(self.evidence)


def search_case(case: Case, query: str, lang: Optional[str] = None, limit: int = 25) -> SearchResults:
    from forense.core.execution import execution_overview
    from forense.presentation import finding_description, finding_title

    query = query.strip()
    results = SearchResults(query)
    if len(query) < 2:
        return results
    needle = query.lower()
    for finding in case.findings():
        text = " ".join((finding_title(finding, lang), finding_description(finding, lang), finding["code"],
                         json.dumps(finding.get("params") or {}, ensure_ascii=False),
                         (finding.get("review") or {}).get("note") or ""))
        if needle in text.lower() or needle in text.lower().replace("\\\\", "\\"):
            results.findings.append(finding)
    page = case.events(search=query, limit=limit)
    results.events, results.events_total = page.rows, page.total
    pattern = json_like(query)
    rows = case.conn.execute(
        "SELECT r.analysis_id, a.module, a.evidence_id, r.artifact, COUNT(*) AS n, MIN(r.data) AS sample "
        "FROM records r JOIN analyses a ON a.id = r.analysis_id WHERE r.data LIKE ? ESCAPE '!' "
        "GROUP BY r.analysis_id, r.artifact ORDER BY n DESC LIMIT 60", (pattern,)).fetchall()
    for row in rows:
        try:
            sample = json.loads(row["sample"])
        except ValueError:
            sample = {}
        hit = next((f"{k}: {v}" for k, v in sample.items() if needle in str(v).lower()), "")
        results.records.append({"analysis_id": row["analysis_id"], "module": row["module"],
                                "evidence_id": row["evidence_id"], "artifact": row["artifact"],
                                "count": row["n"], "sample": hit[:300]})
    results.programs = execution_overview(case, search=query)[:limit]
    for item in case.evidence_list():
        text = " ".join((item.id, item.description, item.source, item.path, *item.hashes.values())).lower()
        if needle in text:
            results.evidence.append(item)
    return results
