"""The next step of a case: what the analyst should do now, shown by the CLI and the web.

The workflow is the one every examination follows: evidence -> analysis -> review of the findings ->
conclusions -> report -> verification. The guide looks at the case and names the first step that is still open,
so nobody has to remember where they left a case.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sabueso.core.case import Case

# Custody actions that change what a report would say: a report older than any of them is out of date.
_CHANGES_REPORT = frozenset({"analysis_completed", "analysis_deleted", "review_recorded", "conclusions_updated",
                             "evidence_derived"})


@dataclass
class Step:
    code: str  # done | add_evidence | analyse | review | conclusions | report
    params: dict = field(default_factory=dict)
    endpoint: str = "dashboard"  # web page where the step is done

    def text(self, channel: str, case: str, lang: str | None = None) -> str:
        """``channel`` is ``cli`` (with the command to run) or ``web`` (with what to click)."""
        from sabueso.i18n import t

        return t(f"guide.{self.code}.{channel}", lang, case=case, **self.params)


def next_step(case: Case) -> Step:
    evidence = case.evidence_list()
    if not evidence:
        return Step("add_evidence", endpoint="evidence")
    analyses = case.analyses()
    analysed = {a.evidence_id for a in analyses}
    pending = [item for item in evidence if item.id not in analysed]
    if pending:
        return Step("analyse", {"id": pending[0].id}, endpoint="dashboard")
    progress = case.review_progress()
    if progress["needs_review"]:
        return Step("review", {"pending": progress["needs_review"], "total": progress["total"]}, endpoint="findings")
    if case.conclusions() is None:
        return Step("conclusions", endpoint="conclusions")
    last_change = last_report = 0
    for entry in case.custody.entries():
        if entry.action in _CHANGES_REPORT:
            last_change = entry.seq
        elif entry.action == "report_generated":
            last_report = entry.seq
    if last_report <= last_change:
        return Step("report", endpoint="reports")
    return Step("done", endpoint="custody")
