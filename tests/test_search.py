"""Case-wide search, literal LIKE patterns and the timeline histogram."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from forense.charts import bucketize
from forense.cli import EXIT_OK, main
from forense.core.case import Case, json_like, like
from forense.core.search import search_case
from forense.web import create_app


@pytest.fixture(scope="module")
def demo_case(tmp_path_factory):
    root = tmp_path_factory.mktemp("search")
    assert main(["demo", str(root), "-a", "Tester"]) == EXIT_OK
    return root / "case_demo"


def test_like_patterns_are_literal():
    assert like("50%_off!") == "%50!%!_off!!%"
    assert json_like('C:\\Users\\"x"') == '%C:\\\\Users\\\\\\"x\\"%'


def test_record_search_handles_backslashes(demo_case):
    with Case.open(demo_case) as case:
        registry = next(a for a in case.analyses() if a.module == "registry")
        assert case.records(registry.id, search="Users\\Public").total > 0
        assert case.records(registry.id, search="Users\\Public").total == \
            case.records(registry.id, search="users\\public").total
        assert case.records(registry.id, search="%SystemRoot%").total > 0  # literal percent signs
        assert case.records(registry.id, search="Q%Z").total == 0  # not a wildcard


def test_search_everything(demo_case):
    with Case.open(demo_case) as case:
        results = search_case(case, "mimikatz", "en")
        assert results.findings and results.events_total and results.records and results.programs
        assert any(r["module"] == "prefetch" for r in results.records)
        assert any("mimikatz" in r["sample"].lower() for r in results.records)
        assert results.total >= len(results.findings) + results.events_total
        assert search_case(case, "Users\\Public\\svchost.exe", "en").findings
        assert search_case(case, "x", "en").total == 0  # too short
        assert search_case(case, "no-such-thing-anywhere", "en").total == 0
        evidence = case.evidence_list()[0]
        assert search_case(case, evidence.hashes["sha256"][:16], "en").evidence == [evidence]


def test_event_histogram_resolution(demo_case):
    with Case.open(demo_case) as case:
        rows, first, last, resolution = case.event_histogram(start="2026-09-14T02:00:00", end="2026-09-14T05:00:00Z")
        assert resolution == 60 and rows and first.startswith("2026-09-14") and rows[0][0].endswith(":00Z")
        assert sum(r[1] for r in rows) == case.events(start="2026-09-14T02:00:00", end="2026-09-14T05:00:00Z").total
        _, _, _, wide = case.event_histogram()
        assert wide == 86400  # years of events: one row per day
        assert case.event_histogram(search="no-such-thing") == ([], None, None, 3600)


def test_bucketize_respects_the_data_resolution():
    start = datetime(2026, 9, 14, 2, tzinfo=timezone.utc)
    end = datetime(2026, 9, 14, 5, tzinfo=timezone.utc)
    rows = [("2026-09-14T02:15:00Z", 3, 1)]
    assert bucketize(rows, start, end, min_seconds=60)[1] == "10min"
    assert bucketize(rows, start, end)[1] == "hour"  # hourly data is never spread over 10-minute bars


def test_web_search_and_timeline_chart(demo_case):
    client = create_app(demo_case.parent).test_client()
    page = client.get("/c/case_demo/search?q=mimikatz&lang=en").get_data(as_text=True)
    assert "Case search" in page and "Defender detected" in page and "/c/case_demo/analyses/" in page
    assert 'name="q"' in client.get("/c/case_demo/").get_data(as_text=True)  # search box in the header
    timeline = client.get("/c/case_demo/timeline?from=2026-09-14T02:00&to=2026-09-14T05:00&q=exe&lang=en")
    html = timeline.get_data(as_text=True)
    assert "viz-activity" in html and "Clear the interval" in html
    assert "q=exe&amp;from=2026-09-14T02:" in html  # bars keep the other filters
    empty = client.get("/c/case_demo/timeline?q=no-such-thing").get_data(as_text=True)
    assert "viz-activity" not in empty
