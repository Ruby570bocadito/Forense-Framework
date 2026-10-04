"""Server-side SVG charts for the web interface and the report (no JavaScript library, CSP friendly).

Charts are drawn with CSS classes (``viz-*``) so the same markup follows the
light and dark themes of the web interface and the print styles of the report.
Every mark carries a ``<title>`` (native tooltip, screen readers) and a
``data-tip`` attribute used by the web tooltip; each chart also comes with a
table view of its data.

Severity uses one ordinal ramp (a single hue, light to dark), validated for
both themes; activity and ATT&CK counts use the accent hue.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html import escape
from typing import Optional

from markupsafe import Markup

SEVERITIES = ("info", "low", "medium", "high", "critical")
# ordinal severity ramp (validated: one hue, monotone lightness, >= 2:1 light end) — light and dark themes
SEVERITY_RAMP = {"light": ("#e8946a", "#d9703f", "#c2501f", "#9c3612", "#6e220a"),
                 "dark": ("#8a3a1c", "#b24c22", "#d9652f", "#f08a55", "#ffb894")}
# sequential accent ramp for counts (ATT&CK matrix cells), light -> dark
COUNT_RAMP = ("#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95")


def severity_color(severity: str, theme: str = "light") -> str:
    return SEVERITY_RAMP[theme][SEVERITIES.index(severity) if severity in SEVERITIES else 0]


def ink_on(color: str) -> str:
    """Black or white text, whichever reads on ``color``."""
    r, g, b = (int(color[i:i + 2], 16) / 255 for i in (1, 3, 5))

    def channel(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    luminance = 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
    return "#0b0b0b" if luminance > 0.25 else "#ffffff"


def nice_ticks(maximum: float, count: int = 4) -> list[int]:
    """Clean axis ticks from 0 to at least ``maximum`` (0, 5, 10, 15 / 0, 250, 500...)."""
    if maximum <= 0:
        return [0, 1]
    raw = maximum / count
    magnitude = 10 ** math.floor(math.log10(raw))
    step = next(m * magnitude for m in (1, 2, 2.5, 5, 10) if m * magnitude >= raw)
    step = max(1, int(step)) if step >= 1 else 1
    top = int(math.ceil(maximum / step) * step)
    return list(range(0, top + 1, step))


def _tip(text: str) -> str:
    return f' data-tip="{escape(text, quote=True)}"'


# -- activity over time -------------------------------------------------------------------------
@dataclass
class Bucket:
    start: datetime
    count: int
    flagged: int = 0  # events with severity >= medium


UNITS = (  # (name, seconds, label format)
    ("10min", 600, "%d/%m %H:%M"), ("30min", 1800, "%d/%m %H:%M"), ("hour", 3600, "%d/%m %H:%M"), ("6h", 6 * 3600, "%d/%m %H:%M"), ("day", 86400, "%d/%m/%Y"),
    ("week", 7 * 86400, "%d/%m/%Y"), ("month", 30 * 86400, "%m/%Y"),
)


def choose_unit(start: datetime, end: datetime, max_buckets: int = 72, min_seconds: int = 3600) -> tuple[str, int, str]:
    """The finest unit that keeps at most ``max_buckets`` bars and is not finer than the data (``min_seconds``)."""
    span = max((end - start).total_seconds(), 1)
    for unit in UNITS:
        if unit[1] >= min_seconds and span / unit[1] <= max_buckets:
            return unit
    return UNITS[-1]


def bucketize(rows: list[tuple[str, int, int]], start: datetime, end: datetime,
              min_seconds: int = 3600) -> tuple[list[Bucket], str]:
    """``(timestamp, events, flagged events)`` rows (per hour, or per ``min_seconds``) summed per bucket."""
    name, seconds, _ = choose_unit(start, end, min_seconds=min_seconds)
    origin = datetime.fromtimestamp(math.floor(start.timestamp() / seconds) * seconds, timezone.utc)
    total = max(1, math.ceil((end - origin).total_seconds() / seconds))
    buckets = [Bucket(origin + timedelta(seconds=i * seconds), 0) for i in range(total)]
    for stamp, count, flagged in rows:
        try:
            when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        index = int((when - origin).total_seconds() // seconds)
        if 0 <= index < total:
            buckets[index].count += count
            buckets[index].flagged += flagged
    return buckets, name


def activity_chart(buckets: list[Bucket], unit: str, findings: list[dict], labels: dict,
                   link: Optional[str] = None) -> Markup:
    """Column chart of events per bucket, with a strip of findings (by severity) underneath."""
    if not buckets:
        return Markup("")
    width, height, left, right, top = 1100, 236, 46, 12, 12
    plot_h, strip_y = 140, 206
    plot_w = width - left - right
    seconds = next(u[1] for u in UNITS if u[0] == unit)
    fmt = next(u[2] for u in UNITS if u[0] == unit)
    ticks = nice_ticks(max(b.count for b in buckets))
    scale = plot_h / ticks[-1]
    slot = plot_w / len(buckets)
    bar = min(24.0, max(2.0, slot - 2))
    parts = [f'<svg class="viz viz-activity" viewBox="0 0 {width} {height}" role="img" '
             f'aria-label="{escape(labels["title"])}" preserveAspectRatio="xMidYMid meet">']
    for tick in ticks:
        y = top + plot_h - tick * scale
        parts.append(f'<line class="viz-grid" x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}"/>'
                     f'<text class="viz-tick" x="{left - 6}" y="{y + 4:.1f}" text-anchor="end">{tick:,}</text>')
    for i, b in enumerate(buckets):
        if not b.count:
            continue
        x = left + i * slot + (slot - bar) / 2
        h = max(1.0, b.count * scale)
        y = top + plot_h - h
        end = b.start + timedelta(seconds=seconds)
        end_text = end.strftime("%H:%M" if unit in ("10min", "30min", "hour", "6h") else "%Y-%m-%d")
        tip = f'{b.start:%Y-%m-%d %H:%M} – {end_text}: {b.count:,} {labels["events"]}' + \
            (f', {b.flagged} {labels["flagged"]}' if b.flagged else "")
        radius = min(4.0, bar / 2, h)
        cls = "viz-bar viz-bar-flagged" if b.flagged else "viz-bar"
        joiner = "&" if link and "?" in link else "?"
        href = f'{link}{joiner}from={b.start:%Y-%m-%dT%H:%M}&to={end:%Y-%m-%dT%H:%M}' if link else ""
        shape = (f'<path class="{cls}" d="M{x:.1f},{y + h:.1f} V{y + radius:.1f} Q{x:.1f},{y:.1f} '
                 f'{x + radius:.1f},{y:.1f} H{x + bar - radius:.1f} Q{x + bar:.1f},{y:.1f} {x + bar:.1f},'
                 f'{y + radius:.1f} V{y + h:.1f} Z"{_tip(tip)}><title>{escape(tip)}</title></path>')
        parts.append(f'<a href="{escape(href)}">{shape}</a>' if href else shape)
    parts.append(f'<line class="viz-axis" x1="{left}" x2="{width - right}" y1="{top + plot_h}" y2="{top + plot_h}"/>')
    step = max(1, math.ceil(len(buckets) / 6))
    for i in range(0, len(buckets), step):
        x = left + i * slot + slot / 2
        parts.append(f'<text class="viz-tick" x="{x:.1f}" y="{top + plot_h + 16}" text-anchor="middle">'
                     f'{buckets[i].start.strftime(fmt)}</text>')
    # findings strip: one tick per finding, colored by severity, in time order
    origin = buckets[0].start.timestamp()
    span = len(buckets) * seconds
    parts.append(f'<text class="viz-tick" x="{left}" y="{strip_y - 14}">{escape(labels["findings"])}</text>')
    parts.append(f'<line class="viz-grid" x1="{left}" x2="{width - right}" y1="{strip_y}" y2="{strip_y}"/>')
    for f in sorted(findings, key=lambda f: SEVERITIES.index(f["severity"])):
        try:
            when = datetime.fromisoformat(f["timestamp"].replace("Z", "+00:00")).timestamp()
        except (AttributeError, ValueError):
            continue
        if not origin <= when <= origin + span:
            continue
        x = left + (when - origin) / span * plot_w
        tip = f'{f["timestamp"][:16].replace("T", " ")} · {f["label"]}'
        parts.append(f'<rect class="viz-sev viz-sev-{f["severity"]}" x="{x - 2:.1f}" y="{strip_y - 9}" width="4" '
                     f'height="18" rx="2"{_tip(tip)}><title>{escape(tip)}</title></rect>')
    parts.append("</svg>")
    return Markup("".join(parts))


# -- severity breakdown ----------------------------------------------------------------------------
def severity_bar(counts: dict[str, int], labels: dict[str, str]) -> Markup:
    """Horizontal stacked bar (most severe first) with a legend; part-to-whole of the findings."""
    order = [s for s in reversed(SEVERITIES) if counts.get(s)]
    total = sum(counts.get(s, 0) for s in order)
    if not total:
        return Markup("")
    width, height, gap = 760, 22, 2
    usable = width - gap * (len(order) - 1)
    parts = [f'<svg class="viz viz-severity" viewBox="0 0 {width} {height}" role="img" '
             f'aria-label="{escape(labels["title"])}" preserveAspectRatio="none">']
    x = 0.0
    for index, severity in enumerate(order):
        w = max(3.0, counts[severity] / total * usable)
        tip = f'{labels[severity]}: {counts[severity]} ({counts[severity] / total:.0%})'
        rx = 4 if index in (0, len(order) - 1) else 0
        parts.append(f'<rect class="viz-sev viz-sev-{severity}" x="{x:.1f}" y="0" width="{w:.1f}" height="{height}" '
                     f'rx="{rx}"{_tip(tip)}><title>{escape(tip)}</title></rect>')
        x += w + gap
    parts.append("</svg>")
    legend = "".join(f'<span class="viz-key"><i class="viz-swatch viz-sev-{s}"></i>{escape(labels[s])} '
                     f'<b>{counts[s]}</b></span>' for s in order)
    return Markup("".join(parts) + f'<div class="viz-legend">{legend}</div>')


# -- ATT&CK -------------------------------------------------------------------------------------
def tactic_bars(rows: list[tuple[str, int]], labels: dict) -> Markup:
    """Horizontal bars (HTML, so text keeps its size): techniques per tactic in kill-chain order, one hue."""
    if not rows:
        return Markup("")
    maximum = max(count for _, count in rows) or 1
    items = []
    for name, count in rows:
        tip = f'{name}: {count} {labels["techniques"]}'
        bar = (f'<i class="viz-hbar" style="width:{max(2.0, count / maximum * 100):.1f}%"{_tip(tip)}></i>'
               if count else "")
        items.append(f'<div class="viz-hrow"><span class="viz-hlabel">{escape(name)}</span>'
                     f'<span class="viz-htrack">{bar}</span><b class="viz-hvalue{" muted" if not count else ""}">'
                     f'{count}</b></div>')
    return Markup(f'<div class="viz-hbars" role="img" aria-label="{escape(labels["title"])}">{"".join(items)}</div>')


def count_color(count: int, maximum: int) -> str:
    if count <= 0:
        return ""
    index = min(len(COUNT_RAMP) - 1, int(round((count / max(maximum, 1)) * (len(COUNT_RAMP) - 1))))
    return COUNT_RAMP[max(1, index)]
