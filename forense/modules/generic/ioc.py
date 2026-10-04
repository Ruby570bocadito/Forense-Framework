"""Strings and indicators of compromise (IOCs).

Extracts ASCII and UTF-16LE strings from any file and finds URLs, e-mail
addresses, IPv4 addresses and Windows registry paths in them. An optional
watchlist (one indicator per line) raises findings when a known-bad indicator
appears in the evidence.
"""

from __future__ import annotations

import mmap
import re
from collections import Counter, defaultdict
from pathlib import Path

from forense.core.utils import iter_files, relative_name
from forense.modules.base import AnalysisContext, Module, Option, register

IOC_PATTERNS = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\\^`{|}]+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b"),
    "ipv4": re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
                       r"(?!\.?\d)"),
    "registry_key": re.compile(r"\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU)"
                               r"\\[^\s\"'<>]+", re.IGNORECASE),
}
_TRAILING = ".,;:)]}'\""
MAX_FILE_SIZE = 2 * 1024 ** 3


def load_watchlist(path: Path) -> set[str]:
    items = set()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                items.add(line.lower())
    return items


@register
class IocModule(Module):
    name = "ioc"
    category = "generic"
    options = (
        Option("min_length", 5, "int"),
        Option("save_strings", False, "bool"),
        Option("watchlist", None, "path"),
    )

    def analyze(self, ctx: AnalysisContext) -> None:
        min_len = max(3, ctx.options["min_length"])
        ascii_re = re.compile(rb"[\x20-\x7e\t]{%d,}" % min_len)
        utf16_re = re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % min_len)
        watchlist = load_watchlist(ctx.options["watchlist"]) if ctx.options["watchlist"] else set()
        watch_re = re.compile("|".join(re.escape(w) for w in sorted(watchlist, key=len, reverse=True)),
                              re.IGNORECASE) if watchlist else None
        strings_out = None
        if ctx.options["save_strings"]:
            strings_path = ctx.output_dir / "strings.tsv"
            strings_out = open(strings_path, "w", encoding="utf-8")
            ctx.add_artifact(strings_path)

        counts: Counter = Counter()
        unique: dict[str, Counter] = defaultdict(Counter)
        matched: set[tuple[str, str]] = set()
        files = string_count = 0
        try:
            for path in iter_files(ctx.target, on_error=ctx.error):
                rel = relative_name(path, ctx.target)
                try:
                    with open(path, "rb") as fh:
                        size = fh.seek(0, 2)
                        if size == 0 or size > MAX_FILE_SIZE:
                            continue
                        files += 1
                        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                            for encoding, regex, width in (("ascii", ascii_re, 1), ("utf-16le", utf16_re, 2)):
                                for match in regex.finditer(mm):
                                    text = match.group().decode("ascii" if width == 1 else "utf-16-le")
                                    string_count += 1
                                    if strings_out:
                                        strings_out.write(f"{rel}\t{match.start()}\t{encoding}\t{text}\n")
                                    for kind, pattern in IOC_PATTERNS.items():
                                        for found in pattern.finditer(text):
                                            value = found.group().rstrip(_TRAILING)
                                            offset = match.start() + found.start() * width
                                            counts[kind] += 1
                                            unique[kind][value] += 1
                                            ctx.record("ioc", {"file": rel, "offset": offset, "encoding": encoding,
                                                               "type": kind, "value": value})
                                    if watch_re is not None:
                                        self._watch(ctx, watch_re, matched, rel, match.start(), width, text)
                except OSError as exc:
                    ctx.error(rel, exc)
        finally:
            if strings_out:
                strings_out.close()
        ctx.summary.update({
            "files": files, "strings": string_count, "iocs_per_type": dict(counts),
            "top_values": {kind: dict(c.most_common(15)) for kind, c in unique.items()},
            "watchlist_size": len(watchlist), "watchlist_hits": len(matched),
        })

    @staticmethod
    def _watch(ctx: AnalysisContext, watch_re: re.Pattern, matched: set, rel: str, offset: int, width: int,
               text: str) -> None:
        for found in watch_re.finditer(text):
            indicator = found.group().lower()
            if (rel, indicator) not in matched:
                matched.add((rel, indicator))
                ctx.finding("ioc.watchlist_match", "high", None, indicator=indicator, file=rel,
                            offset=offset + found.start() * width)
