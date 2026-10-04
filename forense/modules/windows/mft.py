"""NTFS $MFT: file system timeline, deleted entries, downloads (Zone.Identifier) and timestomping."""

from __future__ import annotations

from collections import Counter
from pathlib import Path, PureWindowsPath

from forense.core.heuristics import EXECUTABLE_EXTENSIONS
from forense.core.utils import dt_or_none_iso, find_files, relative_name
from forense.modules.base import AnalysisContext, Module, Option, register
from forense.parsers.mft import MftError, MftReader, PathResolver, parse_zone_identifier

ZONES = {"0": "local", "1": "intranet", "2": "trusted", "3": "internet", "4": "restricted"}


def _macb(times: dict) -> list[tuple[object, str]]:
    """Group identical timestamps: [(datetime, 'm.cb'), ...]."""
    grouped: dict = {}
    for flag, key in (("m", "modified"), ("a", "accessed"), ("c", "mft_modified"), ("b", "created")):
        value = times.get(key)
        if value is not None:
            grouped.setdefault(value, set()).add(flag)
    return [(ts, "".join(f if f in flags else "." for f in "macb")) for ts, flags in grouped.items()]


@register
class MftModule(Module):
    name = "mft"
    category = "windows"
    triage = True
    options = (
        Option("timeline", "si", "choice", choices=("si", "si+fn", "none")),
        Option("include_deleted", True, "bool"),
    )

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: p.name.lower() in ("$mft", "mft", "$mft.bin", "mft.bin"))

    def analyze(self, ctx: AnalysisContext) -> None:
        ctx.summary["mft_files"] = {}
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            try:
                self._analyze_file(ctx, path, rel)
            except (OSError, MftError) as exc:
                ctx.error(rel, exc)

    def _analyze_file(self, ctx: AnalysisContext, path: Path, rel: str) -> None:
        resolver = PathResolver()
        ctx.progress(f"{rel}: paths")
        with MftReader.open(path) as reader:
            for entry in reader:
                resolver.add(entry)

        timeline = ctx.options["timeline"]
        include_deleted = ctx.options["include_deleted"]
        stats: Counter = Counter()
        ctx.progress(f"{rel}: records")
        with MftReader.open(path) as reader:
            for entry in reader:
                if entry.base_record or not entry.name:
                    continue
                stats["entries"] += 1
                stats["directories" if entry.is_directory else "files"] += 1
                if not entry.in_use:
                    stats["deleted"] += 1
                    if not include_deleted:
                        continue
                full_path = resolver.path(entry.record)
                si = entry.si.as_datetimes() if entry.si else {}
                fn = entry.fn.as_datetimes() if entry.fn else {}
                zone = parse_zone_identifier(entry.zone_identifier) if entry.zone_identifier else {}
                indicators = entry.timestomp_indicators
                ctx.record("mft_entry", {
                    "record": entry.record, "sequence": entry.sequence, "in_use": entry.in_use,
                    "directory": entry.is_directory, "path": full_path, "size": entry.size,
                    "si_created": dt_or_none_iso(si.get("created")), "si_modified": dt_or_none_iso(si.get("modified")),
                    "si_mft_modified": dt_or_none_iso(si.get("mft_modified")),
                    "si_accessed": dt_or_none_iso(si.get("accessed")),
                    "fn_created": dt_or_none_iso(fn.get("created")), "fn_modified": dt_or_none_iso(fn.get("modified")),
                    "ads": ", ".join(entry.ads), "zone_id": zone.get("ZoneId", ""),
                    "host_url": zone.get("HostUrl", ""), "referrer_url": zone.get("ReferrerUrl", ""),
                    "timestomp_indicators": ", ".join(indicators),
                })
                state = "" if entry.in_use else " [deleted]"
                if timeline != "none":
                    for ts, macb in _macb(si):
                        ctx.event(ts, "fs_si", f"[{macb}] {full_path}{state}", rel)
                    if timeline == "si+fn":
                        for ts, macb in _macb(fn):
                            ctx.event(ts, "fs_fn", f"[{macb}] {full_path}{state}", rel)

                if indicators:
                    stats["timestomp_suspects"] += 1
                    if len(indicators) == 2:
                        ctx.finding("mft.timestomping", "high", si.get("created"), path=full_path,
                                    si_created=dt_or_none_iso(si.get("created")),
                                    fn_created=dt_or_none_iso(fn.get("created")))
                if zone:
                    stats["downloaded"] += 1
                    ext = PureWindowsPath(full_path).suffix.lower().lstrip(".")
                    if ext in EXECUTABLE_EXTENSIONS and zone.get("ZoneId") in ("3", "4"):
                        ctx.finding("mft.downloaded_executable", "medium", fn.get("created") or si.get("created"),
                                    path=full_path, url=zone.get("HostUrl") or zone.get("ReferrerUrl") or "-",
                                    zone=ZONES.get(zone.get("ZoneId", ""), zone.get("ZoneId", "")))
                if entry.ads and any(a != "Zone.Identifier" for a in entry.ads) and not entry.is_directory:
                    stats["with_ads"] += 1
        ctx.summary["mft_files"][rel] = dict(stats)
