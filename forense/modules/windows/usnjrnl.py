"""NTFS change journal ($UsnJrnl:$J): file creation, deletion and renaming history.

Full paths are rebuilt with the $MFT of the same volume when it is present in
the evidence (``C/$MFT`` next to ``C/$Extend/$J``). Detects offensive tools
written to disk, deleted Prefetch files and event logs (anti-forensics), mass
renaming to a new extension (ransomware) and mass deletion.
"""

from __future__ import annotations

from collections import deque
from datetime import timedelta
from pathlib import Path, PureWindowsPath
from typing import Optional

from forense.core.heuristics import EXECUTABLE_EXTENSIONS, is_suspicious_location, tool_category
from forense.core.utils import find_files, iso, relative_name
from forense.modules.base import AnalysisContext, Module, Option, register
from forense.parsers.mft import MftError, MftReader, PathResolver
from forense.parsers.usnjrnl import (
    CLOSE,
    FILE_CREATE,
    FILE_DELETE,
    RENAME_NEW,
    RENAME_OLD,
    iter_records,
    open_journal,
    reason_names,
)

JOURNAL_NAMES = {"$j", "$usnjrnl_$j", "$usnjrnl%3a$j", "usnjrnl_j", "$usnjrnl.$j", "$usnjrnl-$j", "usnjrnl.j"}
MFT_NAMES = ("$mft", "mft", "$mft.bin", "mft.bin")
# Extensions renamed in bulk by normal software (updates, browsers, Office).
BENIGN_RENAME_EXTENSIONS = {"", ".tmp", ".temp", ".bak", ".old", ".log", ".etl", ".partial", ".crdownload",
                            ".download", ".pf", ".db", ".dat", ".json", ".xml", ".txt", ".jsonlz4", ".mozlz4",
                            ".sqlite", ".dll", ".exe", ".cab", ".msi", ".mum", ".cat", ".manifest", ".evtx",
                            ".ini", ".lock", ".png", ".jpg", ".ldb", ".js", ".css", ".html"}
WINDOW = timedelta(minutes=10)


def _extension(name: str) -> str:
    return PureWindowsPath(name).suffix.lower()


def _volume_root(journal: Path) -> Path:
    """``C`` for ``C/$Extend/$J`` (the folder that holds $Extend)."""
    return journal.parent.parent if journal.parent.name.lower() == "$extend" else journal.parent


@register
class UsnJrnlModule(Module):
    name = "usnjrnl"
    category = "windows"
    triage = True
    options = (
        Option("records", "close", "choice", choices=("close", "all")),
        Option("timeline", "changes", "choice", choices=("changes", "all", "none")),
        Option("rename_threshold", 200, "int"),
        Option("delete_threshold", 1000, "int"),
    )

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: p.name.lower() in JOURNAL_NAMES)

    def analyze(self, ctx: AnalysisContext) -> None:
        mfts = find_files(ctx.target, lambda p: p.name.lower() in MFT_NAMES) if ctx.target.is_dir() else []
        ctx.summary["journals"] = {}
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            resolver = self._resolver(ctx, path, mfts)
            try:
                with open_journal(path) as data:
                    stats = self._journal(ctx, rel, data, resolver)
            except (OSError, ValueError) as exc:
                ctx.error(rel, exc)
                continue
            stats["paths"] = "mft" if resolver else "names_only"
            ctx.summary["journals"][rel] = stats

    @staticmethod
    def _resolver(ctx: AnalysisContext, journal: Path, mfts: list[Path]) -> Optional[PathResolver]:
        root = _volume_root(journal)
        candidates = [m for m in mfts if m.parent == root] or (mfts if len(mfts) == 1 else [])
        if not candidates:
            return None
        resolver = PathResolver()
        try:
            with MftReader.open(candidates[0]) as reader:
                for entry in reader:
                    resolver.add(entry)
        except (OSError, MftError) as exc:
            ctx.error(relative_name(candidates[0], ctx.target), exc)
            return None
        return resolver

    def _journal(self, ctx: AnalysisContext, rel: str, data, resolver: Optional[PathResolver]) -> dict:
        options = ctx.options
        counts = {"records": 0, "created": 0, "deleted": 0, "renamed": 0}
        first = last = None
        old_names: dict[tuple, str] = {}
        created_exe: dict[tuple, str] = {}
        renames: dict[str, list] = {}
        deletes: deque = deque()
        max_deletes = (0, None)
        tools_seen: set[str] = set()
        anti = {"prefetch": [0, None], "evtx": [0, None]}
        executable_findings = 0

        for record in iter_records(data):
            counts["records"] += 1
            first = first or record.timestamp
            last = record.timestamp
            key = (record.entry, record.sequence)
            path = f"{resolver.path_checked(record.parent_entry, record.parent_sequence).rstrip(chr(92))}\\" \
                f"{record.name}" if resolver else record.name
            if record.reason & RENAME_OLD:
                old_names[key] = path
            if options["records"] == "all" or record.reason & (CLOSE | RENAME_OLD):
                ctx.record("usn_record", {
                    "usn": record.usn, "timestamp": iso(record.timestamp), "name": record.name, "path": path,
                    "mft_entry": record.entry, "sequence": record.sequence, "parent_entry": record.parent_entry,
                    "reasons": reason_names(record.reason), "attributes": f"0x{record.attributes:x}",
                    "directory": record.is_directory, "journal": rel,
                })
            if options["timeline"] == "all":
                ctx.event(record.timestamp, "usn_change", f"{path} [{reason_names(record.reason)}]", rel)
            if not record.reason & CLOSE:
                continue
            when = record.timestamp
            ext = _extension(record.name)
            if record.reason & FILE_DELETE:
                counts["deleted"] += 1
                event, details = "usn_file_deleted", path
                deletes.append(when)
                while deletes and when - deletes[0] > WINDOW:
                    deletes.popleft()
                if len(deletes) > max_deletes[0]:
                    max_deletes = (len(deletes), when)
                if ext == ".pf":
                    anti["prefetch"][0] += 1
                    anti["prefetch"][1] = anti["prefetch"][1] or when
                elif ext == ".evtx":
                    anti["evtx"][0] += 1
                    anti["evtx"][1] = anti["evtx"][1] or when
                origin = created_exe.pop(key, None)
                if origin and executable_findings < 50 and is_suspicious_location(origin) \
                        and "\\appdata\\local\\temp\\" not in origin.lower():
                    executable_findings += 1
                    ctx.finding("usnjrnl.executable_created_deleted", "medium", when, path=origin)
            elif record.reason & RENAME_NEW:
                counts["renamed"] += 1
                old = old_names.pop(key, "")
                event, details = "usn_file_renamed", f"{old or '?'} → {path}"
                old_ext = _extension(old)
                if ext != old_ext and ext not in BENIGN_RENAME_EXTENSIONS:
                    bucket = renames.setdefault(ext, [0, set(), when, when])
                    bucket[0] += 1
                    bucket[1].add(old_ext)
                    bucket[3] = when
            elif record.reason & FILE_CREATE:
                counts["created"] += 1
                event, details = "usn_file_created", path
            else:
                continue
            if record.reason & (FILE_CREATE | RENAME_NEW) and not record.is_directory:
                if ext.lstrip(".") in EXECUTABLE_EXTENSIONS:
                    created_exe[key] = path
                category = tool_category(record.name)
                if category and record.name.lower() not in tools_seen:
                    tools_seen.add(record.name.lower())
                    ctx.finding(f"usnjrnl.{category}", "high" if category == "attack_tool" else "medium", when,
                                path=path)
            if options["timeline"] == "changes":
                ctx.event(when, event, details, rel)

        if anti["prefetch"][0]:
            ctx.finding("usnjrnl.prefetch_deleted", "medium", anti["prefetch"][1], count=anti["prefetch"][0])
        if anti["evtx"][0]:
            ctx.finding("usnjrnl.evtx_deleted", "high", anti["evtx"][1], count=anti["evtx"][0])
        for ext, (count, old_exts, start, end) in renames.items():
            if count >= options["rename_threshold"] and len(old_exts) >= 3:
                ctx.finding("usnjrnl.mass_rename", "critical", start, extension=ext, count=count,
                            extensions=len(old_exts), end=iso(end))
        if max_deletes[0] >= options["delete_threshold"]:
            ctx.finding("usnjrnl.mass_deletion", "medium", max_deletes[1], count=max_deletes[0])
        return {**counts, "first": iso(first) if first else None, "last": iso(last) if last else None}
