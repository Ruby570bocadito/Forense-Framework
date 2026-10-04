"""Windows Recycle Bin ($Recycle.Bin): what was deleted, when, by whom and from where."""

from __future__ import annotations

from pathlib import Path, PureWindowsPath

from forense.core.heuristics import ARCHIVE_EXTENSIONS, EXECUTABLE_EXTENSIONS
from forense.core.utils import dt_or_none_iso, find_files, relative_name
from forense.modules.base import AnalysisContext, Module, register
from forense.parsers.recyclebin import RecycleBinError, parse_i_file


@register
class RecycleBinModule(Module):
    name = "recyclebin"
    category = "windows"
    triage = True

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: p.name.upper().startswith("$I"))

    def analyze(self, ctx: AnalysisContext) -> None:
        total = recoverable = 0
        per_user: dict[str, int] = {}
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            try:
                if path.stat().st_size > 65536:
                    continue
                item = parse_i_file(path.read_bytes())
            except (OSError, RecycleBinError) as exc:
                ctx.error(rel, exc)
                continue
            sid = path.parent.name if path.parent.name.upper().startswith("S-1-") else ""
            content = path.with_name(path.name[0] + ("R" if path.name[1] == "I" else "r") + path.name[2:])
            has_content = content.exists()
            total += 1
            recoverable += has_content
            per_user[sid or "-"] = per_user.get(sid or "-", 0) + 1
            ctx.record("deleted_file", {
                "file": rel, "original_path": item.original_path, "original_size": item.original_size,
                "deleted": dt_or_none_iso(item.deleted), "sid": sid, "content_present": has_content,
                "content_file": relative_name(content, ctx.target) if has_content else "", "format": item.version,
            })
            ctx.event(item.deleted, "file_deleted", f"{item.original_path} ({item.original_size} B) sid={sid}", rel)
            ext = PureWindowsPath(item.original_path).suffix.lower().lstrip(".")
            if ext in EXECUTABLE_EXTENSIONS or ext in ARCHIVE_EXTENSIONS:
                code = "recyclebin.deleted_executable" if ext in EXECUTABLE_EXTENSIONS else "recyclebin.deleted_archive"
                ctx.finding(code, "low", item.deleted, path=item.original_path, sid=sid or "-")
        ctx.summary.update({"deleted_items": total, "content_recoverable": recoverable, "per_sid": per_user})
