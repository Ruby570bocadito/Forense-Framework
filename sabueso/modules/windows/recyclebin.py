"""Windows Recycle Bin: what was deleted, when, by whom and from where.

``$Recycle.Bin/<SID>/$I*`` (Vista and later) and ``RECYCLER/<SID>/INFO2`` (2000, XP, Server 2003).
"""

from __future__ import annotations

from pathlib import Path, PureWindowsPath

from sabueso.core.heuristics import ARCHIVE_EXTENSIONS, EXECUTABLE_EXTENSIONS
from sabueso.core.utils import FileTooLarge, dt_or_none_iso, find_files, read_capped, relative_name
from sabueso.modules.base import AnalysisContext, Module, register
from sabueso.parsers.recyclebin import RecycleBinError, parse_i_file, parse_info2

_MAX_I_FILE_SIZE = 65536
_MAX_INFO2_SIZE = 16 * 1024 * 1024  # 20 000 records of 800 bytes


@register
class RecycleBinModule(Module):
    name = "recyclebin"
    category = "windows"
    triage = True

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: p.name.upper().startswith("$I") or p.name.upper() == "INFO2")

    def analyze(self, ctx: AnalysisContext) -> None:
        total = recoverable = 0
        per_user: dict[str, int] = {}
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            if path.name.upper() == "INFO2":
                found, present = self._info2(ctx, path, rel)
                total += found
                recoverable += present
                sid = path.parent.name if path.parent.name.upper().startswith("S-1-") else "-"
                per_user[sid] = per_user.get(sid, 0) + found
                continue
            try:
                item = parse_i_file(read_capped(path, _MAX_I_FILE_SIZE))
            except FileTooLarge:
                continue
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
            self._flag(ctx, item.original_path, item.deleted, sid)
        ctx.summary.update({"deleted_items": total, "content_recoverable": recoverable, "per_sid": per_user})

    @staticmethod
    def _flag(ctx: AnalysisContext, original_path: str, deleted, sid: str) -> None:
        ext = PureWindowsPath(original_path).suffix.lower().lstrip(".")
        if ext in EXECUTABLE_EXTENSIONS or ext in ARCHIVE_EXTENSIONS:
            code = "recyclebin.deleted_executable" if ext in EXECUTABLE_EXTENSIONS else "recyclebin.deleted_archive"
            ctx.finding(code, "low", deleted, path=original_path, sid=sid or "-")

    def _info2(self, ctx: AnalysisContext, path: Path, rel: str) -> tuple[int, int]:
        """Records of an XP-era INFO2; the content of each sits next to it as D<drive><index><ext>."""
        try:
            items = parse_info2(read_capped(path, _MAX_INFO2_SIZE))
        except FileTooLarge:
            return 0, 0
        except (OSError, RecycleBinError) as exc:
            ctx.error(rel, exc)
            return 0, 0
        sid = path.parent.name if path.parent.name.upper().startswith("S-1-") else ""
        present = 0
        for item in items:
            content = path.with_name(f"D{item.drive}{item.index}{PureWindowsPath(item.original_path).suffix}")
            has_content = content.exists()
            present += has_content
            ctx.record("deleted_file", {
                "file": rel, "original_path": item.original_path, "original_size": item.size,
                "deleted": dt_or_none_iso(item.deleted), "sid": sid, "content_present": has_content,
                "content_file": relative_name(content, ctx.target) if has_content else content.name,
                "format": "INFO2",
            })
            ctx.event(item.deleted, "file_deleted", f"{item.original_path} ({item.size} B) sid={sid}", rel)
            self._flag(ctx, item.original_path, item.deleted, sid)
        return len(items), present
