"""Shell links (.lnk) and custom jump lists: evidence of opened files and folders."""

from __future__ import annotations

import os
from pathlib import Path

from forense.core.heuristics import autostart_suspicion, suspicious_command_rules
from forense.core.utils import dt_or_none_iso, find_files, relative_name, ts_to_iso
from forense.modules.base import AnalysisContext, Module, register
from forense.parsers.lnk import LnkError, LnkFile, find_embedded_lnks, parse_lnk

MAX_LNK_SIZE = 16 * 1024 * 1024


def _is_candidate(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".lnk") or name.endswith(".customdestinations-ms")


@register
class LnkModule(Module):
    name = "lnk"
    category = "windows"
    triage = True

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, _is_candidate)

    def analyze(self, ctx: AnalysisContext) -> None:
        drive_types: dict[str, int] = {}
        total = 0
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            try:
                if path.stat().st_size > MAX_LNK_SIZE:
                    continue
                data = path.read_bytes()
                st = path.stat()
            except OSError as exc:
                ctx.error(rel, exc)
                continue
            if path.name.lower().endswith(".customdestinations-ms"):
                items = [(f"{rel}@{offset}", lnk) for offset, lnk in find_embedded_lnks(data)]
                source = "jumplist"
            else:
                try:
                    items = [(rel, parse_lnk(data))]
                except LnkError as exc:
                    ctx.error(rel, exc)
                    continue
                source = "lnk"
            for name, lnk in items:
                total += 1
                drive_types[lnk.drive_type or "-"] = drive_types.get(lnk.drive_type or "-", 0) + 1
                self._emit(ctx, name, lnk, source, st if source == "lnk" else None)
        ctx.summary.update({"links": total, "drive_types": drive_types})

    @staticmethod
    def _emit(ctx: AnalysisContext, name: str, lnk: LnkFile, source: str, st: os.stat_result | None) -> None:
        target = lnk.target_path
        command = f"{target} {lnk.arguments}".strip()
        record = {
            "file": name, "source": source, "target_path": target, "arguments": lnk.arguments,
            "working_dir": lnk.working_dir, "relative_path": lnk.relative_path,
            "target_created": dt_or_none_iso(lnk.target_created),
            "target_modified": dt_or_none_iso(lnk.target_modified),
            "target_accessed": dt_or_none_iso(lnk.target_accessed),
            "target_size": lnk.target_size, "drive_type": lnk.drive_type, "volume_serial": lnk.volume_serial,
            "volume_label": lnk.volume_label, "network_path": lnk.network_path, "machine_id": lnk.machine_id,
            "mac_address": lnk.mac_address,
            "lnk_created": ts_to_iso(st.st_ctime) if st and os.name == "nt" else None,
            "lnk_modified": ts_to_iso(st.st_mtime) if st else None,
        }
        ctx.record("shell_link", record)
        label = target or lnk.name or name
        if st is not None:
            ctx.event(st.st_mtime, "file_opened", f"{label} (lnk)", name)
        ctx.event(lnk.target_created, "lnk_target_created", label, name)
        ctx.event(lnk.target_modified, "lnk_target_modified", label, name)

        lowered = name.lower().replace("/", "\\")
        seen = st.st_mtime if st is not None else lnk.target_modified
        if "\\start menu\\programs\\startup\\" in lowered:
            reasons = autostart_suspicion(command)
            ctx.finding("lnk.startup_item", "high" if reasons else "medium", seen, link=name,
                        target=command, reasons=", ".join(reasons) or "-")
        else:
            rules = suspicious_command_rules(command)
            if rules:
                ctx.finding("lnk.suspicious_arguments", "high", seen, link=name, target=command,
                            rules=", ".join(rules))
        if lnk.drive_type == "removable":
            ctx.finding("lnk.removable_media", "low", lnk.target_accessed or lnk.target_modified, link=name,
                        target=label, serial=lnk.volume_serial or "-", label=lnk.volume_label or "-")
