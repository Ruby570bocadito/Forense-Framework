"""Jump lists: files and connections recently opened with each application (Explorer, Office, RDP...)."""

from __future__ import annotations

from pathlib import Path

from forense.core.heuristics import suspicious_command_rules
from forense.core.utils import dt_or_none_iso, find_files, relative_name
from forense.modules.base import AnalysisContext, Module, register
from forense.parsers.jumplist import RDP_APP_ID, parse_automatic, parse_custom

AUTOMATIC = ".automaticdestinations-ms"
CUSTOM = ".customdestinations-ms"


@register
class JumpListsModule(Module):
    name = "jumplists"
    category = "windows"
    triage = True

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: p.name.lower().endswith((AUTOMATIC, CUSTOM)))

    def analyze(self, ctx: AnalysisContext) -> None:
        apps: dict[str, int] = {}
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            try:
                jump = parse_automatic(path) if path.name.lower().endswith(AUTOMATIC) else parse_custom(path)
            except Exception as exc:  # noqa: BLE001 - corrupt OLE containers raise various errors
                ctx.error(rel, exc)
                continue
            label = jump.application or jump.app_id
            apps[label] = apps.get(label, 0) + len(jump.entries)
            for entry in jump.entries:
                self._emit(ctx, rel, jump, entry, label)
        ctx.summary.update({"jump_lists": len(self.discover(ctx.target)), "entries_per_application": apps})

    @staticmethod
    def _emit(ctx: AnalysisContext, rel: str, jump, entry, label: str) -> None:
        lnk, dest = entry.lnk, entry.dest
        target = (lnk.target_path if lnk else "") or (dest.path if dest else "") or (lnk.name if lnk else "")
        arguments = lnk.arguments if lnk else ""
        ctx.record("jumplist_entry", {
            "file": rel, "kind": jump.kind, "app_id": jump.app_id, "application": jump.application,
            "entry": entry.stream, "target_path": target, "arguments": arguments,
            "last_access": dt_or_none_iso(dest.last_modified) if dest else None,
            "access_count": dest.access_count if dest else None, "pinned": dest.pinned if dest else None,
            "hostname": (dest.hostname if dest else "") or (lnk.machine_id if lnk else ""),
            "target_created": dt_or_none_iso(lnk.target_created) if lnk else None,
            "target_modified": dt_or_none_iso(lnk.target_modified) if lnk else None,
            "drive_type": lnk.drive_type if lnk else "", "volume_serial": lnk.volume_serial if lnk else "",
            "mac_address": lnk.mac_address if lnk else "",
        })
        when = dest.last_modified if dest else None
        ctx.event(when, "jumplist_access", f"{label}: {target} {arguments}".strip(), rel)
        if jump.app_id == RDP_APP_ID:
            ctx.finding("jumplist.rdp_connection", "low", when, target=f"{target} {arguments}".strip())
        if lnk and lnk.drive_type == "removable":
            ctx.finding("lnk.removable_media", "low", when or lnk.target_accessed, link=rel, target=target,
                        serial=lnk.volume_serial or "-", label=lnk.volume_label or "-")
        rules = suspicious_command_rules(f"{target} {arguments}")
        if rules:
            ctx.finding("lnk.suspicious_arguments", "high", when, link=rel, target=f"{target} {arguments}".strip(),
                        rules=", ".join(rules))
