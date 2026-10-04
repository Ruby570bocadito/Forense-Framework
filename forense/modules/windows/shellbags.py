"""ShellBags (UsrClass.dat / NTUSER.DAT): folders a user browsed, including removable, network and deleted ones."""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Optional

from forense.core.utils import dt_or_none_iso, find_files, relative_name
from forense.modules.base import AnalysisContext, Module, register
from forense.parsers.regf import RegistryError, RegistryHive, RegistryKey
from forense.parsers.shellitems import join_path, parse_shell_item

BAG_ROOTS = (
    "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",  # UsrClass.dat (Vista+)
    "Software\\Microsoft\\Windows\\Shell\\BagMRU",  # NTUSER.DAT (XP)
    "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",  # NTUSER.DAT (XP)
)
_ADMIN_SHARE = re.compile(r"^\\\\[^\\]+\\(admin\$|[a-z]\$|ipc\$)", re.IGNORECASE)
MAX_DEPTH = 64


def _mru_order(key: RegistryKey) -> list[int]:
    raw = key.get("MRUListEx")
    if not isinstance(raw, bytes):
        return []
    return [i for (i,) in struct.iter_unpack("<I", raw[:len(raw) // 4 * 4]) if i != 0xFFFFFFFF]


def _user_from_path(path: Path) -> str:
    parts = [p.lower() for p in path.parts]
    if "users" in parts and parts.index("users") + 1 < len(parts) - 1:
        return path.parts[parts.index("users") + 1]
    return ""


@register
class ShellBagsModule(Module):
    name = "shellbags"
    category = "windows"
    triage = True

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: p.name.lower() in ("usrclass.dat", "ntuser.dat"))

    def analyze(self, ctx: AnalysisContext) -> None:
        total = 0
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            user = _user_from_path(path)
            try:
                with RegistryHive(path) as hive:
                    for root_path in BAG_ROOTS:
                        root = hive.open(root_path)
                        if root is not None:
                            total += self._walk(ctx, root, "", rel, user, 0)
            except (RegistryError, OSError, struct.error) as exc:
                ctx.error(rel, exc)
        ctx.summary["folders"] = total

    def _walk(self, ctx: AnalysisContext, key: RegistryKey, parent: str, rel: str, user: str, depth: int) -> int:
        if depth > MAX_DEPTH:
            return 0
        order = _mru_order(key)
        count = 0
        for value in key.values():
            if not value.name.isdigit():
                continue
            item = parse_shell_item(value.raw)
            path = join_path(parent, item)
            child = key.subkey(value.name)
            position = order.index(int(value.name)) + 1 if int(value.name) in order else None
            count += 1
            ctx.record("shellbag", {
                "file": rel, "user": user, "path": path, "item_type": item.kind, "mru_position": position,
                "last_interacted": dt_or_none_iso(key.last_written) if position == 1 else None,
                "key_last_written": dt_or_none_iso(child.last_written if child else None),
                "created": dt_or_none_iso(item.created), "modified": dt_or_none_iso(item.modified),
                "accessed": dt_or_none_iso(item.accessed), "mft_entry": item.mft_entry,
                "mft_sequence": item.mft_sequence,
            })
            if position == 1:  # the parent key was last written when this folder was last opened
                ctx.event(key.last_written, "folder_accessed", f"{user}: {path}", rel)
            self._check(ctx, path, item.kind, user, key.last_written if position == 1 else None)
            if child is not None:
                count += self._walk(ctx, child, path, rel, user, depth + 1)
        return count

    @staticmethod
    def _check(ctx: AnalysisContext, path: str, kind: str, user: str, when: Optional[object]) -> None:
        if kind == "network" or path.startswith("\\\\"):
            if _ADMIN_SHARE.match(path):
                ctx.finding("shellbags.admin_share", "medium", when, path=path, user=user or "-")
