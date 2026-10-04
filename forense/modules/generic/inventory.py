"""File inventory: metadata, hashes, real file type, disguised files and file system timeline."""

from __future__ import annotations

import os
import stat
from collections import Counter

from forense.core.errors import ModuleError
from forense.core.hashing import hash_file, validate_algorithms
from forense.core.signatures import check_extension, extension_of, read_header
from forense.core.utils import iter_files, relative_name, ts_to_iso
from forense.modules.base import AnalysisContext, Module, Option, register


def _is_recycle_bin_metadata(path) -> bool:
    return path.name.upper().startswith("$I") and path.parent.name.upper().startswith("S-1-")


@register
class InventoryModule(Module):
    name = "inventory"
    category = "generic"
    triage = True
    options = (
        Option("hashes", ("sha256",), "list"),
        Option("timeline", True, "bool"),
    )

    def analyze(self, ctx: AnalysisContext) -> None:
        algorithms = list(ctx.options["hashes"])
        if algorithms in (["none"], ["ninguno"]):
            algorithms = []
        try:
            algorithms = validate_algorithms(algorithms)
        except ValueError as exc:
            raise ModuleError("error.option_invalid", option="hashes", value=str(exc)) from None

        types: Counter = Counter()
        total_size = files = mismatches = 0
        bodyfile = ctx.output_dir / "bodyfile.txt"
        with open(bodyfile, "w", encoding="utf-8", newline="\n") as body:
            for path in iter_files(ctx.target, on_error=ctx.error):
                rel = relative_name(path, ctx.target)
                try:
                    st = path.lstat()  # metadata first: reading content may update atime
                    header = read_header(path)
                    hashes = hash_file(path, algorithms) if algorithms else {}
                except OSError as exc:
                    ctx.error(rel, exc)
                    continue
                files += 1
                total_size += st.st_size
                signature, reason = check_extension(path, header)
                if reason and _is_recycle_bin_metadata(path):
                    reason = None  # $I files keep the original extension but hold metadata
                types[signature.name if signature else "-"] += 1
                birth = getattr(st, "st_birthtime", None)
                ctx.record("file", {
                    "path": rel, "size": st.st_size, "mtime": ts_to_iso(st.st_mtime), "atime": ts_to_iso(st.st_atime),
                    "ctime": ts_to_iso(st.st_ctime), "crtime": ts_to_iso(birth) if birth else None,
                    "mode": stat.filemode(st.st_mode), "uid": st.st_uid, "gid": st.st_gid, "inode": st.st_ino,
                    "detected_type": signature.name if signature else "", "extension_mismatch": reason or "",
                    **hashes,
                })
                if reason:
                    mismatches += 1
                    ctx.finding(f"file.{reason}", "medium", st.st_mtime, path=rel, extension=extension_of(path) or "-",
                                detected=signature.name if signature else "-")
                if ctx.options["timeline"]:
                    self._timeline(ctx, rel, st, birth)
                body.write("|".join([
                    hashes.get("md5", "0"), rel.replace("|", "\\|"), str(st.st_ino), stat.filemode(st.st_mode),
                    str(st.st_uid), str(st.st_gid), str(st.st_size), str(int(st.st_atime)), str(int(st.st_mtime)),
                    str(int(st.st_ctime)), str(int(birth or 0)),
                ]) + "\n")
        ctx.add_artifact(bodyfile)
        ctx.summary.update({
            "files": files, "total_size": total_size, "detected_types": dict(types.most_common()),
            "extension_mismatches": mismatches, "hash_algorithms": ", ".join(algorithms) or "-",
            "ctime_meaning": "creation (Windows)" if os.name == "nt" else "metadata change (POSIX)",
        })

    @staticmethod
    def _timeline(ctx: AnalysisContext, rel: str, st: os.stat_result, birth: float | None) -> None:
        grouped: dict[float, set] = {}
        for flag, value in (("m", st.st_mtime), ("a", st.st_atime), ("c", st.st_ctime), ("b", birth)):
            if value:
                grouped.setdefault(value, set()).add(flag)
        for ts, flags in grouped.items():
            macb = "".join(f if f in flags else "." for f in "macb")
            ctx.event(ts, "fs_stat", f"[{macb}] {rel} ({st.st_size} B)", rel)
