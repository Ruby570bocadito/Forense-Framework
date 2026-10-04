"""Windows Prefetch (.pf): program execution, run counts and the files each program loaded.

Parsing (all versions, including Windows 10/11 MAM-compressed files) is done by
libscca (``pyscca``).
"""

from __future__ import annotations

from pathlib import Path

from forense.core.heuristics import EXECUTABLE_EXTENSIONS, is_suspicious_location, strip_device, tool_category
from forense.core.utils import dt_or_none_iso, filetime_to_dt, find_files, relative_name
from forense.modules.base import AnalysisContext, Module, Option, register

MAX_RUN_TIMES = 8


def _run_times(scca) -> list:
    times = []
    for index in range(MAX_RUN_TIMES):
        try:
            value = scca.get_last_run_time_as_integer(index)
        except OSError:
            break
        dt = filetime_to_dt(value)
        if dt:
            times.append(dt)
    return times


@register
class PrefetchModule(Module):
    name = "prefetch"
    category = "windows"
    triage = True
    options = (Option("loaded_files", True, "bool"),)

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: p.suffix.lower() == ".pf")

    def analyze(self, ctx: AnalysisContext) -> None:
        import pyscca

        executables = set()
        versions: dict[int, int] = {}
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            scca = pyscca.file()
            try:
                with open(path, "rb") as fh:
                    scca.open_file_object(fh)
                    try:
                        self._emit(ctx, scca, rel, ctx.options["loaded_files"])
                        executables.add(scca.executable_filename)
                        versions[scca.format_version] = versions.get(scca.format_version, 0) + 1
                    finally:
                        scca.close()
            except OSError as exc:
                ctx.error(rel, exc)
        ctx.summary.update({"prefetch_files": sum(versions.values()), "executables": len(executables),
                            "format_versions": {str(k): v for k, v in sorted(versions.items())}})

    @staticmethod
    def _emit(ctx: AnalysisContext, scca, rel: str, with_files: bool) -> None:
        exe = scca.executable_filename or ""
        runs = _run_times(scca)
        loaded = [scca.get_filename(i) for i in range(scca.number_of_filenames)]
        exe_paths = [strip_device(p) for p in loaded if p.upper().endswith("\\" + exe.upper())]
        full_path = exe_paths[0] if exe_paths else exe
        volumes = []
        for i in range(scca.number_of_volumes):
            volume = scca.get_volume_information(i)
            volumes.append({"device": volume.device_path, "serial": f"{volume.serial_number:08X}",
                            "created": dt_or_none_iso(filetime_to_dt(volume.get_creation_time_as_integer()))})
        ctx.record("prefetch", {
            "file": rel, "executable": exe, "path": full_path, "prefetch_hash": f"{scca.prefetch_hash:08X}",
            "run_count": scca.run_count, "last_run": dt_or_none_iso(runs[0]) if runs else None,
            "previous_runs": [dt_or_none_iso(t) for t in runs[1:]], "volumes": volumes,
            "loaded_file_count": len(loaded), "format": scca.format_version,
            **({"loaded_files": [strip_device(p) for p in loaded]} if with_files else {}),
        })
        for when in runs:
            ctx.event(when, "program_executed", f"Prefetch: {full_path} (x{scca.run_count})", rel)

        first = runs[-1] if runs else None
        category = tool_category(exe)
        if category:
            ctx.finding(f"prefetch.{category}", "high" if category == "attack_tool" else "medium", runs[0] if runs else None,
                        executable=exe, path=full_path, runs=scca.run_count, first=dt_or_none_iso(first) or "-")
        elif is_suspicious_location(full_path):
            ctx.finding("prefetch.suspicious_execution", "medium", runs[0] if runs else None, executable=exe,
                        path=full_path, runs=scca.run_count)
        odd = [strip_device(p) for p in loaded
               if is_suspicious_location(strip_device(p))
               and Path(p.replace("\\", "/")).suffix.lower().lstrip(".") in EXECUTABLE_EXTENSIONS]
        if odd and not is_suspicious_location(full_path):
            ctx.finding("prefetch.suspicious_module", "medium", runs[0] if runs else None, executable=exe,
                        modules=", ".join(odd[:3]) + (f" (+{len(odd) - 3})" if len(odd) > 3 else ""))
