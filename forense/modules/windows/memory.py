"""Windows memory (RAM) analysis with Volatility 3: processes, command lines, connections, injected code, services.

The target is a memory image (raw, crash dump, VMware...) analysed by running
Volatility 3, or a folder with Volatility JSON outputs already produced by the
analyst (``vol -r json -f mem.raw windows.pslist > pslist.json``).
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Optional

from forense.core.errors import ModuleError
from forense.core.heuristics import (
    ATTACK_TOOLS,
    REMOTE_ACCESS_TOOLS,
    SYSTEM_BINARIES,
    autostart_suspicion,
    is_suspicious_location,
    suspicious_command_rules,
)
from forense.core.heuristics import lookalike_of as _lookalike
from forense.core.utils import normalize_ts
from forense.i18n import t
from forense.modules.base import AnalysisContext, Module, Option, register
from forense.parsers.volatility import (
    DEFAULT_PLUGINS,
    PLUGINS,
    VolatilityError,
    find_memory_image,
    find_outputs,
    parse_output,
    run_plugin,
    volatility_command,
)

# Expected parent of core Windows processes (only checked when the parent is still present).
EXPECTED_PARENTS = {
    "smss.exe": {"system", "smss.exe"},
    "wininit.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "csrss.exe": {"smss.exe"},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "lsaiso.exe": {"wininit.exe"},
    "svchost.exe": {"services.exe", "msmpeng.exe"},
    "spoolsv.exe": {"services.exe"},
    "searchindexer.exe": {"services.exe"},
    "runtimebroker.exe": {"svchost.exe"},
    "taskhostw.exe": {"svchost.exe", "services.exe"},
}
SINGLETONS = ("lsass.exe", "services.exe", "wininit.exe", "lsaiso.exe")
SYSTEM_DIRS = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\systemroot\\system32\\", "\\windows\\explorer.exe",
               "\\windows\\winsxs\\", "\\windows\\servicing\\")
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe",
          "visio.exe"}
SERVERS = {"w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "tomcat9.exe", "sqlservr.exe", "wmiprvse.exe",
           "php-cgi.exe", "java.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
          "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe"}
# Processes where executable private memory is normal (JIT compilers, security products).
JIT_PROCESSES = {"msmpeng.exe", "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "powershell.exe",
                 "pwsh.exe", "smartscreen.exe", "searchapp.exe", "teams.exe", "slack.exe", "code.exe", "java.exe",
                 "javaw.exe", "dotnet.exe", "msedgewebview2.exe", "onedrive.exe", "mpdefendercoreservice.exe"}
ESTABLISHED = {"ESTABLISHED", "SYN_SENT", "CLOSE_WAIT", "SYN_RCVD", "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK",
               "CLOSING", "TIME_WAIT"}


def _known(name: str, names) -> Optional[str]:
    """Match a (possibly 14/15-character truncated) image name against a set of executables."""
    name = name.lower()
    if name in names:
        return name
    if len(name) >= 14:
        return next((n for n in names if n.startswith(name)), None)
    return None


_INTERNAL = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8",
    "224.0.0.0/4", "255.255.255.255/32", "::1/128", "::/128", "fc00::/7", "fe80::/10", "ff00::/8"))


def _external(address: str) -> bool:
    """Outside the organisation: not private, loopback, link-local or multicast."""
    try:
        ip = ipaddress.ip_address(address.split("%")[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not any(ip.version == net.version and ip in net for net in _INTERNAL)


class _Process:
    __slots__ = ("pid", "ppid", "name", "created", "exited", "threads", "handles", "session", "wow64", "offset",
                 "in_pslist", "in_psscan", "path", "cmdline", "parent")

    def __init__(self, row: dict) -> None:
        self.pid = row.get("PID")
        self.ppid = row.get("PPID")
        self.name = row.get("ImageFileName") or ""
        self.created = normalize_ts(row.get("CreateTime"))
        self.exited = normalize_ts(row.get("ExitTime"))
        self.threads = row.get("Threads")
        self.handles = row.get("Handles")
        self.session = row.get("SessionId")
        self.wow64 = row.get("Wow64")
        self.offset = row.get("Offset(V)") or row.get("Offset(P)") or row.get("Offset")
        self.in_pslist = self.in_psscan = False
        self.path = ""
        self.cmdline = ""
        self.parent: Optional[_Process] = None

    @property
    def key(self) -> tuple:
        return self.pid, self.created

    @property
    def active(self) -> bool:
        return not self.exited

    @property
    def image(self) -> str:
        """Full executable name when the path is known (ImageFileName is truncated to 15 characters)."""
        source = self.path or (self.cmdline.split('"')[1] if self.cmdline.startswith('"') else "")
        name = source.replace("/", "\\").rsplit("\\", 1)[-1] if source else ""
        return name if name.lower().startswith(self.name.lower()[:14]) and name else self.name

    @property
    def label(self) -> str:
        return f"{self.image} (PID {self.pid})"


@register
class MemoryModule(Module):
    name = "memory"
    category = "windows"
    options = (
        Option("plugins", list(DEFAULT_PLUGINS), "list"),
        Option("vol_path", None, "path"),
        Option("symbols", None, "path"),
        Option("offline", False, "bool"),
        Option("timeout", 60, "int"),
    )

    def discover(self, target: Path) -> list[Path]:
        if target.is_file():
            return [target]
        outputs = find_outputs(target)
        if outputs:
            return list(outputs.values())
        image = find_memory_image(target)
        return [image] if image else []

    # -- acquisition of the plugin outputs ------------------------------------------------------
    def _collect(self, ctx: AnalysisContext) -> dict[str, list[dict]]:
        wanted = [p.lower() for p in ctx.options["plugins"]]
        unknown = [p for p in wanted if p not in PLUGINS]
        if unknown:
            raise ModuleError("error.memory_plugin_unknown", plugins=", ".join(unknown),
                              available=", ".join(PLUGINS))
        results: dict[str, list[dict]] = {}
        status: dict[str, str] = {}
        if ctx.target.is_dir() and find_outputs(ctx.target):
            ctx.summary["source"] = t("memory.source.imported")
            for plugin, path in find_outputs(ctx.target).items():
                if plugin not in wanted:
                    continue
                try:
                    results[plugin] = parse_output(path.read_text(encoding="utf-8-sig", errors="replace"))
                    status[plugin] = "ok"
                except (VolatilityError, ValueError) as exc:
                    ctx.error(path.name, exc)
                    status[plugin] = "failed"
        else:
            image = ctx.target if ctx.target.is_file() else find_memory_image(ctx.target)
            if image is None:
                raise ModuleError("error.memory_no_input", path=str(ctx.target))
            command = volatility_command(str(ctx.options["vol_path"]) if ctx.options["vol_path"] else None)
            if command is None:
                raise ModuleError("error.memory_vol_missing")
            ctx.summary["source"] = t("memory.source.volatility")
            ctx.summary["image"] = image.name
            raw = ctx.output_dir / "volatility"
            raw.mkdir(parents=True, exist_ok=True)
            for plugin in wanted:
                ctx.progress(f"volatility {plugin}")
                try:
                    results[plugin] = run_plugin(command, image, plugin, raw / f"{plugin}.json",
                                                 str(ctx.options["symbols"]) if ctx.options["symbols"] else None,
                                                 ctx.options["offline"], ctx.options["timeout"] * 60)
                    status[plugin] = "ok"
                except VolatilityError as exc:
                    ctx.error(plugin, exc)
                    status[plugin] = "failed"
            if any(raw.iterdir()):
                ctx.add_artifact(raw)
        for plugin in wanted:
            status.setdefault(plugin, "missing")
        ctx.summary["plugins"] = status
        if not any(s == "ok" for s in status.values()):
            raise ModuleError("error.memory_no_results", errors="; ".join(e["error"] for e in ctx.errors[:3]) or "-")
        return results

    # -- analysis -----------------------------------------------------------------------------
    def analyze(self, ctx: AnalysisContext) -> None:
        results = self._collect(ctx)
        if results.get("info"):
            info = {str(r.get("Variable")): r.get("Value") for r in results["info"]}
            ctx.record("memory_info", info)
            ctx.summary["system"] = {k: info.get(k) for k in ("NtBuildLab", "SystemTime", "NtMajorVersion",
                                                              "NtMinorVersion", "Is64Bit") if info.get(k) is not None}
        processes = self._processes(ctx, results)
        connections = self._connections(ctx, results.get("netscan", []), processes)
        injections = self._malfind(ctx, results.get("malfind", []), processes)
        services = self._services(ctx, results.get("svcscan", []))
        ctx.summary.update({
            "processes": len(processes), "active_processes": sum(p.active for p in processes),
            "hidden_processes": sum(1 for p in processes if p.active and p.in_psscan and not p.in_pslist
                                    and "pslist" in results),
            "connections": connections, "injected_regions": injections, "services": services,
        })

    def _processes(self, ctx: AnalysisContext, results: dict) -> list[_Process]:
        by_key: dict[tuple, _Process] = {}
        for source in ("pslist", "psscan", "pstree"):
            for row in results.get(source, []):
                if row.get("PID") is None:
                    continue
                process = _Process(row)
                process = by_key.setdefault(process.key, process)
                if source == "pslist":
                    process.in_pslist = True
                elif source == "psscan":
                    process.in_psscan = True
                elif row.get("Path"):
                    process.path = row["Path"]
                    process.cmdline = process.cmdline or row.get("Cmd") or ""
        by_pid: dict[int, list[_Process]] = {}
        for process in by_key.values():
            by_pid.setdefault(process.pid, []).append(process)
        for row in results.get("cmdline", []):
            args = row.get("Args")
            if isinstance(args, str) and args and not args.startswith(("Required memory", "Process ")):
                for process in by_pid.get(row.get("PID"), []):
                    if process.active or len(by_pid[row["PID"]]) == 1:
                        process.cmdline = args
        processes = sorted(by_key.values(), key=lambda p: (p.created or "", p.pid))
        for process in processes:
            candidates = [p for p in by_pid.get(process.ppid, []) if p is not process
                          and (not p.created or not process.created or p.created <= process.created)]
            process.parent = max(candidates, key=lambda p: p.created or "") if candidates else None

        scanned = "psscan" in results and "pslist" in results
        for process in processes:
            parent = process.parent
            ctx.record("memory_process", {
                "pid": process.pid, "ppid": process.ppid, "name": process.image, "parent": parent.image if parent
                else "", "created": process.created, "exited": process.exited, "threads": process.threads,
                "handles": process.handles, "session": process.session, "wow64": process.wow64,
                "path": process.path, "cmdline": process.cmdline, "in_pslist": process.in_pslist,
                "in_psscan": process.in_psscan, "offset": process.offset,
            })
            details = f"{process.label} ← {parent.label if parent else f'PPID {process.ppid}'}"
            ctx.event(process.created, "memory_process_start", f"{details}: {process.cmdline or process.path}".rstrip(": "),
                      "memory")
            if process.exited:
                ctx.event(process.exited, "memory_process_exit", process.label, "memory")
            self._check_process(ctx, process, scanned)

        for name in SINGLETONS:
            running = [p for p in processes if p.active and p.image.lower() == name and (p.in_pslist or not scanned)]
            if len(running) > 1:
                ctx.finding("memory.duplicate_system_process", "high", running[-1].created, name=name,
                            pids=", ".join(str(p.pid) for p in running))
        return processes

    @staticmethod
    def _check_process(ctx: AnalysisContext, process: _Process, scanned: bool) -> None:
        name = process.image.lower()
        when = process.created
        parent = process.parent
        if scanned and process.active and process.in_psscan and not process.in_pslist and process.threads:
            ctx.finding("memory.hidden_process", "high", when, process=process.label, offset=_hex(process.offset))
        expected = EXPECTED_PARENTS.get(name)
        if expected and parent and parent.image.lower() not in expected:
            ctx.finding("memory.unexpected_parent", "high", when, process=process.label, parent=parent.label,
                        expected=", ".join(sorted(expected)))
        if parent and name in SHELLS:
            parent_name = parent.image.lower()
            if parent_name in OFFICE or parent_name in SERVERS:
                ctx.finding("memory.suspicious_child", "high", when, process=process.label, parent=parent.label,
                            cmdline=process.cmdline or "-")
        location = process.path or (process.cmdline if process.cmdline[:1] in ('"', "\\") or process.cmdline[1:3]
                                    == ":\\" else "")
        if name in SYSTEM_BINARIES and location and not any(d in location.lower() for d in SYSTEM_DIRS):
            ctx.finding("memory.masquerading", "high", when, process=process.label, path=location)
        else:
            real = _lookalike(name)
            if real:
                ctx.finding("memory.lookalike_name", "high", when, process=process.label, imitates=real,
                            path=location or "-")
            elif location and is_suspicious_location(location):
                ctx.finding("memory.suspicious_location", "medium", when, process=process.label, path=location)
        if _known(name, ATTACK_TOOLS):
            ctx.finding("memory.attack_tool", "high", when, process=process.label, cmdline=process.cmdline or "-")
        elif _known(name, REMOTE_ACCESS_TOOLS):
            ctx.finding("memory.remote_access", "medium", when, process=process.label, cmdline=process.cmdline or "-")
        rules = suspicious_command_rules(process.cmdline)
        if rules:
            ctx.finding("memory.suspicious_cmdline", "high", when, process=process.label, cmdline=process.cmdline,
                        rules=", ".join(rules))

    @staticmethod
    def _connections(ctx: AnalysisContext, rows: list[dict], processes: list[_Process]) -> int:
        names = {p.pid: p for p in processes if p.active}
        count = 0
        for row in rows:
            if row.get("Proto") is None:
                continue
            count += 1
            owner = names.get(row.get("PID"))
            owner_name = owner.image if owner else (row.get("Owner") or "")
            remote = f"{row.get('ForeignAddr')}:{row.get('ForeignPort')}"
            data = {"proto": row.get("Proto"), "local": f"{row.get('LocalAddr')}:{row.get('LocalPort')}",
                    "remote": remote, "state": row.get("State") or "", "pid": row.get("PID"), "owner": owner_name,
                    "created": normalize_ts(row.get("Created"))}
            ctx.record("memory_connection", data)
            state = (row.get("State") or "").upper()
            if state == "LISTENING" or not row.get("ForeignAddr") or row.get("ForeignAddr") in ("*", "0.0.0.0", "::"):
                continue
            ctx.event(data["created"], "memory_connection",
                      f"{data['proto']} {data['local']} → {remote} {state} ({owner_name} PID {row.get('PID')})",
                      "memory")
            lowered = owner_name.lower()
            if _external(str(row.get("ForeignAddr"))) and state in ESTABLISHED and (
                    lowered in SHELLS or _known(lowered, ATTACK_TOOLS)
                    or (owner and owner.path and is_suspicious_location(owner.path))):
                ctx.finding("memory.suspicious_connection", "medium", data["created"],
                            process=f"{owner_name} (PID {row.get('PID')})", remote=remote, state=state)
        return count

    @staticmethod
    def _malfind(ctx: AnalysisContext, rows: list[dict], processes: list[_Process]) -> int:
        names = {p.pid: p for p in processes if p.active}
        per_process: dict[int, list[dict]] = {}
        for row in rows:
            if row.get("PID") is None or row.get("Start VPN") is None:
                continue
            hexdump = str(row.get("Hexdump") or "")
            region = {"pid": row.get("PID"), "process": row.get("Process") or "", "start": _hex(row.get("Start VPN")),
                      "end": _hex(row.get("End VPN")), "protection": row.get("Protection") or "",
                      "tag": row.get("Tag") or "", "commit_charge": row.get("CommitCharge"),
                      "private": row.get("PrivateMemory"), "pe_header": hexdump.lower().startswith("4d 5a"),
                      "hexdump": hexdump[:192], "disasm": str(row.get("Disasm") or "")[:400]}
            ctx.record("memory_injection", region)
            per_process.setdefault(region["pid"], []).append(region)
        for pid, regions in per_process.items():
            process = names.get(pid)
            name = process.image if process else regions[0]["process"]
            pe = any(r["pe_header"] for r in regions)
            severity = "high" if pe else ("low" if _known(name, JIT_PROCESSES) else "medium")
            # the injection time is unknown: the process start time would date it misleadingly early
            ctx.finding("memory.injected_code", severity, None,
                        process=f"{name} (PID {pid})", regions=len(regions),
                        addresses=", ".join(r["start"] for r in regions[:5]), pe=pe)
        return len(rows)

    @staticmethod
    def _services(ctx: AnalysisContext, rows: list[dict]) -> int:
        seen = set()
        for row in rows:
            name = row.get("Name")
            if not name:
                continue
            binary = row.get("Binary (Registry)") or row.get("Binary") or ""
            ctx.record("memory_service", {"name": name, "display": row.get("Display") or "", "binary": binary,
                                          "dll": row.get("Dll") or "", "state": row.get("State") or "",
                                          "start": row.get("Start") or "", "type": row.get("Type") or "",
                                          "pid": row.get("PID")})
            key = (name, binary)
            if key in seen:
                continue
            seen.add(key)
            reasons = autostart_suspicion(f"{binary} {row.get('Dll') or ''}")
            if reasons and "SERVICE_KERNEL_DRIVER" not in str(row.get("Type")):
                ctx.finding("memory.suspicious_service", "high", None, service=name, binary=binary,
                            reasons=", ".join(reasons))
        return len(seen)


def _hex(value) -> str:
    return f"0x{value:x}" if isinstance(value, int) else str(value or "")
