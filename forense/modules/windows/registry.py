"""Windows registry hives: system profile, persistence, execution and user activity."""

from __future__ import annotations

import codecs
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from forense.core.heuristics import (
    EXECUTABLE_EXTENSIONS,
    autostart_suspicion,
    is_suspicious_location,
    launches_interpreter,
    suspicious_command_rules,
    tool_category,
)
from forense.core.timezone import WindowsTimeZone
from forense.core.utils import dt_or_none_iso, filetime_to_dt, find_files, iso, relative_name, user_from_path
from forense.modules.base import AnalysisContext, Module, Option, register
from forense.parsers.regf import RegistryError, RegistryHive, decode_utf16_string, identify
from forense.parsers.regf_deleted import recover_deleted
from forense.parsers.shimcache import ShimCacheError, parse_appcompatcache

HIVE_FILENAMES = {"system", "software", "sam", "security", "ntuser.dat", "usrclass.dat", "amcache.hve"}

USB_PROPERTIES = "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}"
USB_TIMES = {"0064": "first_install", "0066": "last_arrival", "0067": "last_removal"}

KNOWN_FOLDERS = {
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "%SystemRoot%\\System32",
    "{6D809377-6AF0-444B-8957-A3773F02200E}": "%ProgramFiles%",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "%ProgramFiles(x86)%",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "%SystemRoot%",
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": "%SystemRoot%\\SysWOW64",
    "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs",
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": "%AppData%\\Microsoft\\Windows\\Start Menu\\Programs",
    "{9E3995AB-1F9C-4F13-B827-48B24B6C7174}": "%AppData%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned",
    "{374DE290-123F-4565-9164-39C4925E467B}": "%UserProfile%\\Downloads",
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "%UserProfile%\\Desktop",
    "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": "%UserProfile%\\Documents",
}
_KNOWN_FOLDER_RE = re.compile("|".join(re.escape(k) for k in KNOWN_FOLDERS), re.IGNORECASE)

RUN_KEYS_MACHINE = (
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
)
RUN_KEYS_USER = (
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
)
NETWORK_NAME_TYPES = {6: "wired", 23: "vpn", 71: "wireless", 243: "mobile_broadband"}

# deleted keys whose removal can be the clean-up of persistence
_DELETED_SERVICE = re.compile(r"(^|\\)controlset\d{3}\\services\\([^\\]+)$", re.IGNORECASE)
_DELETED_TASK = re.compile(r"\\schedule\\taskcache\\tree\\(.+)$", re.IGNORECASE)
_DELETED_IFEO = re.compile(r"\\image file execution options\\([^\\]+)$", re.IGNORECASE)
_DELETED_RUN = re.compile(r"\\currentversion\\(run|runonce)$", re.IGNORECASE)
# with many deleted keys (normal Windows churn), only these reach the timeline
_DELETED_NOTABLE = re.compile(r"\\(services|currentversion\\run|runonce|taskcache|enum\\usbstor|enum\\usb\\"
                              r"|image file execution options|winlogon|uninstall|mounteddevices|bam\\state"
                              r"|appcompatflags|terminal server client|wow6432node\\microsoft\\windows\\currentversion"
                              r"\\run)", re.IGNORECASE)
MAX_DELETED_EVENTS = 200


def _filetime_bytes(raw: object) -> Optional[datetime]:
    if isinstance(raw, (bytes, bytearray)) and len(raw) >= 8:
        return filetime_to_dt(struct.unpack_from("<Q", raw)[0])
    if isinstance(raw, int):
        return filetime_to_dt(raw)
    return None


def _systemtime_dt(raw: object) -> Optional[datetime]:
    """SYSTEMTIME structure (local time of the system) as a naive datetime."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 16:
        return None
    year, month, _dow, day, hour, minute, second, _ms = struct.unpack_from("<8H", raw)
    try:
        return datetime(year, month, day, hour, minute, second) if year else None
    except ValueError:
        return None


def _systemtime(raw: object) -> str:
    value = _systemtime_dt(raw)
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else ""


def _text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if isinstance(value, (bytes, bytearray)):
        return decode_utf16_string(bytes(value)) if len(value) % 2 == 0 else value.hex()
    return str(value)


def _user_from_path(path: Path) -> str:
    return user_from_path(path) or path.parent.name


@register
class RegistryModule(Module):
    name = "registry"
    category = "windows"
    triage = True
    options = [Option("deleted", True, "bool")]

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: p.name.lower() in HIVE_FILENAMES)

    def analyze(self, ctx: AnalysisContext) -> None:
        handlers: dict[str, Callable] = {
            "system": self._system, "software": self._software, "sam": self._sam, "ntuser": self._ntuser,
            "amcache": self._amcache,
        }
        hives: dict[str, list[str]] = {}
        recovered: list[str] = []
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            ctx.progress(rel)
            try:
                with RegistryHive(path) as hive:
                    kind = identify(hive, path.name)
                    hives.setdefault(kind, []).append(rel)
                    ctx.record("hive", {
                        "file": rel, "hive_type": kind, "last_written": dt_or_none_iso(hive.last_written),
                        "dirty": hive.was_dirty, "checksum_ok": hive.checksum_ok, "embedded_name": hive.embedded_name,
                        "recovered_from": ", ".join(hive.recovery.logs) if hive.recovery else "",
                        "log_entries_applied": hive.recovery.entries if hive.recovery else 0,
                        "version": f"{hive.major}.{hive.minor}",
                    })
                    if hive.recovery:
                        recovered.append(rel)
                    elif hive.dirty:
                        ctx.finding("registry.dirty_hive", "low", hive.last_written, file=rel)
                    handler = handlers.get(kind)
                    if handler:
                        handler(ctx, hive, rel, _user_from_path(path))
                    if ctx.options.get("deleted", True):
                        self._deleted(ctx, hive, rel)
            except (RegistryError, OSError, struct.error) as exc:
                ctx.error(rel, exc)
        ctx.summary["hives"] = hives
        if recovered:
            ctx.summary["recovered_hives"] = recovered

    # -- deleted keys and values ---------------------------------------------
    @staticmethod
    def _deleted(ctx: AnalysisContext, hive: RegistryHive, rel: str) -> None:
        try:
            keys, values = recover_deleted(hive)
        except (RegistryError, struct.error, ValueError, IndexError) as exc:
            ctx.error(rel, exc)
            return
        for key in keys:
            ctx.record("registry_deleted_key", {
                "hive": rel, "path": key.path, "partial_path": key.partial,
                "last_written": dt_or_none_iso(key.last_written), "values": len(key.values),
                "value_names": ", ".join(v.name or "(default)" for v in key.values[:20]),
                "still_present": key.still_present, "offset": f"{key.offset:#x}",
            })
            if key.still_present:
                continue  # an older copy of a key that still exists
            if len(keys) <= MAX_DELETED_EVENTS or _DELETED_NOTABLE.search("\\" + key.path):
                ctx.event(key.last_written, "registry_key_deleted", key.path, path=rel)
            data = {(v.name or "").lower(): _text(v.data) for v in key.values}
            service, task, ifeo = (_DELETED_SERVICE.search(key.path), _DELETED_TASK.search(key.path),
                                   _DELETED_IFEO.search(key.path))
            if service:
                image = data.get("imagepath", "")
                severity = "high" if image and (autostart_suspicion(image) or tool_category(image)) else "low"
                ctx.finding("registry.deleted_service", severity, key.last_written, service=service.group(2),
                            image=image or "-", hive=rel)
            elif task:
                ctx.finding("registry.deleted_task", "low", key.last_written, task="\\" + task.group(1), hive=rel)
            elif ifeo and data.get("debugger"):
                ctx.finding("registry.deleted_ifeo", "high", key.last_written, program=ifeo.group(1),
                            debugger=data["debugger"], hive=rel)
        for value in values:
            text = _text(value.data) if value.type in (1, 2, 6, 7) or not isinstance(value.data, bytes) \
                else value.data[:512].hex()
            ctx.record("registry_deleted_value", {
                "hive": rel, "key": value.key_path, "name": value.name, "type": value.type_name,
                "data": text[:4096], "offset": f"{value.offset:#x}",
            })
            command = text if value.type in (1, 2) else ""  # REG_SZ / REG_EXPAND_SZ
            owner_run = bool(value.key_path and _DELETED_RUN.search(value.key_path))
            if command and (owner_run or suspicious_command_rules(command) or launches_interpreter(command)):
                ctx.finding("registry.deleted_suspicious_value", "high" if owner_run else "medium", None,
                            name=value.name or "(default)", data=command[:300], key=value.key_path or "?", hive=rel)
        ctx.summary["deleted_keys"] = ctx.summary.get("deleted_keys", 0) + len(keys)
        ctx.summary["deleted_values"] = ctx.summary.get("deleted_values", 0) + len(values)

    # -- helpers ------------------------------------------------------------
    @staticmethod
    def _autoruns(ctx: AnalysisContext, hive: RegistryHive, rel: str, keys: tuple[str, ...], user: str) -> None:
        for key_path in keys:
            key = hive.open(key_path)
            if key is None:
                continue
            for value in key.values():
                command = _text(value.data)
                ctx.record("autorun", {
                    "file": rel, "user": user, "location": key.path, "name": value.name, "command": command,
                    "key_last_written": dt_or_none_iso(key.last_written),
                })
                reasons = autostart_suspicion(command)
                if reasons:
                    ctx.finding("registry.suspicious_autorun", "high", key.last_written, location=key.path,
                                name=value.name, command=command, reasons=", ".join(reasons), user=user or "-")
            if key.values():
                ctx.event(key.last_written, "autorun_key_modified", f"{key.path} ({len(key.values())})", rel)

    # -- SYSTEM -------------------------------------------------------------
    def _system(self, ctx: AnalysisContext, hive: RegistryHive, rel: str, _user: str) -> None:
        select = hive.open("Select")
        current = select.get("Current", 1) if select else 1
        ccs = hive.open(f"ControlSet{current:03d}") or hive.open("ControlSet001")
        if ccs is None:
            return
        base = ccs.name

        def get(path: str, value: str, default: object = None) -> object:
            key = hive.open(f"{base}\\{path}")
            return key.get(value, default) if key else default

        bias = get("Control\\TimeZoneInformation", "ActiveTimeBias")
        if isinstance(bias, int) and bias > 0x7FFFFFFF:
            bias -= 0x100000000
        shutdown = _filetime_bytes(get("Control\\Windows", "ShutdownTime"))
        info = {
            "file": rel, "control_set": base,
            "computer_name": _text(get("Control\\ComputerName\\ComputerName", "ComputerName")),
            "timezone": _text(get("Control\\TimeZoneInformation", "TimeZoneKeyName")
                              or get("Control\\TimeZoneInformation", "StandardName")),
            "utc_offset_minutes": -bias if isinstance(bias, int) else None,
            "last_shutdown": dt_or_none_iso(shutdown),
        }
        ctx.record("system_info", info)
        ctx.summary["system"] = {k: v for k, v in info.items() if k not in ("file",)}
        ctx.event(shutdown, "system_shutdown", info["computer_name"], rel)

        interfaces = hive.open(f"{base}\\Services\\Tcpip\\Parameters\\Interfaces")
        for key in interfaces.subkeys() if interfaces else []:
            ip = _text(key.get("IPAddress")) or _text(key.get("DhcpIPAddress"))
            if not ip or ip == "0.0.0.0":
                continue
            ctx.record("network_interface", {
                "file": rel, "interface": key.name, "ip_address": ip, "dhcp": bool(key.get("EnableDHCP")),
                "dhcp_server": _text(key.get("DhcpServer")),
                "domain": _text(key.get("DhcpDomain") or key.get("Domain")),
                "dns_servers": _text(key.get("NameServer") or key.get("DhcpNameServer")),
                "key_last_written": dt_or_none_iso(key.last_written),
            })

        self._usb(ctx, hive, rel, base)
        self._services(ctx, hive, rel, base)
        self._shimcache(ctx, hive, rel, base)
        self._bam(ctx, hive, rel, base)

    @staticmethod
    def _usb(ctx: AnalysisContext, hive: RegistryHive, rel: str, base: str) -> None:
        usbstor = hive.open(f"{base}\\Enum\\USBSTOR")
        count = 0
        for device in usbstor.subkeys() if usbstor else []:
            parts = dict(p.split("_", 1) for p in device.name.split("&") if "_" in p)
            for instance in device.subkeys():
                times = {}
                props = instance.subkey(USB_PROPERTIES)
                for code, label in USB_TIMES.items():
                    key = props.subkey(code) if props else None
                    value = key.values()[0] if key and key.values() else None
                    times[label] = _filetime_bytes(value.raw) if value else None
                serial = instance.name.rsplit("&", 1)[0] if instance.name.count("&") == 1 else instance.name
                record = {
                    "file": rel, "vendor": parts.get("Ven", ""), "product": parts.get("Prod", ""),
                    "revision": parts.get("Rev", ""), "serial": serial,
                    "friendly_name": _text(instance.get("FriendlyName")),
                    "first_install": dt_or_none_iso(times["first_install"]),
                    "last_connected": dt_or_none_iso(times["last_arrival"]),
                    "last_removed": dt_or_none_iso(times["last_removal"]),
                    "key_last_written": dt_or_none_iso(instance.last_written),
                }
                ctx.record("usb_device", record)
                count += 1
                label = record["friendly_name"] or f"{record['vendor']} {record['product']}".strip()
                details = f"{label} serial={serial}"
                ctx.event(times["first_install"], "usb_first_connected", details, rel, "low")
                ctx.event(times["last_arrival"], "usb_connected", details, rel)
                ctx.event(times["last_removal"], "usb_disconnected", details, rel)
                ctx.finding("registry.usb_device", "info", times["first_install"] or instance.last_written,
                            device=label, serial=serial, first=record["first_install"] or "-",
                            last=record["last_connected"] or "-")
        ctx.summary["usb_devices"] = count

    @staticmethod
    def _services(ctx: AnalysisContext, hive: RegistryHive, rel: str, base: str) -> None:
        services = hive.open(f"{base}\\Services")
        count = 0
        for key in services.subkeys() if services else []:
            image = _text(key.get("ImagePath"))
            params = key.subkey("Parameters")
            service_dll = _text(params.get("ServiceDll")) if params else ""
            if not image and not service_dll:
                continue
            start = key.get("Start")
            count += 1
            ctx.record("service", {
                "file": rel, "name": key.name, "display_name": _text(key.get("DisplayName")),
                "image_path": image, "service_dll": service_dll, "start": start, "type": key.get("Type"),
                "account": _text(key.get("ObjectName")), "key_last_written": dt_or_none_iso(key.last_written),
            })
            if start in (0, 1, 2):  # boot, system, automatic
                reasons = autostart_suspicion(image) + [r for r in autostart_suspicion(service_dll)
                                                         if r != "script_interpreter"]
                if reasons:
                    ctx.finding("registry.suspicious_service", "high", key.last_written, service=key.name,
                                image=image or service_dll, reasons=", ".join(sorted(set(reasons))))
                    ctx.event(key.last_written, "service_key_modified", f"{key.name}: {image or service_dll}",
                              rel, "high")
        ctx.summary["services"] = count

    @staticmethod
    def _shimcache(ctx: AnalysisContext, hive: RegistryHive, rel: str, base: str) -> None:
        key = hive.open(f"{base}\\Control\\Session Manager\\AppCompatCache")
        value = key.value("AppCompatCache") if key else None
        if value is None:
            return
        try:
            fmt, entries = parse_appcompatcache(value.raw)
        except (ShimCacheError, struct.error) as exc:
            ctx.error(f"{rel}:AppCompatCache", exc)
            return
        for entry in entries:
            ctx.record("shimcache", {
                "file": rel, "position": entry.position, "path": entry.path,
                "last_modified": dt_or_none_iso(entry.last_modified), "executed": entry.executed, "format": fmt,
            })
            ctx.event(entry.last_modified, "shimcache_entry", entry.path, rel)
        ctx.summary["shimcache_entries"] = len(entries)

    @staticmethod
    def _bam(ctx: AnalysisContext, hive: RegistryHive, rel: str, base: str) -> None:
        count = 0
        for path in ("Services\\bam\\State\\UserSettings", "Services\\bam\\UserSettings"):
            settings = hive.open(f"{base}\\{path}")
            for sid_key in settings.subkeys() if settings else []:
                for value in sid_key.values():
                    when = _filetime_bytes(value.raw) if value.type == 3 else None
                    if when is None:
                        continue
                    count += 1
                    ctx.record("bam", {"file": rel, "sid": sid_key.name, "path": value.name,
                                       "last_execution": iso(when)})
                    ctx.event(when, "program_executed", f"BAM {sid_key.name}: {value.name}", rel)
                    if is_suspicious_location(value.name):
                        ctx.finding("registry.suspicious_execution", "medium", when, source="BAM",
                                    path=value.name, user=sid_key.name)
        ctx.summary["bam_entries"] = count

    # -- SOFTWARE -----------------------------------------------------------
    def _software(self, ctx: AnalysisContext, hive: RegistryHive, rel: str, _user: str) -> None:
        cv = hive.open("Microsoft\\Windows NT\\CurrentVersion")
        if cv is not None:
            install_date = cv.get("InstallDate")
            installed = _filetime_bytes(cv.get("InstallTime"))
            if installed is None and isinstance(install_date, int) and install_date:
                installed = datetime.fromtimestamp(install_date, tz=timezone.utc)
            product = _text(cv.get("ProductName"))
            build = _text(cv.get("CurrentBuild") or cv.get("CurrentBuildNumber"))
            if build.isdigit() and int(build) >= 22000 and "Windows 10" in product:
                product = product.replace("Windows 10", "Windows 11")
            info = {
                "file": rel, "product_name": product, "edition": _text(cv.get("EditionID")),
                "display_version": _text(cv.get("DisplayVersion") or cv.get("ReleaseId")),
                "build": f"{build}.{cv.get('UBR')}" if cv.get("UBR") is not None else build,
                "installed": dt_or_none_iso(installed),
                "registered_owner": _text(cv.get("RegisteredOwner")),
                "registered_organization": _text(cv.get("RegisteredOrganization")),
            }
            ctx.record("os_info", info)
            ctx.summary["os"] = {k: v for k, v in info.items() if k != "file"}
            ctx.event(installed, "os_installed", f"{product} {info['build']}", rel)

            winlogon = cv.subkey("Winlogon")
            if winlogon is not None:
                expected = {"Shell": "explorer.exe", "Userinit": "c:\\windows\\system32\\userinit.exe,"}
                for name, normal in expected.items():
                    value = _text(winlogon.get(name)).strip()
                    if value and value.lower().rstrip(",") != normal.rstrip(","):
                        ctx.finding("registry.winlogon_modified", "high", winlogon.last_written, value_name=name,
                                    value=value)
            ifeo = cv.subkey("Image File Execution Options")
            for key in ifeo.subkeys() if ifeo else []:
                debugger = _text(key.get("Debugger"))
                if debugger:
                    severity = "critical" if key.name.lower() in (
                        "sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe",
                        "atbroker.exe") else "high"
                    ctx.finding("registry.ifeo_debugger", severity, key.last_written, program=key.name,
                                debugger=debugger)
            windows = cv.subkey("Windows")
            appinit = _text(windows.get("AppInit_DLLs")).strip() if windows else ""
            if appinit and windows.get("LoadAppInit_DLLs") == 1:
                ctx.finding("registry.appinit_dlls", "high", windows.last_written, dlls=appinit)

        self._autoruns(ctx, hive, rel, RUN_KEYS_MACHINE, "")

        for base in ("Microsoft\\Windows\\CurrentVersion\\Uninstall",
                     "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"):
            uninstall = hive.open(base)
            for key in uninstall.subkeys() if uninstall else []:
                name = _text(key.get("DisplayName"))
                if not name:
                    continue
                ctx.record("installed_program", {
                    "file": rel, "name": name, "version": _text(key.get("DisplayVersion")),
                    "publisher": _text(key.get("Publisher")), "install_date": _text(key.get("InstallDate")),
                    "install_location": _text(key.get("InstallLocation")),
                    "key_last_written": dt_or_none_iso(key.last_written),
                })
                ctx.event(key.last_written, "program_installed", name, rel)

        profiles = hive.open("Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles")
        zone = WindowsTimeZone.from_evidence(ctx.target) if profiles else None
        for key in profiles.subkeys() if profiles else []:
            created, connected = _systemtime_dt(key.get("DateCreated")), _systemtime_dt(key.get("DateLastConnected"))
            created_utc = zone.to_utc(created) if zone and created else None
            connected_utc = zone.to_utc(connected) if zone and connected else None
            name = _text(key.get("ProfileName"))
            ctx.record("network_profile", {
                "file": rel, "name": name, "description": _text(key.get("Description")),
                "type": NETWORK_NAME_TYPES.get(key.get("NameType"), _text(key.get("NameType"))),
                "created_local": _systemtime(key.get("DateCreated")),
                "last_connected_local": _systemtime(key.get("DateLastConnected")),
                "created": dt_or_none_iso(created_utc), "last_connected": dt_or_none_iso(connected_utc),
            })
            ctx.event(created_utc, "network_first_connected", name, rel)
            ctx.event(connected_utc, "network_last_connected", name, rel)

    # -- SAM ----------------------------------------------------------------
    @staticmethod
    def _sam(ctx: AnalysisContext, hive: RegistryHive, rel: str, _user: str) -> None:
        names = hive.open("SAM\\Domains\\Account\\Users\\Names")
        for name_key in names.subkeys() if names else []:
            default = name_key.value("")
            rid = default.type if default is not None else None
            record = {"file": rel, "username": name_key.name, "rid": rid,
                      "created": dt_or_none_iso(name_key.last_written)}
            user_key = hive.open(f"SAM\\Domains\\Account\\Users\\{rid:08X}") if rid is not None else None
            f_value = user_key.get("F") if user_key else None
            if isinstance(f_value, bytes) and len(f_value) >= 68:
                last_logon, pwd_set, _expires, last_failed = struct.unpack_from("<QQQQ", f_value, 8)
                last_logon, last_failed = filetime_to_dt(last_logon), filetime_to_dt(last_failed)
                pwd_set = filetime_to_dt(pwd_set)
                acb = struct.unpack_from("<H", f_value, 56)[0]
                failed, logons = struct.unpack_from("<HH", f_value, 64)
                record.update({
                    "last_logon": dt_or_none_iso(last_logon), "password_last_set": dt_or_none_iso(pwd_set),
                    "last_failed_logon": dt_or_none_iso(last_failed), "logon_count": logons,
                    "failed_logon_count": failed, "disabled": bool(acb & 0x0001),
                    "password_not_required": bool(acb & 0x0004),
                })
                ctx.event(last_logon, "last_logon", name_key.name, rel)
                ctx.event(pwd_set, "password_changed", name_key.name, rel)
                if rid == 501 and not acb & 0x0001:
                    ctx.finding("registry.guest_enabled", "low", name_key.last_written)
                if acb & 0x0004 and not acb & 0x0001:
                    ctx.finding("registry.password_not_required", "medium", name_key.last_written,
                                user=name_key.name)
            ctx.record("user_account", record)
            ctx.event(name_key.last_written, "account_created", f"{name_key.name} (RID {rid})", rel)

    # -- NTUSER.DAT ---------------------------------------------------------
    def _ntuser(self, ctx: AnalysisContext, hive: RegistryHive, rel: str, user: str) -> None:
        explorer = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
        self._userassist(ctx, hive, rel, user, explorer)
        self._recent_docs(ctx, hive, rel, user, explorer)

        run_mru = hive.open(f"{explorer}\\RunMRU")
        if run_mru is not None:
            order = _text(run_mru.get("MRUList"))
            for position, letter in enumerate(order, 1):
                command = _text(run_mru.get(letter))
                if command.endswith("\\1"):
                    command = command[:-2]
                ctx.record("run_mru", {"file": rel, "user": user, "order": position, "command": command})
                rules = suspicious_command_rules(command)
                if rules:
                    ctx.finding("registry.suspicious_runmru", "high",
                                run_mru.last_written if position == 1 else None, user=user, command=command,
                                rules=", ".join(rules))
            if order:
                latest = _text(run_mru.get(order[0]))
                latest = latest[:-2] if latest.endswith("\\1") else latest
                ctx.event(run_mru.last_written, "run_dialog", f"{user}: {latest}", rel)

        typed = hive.open(f"{explorer}\\TypedPaths")
        for value in typed.values() if typed else []:
            ctx.record("typed_path", {"file": rel, "user": user, "name": value.name, "path": _text(value.data)})

        wheel = hive.open(f"{explorer}\\WordWheelQuery")
        for value in wheel.values() if wheel else []:
            if value.name.isdigit():
                ctx.record("search_term", {"file": rel, "user": user, "term": _text(value.raw)})

        self._autoruns(ctx, hive, rel, RUN_KEYS_USER, user)

        servers = hive.open("Software\\Microsoft\\Terminal Server Client\\Servers")
        for key in servers.subkeys() if servers else []:
            ctx.record("rdp_destination", {"file": rel, "user": user, "server": key.name,
                                            "username_hint": _text(key.get("UsernameHint")),
                                            "key_last_written": dt_or_none_iso(key.last_written)})
            ctx.event(key.last_written, "rdp_outbound", f"{user} -> {key.name}", rel)

    @staticmethod
    def _userassist(ctx: AnalysisContext, hive: RegistryHive, rel: str, user: str, explorer: str) -> None:
        root = hive.open(f"{explorer}\\UserAssist")
        for guid_key in root.subkeys() if root else []:
            count_key = guid_key.subkey("Count")
            for value in count_key.values() if count_key else []:
                program = codecs.decode(value.name, "rot_13")
                if program.startswith("UEME_CTL"):
                    continue
                program = _KNOWN_FOLDER_RE.sub(lambda m: KNOWN_FOLDERS[m.group(0).upper()], program)
                raw = value.raw
                if len(raw) >= 68:
                    runs, focus, focus_ms = struct.unpack_from("<III", raw, 4)
                    last_run = filetime_to_dt(struct.unpack_from("<Q", raw, 60)[0])
                elif len(raw) >= 16:
                    runs = max(0, struct.unpack_from("<I", raw, 4)[0] - 5)
                    focus = focus_ms = 0
                    last_run = filetime_to_dt(struct.unpack_from("<Q", raw, 8)[0])
                else:
                    continue
                ctx.record("userassist", {
                    "file": rel, "user": user, "program": program, "run_count": runs, "focus_count": focus,
                    "focus_seconds": round(focus_ms / 1000, 1), "last_run": dt_or_none_iso(last_run),
                })
                ctx.event(last_run, "program_executed", f"UserAssist {user}: {program} (x{runs})", rel)
                if is_suspicious_location(program) and Path(program.replace("\\", "/")).suffix.lower().lstrip(".") \
                        in EXECUTABLE_EXTENSIONS:
                    ctx.finding("registry.suspicious_execution", "medium", last_run, source="UserAssist",
                                path=program, user=user)

    @staticmethod
    def _recent_docs(ctx: AnalysisContext, hive: RegistryHive, rel: str, user: str, explorer: str) -> None:
        root = hive.open(f"{explorer}\\RecentDocs")
        if root is None:
            return
        for key in [root] + root.subkeys():
            mru = key.get("MRUListEx")
            order = []
            if isinstance(mru, bytes):
                order = [i for (i,) in struct.iter_unpack("<I", mru[:len(mru) // 4 * 4]) if i != 0xFFFFFFFF]
            extension = "" if key is root else key.name
            for position, index in enumerate(order, 1):
                value = key.value(str(index))
                if value is None or not isinstance(value.raw, bytes):
                    continue
                name = decode_utf16_string(value.raw)
                if key is root:
                    ctx.record("recent_doc", {"file": rel, "user": user, "order": position, "name": name})
                if position == 1:
                    ctx.event(key.last_written, "recent_doc_opened",
                              f"{user}: {name}" + (f" [{extension}]" if extension else ""), rel)

    # -- Amcache.hve -------------------------------------------------------------
    @staticmethod
    def _amcache(ctx: AnalysisContext, hive: RegistryHive, rel: str, _user: str) -> None:
        count = 0
        inventory = hive.open("Root\\InventoryApplicationFile")
        for key in inventory.subkeys() if inventory else []:
            path = _text(key.get("LowerCaseLongPath"))
            sha1 = _text(key.get("FileId"))
            sha1 = sha1[4:] if sha1.startswith("0000") and len(sha1) == 44 else sha1
            count += 1
            ctx.record("amcache_file", {
                "file": rel, "path": path, "sha1": sha1, "name": _text(key.get("Name")),
                "publisher": _text(key.get("Publisher")), "product": _text(key.get("ProductName")),
                "version": _text(key.get("Version")), "link_date": _text(key.get("LinkDate")),
                "size": key.get("Size"), "key_last_written": dt_or_none_iso(key.last_written),
            })
            ctx.event(key.last_written, "program_present", f"Amcache: {path} sha1={sha1}", rel)
            if is_suspicious_location(path):
                ctx.finding("registry.suspicious_execution", "low", key.last_written, source="Amcache",
                            path=path, user="-")
        legacy = hive.open("Root\\File")
        for volume in legacy.subkeys() if legacy else []:
            for key in volume.subkeys():
                path = _text(key.get("15"))
                sha1 = _text(key.get("101"))
                sha1 = sha1[4:] if sha1.startswith("0000") and len(sha1) == 44 else sha1
                count += 1
                ctx.record("amcache_file", {"file": rel, "path": path, "sha1": sha1,
                                            "key_last_written": dt_or_none_iso(key.last_written)})
                ctx.event(key.last_written, "program_present", f"Amcache: {path} sha1={sha1}", rel)
        programs = hive.open("Root\\InventoryApplication")
        for key in programs.subkeys() if programs else []:
            ctx.record("amcache_program", {
                "file": rel, "name": _text(key.get("Name")), "version": _text(key.get("Version")),
                "publisher": _text(key.get("Publisher")), "install_date": _text(key.get("InstallDate")),
                "root_dir": _text(key.get("RootDirPath")), "key_last_written": dt_or_none_iso(key.last_written),
            })
        ctx.summary["amcache_files"] = count
