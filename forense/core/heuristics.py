"""Shared detection heuristics for suspicious paths and command lines.

Rules are deliberately conservative and named, so every finding can state
exactly which rule matched. They are triage aids, not verdicts: an analyst
must always confirm them.
"""

from __future__ import annotations

import re

# (rule name, pattern) evaluated case-insensitively against a command line.
COMMAND_RULES: tuple[tuple[str, re.Pattern], ...] = tuple(
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in (
        ("powershell_encoded", r"\b(powershell|pwsh)(\.exe)?\b.*\s[-/]e(c|n[a-z]*)?\s+[a-z0-9+/=]{16,}"),
        ("download_cradle", r"downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|start-bitstransfer|\biwr\s+https?:"),
        ("invoke_expression", r"\b(iex|invoke-expression)\b"),
        ("base64_decode", r"frombase64string"),
        ("amsi_bypass", r"amsiutils|amsiinitfailed|amsiscanbuffer"),
        ("credential_dumping", r"mimikatz|sekurlsa|lsadump|procdump.*lsass|comsvcs(\.dll)?.*minidump"),
        ("hidden_window", r"\s-w(in|indow|indowstyle)?\s+h(idden)?\b"),
        ("execution_policy_bypass", r"-exec(utionpolicy)?\s+bypass|-ep\s+bypass"),
        ("certutil_download", r"certutil(\.exe)?.*(-urlcache|-verifyctl|-decode)"),
        ("mshta_remote", r"mshta(\.exe)?\s+[\"']?(https?|javascript|vbscript):"),
        ("rundll32_script", r"rundll32(\.exe)?.*(javascript:|url\.dll|advpack\.dll.*launchinf)"),
        ("regsvr32_remote", r"regsvr32(\.exe)?.*/i:\s*https?"),
        ("bitsadmin_transfer", r"bitsadmin(\.exe)?.*/(transfer|addfile)"),
        ("shadow_copy_deletion", r"vssadmin(\.exe)?.*delete\s+shadows|wmic(\.exe)?.*shadowcopy.*delete|wbadmin(\.exe)?.*delete\s+(catalog|systemstatebackup)"),
        ("recovery_disabled", r"bcdedit(\.exe)?.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"),
        ("log_clearing", r"wevtutil(\.exe)?\s+(cl|clear-log)\b|clear-eventlog"),
        ("defender_tampering", r"set-mppreference.*-disable|add-mppreference.*-exclusion"),
        ("user_creation", r"\bnet1?(\.exe)?\s+user\s+\S+\s+\S+\s+/add"),
        ("admin_group_add", r"\bnet1?(\.exe)?\s+localgroup\s+administra\w*\s+\S+\s+/add"),
        ("remote_execution", r"psexec|paexec|wmic(\.exe)?\s+/node:|winrs(\.exe)?\s"),
        ("history_clearing", r"clear-history|remove-item.*(consolehost_history|psreadline)"
                             r"|set-psreadlineoption.*historysavestyle\s+savenothing"),
    )
)

_SUSPICIOUS_LOCATIONS = re.compile(
    r"\\(appdata\\local\\temp|windows\\temp|users\\public|perflogs|\$recycle\.bin|appdata\\roaming"
    r"|downloads)\\"
    r"|\\programdata\\[^\\]+\.(exe|dll|ps1|bat|cmd|vbs|js|hta)\b",
    re.IGNORECASE,
)
_SHELL_LAUNCHER = re.compile(r"((\bcmd(\.exe)?|%comspec%)\s+/[ck]|\b(powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\b)",
                             re.IGNORECASE)

EXECUTABLE_EXTENSIONS = frozenset(
    "exe dll scr com pif cpl sys msi msp ps1 psm1 bat cmd vbs vbe js jse wsf wsh hta lnk jar iso img vhd vhdx".split()
)
ARCHIVE_EXTENSIONS = frozenset("zip rar 7z gz tgz tar bz2 xz cab".split())


def suspicious_command_rules(command: str) -> list[str]:
    """Names of every command-line rule matched by ``command``."""
    if not command:
        return []
    return [name for name, pattern in COMMAND_RULES if pattern.search(command)]


def is_suspicious_location(path: str) -> bool:
    """True for user-writable or staging locations commonly abused by malware."""
    return bool(path) and bool(_SUSPICIOUS_LOCATIONS.search(path.replace("/", "\\")))


def launches_interpreter(command: str) -> bool:
    return bool(command) and bool(_SHELL_LAUNCHER.search(command))


def autostart_suspicion(command: str) -> list[str]:
    """Reasons why an autostart entry (service, Run key, task) deserves attention."""
    reasons = suspicious_command_rules(command)
    if is_suspicious_location(command):
        reasons.append("suspicious_location")
    if launches_interpreter(command):
        reasons.append("script_interpreter")
    return reasons

# Executables whose mere execution deserves attention.
ATTACK_TOOLS = frozenset("""
mimikatz.exe mimikatz64.exe mimidrv.sys psexec.exe psexec64.exe psexesvc.exe paexec.exe procdump.exe procdump64.exe
wce.exe pwdump.exe pwdump7.exe gsecdump.exe fgdump.exe lazagne.exe rubeus.exe sharphound.exe bloodhound.exe
adfind.exe kerbrute.exe nanodump.exe safetykatz.exe sharpkatz.exe secretsdump.exe wmiexec.exe smbexec.exe
crackmapexec.exe cme.exe netscan.exe advanced_ip_scanner.exe advanced_port_scanner.exe angryip.exe nmap.exe
masscan.exe rclone.exe megacmd.exe megasync.exe ngrok.exe chisel.exe plink.exe cobaltstrike.exe beacon.exe
""".split())
REMOTE_ACCESS_TOOLS = frozenset("""
anydesk.exe teamviewer.exe teamviewer_service.exe screenconnect.windowsclient.exe screenconnect.clientservice.exe
connectwisecontrol.client.exe atera_agent.exe ateraagent.exe splashtop.exe srservice.exe rustdesk.exe
remoteutilities.exe rutserv.exe rfusclient.exe netsupport.exe client32.exe logmein.exe lmiguardiansvc.exe
ammyy_admin.exe aa_v3.exe radmin.exe tightvnc.exe tvnserver.exe winvnc.exe vncviewer.exe ultravnc.exe
""".split())


def tool_category(executable: str) -> str | None:
    """``attack_tool`` / ``remote_access`` for well-known offensive or remote-control executables."""
    name = executable.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    if name in ATTACK_TOOLS:
        return "attack_tool"
    if name in REMOTE_ACCESS_TOOLS:
        return "remote_access"
    return None


_DEVICE_PREFIX = re.compile(r"^\\(volume\{[^}]*\}|device\\harddiskvolume\d+|\?\?\\[a-z]:)", re.IGNORECASE)


def strip_device(path: str) -> str:
    r"""``\VOLUME{...}\USERS\X`` or ``\Device\HarddiskVolume3\Users\X`` -> ``\USERS\X``."""
    return _DEVICE_PREFIX.sub("", path or "")


# Core Windows binaries that malware imitates (svchost.exe in C:\Users\Public, "scvhost.exe"...).
SYSTEM_BINARIES = (
    "smss.exe", "wininit.exe", "winlogon.exe", "csrss.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe",
    "spoolsv.exe", "searchindexer.exe", "runtimebroker.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe",
    "explorer.exe", "taskhost.exe", "sihost.exe", "ctfmon.exe", "dwm.exe", "fontdrvhost.exe",
)


def _distance(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def lookalike_of(name: str) -> str | None:
    """System binary that ``name`` imitates with a small typo (scvhost.exe -> svchost.exe)."""
    name = name.lower()
    if name in SYSTEM_BINARIES or len(name) < 7:
        return None
    for real in SYSTEM_BINARIES:
        if abs(len(real) - len(name)) <= 2 and 0 < _distance(name, real) <= (1 if len(real) <= 9 else 2):
            return real
    return None
