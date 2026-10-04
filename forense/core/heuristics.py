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
