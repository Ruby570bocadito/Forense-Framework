"""MITRE ATT&CK view of a case: findings mapped to techniques and tactics, and the incident storyline.

Mapping sources, combined for every finding:

* the finding code (``tasks.suspicious_task`` -> T1053.005 Scheduled Task);
* the command-line rules it names (``rules``/``reasons``: ``download_cradle`` -> T1105);
* the offensive tool it mentions (mimikatz -> T1003, rclone -> T1567.002);
* the ATT&CK tags of Sigma rules (``techniques``).

The mapping marks *where to look*, like the findings themselves: a technique is
"observed" when at least one finding supports it, and every cell links back to
those findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from forense.core.heuristics import REMOTE_ACCESS_TOOLS
from forense.i18n import t

# Enterprise tactics in kill-chain order: (short name, ATT&CK id)
TACTICS = (
    ("initial-access", "TA0001"), ("execution", "TA0002"), ("persistence", "TA0003"),
    ("privilege-escalation", "TA0004"), ("defense-evasion", "TA0005"), ("credential-access", "TA0006"),
    ("discovery", "TA0007"), ("lateral-movement", "TA0008"), ("collection", "TA0009"),
    ("command-and-control", "TA0011"), ("exfiltration", "TA0010"), ("impact", "TA0040"),
)
TACTIC_ORDER = {name: index for index, (name, _) in enumerate(TACTICS)}

# technique -> (name, tactics)
TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1003": ("OS Credential Dumping", ("credential-access",)),
    "T1003.001": ("LSASS Memory", ("credential-access",)),
    "T1003.006": ("DCSync", ("credential-access",)),
    "T1014": ("Rootkit", ("defense-evasion",)),
    "T1021.001": ("Remote Desktop Protocol", ("lateral-movement",)),
    "T1021.002": ("SMB/Windows Admin Shares", ("lateral-movement",)),
    "T1027": ("Obfuscated Files or Information", ("defense-evasion",)),
    "T1036.005": ("Masquerading: Match Legitimate Name or Location", ("defense-evasion",)),
    "T1036.008": ("Masquerading: Masquerade File Type", ("defense-evasion",)),
    "T1046": ("Network Service Discovery", ("discovery",)),
    "T1047": ("Windows Management Instrumentation", ("execution",)),
    "T1048": ("Exfiltration Over Alternative Protocol", ("exfiltration",)),
    "T1052.001": ("Exfiltration over USB", ("exfiltration",)),
    "T1053.005": ("Scheduled Task", ("execution", "persistence", "privilege-escalation")),
    "T1055": ("Process Injection", ("defense-evasion", "privilege-escalation")),
    "T1059": ("Command and Scripting Interpreter", ("execution",)),
    "T1059.001": ("PowerShell", ("execution",)),
    "T1070.001": ("Clear Windows Event Logs", ("defense-evasion",)),
    "T1070.003": ("Clear Command History", ("defense-evasion",)),
    "T1070.004": ("File Deletion", ("defense-evasion",)),
    "T1070.006": ("Timestomp", ("defense-evasion",)),
    "T1070.009": ("Clear Persistence", ("defense-evasion",)),
    "T1112": ("Modify Registry", ("defense-evasion", "persistence")),
    "T1071": ("Application Layer Protocol", ("command-and-control",)),
    "T1078": ("Valid Accounts", ("initial-access", "persistence", "defense-evasion")),
    "T1078.001": ("Default Accounts", ("initial-access", "persistence", "defense-evasion")),
    "T1087.002": ("Domain Account Discovery", ("discovery",)),
    "T1098": ("Account Manipulation", ("persistence", "privilege-escalation")),
    "T1105": ("Ingress Tool Transfer", ("command-and-control",)),
    "T1110": ("Brute Force", ("credential-access",)),
    "T1133": ("External Remote Services", ("initial-access", "persistence")),
    "T1135": ("Network Share Discovery", ("discovery",)),
    "T1136.001": ("Create Account: Local Account", ("persistence",)),
    "T1197": ("BITS Jobs", ("defense-evasion", "persistence")),
    "T1204.002": ("User Execution: Malicious File", ("execution",)),
    "T1218.005": ("Mshta", ("defense-evasion",)),
    "T1218.010": ("Regsvr32", ("defense-evasion",)),
    "T1218.011": ("Rundll32", ("defense-evasion",)),
    "T1219": ("Remote Access Software", ("command-and-control",)),
    "T1482": ("Domain Trust Discovery", ("discovery",)),
    "T1485": ("Data Destruction", ("impact",)),
    "T1486": ("Data Encrypted for Impact", ("impact",)),
    "T1490": ("Inhibit System Recovery", ("impact",)),
    "T1543.003": ("Windows Service", ("persistence", "privilege-escalation")),
    "T1546.003": ("WMI Event Subscription", ("persistence", "privilege-escalation")),
    "T1546.008": ("Accessibility Features", ("persistence", "privilege-escalation")),
    "T1546.010": ("AppInit DLLs", ("persistence", "privilege-escalation")),
    "T1546.012": ("Image File Execution Options Injection", ("persistence", "privilege-escalation")),
    "T1547.001": ("Registry Run Keys / Startup Folder", ("persistence", "privilege-escalation")),
    "T1547.004": ("Winlogon Helper DLL", ("persistence", "privilege-escalation")),
    "T1550.002": ("Pass the Hash", ("defense-evasion", "lateral-movement")),
    "T1558": ("Steal or Forge Kerberos Tickets", ("credential-access",)),
    "T1558.003": ("Kerberoasting", ("credential-access",)),
    "T1560.001": ("Archive via Utility", ("collection",)),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", ("defense-evasion",)),
    "T1562.002": ("Disable Windows Event Logging", ("defense-evasion",)),
    "T1564.003": ("Hidden Window", ("defense-evasion",)),
    "T1566.001": ("Spearphishing Attachment", ("initial-access",)),
    "T1567": ("Exfiltration Over Web Service", ("exfiltration",)),
    "T1567.002": ("Exfiltration to Cloud Storage", ("exfiltration",)),
    "T1569.002": ("Service Execution", ("execution",)),
    "T1572": ("Protocol Tunneling", ("command-and-control",)),
}

BY_CODE: dict[str, tuple[str, ...]] = {
    "browser.executable_download": ("T1105",), "browser.dangerous_download": ("T1105",),
    "browser.suspicious_domain": ("T1567",),
    "evtx.audit_policy_changed": ("T1562.002",), "evtx.brute_force": ("T1110",),
    "evtx.brute_force_success": ("T1110", "T1078"), "evtx.defender_disabled": ("T1562.001",),
    "evtx.defender_exclusion": ("T1562.001",), "evtx.log_cleared": ("T1070.001",),
    "evtx.privileged_group_add": ("T1098",), "evtx.rdp_public": ("T1133", "T1021.001"),
    "evtx.service_installed": ("T1543.003",), "evtx.suspicious_command": ("T1059",),
    "evtx.suspicious_powershell": ("T1059.001",), "evtx.task_created": ("T1053.005",),
    "evtx.user_created": ("T1136.001",), "evtx.wmi_persistence": ("T1546.003",),
    "file.content_mismatch": ("T1036.008",), "file.missing_signature": ("T1036.008",),
    "jumplist.rdp_connection": ("T1021.001",), "lnk.startup_item": ("T1547.001",),
    "lnk.suspicious_arguments": ("T1059",),
    "memory.duplicate_system_process": ("T1036.005",), "memory.hidden_process": ("T1014",),
    "memory.injected_code": ("T1055",), "memory.lookalike_name": ("T1036.005",),
    "memory.masquerading": ("T1036.005",), "memory.remote_access": ("T1219",),
    "memory.suspicious_child": ("T1204.002", "T1059"), "memory.suspicious_cmdline": ("T1059",),
    "memory.suspicious_connection": ("T1071",), "memory.suspicious_service": ("T1543.003",),
    "memory.unexpected_parent": ("T1036.005",),
    "mft.downloaded_executable": ("T1105",), "mft.timestomping": ("T1070.006",),
    "prefetch.remote_access": ("T1219",), "psreadline.suspicious_command": ("T1059.001",),
    "registry.appinit_dlls": ("T1546.010",), "registry.guest_enabled": ("T1078.001",),
    "registry.ifeo_debugger": ("T1546.012",), "registry.suspicious_autorun": ("T1547.001",),
    "registry.deleted_service": ("T1070.009", "T1543.003"), "registry.deleted_task": ("T1070.009", "T1053.005"),
    "registry.deleted_ifeo": ("T1070.009", "T1546.012"), "registry.deleted_suspicious_value": ("T1070.009", "T1112"),
    "registry.suspicious_runmru": ("T1059",), "registry.suspicious_service": ("T1543.003",),
    "registry.winlogon_modified": ("T1547.004",), "shellbags.admin_share": ("T1021.002",),
    "srum.large_upload": ("T1048",), "tasks.suspicious_task": ("T1053.005",),
    "usnjrnl.evtx_deleted": ("T1070.001",), "usnjrnl.executable_created_deleted": ("T1070.004",),
    "usnjrnl.mass_deletion": ("T1485",), "usnjrnl.mass_rename": ("T1486",), "usnjrnl.prefetch_deleted": ("T1070.004",),
    "usnjrnl.remote_access": ("T1219",), "wintimeline.remote_access": ("T1219",),
    "wintimeline.suspicious_clipboard": ("T1059",), "wmi.persistence": ("T1546.003",),
    "recyclebin.deleted_archive": ("T1560.001",), "recyclebin.deleted_executable": ("T1070.004",),
}

BY_RULE = {
    "powershell_encoded": ("T1059.001", "T1027"), "download_cradle": ("T1105",), "invoke_expression": ("T1059.001",),
    "base64_decode": ("T1027",), "amsi_bypass": ("T1562.001",), "credential_dumping": ("T1003",),
    "hidden_window": ("T1564.003",), "execution_policy_bypass": ("T1059.001",), "certutil_download": ("T1105",),
    "mshta_remote": ("T1218.005",), "rundll32_script": ("T1218.011",), "regsvr32_remote": ("T1218.010",),
    "bitsadmin_transfer": ("T1197",), "shadow_copy_deletion": ("T1490",), "recovery_disabled": ("T1490",),
    "log_clearing": ("T1070.001",), "defender_tampering": ("T1562.001",), "user_creation": ("T1136.001",),
    "admin_group_add": ("T1098",), "remote_execution": ("T1569.002", "T1021.002"),
    "history_clearing": ("T1070.003",),
}

TOOLS = {
    "T1003": ("mimikatz", "procdump", "nanodump", "lazagne", "pwdump", "wce", "gsecdump", "fgdump", "secretsdump",
              "safetykatz", "sharpkatz", "mimidrv"),
    "T1558": ("rubeus", "kerbrute"),
    "T1087.002": ("sharphound", "bloodhound", "adfind"),
    "T1021.002": ("psexec", "paexec", "psexesvc", "wmiexec", "smbexec", "crackmapexec", "cme"),
    "T1046": ("netscan", "advanced_ip_scanner", "advanced_port_scanner", "angryip", "nmap", "masscan"),
    "T1567.002": ("rclone", "megacmd", "megasync"),
    "T1572": ("ngrok", "chisel", "plink"),
    "T1071": ("cobaltstrike", "beacon"),
}
_TOOL_NAMES = re.compile(r"(?<![a-z0-9_])(" + "|".join(sorted({n for names in TOOLS.values() for n in names},
                                                              key=len, reverse=True)) + r")(?![a-z0-9_])")
_REMOTE_NAMES = re.compile(r"(?<![a-z0-9_])(" + "|".join(re.escape(n[:-4]) for n in sorted(
    REMOTE_ACCESS_TOOLS, key=len, reverse=True)) + r")(?![a-z0-9_])")


def techniques_for(finding: dict) -> list[str]:
    """ATT&CK techniques supported by one finding."""
    code, params = finding.get("code", ""), finding.get("params") or {}
    found: list[str] = list(BY_CODE.get(code, ()))
    for key in ("rules", "reasons"):
        for rule in str(params.get(key) or "").split(","):
            found += BY_RULE.get(rule.strip(), ())
    if code.endswith((".attack_tool", ".remote_access")) or code in ("psreadline.suspicious_command",
                                                                    "evtx.suspicious_command", "defender.detection",
                                                                    "evtx.defender_detection"):
        text = " ".join(str(v) for v in params.values()).lower()
        for match in _TOOL_NAMES.finditer(text):
            found += [tech for tech, names in TOOLS.items() if match.group(1) in names]
        if code.endswith(".remote_access") or _REMOTE_NAMES.search(text):
            found.append("T1219")
    if code == "registry.ifeo_debugger" and str(params.get("program", "")).lower() in (
            "sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe"):
        found.append("T1546.008")
    if code == "sigma.match":
        found += [tech.strip().upper() for tech in str(params.get("techniques") or "").split(",")
                  if tech.strip().upper().startswith("T")]
    return list(dict.fromkeys(tech for tech in found if tech))


@dataclass
class TechniqueHit:
    technique: str
    name: str
    tactic: str
    findings: list[dict] = field(default_factory=list)

    @property
    def first(self) -> Optional[str]:
        times = [f["timestamp"] for f in self.findings if f.get("timestamp")]
        return min(times) if times else None

    @property
    def severity(self) -> str:
        order = ["info", "low", "medium", "high", "critical"]
        return max((f["severity"] for f in self.findings), key=order.index, default="info")

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.technique.replace(".", "/") + "/"


SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def attack_matrix(findings: Iterable[dict], min_severity: str = "medium",
                  include_false_positives: bool = False) -> dict[str, list[TechniqueHit]]:
    """Tactic -> techniques observed (in kill-chain order).

    Findings below ``min_severity`` (JIT noise, routine activity) and those marked as
    false positives are left out; confirmed findings always count.
    """
    threshold = SEVERITY_ORDER.index(min_severity)
    matrix: dict[str, dict[str, TechniqueHit]] = {name: {} for name, _ in TACTICS}
    for finding in findings:
        review = (finding.get("review") or {}).get("status")
        if review == "false_positive" and not include_false_positives:
            continue
        if review != "confirmed" and SEVERITY_ORDER.index(finding.get("severity", "info")) < threshold:
            continue
        for technique in techniques_for(finding):
            name, tactics = TECHNIQUES.get(technique, TECHNIQUES.get(technique.split(".")[0], (technique, ())))
            for tactic in tactics:
                hit = matrix[tactic].setdefault(technique, TechniqueHit(technique, name, tactic))
                hit.findings.append(finding)
    return {tactic: sorted(hits.values(), key=lambda h: (h.first or "9999", h.technique))
            for tactic, hits in matrix.items() if hits}


@dataclass
class Phase:
    tactic: str
    first: Optional[str]
    last: Optional[str]
    techniques: list[TechniqueHit]


def storyline(findings: list[dict]) -> list[Phase]:
    """Tactics observed, in kill-chain order, with their time span."""
    phases = []
    for tactic, hits in attack_matrix(findings).items():
        times = [f["timestamp"] for h in hits for f in h.findings if f.get("timestamp")]
        phases.append(Phase(tactic, min(times) if times else None, max(times) if times else None, hits))
    return sorted(phases, key=lambda p: TACTIC_ORDER[p.tactic])


def draft_summary(findings: list[dict], lang: Optional[str] = None) -> str:
    """A first draft of the incident narrative (the analyst must review and complete it)."""
    from forense.presentation import display_ts, finding_title

    phases = storyline(findings)
    if not phases:
        return t("attack.summary_none", lang)
    times = [p.first for p in phases if p.first] + [p.last for p in phases if p.last]
    lines = [t("attack.summary_intro", lang, start=display_ts(min(times)) if times else "-",
               end=display_ts(max(times)) if times else "-", tactics=len(phases),
               techniques=len({h.technique for p in phases for h in p.techniques}))]
    for phase in phases:
        candidates = sorted({f["id"]: f for h in phase.techniques for f in h.findings}.values(),
                            key=lambda f: (-SEVERITY_ORDER.index(f["severity"]), f.get("timestamp") or "9999"))
        key_findings, codes = [], set()
        for finding in candidates:  # one finding per kind, most severe first
            if finding["code"] not in codes:
                codes.add(finding["code"])
                key_findings.append(finding)
        key_findings = key_findings[:3]
        techniques = ", ".join(f"{h.technique} {h.name}" for h in phase.techniques[:4])
        evidence = "; ".join(f"{finding_title(f, lang)} (#{f['id']})" for f in key_findings)
        lines.append(f"- {t('tactic.' + phase.tactic, lang)} ({display_ts(phase.first) or '-'}): {techniques}. "
                     f"{t('attack.summary_evidence', lang)}: {evidence}.")
    lines.append(t("attack.summary_disclaimer", lang))
    return "\n".join(lines)
