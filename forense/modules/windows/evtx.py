"""Windows event logs (.evtx): parsing, timeline and detection of notable activity."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from forense.core.heuristics import autostart_suspicion, suspicious_command_rules
from forense.core.utils import find_files, relative_name
from forense.modules.base import AnalysisContext, Module, Option, register
from forense.parsers.evtx import WinEvent, iter_events

SECURITY = "security"
SYSTEM = "system"
POWERSHELL = "microsoft-windows-powershell/operational"
POWERSHELL_CLASSIC = "windows powershell"
SYSMON = "microsoft-windows-sysmon/operational"
DEFENDER = "microsoft-windows-windows defender/operational"
RDP_LSM = "microsoft-windows-terminalservices-localsessionmanager/operational"
RDP_RCM = "microsoft-windows-terminalservices-remoteconnectionmanager/operational"
TASKS = "microsoft-windows-taskscheduler/operational"
WMI = "microsoft-windows-wmi-activity/operational"
BITS = "microsoft-windows-bits-client/operational"

LOGON_TYPES = {
    2: "Interactive", 3: "Network", 4: "Batch", 5: "Service", 7: "Unlock", 8: "NetworkCleartext",
    9: "NewCredentials", 10: "RemoteInteractive", 11: "CachedInteractive", 12: "CachedRemoteInteractive",
    13: "CachedUnlock",
}
LOGON_FAILURES = {
    "0xc0000064": "unknown_user", "0xc000006a": "bad_password", "0xc0000234": "locked_out",
    "0xc0000072": "disabled", "0xc000006f": "outside_hours", "0xc0000070": "workstation_restricted",
    "0xc0000071": "password_expired", "0xc0000193": "account_expired", "0xc0000133": "clock_skew",
    "0xc0000224": "must_change_password", "0xc000015b": "logon_type_not_granted", "0xc000006d": "bad_credentials",
}
PRIVILEGED_GROUP_SIDS = ("-544", "-512", "-518", "-519", "-551", "-555", "-548", "-549")
_STANDARD_SERVICE_DIRS = re.compile(
    r"^\W*(%systemroot%|\\systemroot\\|system32\\|c:\\windows\\(system32|syswow64|servicing|winsxs)\\"
    r"|c:\\program files( \(x86\))?\\|%programfiles(\(x86\))?%)",
    re.IGNORECASE,
)
_LOCAL_SOURCES = {"", "-", "127.0.0.1", "::1", "localhost", "local"}


@dataclass(frozen=True)
class Rule:
    type: str  # timeline event type (i18n: etype.<type>)
    fields: tuple[str, ...]
    severity: str = "info"


RULES: dict[tuple[str, int], Rule] = {
    (SECURITY, 1102): Rule("log_cleared", ("SubjectDomainName", "SubjectUserName"), "high"),
    (SECURITY, 4616): Rule("system_time_changed", ("SubjectUserName", "PreviousTime", "NewTime", "ProcessName")),
    (SECURITY, 4624): Rule("logon", ("TargetDomainName", "TargetUserName", "LogonType", "IpAddress",
                                     "WorkstationName", "ProcessName")),
    (SECURITY, 4625): Rule("logon_failed", ("TargetDomainName", "TargetUserName", "LogonType", "IpAddress",
                                            "WorkstationName", "Status", "SubStatus"), "low"),
    (SECURITY, 4634): Rule("logoff", ("TargetDomainName", "TargetUserName", "LogonType")),
    (SECURITY, 4647): Rule("logoff", ("TargetDomainName", "TargetUserName")),
    (SECURITY, 4648): Rule("explicit_credentials", ("SubjectUserName", "TargetUserName", "TargetServerName",
                                                    "IpAddress", "ProcessName")),
    (SECURITY, 4688): Rule("process_created", ("SubjectUserName", "NewProcessName", "CommandLine",
                                               "ParentProcessName")),
    (SECURITY, 4697): Rule("service_installed", ("SubjectUserName", "ServiceName", "ServiceFileName"), "medium"),
    (SECURITY, 4698): Rule("task_created", ("SubjectUserName", "TaskName"), "medium"),
    (SECURITY, 4699): Rule("task_deleted", ("SubjectUserName", "TaskName")),
    (SECURITY, 4702): Rule("task_updated", ("SubjectUserName", "TaskName")),
    (SECURITY, 4719): Rule("audit_policy_changed", ("SubjectUserName", "CategoryId", "SubcategoryId",
                                                    "AuditPolicyChanges"), "medium"),
    (SECURITY, 4720): Rule("user_created", ("SubjectUserName", "TargetDomainName", "TargetUserName"), "medium"),
    (SECURITY, 4722): Rule("user_enabled", ("SubjectUserName", "TargetUserName")),
    (SECURITY, 4724): Rule("password_reset", ("SubjectUserName", "TargetUserName")),
    (SECURITY, 4725): Rule("user_disabled", ("SubjectUserName", "TargetUserName")),
    (SECURITY, 4726): Rule("user_deleted", ("SubjectUserName", "TargetUserName"), "medium"),
    (SECURITY, 4728): Rule("group_member_added", ("SubjectUserName", "MemberName", "MemberSid", "TargetUserName")),
    (SECURITY, 4732): Rule("group_member_added", ("SubjectUserName", "MemberName", "MemberSid", "TargetUserName")),
    (SECURITY, 4756): Rule("group_member_added", ("SubjectUserName", "MemberName", "MemberSid", "TargetUserName")),
    (SECURITY, 4740): Rule("account_locked", ("TargetUserName", "TargetDomainName"), "low"),
    (SECURITY, 4771): Rule("kerberos_preauth_failed", ("TargetUserName", "IpAddress", "Status"), "low"),
    (SECURITY, 4776): Rule("ntlm_validation", ("TargetUserName", "Workstation", "Status")),
    (SECURITY, 4778): Rule("rdp_reconnected", ("AccountDomain", "AccountName", "ClientName", "ClientAddress")),
    (SECURITY, 4779): Rule("rdp_disconnected", ("AccountDomain", "AccountName", "ClientName", "ClientAddress")),
    (SECURITY, 5140): Rule("share_accessed", ("SubjectUserName", "ShareName", "IpAddress")),
    (SYSTEM, 104): Rule("log_cleared", ("SubjectDomainName", "SubjectUserName", "Channel"), "high"),
    (SYSTEM, 1074): Rule("shutdown_initiated", ("param7", "param1", "param5", "param3")),
    (SYSTEM, 6005): Rule("eventlog_started", ()),
    (SYSTEM, 6006): Rule("eventlog_stopped", ()),
    (SYSTEM, 6008): Rule("unexpected_shutdown", ("param1", "param2"), "low"),
    (SYSTEM, 7040): Rule("service_start_changed", ("param1", "param2", "param3")),
    (SYSTEM, 7045): Rule("service_installed", ("ServiceName", "ImagePath", "StartType", "AccountName"), "medium"),
    (POWERSHELL, 4104): Rule("powershell_script", ("ScriptBlockText", "Path")),
    (POWERSHELL_CLASSIC, 400): Rule("powershell_started", ("param3",)),
    (SYSMON, 1): Rule("process_created", ("User", "Image", "CommandLine", "ParentImage", "Hashes")),
    (SYSMON, 3): Rule("network_connection", ("User", "Image", "DestinationIp", "DestinationPort",
                                             "DestinationHostname")),
    (SYSMON, 22): Rule("dns_query", ("Image", "QueryName", "QueryResults")),
    (DEFENDER, 1116): Rule("malware_detected", ("Threat Name", "Path", "Detection User", "Process Name"), "high"),
    (DEFENDER, 1117): Rule("malware_action", ("Threat Name", "Path", "Action Name"), "high"),
    (DEFENDER, 5001): Rule("defender_disabled", (), "high"),
    (DEFENDER, 5007): Rule("defender_config_changed", ("Old Value", "New Value")),
    (RDP_LSM, 21): Rule("rdp_logon", ("User", "SessionID", "Address")),
    (RDP_LSM, 24): Rule("rdp_disconnected", ("User", "SessionID", "Address")),
    (RDP_LSM, 25): Rule("rdp_reconnected", ("User", "SessionID", "Address")),
    (RDP_RCM, 1149): Rule("rdp_authenticated", ("Param1", "Param2", "Param3")),
    (TASKS, 106): Rule("task_created", ("TaskName", "UserContext"), "medium"),
    (TASKS, 141): Rule("task_deleted", ("TaskName", "UserName")),
    (TASKS, 200): Rule("task_executed", ("TaskName", "ActionName")),
    (WMI, 5861): Rule("wmi_subscription", ("Namespace", "ESS", "CONSUMER", "PossibleCause"), "high"),
    (BITS, 59): Rule("bits_job", ("name", "url")),
}


def _clean(value: str, limit: int = 400) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[:limit] + "…"


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.strip("[]")).is_global
    except ValueError:
        return False


def _user(event: WinEvent, domain: str = "TargetDomainName", name: str = "TargetUserName") -> str:
    user = event.get(name)
    dom = event.get(domain)
    return f"{dom}\\{user}" if dom and user else user


@register
class EvtxModule(Module):
    name = "evtx"
    category = "windows"
    triage = True
    options = (
        Option("records", "all", "choice", choices=("all", "notable", "none")),
        Option("timeline_all", False, "bool"),
        Option("brute_force_threshold", 10, "int"),
    )

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: p.suffix.lower() == ".evtx")

    def analyze(self, ctx: AnalysisContext) -> None:
        state = _State(ctx.options["brute_force_threshold"])
        files = self.discover(ctx.target)
        for path in files:
            rel = relative_name(path, ctx.target)
            ctx.progress(rel)
            errors: list[str] = []
            count = 0
            try:
                for event in iter_events(path, errors):
                    count += 1
                    self._process(ctx, state, event, rel)
            except OSError as exc:
                ctx.error(rel, exc)
            except Exception as exc:  # unreadable/corrupt file header
                ctx.error(rel, exc)
            if errors:
                ctx.error(rel, f"{len(errors)} corrupt records skipped (first: {errors[0]})")
            state.per_file[rel] = count
        state.finish(ctx)

    def _process(self, ctx: AnalysisContext, state: "_State", event: WinEvent, file: str) -> None:
        channel = event.channel.lower()
        rule = RULES.get((channel, event.event_id))
        if rule is None and channel.startswith(POWERSHELL_CLASSIC) and event.event_id == 400:
            rule = RULES[(POWERSHELL_CLASSIC, 400)]
        state.observe(event, channel)

        mode = ctx.options["records"]
        if mode == "all" or (mode == "notable" and rule is not None):
            ctx.record("event", {
                "timestamp": event.timestamp, "computer": event.computer, "channel": event.channel,
                "provider": event.provider, "event_id": event.event_id, "record_id": event.record_id,
                "user_sid": event.user_sid, "file": file,
                "data": {k: v for k, v in event.data.items() if v not in (None, "", "-")},
            })

        if rule is not None:
            details = self._details(event, rule)
            ctx.event(event.timestamp, rule.type, details, f"{file}#{event.record_id}", rule.severity)
            self._detect(ctx, state, event, channel, rule)
        elif ctx.options["timeline_all"]:
            details = "; ".join(f"{k}={_clean(v, 120)}" for k, v in list(event.data.items())[:8]
                                if v not in (None, "", "-"))
            ctx.event(event.timestamp, "event", f"{event.channel}/{event.event_id} {details}".strip(),
                      f"{file}#{event.record_id}")

    @staticmethod
    def _details(event: WinEvent, rule: Rule) -> str:
        parts = []
        for name in rule.fields:
            value = event.get(name)
            if not value:
                continue
            if name == "LogonType":
                try:
                    value = f"{value} ({LOGON_TYPES.get(int(value), '?')})"
                except ValueError:
                    pass
            elif name in ("Status", "SubStatus"):
                value = f"{value} ({LOGON_FAILURES.get(value.lower(), '?')})"
            parts.append(f"{name}={_clean(value)}")
        prefix = f"{event.computer} " if event.computer else ""
        return prefix + "; ".join(parts) if parts else prefix.strip()

    def _detect(self, ctx: AnalysisContext, state: "_State", event: WinEvent, channel: str, rule: Rule) -> None:
        eid, ts = event.event_id, event.timestamp
        if rule.type == "log_cleared":
            ctx.finding("evtx.log_cleared", "high", ts, channel=event.get("Channel") or event.channel,
                        user=_user(event, "SubjectDomainName", "SubjectUserName"), computer=event.computer)
        elif (channel, eid) == (SECURITY, 4624):
            state.logon(event)
        elif (channel, eid) == (SECURITY, 4625):
            state.failure(event)
        elif rule.type == "user_created":
            state.sid_names[event.get("TargetSid")] = _user(event)
            ctx.finding("evtx.user_created", "medium", ts, user=_user(event),
                        by=_user(event, "SubjectDomainName", "SubjectUserName"), computer=event.computer)
        elif rule.type == "group_member_added":
            sid = event.get("TargetSid")
            if any(sid.endswith(suffix) for suffix in PRIVILEGED_GROUP_SIDS):
                member_sid = event.get("MemberSid")
                ctx.finding("evtx.privileged_group_add", "high", ts,
                            member=event.get("MemberName") or state.sid_names.get(member_sid, member_sid),
                            group=event.get("TargetUserName"), by=event.get("SubjectUserName"),
                            computer=event.computer)
        elif rule.type == "service_installed":
            image = event.get("ImagePath") or event.get("ServiceFileName")
            reasons = autostart_suspicion(image)
            if "credential_dumping" in reasons:
                severity = "critical"
            elif reasons:
                severity = "high"
            else:
                severity = "info" if _STANDARD_SERVICE_DIRS.match(image) else "medium"
            ctx.finding("evtx.service_installed", severity, ts, service=event.get("ServiceName"),
                        image=_clean(image), reasons=", ".join(reasons) or "-", computer=event.computer)
        elif rule.type == "task_created":
            ctx.finding("evtx.task_created", "medium", ts, task=event.get("TaskName"),
                        by=event.get("SubjectUserName") or event.get("UserContext"), computer=event.computer)
        elif rule.type == "process_created":
            command = event.get("CommandLine") or event.get("NewProcessName") or event.get("Image")
            self._check_command(ctx, event, command, event.get("NewProcessName") or event.get("Image"))
        elif rule.type == "powershell_script":
            script = event.get("ScriptBlockText")
            rules = suspicious_command_rules(script)
            if rules:
                ctx.finding("evtx.suspicious_powershell", "high", ts, rules=", ".join(rules),
                            snippet=_clean(script, 300), computer=event.computer)
        elif rule.type == "powershell_started":
            host = event.get("param3")
            marker = "HostApplication="
            if marker in host:
                command = host.split(marker, 1)[1].splitlines()[0]
                self._check_command(ctx, event, command, "powershell.exe")
        elif rule.type == "malware_detected":
            ctx.finding("evtx.defender_detection", "high", ts, threat=event.get("Threat Name"),
                        path=event.get("Path"), user=event.get("Detection User"), computer=event.computer)
        elif rule.type == "defender_disabled":
            ctx.finding("evtx.defender_disabled", "high", ts, computer=event.computer)
        elif rule.type == "defender_config_changed" and "exclusion" in event.get("New Value").lower():
            ctx.finding("evtx.defender_exclusion", "high", ts, value=_clean(event.get("New Value")),
                        computer=event.computer)
        elif rule.type == "audit_policy_changed":
            ctx.finding("evtx.audit_policy_changed", "medium", ts, by=event.get("SubjectUserName"),
                        computer=event.computer)
        elif rule.type == "wmi_subscription":
            ctx.finding("evtx.wmi_persistence", "high", ts, consumer=_clean(event.get("CONSUMER")),
                        cause=_clean(event.get("PossibleCause")), computer=event.computer)
        elif rule.type in ("rdp_logon", "rdp_authenticated"):
            ip = event.get("Address") or event.get("Param3")
            user = event.get("User") or event.get("Param1")
            state.rdp(user, ip, ts)

    @staticmethod
    def _check_command(ctx: AnalysisContext, event: WinEvent, command: str, process: str) -> None:
        rules = suspicious_command_rules(command)
        if not rules:
            return
        severity = "critical" if {"shadow_copy_deletion", "credential_dumping", "log_clearing"} & set(rules) \
            else "high"
        ctx.finding("evtx.suspicious_command", severity, event.timestamp, rules=", ".join(rules),
                    command=_clean(command, 300), process=process,
                    user=event.get("SubjectUserName") or event.get("User"), computer=event.computer)


class _State:
    """Aggregates used for summary figures and cross-event detections."""

    def __init__(self, threshold: int) -> None:
        self.threshold = threshold
        self.per_file: dict[str, int] = {}
        self.channels: Counter = Counter()
        self.ids: Counter = Counter()
        self.computers: Counter = Counter()
        self.first = self.last = None
        self.failures: dict[str, list] = defaultdict(list)  # ip -> [(ts, user)]
        self.successes: dict[str, list] = defaultdict(list)  # ip -> [(ts, user, logon type)]
        self.logons = Counter()
        self.rdp_sources: Counter = Counter()
        self.rdp_first: dict[tuple, str] = {}
        self.sid_names: dict[str, str] = {}

    def observe(self, event: WinEvent, channel: str) -> None:
        self.channels[event.channel] += 1
        self.ids[f"{event.channel}/{event.event_id}"] += 1
        if event.computer:
            self.computers[event.computer] += 1
        if event.timestamp:
            self.first = min(self.first or event.timestamp, event.timestamp)
            self.last = max(self.last or event.timestamp, event.timestamp)

    def logon(self, event: WinEvent) -> None:
        self.logons["success"] += 1
        if event.get("TargetUserSid"):
            self.sid_names.setdefault(event.get("TargetUserSid"), _user(event))
        ip = event.get("IpAddress")
        logon_type = event.get("LogonType")
        if ip.lower() not in _LOCAL_SOURCES:
            self.successes[ip].append((event.timestamp, _user(event), logon_type))
        if logon_type == "10":
            self.rdp(_user(event), ip, event.timestamp)

    def failure(self, event: WinEvent) -> None:
        self.logons["failed"] += 1
        ip = event.get("IpAddress")
        if ip.lower() not in _LOCAL_SOURCES:
            self.failures[ip].append((event.timestamp, _user(event)))

    def rdp(self, user: str, ip: str, ts: str) -> None:
        if not ip or ip.lower() in _LOCAL_SOURCES:
            return
        key = (user, ip)
        self.rdp_sources[key] += 1
        self.rdp_first[key] = min(self.rdp_first.get(key, ts), ts)

    def finish(self, ctx: AnalysisContext) -> None:
        for ip, attempts in self.failures.items():
            if len(attempts) < self.threshold:
                continue
            attempts.sort()
            users = Counter(user for _, user in attempts)
            ctx.finding("evtx.brute_force", "high", attempts[0][0], ip=ip, count=len(attempts),
                        users=", ".join(u for u, _ in users.most_common(5)), first=attempts[0][0],
                        last=attempts[-1][0])
            after = [s for s in self.successes.get(ip, []) if s[0] >= attempts[0][0]]
            if after:
                ts, user, logon_type = min(after)
                ctx.finding("evtx.brute_force_success", "critical", ts, ip=ip, failures=len(attempts),
                            user=user, logon_type=logon_type)
        for (user, ip), count in self.rdp_sources.items():
            if _is_public(ip):
                ctx.finding("evtx.rdp_public", "medium", self.rdp_first[(user, ip)], user=user, ip=ip, count=count)

        top_failed = sorted(((ip, len(a)) for ip, a in self.failures.items()), key=lambda x: -x[1])[:10]
        ctx.summary.update({
            "files": len(self.per_file),
            "events": sum(self.per_file.values()),
            "events_per_file": dict(sorted(self.per_file.items())),
            "first_event": self.first,
            "last_event": self.last,
            "computers": dict(self.computers.most_common(10)),
            "events_per_channel": dict(self.channels.most_common()),
            "top_event_ids": dict(self.ids.most_common(15)),
            "successful_logons": self.logons["success"],
            "failed_logons": self.logons["failed"],
            "top_failed_logon_sources": {ip: n for ip, n in top_failed},
            "rdp_sources": {f"{u} @ {ip}": n for (u, ip), n in self.rdp_sources.most_common(20)},
        })
