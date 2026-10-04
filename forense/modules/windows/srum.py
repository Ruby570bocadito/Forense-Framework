"""SRUM (SRUDB.dat): per-application network traffic and activity — evidence of exfiltration."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from forense.core.heuristics import is_suspicious_location, strip_device, tool_category
from forense.core.utils import dt_or_none_iso, find_files, human_size, relative_name
from forense.modules.base import AnalysisContext, Module, Option, register
from forense.parsers.srum import APP_RESOURCE_USAGE, NETWORK_CONNECTIVITY, NETWORK_USAGE, SrumDatabase

MB = 1024 * 1024


@register
class SrumModule(Module):
    name = "srum"
    category = "windows"
    triage = True
    options = (
        Option("upload_threshold_mb", 500, "int"),
        Option("app_usage", True, "bool"),
    )

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: p.name.lower() == "srudb.dat")

    def analyze(self, ctx: AnalysisContext) -> None:
        threshold = ctx.options["upload_threshold_mb"] * MB
        totals: dict[str, dict] = defaultdict(lambda: {"sent": 0, "received": 0, "first": None, "last": None,
                                                       "users": set()})
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            ctx.progress(rel)
            try:
                with SrumDatabase(path) as db:
                    self._network(ctx, db, rel, totals)
                    self._connectivity(ctx, db, rel)
                    if ctx.options["app_usage"]:
                        self._app_usage(ctx, db, rel)
            except OSError as exc:
                ctx.error(rel, exc)

        for app, t in sorted(totals.items(), key=lambda kv: -kv[1]["sent"]):
            app_path = strip_device(app)
            category = tool_category(app_path)
            suspicious = is_suspicious_location(app_path) or category is not None
            if t["sent"] >= threshold or (suspicious and t["sent"] >= 10 * MB):
                ctx.finding("srum.large_upload", "high" if suspicious else "medium", t["first"], app=app,
                            sent=human_size(t["sent"]), received=human_size(t["received"]),
                            first=dt_or_none_iso(t["first"]) or "-", last=dt_or_none_iso(t["last"]) or "-",
                            users=", ".join(sorted(t["users"])) or "-")
        top = sorted(totals.items(), key=lambda kv: -kv[1]["sent"])[:10]
        ctx.summary.update({
            "applications_with_traffic": len(totals),
            "top_uploaders": {app: human_size(t["sent"]) for app, t in top if t["sent"]},
        })

    @staticmethod
    def _network(ctx: AnalysisContext, db: SrumDatabase, rel: str, totals: dict) -> None:
        for row in db.rows(NETWORK_USAGE):
            sent, received = row.get("BytesSent") or 0, row.get("BytesRecvd") or 0
            ctx.record("srum_network", {
                "file": rel, "timestamp": dt_or_none_iso(row["timestamp"]), "application": row["app"],
                "user": row["user"], "bytes_sent": sent, "bytes_received": received,
                "interface_luid": row.get("InterfaceLuid"), "profile_id": row.get("L2ProfileId"),
            })
            t = totals[row["app"]]
            t["sent"] += sent
            t["received"] += received
            t["users"].add(row["user"])
            if row["timestamp"]:
                t["first"] = min(t["first"] or row["timestamp"], row["timestamp"])
                t["last"] = max(t["last"] or row["timestamp"], row["timestamp"])
            if sent >= 50 * MB:
                ctx.event(row["timestamp"], "network_usage",
                          f"{row['app']} sent={human_size(sent)} received={human_size(received)} user={row['user']}",
                          rel, "low")

    @staticmethod
    def _connectivity(ctx: AnalysisContext, db: SrumDatabase, rel: str) -> None:
        for row in db.rows(NETWORK_CONNECTIVITY):
            ctx.record("srum_connectivity", {
                "file": rel, "timestamp": dt_or_none_iso(row["timestamp"]), "application": row["app"],
                "user": row["user"], "connected_seconds": row.get("ConnectedTime"),
                "connect_start": dt_or_none_iso(row.get("ConnectStartTime")), "profile_id": row.get("L2ProfileId"),
                "interface_luid": row.get("InterfaceLuid"),
            })
            ctx.event(row.get("ConnectStartTime"), "network_connected",
                      f"profile={row.get('L2ProfileId')} interface={row.get('InterfaceLuid')}", rel)

    @staticmethod
    def _app_usage(ctx: AnalysisContext, db: SrumDatabase, rel: str) -> None:
        for row in db.rows(APP_RESOURCE_USAGE):
            ctx.record("srum_app_usage", {
                "file": rel, "timestamp": dt_or_none_iso(row["timestamp"]), "application": row["app"],
                "user": row["user"], "foreground_cycles": row.get("ForegroundCycleTime"),
                "background_cycles": row.get("BackgroundCycleTime"),
                "bytes_read": (row.get("ForegroundBytesRead") or 0) + (row.get("BackgroundBytesRead") or 0),
                "bytes_written": (row.get("ForegroundBytesWritten") or 0) + (row.get("BackgroundBytesWritten") or 0),
            })
