"""setupapi.dev.log: first installation of every device (USB storage, phones, other hardware).

The section header of each device installation gives the device instance ID
(vendor, product and serial number) and its start time, which is the first
time the device was connected to the system. Times are written in the system
local time: they are converted to UTC with the time zone rules of the SYSTEM
hive found in the same evidence (daylight saving time included), or with a
fixed ``utc_offset``.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from forense.core.errors import ModuleError
from forense.core.timezone import WindowsTimeZone
from forense.core.utils import find_files, iso, relative_name
from forense.modules.base import AnalysisContext, Module, Option, register

_SECTION = re.compile(r"^>>>\s+\[(?P<title>[^\]]*?)\s+-\s+(?P<device>[^\]]+)\]\s*$")
_START = re.compile(r"^>>>\s+Section start (?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")
_END = re.compile(r"^<<<\s+\[Exit status:\s*(?P<status>[^\]]+)\]")
_USBSTOR = re.compile(r"^USBSTOR\\(?P<type>[^&\\]+)&Ven_(?P<vendor>[^&\\]*)&Prod_(?P<product>[^&\\]*)"
                      r"(?:&Rev_(?P<rev>[^\\]*))?\\(?P<serial>.+)$", re.IGNORECASE)
_USB = re.compile(r"^USB\\VID_(?P<vid>[0-9a-f]{4})&PID_(?P<pid>[0-9a-f]{4})(?:&[^\\]*)?\\(?P<serial>.+)$", re.IGNORECASE)
_OFFSET = re.compile(r"^([+-])(\d{1,2}):?(\d{2})$")


def parse_offset(value: str) -> Optional[timedelta]:
    if not value:
        return None
    match = _OFFSET.match(value.strip())
    if not match:
        raise ModuleError("error.option_invalid", option="utc_offset", value=value)
    delta = timedelta(hours=int(match.group(2)), minutes=int(match.group(3)))
    return -delta if match.group(1) == "-" else delta


def classify(device: str) -> dict:
    """Device class, vendor, product and serial number from a device instance ID."""
    match = _USBSTOR.match(device)
    if match:
        serial = match.group("serial")
        return {"class": "usb_storage", "vendor": match.group("vendor").replace("_", " "),
                "product": match.group("product").replace("_", " "), "serial": serial.rsplit("&", 1)[0]
                if serial.endswith("&0") else serial}
    match = _USB.match(device)
    if match:
        return {"class": "usb", "vendor": f"VID_{match.group('vid').upper()}",
                "product": f"PID_{match.group('pid').upper()}", "serial": match.group("serial")}
    upper = device.upper()
    if upper.startswith(("SWD\\WPDBUSENUM", "WPDBUSENUMROOT")):
        return {"class": "portable_device", "vendor": "", "product": "", "serial": device.rsplit("\\", 1)[-1]}
    if upper.startswith("SCSI\\DISK") or upper.startswith("STORAGE\\VOLUME"):
        return {"class": "disk", "vendor": "", "product": "", "serial": ""}
    return {"class": "other", "vendor": "", "product": "", "serial": ""}


def parse_log(text: str) -> list[dict]:
    """Device installation sections: title, device, start time (local) and exit status."""
    sections: list[dict] = []
    current: Optional[dict] = None
    for line in text.splitlines():
        match = _SECTION.match(line)
        if match:
            current = {"title": match.group("title").strip(), "device": match.group("device").strip(), "start": None,
                       "status": ""}
            sections.append(current)
            continue
        if current is None:
            continue
        match = _START.match(line)
        if match and current["start"] is None:
            raw = match.group("ts")
            current["start"] = datetime.strptime(raw[:19], "%Y/%m/%d %H:%M:%S").replace(
                microsecond=int((raw[20:] + "000000")[:6]) if len(raw) > 19 else 0)
            continue
        match = _END.match(line)
        if match:
            current["status"] = match.group("status").strip()
            current = None
    return sections


@register
class SetupApiModule(Module):
    name = "setupapi"
    category = "windows"
    triage = True
    options = (Option("utc_offset", "", "str"), Option("all_devices", False, "bool"))

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: p.name.lower().startswith("setupapi.dev") and p.suffix.lower() == ".log")

    def analyze(self, ctx: AnalysisContext) -> None:
        offset = parse_offset(ctx.options["utc_offset"])
        zone = None if offset is not None else WindowsTimeZone.from_evidence(ctx.target)

        def to_utc(local: datetime) -> datetime:
            if offset is not None:
                return (local - offset).replace(tzinfo=timezone.utc)
            if zone is not None:
                return zone.to_utc(local)
            return local.replace(tzinfo=timezone.utc)

        seen: dict[str, datetime] = {}
        classes: dict[str, int] = {}
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            try:
                data = path.read_bytes()
            except OSError as exc:
                ctx.error(rel, exc)
                continue
            text = data.decode("utf-16", "replace") if data[:2] in (b"\xff\xfe", b"\xfe\xff") \
                else data.decode("utf-8", "replace")
            for section in parse_log(text):
                if "device install" not in section["title"].lower() or section["start"] is None:
                    continue
                info = classify(section["device"])
                if info["class"] in ("other", "disk") and not ctx.options["all_devices"]:
                    continue
                local = section["start"]
                when = to_utc(local)
                key = section["device"].lower()
                if key in seen and seen[key] <= when:
                    continue
                first = key not in seen
                seen[key] = when
                classes[info["class"]] = classes.get(info["class"], 0) + first
                ctx.record("device_install", {
                    "file": rel, "device": section["device"], "class": info["class"], "vendor": info["vendor"],
                    "product": info["product"], "serial": info["serial"], "first_install": iso(when),
                    "local_time": local.strftime("%Y-%m-%d %H:%M:%S"), "status": section["status"],
                    "title": section["title"],
                })
                ctx.event(when, "device_first_install",
                          f"{info['class']}: {info['vendor']} {info['product']} serial={info['serial'] or '-'}".strip(),
                          rel)
                if info["class"] == "usb_storage" or (info["class"] == "portable_device"
                                                      and "usbstor" not in section["device"].lower()):
                    ctx.finding("setupapi.external_storage", "low", when, vendor=info["vendor"] or "-",
                                product=info["product"] or "-", serial=info["serial"] or "-")
        ctx.summary.update({"devices": classes, "time_conversion": ctx.options["utc_offset"] if offset is not None
                            else (zone.name or "SYSTEM") if zone else "none"})
