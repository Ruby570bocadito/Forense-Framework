"""Windows time zone rules from the SYSTEM hive, to convert local times (setupapi, NetworkList...) to UTC.

``ControlSet\\Control\\TimeZoneInformation`` holds the base bias, the standard and
daylight biases and the daylight saving transitions as SYSTEMTIME rules
("last Sunday of March at 02:00"). Applying them per timestamp gives the right
offset in summer and in winter, unlike ``ActiveTimeBias`` (the offset in force
when the system was shut down).
"""

from __future__ import annotations

import calendar
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from forense.core.utils import find_files


def _signed(value) -> int:
    value = int(value or 0)
    return value - 0x100000000 if value > 0x7FFFFFFF else value


def _rule(raw) -> Optional[tuple[int, int, int, int, int]]:
    """(month, day of week, occurrence, hour, minute) of a SYSTEMTIME transition rule."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 16:
        return None
    _year, month, dow, occurrence, hour, minute, _s, _ms = struct.unpack_from("<8H", raw)
    if not (1 <= month <= 12 and dow <= 6 and 1 <= occurrence <= 5 and hour <= 23 and minute <= 59):
        return None  # no rule (month 0) or a damaged one: no daylight saving time is applied
    return month, dow, occurrence, hour, minute


def _transition(year: int, rule: tuple[int, int, int, int, int]) -> datetime:
    month, dow, occurrence, hour, minute = rule
    days = calendar.monthrange(year, month)[1]
    python_dow = (dow - 1) % 7  # SYSTEMTIME: 0 = Sunday; Python: 0 = Monday
    matches = [d for d in range(1, days + 1) if datetime(year, month, d).weekday() == python_dow]
    day = matches[min(occurrence, len(matches)) - 1]
    return datetime(year, month, day, hour, minute)


@dataclass
class WindowsTimeZone:
    name: str
    bias: int  # minutes; UTC = local + bias
    standard_bias: int = 0
    daylight_bias: int = 0
    standard_start: Optional[tuple] = None
    daylight_start: Optional[tuple] = None

    def is_dst(self, local: datetime) -> bool:
        if not self.standard_start or not self.daylight_start:
            return False
        local = local.replace(tzinfo=None)
        dst_start = _transition(local.year, self.daylight_start)
        dst_end = _transition(local.year, self.standard_start)
        if dst_start < dst_end:  # northern hemisphere
            return dst_start <= local < dst_end
        return local >= dst_start or local < dst_end

    def utc_offset(self, local: datetime) -> timedelta:
        """Offset of local time from UTC (e.g. +2 h in Madrid in summer)."""
        bias = self.bias + (self.daylight_bias if self.is_dst(local) else self.standard_bias)
        return timedelta(minutes=-bias)

    def to_utc(self, local: datetime) -> datetime:
        return (local.replace(tzinfo=None) - self.utc_offset(local)).replace(tzinfo=timezone.utc)

    @classmethod
    def from_hive(cls, hive) -> Optional["WindowsTimeZone"]:
        select = hive.open("Select")
        current = select.get("Current", 1) if select else 1
        key = hive.open(f"ControlSet{int(current):03d}\\Control\\TimeZoneInformation") \
            or hive.open("ControlSet001\\Control\\TimeZoneInformation")
        if key is None:
            return None
        name = key.get("TimeZoneKeyName") or key.get("StandardName") or ""
        name = name.split("\x00")[0] if isinstance(name, str) else ""
        if key.get("Bias") is None:
            active = key.get("ActiveTimeBias")
            return cls(name, _signed(active)) if active is not None else None
        if key.get("DynamicDaylightTimeDisabled") == 1:  # "Adjust for daylight saving time" switched off
            return cls(name, _signed(key.get("Bias")), _signed(key.get("StandardBias")))
        return cls(name, _signed(key.get("Bias")), _signed(key.get("StandardBias")), _signed(key.get("DaylightBias")),
                   _rule(key.get("StandardStart")), _rule(key.get("DaylightStart")))

    @classmethod
    def from_evidence(cls, target: Path) -> Optional["WindowsTimeZone"]:
        """Time zone of the SYSTEM hive found in an evidence folder, if any."""
        from forense.parsers.regf import RegistryError, RegistryHive

        if not Path(target).is_dir():
            return None
        hives = find_files(target, lambda p: p.name.upper() == "SYSTEM")
        for path in sorted(hives, key=lambda p: p.parent.name.lower() != "config"):
            try:
                with RegistryHive(path) as hive:
                    tz = cls.from_hive(hive)
            except (OSError, RegistryError, ValueError, struct.error):
                continue
            if tz:
                return tz
        return None
