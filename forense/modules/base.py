"""Analysis module API.

A module receives an :class:`AnalysisContext` and reports through it:

* ``ctx.record(artifact, data)``: a parsed artifact row (shown in tables, exportable).
* ``ctx.event(timestamp, type, details, path)``: an entry for the case super-timeline.
* ``ctx.finding(code, severity, ...)``: something an analyst should look at.
* ``ctx.summary``: key figures of the run.

Records and events use language-neutral field names and codes; their labels
are translated at presentation time (see :mod:`forense.i18n`).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from forense.core.errors import ModuleError
from forense.core.utils import TimeLike, normalize_ts, parse_datetime
from forense.i18n import t

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

_TRUE = {"1", "true", "yes", "y", "si", "sí", "s", "on"}
_FALSE = {"0", "false", "no", "n", "off"}


@dataclass(frozen=True)
class Option:
    """A module option. ``kind``: str, int, bool, list, datetime, path or choice."""

    name: str
    default: Any = None
    kind: str = "str"
    choices: tuple = ()
    required: bool = False

    def parse(self, raw: Any) -> Any:
        if raw is None or raw == "":
            if self.required:
                raise ModuleError("error.option_required", option=self.name)
            return self.default
        if not isinstance(raw, str):
            return raw
        raw = raw.strip()
        try:
            if self.kind == "int":
                return int(raw)
            if self.kind == "bool":
                low = raw.lower()
                if low in _TRUE:
                    return True
                if low in _FALSE:
                    return False
                raise ValueError(raw)
            if self.kind == "list":
                return [item.strip().lower() for item in raw.split(",") if item.strip()]
            if self.kind == "datetime":
                return parse_datetime(raw)
            if self.kind == "path":
                path = Path(raw).expanduser()
                if not path.exists():
                    raise ModuleError("error.option_path_missing", option=self.name, path=raw)
                return path
            if self.kind == "choice" and raw.lower() not in self.choices:
                raise ValueError(raw)
            return raw.lower() if self.kind == "choice" else raw
        except ModuleError:
            raise
        except ValueError:
            raise ModuleError("error.option_invalid", option=self.name, value=raw) from None


class ResultSink:
    """Destination of module output. The in-memory version is used by tests and the API."""

    def __init__(self) -> None:
        self.records: list[tuple[str, dict]] = []
        self.events: list[dict] = []
        self.findings: list[dict] = []

    def add_records(self, items: list[tuple[str, dict]]) -> None:
        self.records.extend(items)

    def add_events(self, items: list[dict]) -> None:
        self.events.extend(items)

    def add_findings(self, items: list[dict]) -> None:
        self.findings.extend(items)


def canonical(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def record_line(artifact: str, data_json: str) -> bytes:
    return f"{artifact}\x1f{data_json}\n".encode("utf-8")


def item_line(item: dict) -> bytes:
    return f"{canonical(item)}\n".encode("utf-8")


def combine_result_hashes(records: str, events: str, findings: str) -> str:
    """Results hash of an analysis: SHA-256 over the per-kind hashes (each in emission order)."""
    return hashlib.sha256(f"{records}:{events}:{findings}".encode("ascii")).hexdigest()


class AnalysisContext:
    """Everything a module needs while it runs."""

    FLUSH_EVERY = 2000

    def __init__(self, target: Path, output_dir: Path, options: dict, sink: Optional[ResultSink] = None,
                 evidence_id: str = "", module: str = "",
                 progress: Optional[Callable[[str], None]] = None) -> None:
        self.target = Path(target)
        self.output_dir = Path(output_dir)
        self.options = options
        self.sink = sink if sink is not None else ResultSink()
        self.evidence_id = evidence_id
        self.module = module
        self.summary: dict[str, Any] = {}
        self.errors: list[dict] = []
        self.artifacts: list[str] = []
        self.counts = {"records": 0, "events": 0, "findings": 0}
        self._progress = progress
        self._records: list[tuple[str, dict]] = []
        self._events: list[dict] = []
        self._findings: list[dict] = []
        self._hashers = {kind: hashlib.sha256() for kind in ("records", "events", "findings")}

    # -- output ---------------------------------------------------------
    def record(self, artifact: str, data: dict) -> None:
        self._records.append((artifact, data))
        self._hashers["records"].update(record_line(artifact, canonical(data)))
        self.counts["records"] += 1
        self._maybe_flush()

    def event(self, timestamp: TimeLike, type: str, details: str = "", path: str = "",
              severity: str = "info") -> None:
        """Add a timeline event. Events without a valid timestamp are ignored."""
        try:
            ts = normalize_ts(timestamp)
        except (ValueError, OverflowError, OSError):
            ts = None
        if not ts:
            return
        item = {"timestamp": ts, "source": self.module, "type": type, "details": details or "",
                "path": path or "", "severity": severity}
        self._events.append(item)
        self._hashers["events"].update(item_line(item))
        self.counts["events"] += 1
        self._maybe_flush()

    def finding(self, code: str, severity: str, timestamp: TimeLike = None, **params: Any) -> None:
        """Report a finding; ``code`` maps to ``finding.<code>.title`` / ``.description`` texts."""
        if severity not in SEVERITY_RANK:
            raise ValueError(severity)
        try:
            ts = normalize_ts(timestamp)
        except (ValueError, OverflowError, OSError):
            ts = None
        item = {"code": code, "severity": severity, "timestamp": ts, "params": params}
        self._findings.append(item)
        self._hashers["findings"].update(item_line(item))
        self.counts["findings"] += 1
        self._maybe_flush()

    def error(self, path: Any, exc: Any) -> None:
        message = f"{type(exc).__name__}: {exc}" if isinstance(exc, BaseException) else str(exc)
        self.errors.append({"path": str(path), "error": message})

    def add_artifact(self, path: Path) -> None:
        self.artifacts.append(Path(path).relative_to(self.output_dir).as_posix())

    def progress(self, message: str) -> None:
        if self._progress:
            self._progress(message)

    # -- plumbing -------------------------------------------------------
    def _maybe_flush(self) -> None:
        if len(self._records) + len(self._events) + len(self._findings) >= self.FLUSH_EVERY:
            self.flush()

    def flush(self) -> None:
        if self._records:
            self.sink.add_records(self._records)
            self._records = []
        if self._events:
            self.sink.add_events(self._events)
            self._events = []
        if self._findings:
            self.sink.add_findings(self._findings)
            self._findings = []

    @property
    def results_sha256(self) -> str:
        """Hash of every record, event and finding (see :func:`combine_result_hashes`)."""
        return combine_result_hashes(*(h.hexdigest() for h in self._hashers.values()))


class Module:
    """Base class of analysis modules. Subclasses are registered with :func:`register`."""

    name: str = ""
    category: str = "generic"  # "windows" | "generic"
    targets: tuple[str, ...] = ("file", "directory")
    options: tuple[Option, ...] = ()
    triage: bool = False  # included in automatic triage runs

    def title(self, lang: Optional[str] = None) -> str:
        return t(f"module.{self.name}.title", lang)

    def description(self, lang: Optional[str] = None) -> str:
        return t(f"module.{self.name}.description", lang)

    def option_help(self, option: Option, lang: Optional[str] = None) -> str:
        return t(f"module.{self.name}.opt.{option.name}", lang)

    def parse_options(self, raw: Optional[dict] = None) -> dict:
        raw = dict(raw or {})
        known = {opt.name for opt in self.options}
        unknown = sorted(set(raw) - known)
        if unknown:
            raise ModuleError("error.option_unknown", option=", ".join(unknown), module=self.name)
        return {opt.name: opt.parse(raw.get(opt.name)) for opt in self.options}

    def check_target(self, target: Path) -> None:
        kind = "directory" if target.is_dir() else "file" if target.is_file() else None
        if kind is None:
            raise ModuleError("error.target_missing", path=str(target))
        if kind not in self.targets:
            raise ModuleError(f"error.target_requires_{self.targets[0]}", module=self.name)

    def discover(self, target: Path) -> list[Path]:
        """Artifacts this module would process in ``target`` (used by triage)."""
        return [target]

    def analyze(self, ctx: AnalysisContext) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def run(self, target: Path, output_dir: Path, options: Optional[dict] = None,
            sink: Optional[ResultSink] = None, evidence_id: str = "",
            progress: Optional[Callable[[str], None]] = None) -> AnalysisContext:
        """Validate and execute the module, returning the finished context."""
        target = Path(target)
        self.check_target(target)
        parsed = self.parse_options(options)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        ctx = AnalysisContext(target, output_dir, parsed, sink, evidence_id, self.name, progress)
        self.analyze(ctx)
        ctx.flush()
        return ctx


_REGISTRY: dict[str, type[Module]] = {}


def register(cls: type[Module]) -> type[Module]:
    if not cls.name:
        raise ValueError(f"{cls.__name__} has no name")
    _REGISTRY[cls.name] = cls
    return cls


def get_module(name: str) -> Module:
    _load_builtin_modules()
    try:
        return _REGISTRY[name.lower()]()
    except KeyError:
        raise ModuleError("error.module_unknown", module=name) from None


def available_modules() -> list[Module]:
    _load_builtin_modules()
    return [cls() for _, cls in sorted(_REGISTRY.items(), key=lambda kv: (kv[1].category != "windows", kv[0]))]


def _load_builtin_modules() -> None:
    import forense.modules  # noqa: F401  (imports register every built-in module)
