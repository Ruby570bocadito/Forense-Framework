"""Automation: playbooks that take evidence from registration to report, and a watched drop folder.

A playbook is a list of steps run in order on a case:

``triage``    every triage module (disk images extracted first, memory to Volatility)
``memory``    the memory module on memory dumps / Volatility outputs
``intel``     hash lists, IOC watchlists and YARA rules from the configuration
``modules``   explicit modules with options: ``{modules: {evtx: {sigma_min_level: high}}}``
``report``    HTML report (and PDF) in the configured languages
``export``    CSV/JSON exports: findings, timeline, execution, stix

Built-in playbooks: ``triage``, ``quick`` and ``full``; a YAML file with
``steps:`` defines a custom one.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import yaml

from forense.core.case import Case
from forense.core.config import Config, get_config
from forense.core.errors import ForenseError
from forense.core.utils import stamped_path
from forense.i18n import t

BUILTIN_PLAYBOOKS: dict[str, list] = {
    "triage": ["triage", "report"],
    "quick": [{"modules": {"registry": {}, "prefetch": {}, "evtx": {}, "tasks": {}, "psreadline": {}, "mft": {}}},
              "report"],
    "full": ["triage", "intel", "report", {"export": ["findings", "timeline", "execution", "stix"]}],
}
Progress = Callable[[str], None]


@dataclass
class StepResult:
    step: str
    status: str  # ok | skipped | failed
    detail: str = ""


@dataclass
class AutomationResult:
    case_path: Path
    evidence: list[str] = field(default_factory=list)
    steps: list[StepResult] = field(default_factory=list)
    reports: list[Path] = field(default_factory=list)
    exports: list[Path] = field(default_factory=list)


def load_playbook(name: str) -> list:
    """Steps of a built-in playbook or of a YAML file (``steps: [...]``)."""
    if name in BUILTIN_PLAYBOOKS:
        return BUILTIN_PLAYBOOKS[name]
    path = Path(name).expanduser()
    if not path.is_file():
        raise ForenseError("error.playbook_unknown", name=name, available=", ".join(BUILTIN_PLAYBOOKS))
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ForenseError("error.playbook_invalid", name=name, error=str(exc).splitlines()[0]) from exc
    steps = data.get("steps") if isinstance(data, dict) else None
    if not isinstance(steps, list) or not steps:
        raise ForenseError("error.playbook_invalid", name=name, error="'steps' must be a non-empty list")
    return steps


def _step(spec) -> tuple[str, object]:
    if isinstance(spec, str):
        return spec, None
    if isinstance(spec, dict) and len(spec) == 1:
        return next(iter(spec.items()))
    raise ForenseError("error.playbook_invalid", name="?", error=f"bad step: {spec!r}")


def module_options(config: Config) -> dict[str, dict]:
    """Per-module options derived from the configuration (Sigma rules, VSS, Volatility symbols)."""
    options: dict[str, dict] = {"image": {"vss": bool(config.value("image.vss"))}, "memory": {}, "evtx": {}}
    sigma = config.paths("intel.sigma_rules")
    if sigma and sigma[0].exists():
        options["evtx"] = {"sigma_rules": str(sigma[0]),
                           "sigma_min_level": config.value("intel.sigma_min_level") or "medium"}
    symbols = config.paths("memory.symbols")
    if symbols and symbols[0].exists():
        options["memory"]["symbols"] = str(symbols[0])
    if config.value("memory.offline"):
        options["memory"]["offline"] = True
    return options


def run_playbook(case: Case, evidence_ids: list[str], steps: list, config: Optional[Config] = None,
                 actor: Optional[str] = None, progress: Optional[Progress] = None) -> AutomationResult:
    from forense.image import evidence_kind

    config = config or get_config()
    say = progress or (lambda _message: None)
    result = AutomationResult(case.root, list(evidence_ids))
    options = module_options(config)
    for spec in steps:
        name, args = _step(spec)
        say(t("auto.step", step=name))
        try:
            if name == "triage":
                for evidence_id in evidence_ids:
                    outcome = case.triage(evidence_id, actor, progress, options)
                    done = sum(1 for _, analysis, _ in outcome if analysis is not None)
                    result.steps.append(StepResult(f"triage {evidence_id}", "ok", t("auto.modules_run", count=done)))
            elif name == "memory":
                for evidence_id in evidence_ids:
                    if evidence_kind(Path(case.get_evidence(evidence_id).path)) in ("memory", "volatility"):
                        analysis = case.run_analysis("memory", evidence_id, options.get("memory"), actor, progress)
                        result.steps.append(StepResult(f"memory {evidence_id}", analysis.status,
                                                       t("auto.findings", count=analysis.finding_count)))
            elif name == "intel":
                result.steps += _intel(case, _analysable(case, evidence_ids), config, actor, progress)
            elif name == "modules":
                for module, module_args in (args or {}).items():
                    for evidence_id in _analysable(case, evidence_ids):
                        analysis = case.run_analysis(module, evidence_id, {**options.get(module, {}),
                                                                           **(module_args or {})}, actor, progress)
                        result.steps.append(StepResult(f"{module} {evidence_id}", analysis.status,
                                                       t("auto.findings", count=analysis.finding_count)))
            elif name == "report":
                result.reports += _reports(case, config, args or {}, actor)
                result.steps.append(StepResult("report", "ok", ", ".join(p.name for p in result.reports)))
            elif name == "export":
                result.exports += _exports(case, args or ["findings", "timeline"], actor)
                result.steps.append(StepResult("export", "ok", ", ".join(p.name for p in result.exports)))
            else:
                raise ForenseError("error.playbook_invalid", name="?", error=f"unknown step: {name}")
        except ForenseError as exc:
            result.steps.append(StepResult(name, "failed", exc.message()))
    return result


def _analysable(case: Case, evidence_ids: list[str]) -> list[str]:
    """The evidence to search with intelligence: extracted artifacts replace the disk image they come from."""
    from forense.image import evidence_kind

    targets = []
    for evidence_id in evidence_ids:
        derived = case.derived_evidence(evidence_id)
        if derived:
            targets += [d.id for d in derived]
        elif evidence_kind(Path(case.get_evidence(evidence_id).path)) not in ("memory", "volatility", "disk_image"):
            targets.append(evidence_id)
    return targets


def _intel(case: Case, evidence_ids: list[str], config: Config, actor: Optional[str],
           progress: Optional[Progress]) -> list[StepResult]:
    runs = [("hashset", "hash_list", p) for p in config.paths("intel.hash_lists")]
    runs += [("ioc", "watchlist", p) for p in config.paths("intel.watchlists")]
    runs += [("yara", "rules", p) for p in config.paths("intel.yara_rules")]
    if not runs:
        return [StepResult("intel", "skipped", t("auto.no_intel"))]
    results = []
    for module, option, path in runs:
        if not path.exists():
            results.append(StepResult(f"{module} {path.name}", "failed", t("auto.missing", path=str(path))))
            continue
        for evidence_id in evidence_ids:
            analysis = case.run_analysis(module, evidence_id, {option: str(path)}, actor, progress)
            results.append(StepResult(f"{module} {evidence_id} ({path.name})", analysis.status,
                                      t("auto.findings", count=analysis.finding_count)))
    return results


def _reports(case: Case, config: Config, args: dict, actor: Optional[str]) -> list[Path]:
    from forense.report import generate_report

    languages = args.get("languages") or config.value("report.languages") or [None]
    pdf = args.get("pdf", config.value("report.pdf"))
    paths = []
    for lang in languages:
        html = generate_report(case, lang, actor=actor)
        paths.append(html)
        if pdf:
            from forense.report.pdf import html_to_pdf

            try:
                paths.append(html_to_pdf(html, case=case, actor=actor))
            except ForenseError:
                pass  # no headless browser available: the HTML report is still there
    return paths


def _exports(case: Case, kinds: list[str], actor: Optional[str]) -> list[Path]:
    from forense.core import exports

    folder = case.root / "exports"
    functions = {"findings": exports.export_findings, "timeline": exports.export_timeline,
                 "execution": exports.export_execution}
    paths = []
    for kind in kinds:
        if kind == "stix":
            from forense.core.stix import export_stix

            paths.append(export_stix(case, stamped_path(folder, "iocs", ".stix.json"), actor=actor))
        elif kind in functions:
            paths.append(functions[kind](case, stamped_path(folder, kind, ".csv"), "csv", actor=actor))
    return paths


# -- creating cases and processing a drop folder ------------------------------------------------
def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._") or "case"


def auto(paths: list[Path], case_dir: Optional[Path] = None, new_case: Optional[Path] = None,
         name: Optional[str] = None, investigator: Optional[str] = None, playbook: Optional[str] = None,
         copy: bool = False, description: str = "", config: Optional[Config] = None, actor: Optional[str] = None,
         progress: Optional[Progress] = None) -> AutomationResult:
    """Register ``paths`` in a case (existing, new or created in the workspace) and run a playbook."""
    config = config or get_config()
    steps = load_playbook(playbook or config.value("automation.playbook") or "full")
    actor = actor or config.value("analyst") or None
    if case_dir is not None:
        case = Case.open(Path(case_dir))
    else:
        if new_case is None:
            workspace = Path(config.value("workspace") or ".").expanduser()
            new_case = _new_case_dir(workspace, Path(f"auto_{Path(paths[0]).name}"))
        case = Case.create(Path(new_case), name or t("auto.case_name", evidence=Path(paths[0]).name),
                           investigator or actor or t("auto.investigator"), description,
                           organization=config.value("organization") or "")
    with case:
        evidence_ids = []
        for path in paths:
            if progress:
                progress(t("auto.registering", path=str(path)))
            evidence = case.add_evidence(Path(path), description or Path(path).name, copy=copy, actor=actor)
            evidence_ids.append(evidence.id)
        return run_playbook(case, evidence_ids, steps, config, actor, progress)


STATE_FILE = ".forense-watch.json"


def _new_case_dir(workspace: Path, item: Path) -> Path:
    base = workspace / f"{datetime.now():%Y%m%d_%H%M%S}_{slug(item.stem)}"
    path, counter = base, 2
    while path.exists():
        path = base.with_name(f"{base.name}_{counter}")
        counter += 1
    return path


def _fingerprint(path: Path) -> tuple[int, float]:
    if path.is_file():
        stat = path.stat()
        return stat.st_size, stat.st_mtime
    total, latest = 0, 0.0
    for item in path.rglob("*"):
        if item.is_file():
            stat = item.stat()
            total += stat.st_size
            latest = max(latest, stat.st_mtime)
    return total, latest


def watch(inbox: Path, workspace: Path, playbook: Optional[str] = None, interval: float = 15.0, once: bool = False,
          config: Optional[Config] = None, progress: Optional[Progress] = None,
          stop: Optional[Callable[[], bool]] = None) -> list[AutomationResult]:
    """Process every new item dropped in ``inbox`` into its own case in ``workspace``.

    An item is processed once its size and modification time are stable between two
    polls (so copies still in progress are not taken). State is kept in
    ``workspace/.forense-watch.json`` so a restart does not process items again.
    """
    inbox, workspace = Path(inbox), Path(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    state_path = workspace / STATE_FILE
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.is_file() else {}
    seen: dict[str, tuple] = {}
    results = []
    while True:
        for item in sorted(inbox.iterdir()) if inbox.is_dir() else []:
            key = str(item.resolve())
            if key in state or item.name.startswith(".") or item.name.endswith((".part", ".tmp", ".crdownload")):
                continue
            fingerprint = _fingerprint(item)
            if seen.get(key) != fingerprint and not once:
                seen[key] = fingerprint  # changed (or first seen): wait for the next poll
                continue
            if progress:
                progress(t("auto.watch_item", item=item.name))
            case_dir = _new_case_dir(workspace, item)
            try:
                result = auto([item], new_case=case_dir, name=item.name, playbook=playbook, config=config,
                              progress=progress)
                results.append(result)
                state[key] = {"case": str(case_dir), "processed": datetime.now(timezone.utc).isoformat(),
                              "status": "ok"}
            except Exception as exc:  # noqa: BLE001 - one bad item must not stop the watcher
                error = exc.message() if isinstance(exc, ForenseError) else f"{type(exc).__name__}: {exc}"
                if progress:
                    progress(f"{t('common.error')}: {error}")
                state[key] = {"case": str(case_dir), "processed": datetime.now(timezone.utc).isoformat(),
                              "status": "failed", "error": error}
            state_path.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")
        if once or (stop and stop()):
            return results
        time.sleep(interval)
