"""`forense doctor`: check that the installation can do everything (dependencies, PDF, config, workspace).

Each check reports ``ok``, ``warn`` (works with reduced functionality),
``missing`` (an optional part is not installed) or ``error`` (a required part
is missing or broken: the command exits with an error).
"""

from __future__ import annotations

import importlib
import importlib.metadata
import os
import platform
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse

from forense import __version__

# (import name, distribution, purpose key, required)
DEPENDENCIES = (
    ("evtx", "evtx", "doctor.purpose.evtx", True),
    ("flask", "Flask", "doctor.purpose.web", True),
    ("yaml", "PyYAML", "doctor.purpose.yaml", True),
    ("olefile", "olefile", "doctor.purpose.jumplists", True),
    ("pyscca", "libscca-python", "doctor.purpose.prefetch", True),
    ("pyesedb", "libesedb-python", "doctor.purpose.srum", True),
    ("pytsk3", "pytsk3", "doctor.purpose.tsk", True),
    ("pyewf", "libewf-python", "doctor.purpose.e01", True),
    ("pyvhdi", "libvhdi-python", "doctor.purpose.vhd", True),
    ("pyvmdk", "libvmdk-python", "doctor.purpose.vmdk", True),
    ("pyqcow", "libqcow-python", "doctor.purpose.qcow", True),
    ("pyvshadow", "libvshadow-python", "doctor.purpose.vss", True),
    ("pybde", "libbde-python", "doctor.purpose.bitlocker", True),
    ("yara_x", "yara-x", "doctor.purpose.yara", True),
)


@dataclass
class Check:
    name: str
    status: str  # ok | warn | missing | error
    detail: str
    purpose: str = ""


def _version(distribution: str, module) -> str:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return str(getattr(module, "__version__", "") or getattr(module, "get_version", lambda: "")() or "")


def _dependency(name: str, distribution: str, purpose: str, required: bool) -> Check:
    from forense.i18n import t

    try:
        module = importlib.import_module(name)
    except Exception as exc:  # noqa: BLE001 - ImportError or a broken native library
        detail = f"{type(exc).__name__}: {exc}".splitlines()[0][:160]
        return Check(distribution, "error" if required else "missing", detail, t(purpose))
    return Check(distribution, "ok", _version(distribution, module), t(purpose))


def run_checks(config=None) -> list[Check]:
    from forense.core.config import get_config, load_config
    from forense.core.errors import ForenseError
    from forense.i18n import get_language, t
    from forense.parsers.volatility import volatility_command
    from forense.report.pdf import find_browser

    checks = [Check("Forense-Framework", "ok", f"{__version__} · {'exe' if getattr(sys, 'frozen', False) else 'python'}",
                    t("doctor.purpose.framework")),
              Check("Python", "ok" if sys.version_info >= (3, 10) else "error",
                    f"{platform.python_version()} ({platform.system()} {platform.release()}, {platform.machine()})",
                    t("doctor.purpose.python"))]
    checks += [_dependency(*dep) for dep in DEPENDENCIES]

    command = volatility_command()
    try:
        vol_detail = importlib.metadata.version("volatility3")
    except importlib.metadata.PackageNotFoundError:
        vol_detail = command[-1] if command else t("doctor.volatility_hint")
    checks.append(Check("Volatility 3", "ok" if command else "missing", vol_detail, t("doctor.purpose.memory")))
    browser = find_browser()
    checks.append(Check(t("doctor.browser"), "ok" if browser and Path(browser).exists() else "warn",
                        browser or t("doctor.browser_hint"), t("doctor.purpose.pdf")))

    try:
        config = config or load_config(get_config().path)
        checks.append(Check(t("doctor.config"), "ok" if config.loaded else "missing",
                            f"{config.path}" + ("" if config.loaded else f" — {t('doctor.config_hint')}"),
                            t("doctor.purpose.config")))
    except ForenseError as exc:
        checks.append(Check(t("doctor.config"), "error", exc.message(), t("doctor.purpose.config")))
        config = get_config()
    webhook = str(config.value("notify.webhook") or "")
    checks.append(Check(t("doctor.notify"), "ok" if webhook else "missing",
                        (urlparse(webhook).hostname or webhook[:40]) if webhook else t("doctor.notify_hint"),
                        t("doctor.purpose.notify")))
    workspace = Path(os.path.expandvars(str(config.value("workspace") or os.environ.get("FORENSE_WORKSPACE") or
                                            "."))).expanduser()
    checks.append(_writable(workspace, t("doctor.workspace"), t("doctor.purpose.workspace")))
    for key, label in (("intel.hash_lists", "doctor.hash_lists"), ("intel.watchlists", "doctor.watchlists"),
                       ("intel.yara_rules", "doctor.yara_rules"), ("intel.sigma_rules", "doctor.sigma_rules")):
        missing = [str(p) for p in config.paths(key) if not p.exists()]
        if missing:
            checks.append(Check(t(label), "warn", t("doctor.path_missing", paths=", ".join(missing)),
                                t("doctor.purpose.intel")))

    rules = Path(__file__).parent / "sigma" / "rules"
    count = len(list(rules.glob("*.yml"))) if rules.is_dir() else 0
    checks.append(Check(t("doctor.sigma_bundled"), "ok" if count else "error", str(count), t("doctor.purpose.sigma")))
    checks.append(Check(t("doctor.language"), "ok", get_language(), t("doctor.purpose.language")))
    if os.name == "nt":
        checks.append(Check(t("doctor.admin"), "ok" if _is_admin() else "warn",
                            t("doctor.yes") if _is_admin() else t("doctor.admin_hint"), t("doctor.purpose.collect")))
    return checks


def _writable(path: Path, name: str, purpose: str) -> Check:
    try:
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path, prefix=".forense-doctor-"):
            pass
    except OSError as exc:
        return Check(name, "error", f"{path.resolve()}: {exc.strerror or exc}", purpose)
    return Check(name, "ok", str(path.resolve()), purpose)


def _is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return False


def healthy(checks: list[Check]) -> bool:
    return not any(c.status == "error" for c in checks)


def as_dicts(checks: list[Check]) -> list[dict]:
    return [asdict(c) for c in checks]


def summary(checks: list[Check]) -> dict[str, int]:
    counts: dict[str, int] = {"ok": 0, "warn": 0, "missing": 0, "error": 0}
    for check in checks:
        counts[check.status] = counts.get(check.status, 0) + 1
    return counts
