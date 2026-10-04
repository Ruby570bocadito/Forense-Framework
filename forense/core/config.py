"""User configuration (YAML): analyst, language, workspace, intelligence lists and automation defaults.

Location: ``--config FILE``, the ``FORENSE_CONFIG`` variable, or
``%APPDATA%\\Forense\\config.yaml`` (Windows) / ``~/.config/forense/config.yaml``.
Command-line options always win over the configuration.
"""

from __future__ import annotations

import copy
import os
import re
from pathlib import Path
from typing import Any, Optional

import yaml

from forense.core.errors import ForenseError

DEFAULTS: dict[str, Any] = {
    "analyst": "",
    "language": "",
    "organization": "",
    "workspace": "",
    "intel": {
        "hash_lists": [],      # known-bad hash lists (one hash per line)
        "watchlists": [],      # IOC watchlists (IPs, domains, e-mails...)
        "yara_rules": [],      # .yar files or folders
        "sigma_rules": "",     # folder of Sigma rules (e.g. SigmaHQ) applied to EVTX
        "sigma_min_level": "medium",
    },
    "image": {"vss": False},
    "memory": {"symbols": "", "offline": False},
    "report": {"languages": [], "pdf": False},
    "automation": {"playbook": "full"},
    "web": {"host": "127.0.0.1", "port": 8765},
}

TEMPLATE = """\
# Forense-Framework — configuración / configuration
# Las opciones de la línea de órdenes tienen prioridad. / Command-line options take precedence.

analyst: ""            # nombre en la cadena de custodia / name in the chain of custody
language: ""           # es | en (vacío = idioma del sistema / empty = system language)
organization: ""
workspace: ""          # carpeta de casos / cases folder (web, auto, watch)

intel:                 # inteligencia aplicada en el análisis automático / used by automation
  hash_lists: []       # [C:\\\\intel\\\\malware_sha256.txt]
  watchlists: []       # [C:\\\\intel\\\\iocs.txt]
  yara_rules: []       # [C:\\\\intel\\\\yara]
  sigma_rules: ""      # C:\\\\intel\\\\sigma   (forense sigma download C:\\\\intel\\\\sigma)
  sigma_min_level: medium

image:
  vss: false           # extraer también de las instantáneas / also extract from shadow copies

memory:
  symbols: ""          # carpeta de símbolos de Volatility / Volatility symbols folder
  offline: false

report:
  languages: []        # [es, en] (vacío = idioma actual / empty = current language)
  pdf: false           # también en PDF (necesita Edge, Chrome o Chromium) / also as PDF

automation:
  playbook: full       # triage | full | quick | ruta a un .yaml / path to a .yaml

web:
  host: 127.0.0.1
  port: 8765
"""


def default_path() -> Path:
    if os.environ.get("FORENSE_CONFIG"):
        return Path(os.environ["FORENSE_CONFIG"]).expanduser()
    if os.name == "nt" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "Forense" / "config.yaml"
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "forense" / "config.yaml"


def _merge(base: dict, extra: dict) -> dict:
    merged = copy.deepcopy(base)
    for key, value in (extra or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


class Config(dict):
    """Configuration with dotted access: ``config.get_path("intel.hash_lists")``."""

    path: Optional[Path] = None
    loaded: bool = False

    def value(self, dotted: str, default: Any = None) -> Any:
        node: Any = self
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def paths(self, dotted: str) -> list[Path]:
        """A path or list of paths, expanded (``~``, environment variables)."""
        raw = self.value(dotted) or []
        items = raw if isinstance(raw, list) else [raw]
        return [Path(os.path.expandvars(str(item))).expanduser() for item in items if str(item).strip()]


def load_config(path: Optional[Path] = None) -> Config:
    path = Path(path) if path else default_path()
    data: dict = {}
    if path.is_file():
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ForenseError("error.config_invalid", path=str(path), error=str(exc).splitlines()[0]) from exc
        if not isinstance(data, dict):
            raise ForenseError("error.config_invalid", path=str(path), error="not a mapping")
    config = Config(_merge(DEFAULTS, data))
    config.path = path
    config.loaded = path.is_file()
    return config


def _yaml_string(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"  # single quotes: Windows backslashes stay as they are


def write_template(path: Optional[Path] = None, overwrite: bool = False, **values: str) -> Path:
    """Write the commented template; ``values`` fill top-level keys (``analyst``, ``workspace``...)."""
    path = Path(path) if path else default_path()
    if path.exists() and not overwrite:
        raise ForenseError("error.config_exists", path=str(path))
    text = TEMPLATE
    for key, value in values.items():
        if value:
            text = re.sub(rf'^{key}: ""', lambda _m, k=key, v=value: f"{k}: {_yaml_string(v)}", text, count=1,
                          flags=re.M)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


_current: Optional[Config] = None


def get_config() -> Config:
    """The configuration of the running process (loaded once)."""
    global _current
    if _current is None:
        try:
            _current = load_config()
        except ForenseError:
            _current = Config(copy.deepcopy(DEFAULTS))
    return _current


def set_config(config: Optional[Config]) -> None:
    global _current
    _current = config
