"""Sabueso-Framework: framework modular de análisis forense digital."""

__version__ = "0.4.0"

import os as _os

# Variables from before the project was renamed (FORENSE_*) keep working unless the SABUESO_* one is set.
for _name, _value in list(_os.environ.items()):
    if _name.startswith("FORENSE_"):
        _os.environ.setdefault("SABUESO_" + _name[len("FORENSE_"):], _value)
