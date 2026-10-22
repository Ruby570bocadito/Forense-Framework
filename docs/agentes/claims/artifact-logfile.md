# claim: artifact-logfile

- ID: IMP-1
- Fecha: 2026-10-22 18:05 UTC
- Rutas: forense/parsers/logfile.py (nuevo), forense/parsers/mft.py (solo exponer apply_fixups),
  forense/modules/windows/logfile.py (nuevo), forense/modules/__init__.py (solo añadir import),
  forense/demo/builders.py, forense/demo/__init__.py, forense/locales/es.json + en.json (solo añadir claves),
  tests/test_parsers.py, tests/test_modules.py, tests/test_artifacts.py (si procede)
