# claim: artifact-rdp-cache

- ID: IMP-1
- Inicio: 2026-10-23 (sesión 3)
- Tarea ROADMAP: (IMP-1) artifact-rdp-cache — RDP Bitmap Cache (bCache*.bin / Cache*.bin, Tile_*.bmp):
  actividad RDP histórica; entrega completa
- Rutas que tocará:
  - forense/modules/windows/rdp_cache.py (nuevo módulo triage: extrae tiles como BMP, hallazgo LOW)
  - forense/core/attack.py (mapeo ATT&CK del hallazgo: T1021.001)
  - forense/modules/__init__.py (solo-adición: import)
  - forense/locales/es.json, en.json (solo-adición: módulo, artifact, fields, finding)
  - forense/demo/builders.py (build_rdp_cache) y forense/demo/__init__.py (Cache0001.bin de la historia)
  - tests/test_modules.py, tests/test_core.py (módulo, tolerancia a corrupción, triaje demo)
- Formato: contenedor documentado y estable (cabecera 12 bytes; tile = Key1+Key2+Width+Height+
  BITMAPINFOHEADER 40 bytes + píxeles bottom-up) → síntesis honesta en demo y tests.
