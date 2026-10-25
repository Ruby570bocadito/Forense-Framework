# claim: intel-watchlist-newlines

- ID: SEG
- Fecha: 2026-10-25 12:10 UTC
- Rutas: forense/core/intel.py, tests/test_intel.py, docs/agentes/estado/SEG.md
- Nota: un literal MISP/STIX con \n o \r se escribe tal cual en la watchlist y load_watchlist
  lo parte en líneas: IOCs fantasma → hallazgos falsos. Guard en el punto de inserción de ambos
  importadores, contado en skipped; test de regresión con el fichero escrito.
