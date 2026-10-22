# claim: h-009-exportar-alias

- ID: IMP-1
- Inicio: 2026-10-23T01:00Z
- Hallazgo: H-009 (exportar no acepta los términos en español de su propia ayuda; error de argparse en inglés)
- Rutas que tocaré: forense/cli.py, forense/locales/es.json, forense/locales/en.json, tests/test_cli.py
- Plan: `export what` acepta los términos es/en (y variantes con tilde) mediante un mapa de alias que usa los
  mismos nombres que los subcomandos (analisis, cronologia, hallazgos, ejecucion, custodia); validación manual
  con error localizado en vez de choices de argparse.
