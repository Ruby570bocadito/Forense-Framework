# claim: h-005-evidencia-duplicada

- ID: IMP-1
- Inicio: 2026-10-23T00:00Z
- Hallazgo: H-005 (evidencia duplicada sin aviso)
- Rutas que tocaré: forense/core/case.py, forense/cli.py, forense/locales/es.json, forense/locales/en.json,
  tests/test_core.py, tests/test_cli.py
- Plan: `add_evidence` detecta contenido ya registrado (misma SHA-256) y lo expone en la Evidence devuelta;
  la CLI emite un aviso por stderr en el idioma de la sesión, sin bloquear el registro.
