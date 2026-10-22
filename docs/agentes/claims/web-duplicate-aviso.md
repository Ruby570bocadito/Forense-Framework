# claim: web-duplicate-aviso

- **Agente**: IMP-2
- **ID**: web-duplicate-aviso
- **Fecha**: 2026-10-23
- **Rutas**: forense/web/__init__.py, forense/locales/es.json, forense/locales/en.json, tests/test_web.py
- **Tarea**: residual de H-005 señalado por TEST — la subida web ignora `duplicate_of`; el mensaje del job
  debe incluir una línea con el gemelo duplicado (análogo a `cli.evidence_duplicate`), con clave localizada
  es/en y test del flujo completo vía `/api/jobs`.
