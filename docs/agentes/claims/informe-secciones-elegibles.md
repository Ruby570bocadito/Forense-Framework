# claim: informe-secciones-elegibles

- ID: IMP-2
- Fecha (UTC): 2026-10-25T12:55:00Z
- Tarea ROADMAP: informe-secciones-elegibles (L6 del roadmap de producto, P2) — elegir qué secciones
  incluye el informe y con qué nivel de detalle (máximo de filas, solo hallazgos confirmados),
  registrado en custodia.

## Rutas que tocará
- forense/report/__init__.py (generate_report: opciones de secciones y detalle)
- forense/report/templates/report.html (renderizado condicional de secciones y nota de recorte)
- forense/web/__init__.py (el formulario de informes pasa las opciones)
- forense/web/templates/reports.html (selector de secciones y detalle)
- forense/locales/es.json, forense/locales/en.json (solo añadir claves)
- tests/test_report.py, tests/test_web.py
