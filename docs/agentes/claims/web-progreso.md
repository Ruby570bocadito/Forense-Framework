# claim: web-progreso

- ID: IMP-2
- Fecha (UTC): 2026-10-25T12:20:00Z
- Tarea ROADMAP: web-progreso (K10 del roadmap de producto, P1) — progreso real de los jobs
  (archivos procesados / total, módulo actual) con Server-Sent Events, cancelación de jobs y cola
  visible.

## Rutas que tocará
- forense/web/jobs.py (progreso incremental, cancelación cooperativa, cola)
- forense/web/__init__.py (endpoint SSE de progreso, POST de cancelación)
- forense/web/templates/ (panel de cola de jobs con progreso y cancelar; base.html si procede)
- forense/locales/es.json, forense/locales/en.json (solo añadir claves web.*)
- tests/test_web.py (y tests de jobs si procede)
