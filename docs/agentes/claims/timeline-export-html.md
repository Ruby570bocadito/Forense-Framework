# claim: timeline-export-html

- ID: IMP-2
- Inicio: 2026-10-23 (sesión 4)
- Tarea: propuesta propia aprobada — exportación de la línea temporal como documento HTML imprimible
  autónomo (mismo camino que el export CSV: POST con CSRF, fichero en exports/ del caso, entrada de
  custodia export_created con sha256).
- Rutas que tocará:
  - forense/report/timeline_html.py (nuevo generador) y forense/report/templates/timeline_export.html
  - forense/web/__init__.py (rama what == "timeline_html" en la ruta export) y templates/timeline.html (botón)
  - forense/locales/es.json, en.json (claves aditivas: web.export_html + export_html.*)
  - tests/test_report.py, tests/test_web.py
- No toca: forense/core/ (solo consume Case.iter_events y custody.append), otros templates, e2e (zona TEST).
- Invariantes: documento sin JS y sin recursos externos (estilo inline, apto para imprimir/archivar),
  autoescape Jinja, timestamps UTC, texto es/en vía locales.
