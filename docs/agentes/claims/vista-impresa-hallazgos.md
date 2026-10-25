# claim: vista-impresa-hallazgos

- ID: IMP-2
- Fecha (UTC): 2026-10-25T11:46:00Z
- Tarea ROADMAP: vista-impresa-hallazgos — vista imprimible de hallazgos análoga a la de la línea
  temporal, anclada a custodia (export_created + sha256). Equivalente a K11 del roadmap de producto.
- Nota: web-duplicada-aviso ya está entregada en main (9a9e803) y verificada en código; no se rehace.

## Rutas que tocará
- forense/report/findings_html.py (nuevo: export_findings_html, mismo camino que timeline_html.py)
- forense/report/templates/findings_export.html (nuevo: documento autónomo, sin JS ni recursos externos)
- forense/web/__init__.py (rama what == "findings_html" en export() + _findings_filters())
- forense/web/templates/findings.html (botón "Exportar HTML (imprimir)" con los filtros actuales)
- forense/locales/es.json, forense/locales/en.json (solo añadir claves export_html.*)
- tests/test_report.py, tests/test_web.py (tests de informe y de la ruta web)
