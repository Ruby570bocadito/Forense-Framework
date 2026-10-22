# claim: web-filtros-guardados

- ID: IMP-2
- Inicio: 2026-10-23 (sesión 5)
- Tarea: propuesta propia aprobada por el operador — guardar y reaplicar filtros de la interfaz por caso
  (hallazgos y línea temporal): chips de filtro guardado, guardado del filtro activo con nombre, borrado.
- Rutas que tocará:
  - forense/web/filters.py (nuevo: almacén JSON por caso con allowlist de claves y tope)
  - forense/web/__init__.py (rutas POST save/delete + variable saved en findings y timeline)
  - forense/web/templates/_saved_filters.html (nuevo), findings.html, timeline.html
  - forense/web/static/style.css (estilos de chips)
  - forense/locales/es.json, en.json (8 claves aditivas web.filters_*)
  - tests/test_web.py
- No toca: forense/core/ (el almacén vive en <caso>/ui/saved_filters.json, escrito por la web), export CSV,
  e2e (zona TEST). Sin entrada en custodia (estado de interfaz, no evidencia).
- Invariantes: POST con CSRF, allowlist estricta de claves de filtro por página (se descartan otras), tope
  20 filtros por caso, nombre recortado a 80, autoescape en el nombre, es/en por locales.
