# IMP-2 — Web e informes

## Hecho (últimas 24 h)
- timeline-export-html (bfea922): exportación de la línea temporal como documento HTML imprimible autónomo,
  junto al CSV existente. Fichero en exports/ del caso anclado a custodia (export_created con sha256, mismo
  formato que el resto de exports), filtros activos aplicados y anotaciones de marcadores incluidas. Sin JS,
  sin recursos externos, estilos inline, thead repetido en cada página impresa; todo valor proveniente de la
  evidencia pasa por autoescape de Jinja. Botón vía formaction en el mismo formulario (CSP limpia). Claves
  web.export_html + export_html.* es/en. Tests: documento autónomo y custodia, filtros, caso vacío, valores
  hostiles escapados y ruta web con CSRF. Suite sobre el árbol pusheado: 321 passed, 1 skipped; ruff limpio.
- web-auth-warning (93599b8): banda permanente en la interfaz cuando arranca sin contraseña (role=status,
  color --warn del tema, en todas las páginas) con referencia a FORENSE_WEB_PASSWORD. SEG la revisó: limpia
  y complementaria al aviso CLI.
- web-labels-analyses (9f88327): asociación explícita etiqueta-control (for/id) en analyses.html, con test.
- report-correlation (06bf996): sección opcional de correlación entre casos en el informe HTML.
- h-008 (b1edf5b): pipeline PDF verificado en la suite sin navegador real (navegador falso multiplataforma,
  timeout, sin navegador y PATH). Pendiente de verificación por TEST.
- web-revision-masiva (90d4996), web-accessibility (b6ad493), reports-hash-display (9b0912a), report-signing
  (3e1671f), web-rendimiento (93074ef): entregas previas ya revisadas por SEG/TEST.

## En curso
- (nada)

## Bloqueado
- (nada)

## Peticiones a otras zonas
- TEST: verificar h-008 (b1edf5b, resuelto-pendiente-verificación) y, si procede, cerrarlo.
- DIR: marcar [x] web-accessibility, reports-hash-display, web-revision-masiva y timeline-export-html
  (entregadas; las dos primeras verificadas por TEST en HTML servido).
- Nota de entorno: los e2e de TEST exigen el script de consola `forense` en PATH (pip install -e .); en esta
  máquina fallaban 3 e2e hasta instalarlo. Sin cambio de código necesario — queda como recordatorio de setup.

## Propuestas para el roadmap
- Guardar filtros de la interfaz por caso (web) — propuesta propia en cola, pendiente de aprobación de DIR.
