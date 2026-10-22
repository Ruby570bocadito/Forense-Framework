# IMP-2 — Web e informes

## Hecho (últimas 24 h)
- web-filtros-guardados (e7962a7): guardar y reaplicar filtros por caso en hallazgos y línea temporal. El
  filtro activo se guarda con nombre (POST + CSRF) y aparece como chip que lo reaplica con un clic; cada chip
  tiene su propio formulario de borrado. Almacén por caso (<caso>/ui/saved_filters.json, escritura atómica)
  para que los atajos viajen con el caso; es estado de interfaz, deliberadamente fuera de la custodia. La
  consulta guardada pasa por allowlist por página (cualquier otra clave se descarta: un formulario falsificado
  no puede colar parámetros), tope 20 filtros por caso con aviso localizado, nombre recortado a 80 y
  autoescapado como cualquier valor. Barra oculta sin filtros que mostrar; guardar deshabilitado sin filtros
  activos; página falsificada → 404. Claves web.filters_* es/en (10). Tests: flujo completo (guardar, chip,
  aplicar, borrar), guardas (CSRF, nombre vacío, consulta vacía, página e id falsos), escaping del nombre,
  timeline y tope, y tolerancia a fichero dañado. Suite sobre el árbol pusheado: 342 passed, 1 skipped;
  ruff limpio.
- timeline-export-html (bfea922): exportación de la línea temporal como HTML imprimible autónomo, anclada a
  custodia (export_created + sha256). Verificado el cierre de H-008 por TEST (e2e con navegador falso).
- web-auth-warning (93599b8), web-labels-analyses (9f88327), report-correlation (06bf996), h-008 (b1edf5b):
  entregas previas, todas revisadas o cerradas por SEG/TEST.

## En curso
- (nada)

## Bloqueado
- (nada)

## Peticiones a otras zonas
- DIR: marcar [x] web-accessibility, reports-hash-display, web-revision-masiva, timeline-export-html y
  web-filtros-guardados (entregadas; accesibilidad y hash-display verificadas por TEST en HTML servido).
- TEST: si toca la web, los filtros guardados viven en <caso>/ui/saved_filters.json (esquina de estado de
  interfaz, sin custodia); los chips y el guardado necesitan un filtro activo para habilitarse.
- Nota de entorno: los e2e exigen el script de consola `forense` en PATH (pip install -e .).

## Propuestas para el roadmap
- (agotadas las de mi zona).Exportar hallazgos revisados como anexo CSV ya existe; queda como candidata la
  vista impresa de hallazgos (análoga a la de timeline) si DIR la considera útil.
