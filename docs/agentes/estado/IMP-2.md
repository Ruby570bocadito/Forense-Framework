# IMP-2 — Web e informes

## Hecho (últimas 24 h)
- vista-impresa-hallazgos (K11 del roadmap de producto; de9adc2): exportación de hallazgos como HTML
  imprimible autónomo (sin JS, sin recursos externos, estilos inline, thead repetido por página),
  mismo camino de entrega que la exportación de la línea temporal: fichero en exports/ del caso y
  entrada de custodia export_created con el SHA-256 real del documento y los filtros aplicados.
  Respeta los filtros de la página de hallazgos (severidad mínima, estado de revisión, técnica
  ATT&CK); cada fila lleva título y descripción, técnicas ATT&CK, evidencia, análisis y último
  veredicto de revisión (nota y revisor); los falsos positivos van atenuados. Botón
  "Exportar HTML (imprimir)" junto al de CSV. Claves es/en: export_html.findings,
  export_html.findings_no_filters. 6 tests (custodia, filtros, estado de revisión, caso vacío,
  escape hostil, ruta web con CSRF). Suite al cerrar: 386 passed, 1 skipped; ruff limpio.
  web-duplicada-aviso ya estaba entregada en main (9a9e803); no se rehizo.

## En curso
- web-progreso (K10, P1): progreso real de jobs (archivos procesados / total, módulo actual) con
  Server-Sent Events, cancelación y cola visible. Reclamada; sin trabajo local todavía.

## Bloqueado
- (nada)

## Peticiones a otras zonas
- DIR: marcar [x] vista-impresa-hallazgos (entregada) y web-duplicada-aviso (9a9e803, sesión previa).
- TEST: si toca verificar, la exportación nueva es POST /c/<slug>/export/findings_html con los
  mismos filtros de query que la página (severity/status/technique); CSRF como el resto de exports.

## Propuestas para el roadmap
- Siguientes de mi zona por prioridad, a la espera de promoción: K9 web-subida-archivos (P1),
  K18 web-accesibilidad-aa (P1; exige axe-core vendido para el e2e, sin recursos externos en
  runtime), L1 informe-plantillas (P1) y L3 informe-pdfa (P1).
