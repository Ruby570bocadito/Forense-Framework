# IMP-2 — Web e informes

## Hecho (últimas 24 h)
- report-signing (3e1671f): firma Ed25519 desacoplada (.sig) de informes HTML y PDF, verificación desde la web,
  huella pública y hashes en custodia, clave privada siempre fuera del caso (FORENSE_SIGN_KEY / FORENSE_SIGN_PUB).
  Dependencia cryptography>=42 justificada en el commit. CLI --sign pendiente de IMP-1.
- web-rendimiento (93074ef): paginación de hallazgos y ejecución (100/página, pager con filtros, totales reales).
- web-accessibility (b6ad493): skip link, aria-current explícito, roles de avisos, aria-live en jobs,
  thead + scope en las 14 tablas, aria-labels, foco visible; temas claro/oscuro intactos.
- reports-hash-display (9b0912a): SHA-256 de cada informe contrastado con la custodia (insignia coincide/cambiado).
- web-revision-masiva (90d4996): selección múltiple en la tabla de hallazgos y estado de revisión en bloque
  con nota opcional; la pista de auditoría sigue siendo una entrada por hallazgo (actor + sello UTC vía
  Case.review_finding). POST con CSRF, estado validado de entrada, ids saneados con tope (1000), hallazgos
  desaparecidos se omiten y se resumen en un aviso. Checkboxes vía atributo form= (sin formularios anidados)
  y "seleccionar todo" en static/app.js (CSP limpia). Claves web.bulk_* es/en; tests: flujo, CSRF, estado
  inválido, selección vacía y fallo parcial.
- h-008 (b1edf5b): el pipeline PDF se verifica ya en la suite sin navegador real: navegador falso multiplataforma
  (shebang POSIX / .bat Windows; el test de custodia PDF deja de saltarse en Windows), timeout → error.pdf_failed,
  sin navegador → error.pdf_no_browser (globs /opt a constante _GLOBS) y descubrimiento por PATH. H-008 queda
  resuelto-pendiente-verificación. Suite: 290 passed, 1 skipped; ruff limpio.

## En curso
- (nada)

## Bloqueado
- (nada)

## Peticiones a otras zonas
- PUL: job de CI con un Chromium real (p. ej. playwright install chromium) que genere un PDF del caso demo y
  compruebe que empieza por %PDF — cubre lo que la suite no puede con navegador falso (origen de H-008).
- IMP-1: exponer --sign en `forense informe` (cli.py) sobre forense/report/signing.py ya operativo.
- DIR: marcar [x] web-accessibility, reports-hash-display y web-revision-masiva (entregadas y verificadas).

## Propuestas para el roadmap
- Asociar for/id en las opciones de módulo de analyses.html (hoy tienen label adyacente sin referencia).
- Clave de firma como opción de configuración report.sign_key en DEFAULTS (core/config.py — IMP-1).
