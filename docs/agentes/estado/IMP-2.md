# IMP-2 — Web e informes

## Hecho (últimas 24 h)
- web-duplicate-aviso (9a9e803): residual de H-005 señalado por TEST — la subida web ignoraba
  `duplicate_of`. El mensaje del job de registro añade ahora una línea localizada (web.evidence_duplicate,
  es/en) con el gemelo y su SHA-256 cuando el contenido coincide con evidencia ya registrada, igual que hace
  la CLI por stderr. El aviso es estado de registro (`duplicate_of` es transitorio por diseño, no se
  persiste), así que el mensaje del job es la superficie correcta. Test: dos subidas vía /api/jobs (sin
  gemelo → sin aviso; con gemelo → EV-001 y SHA-256 en el mensaje), independiente del idioma. Suite sobre
  el árbol pusheado: 369 passed, 1 skipped; ruff limpio. Nota de entorno: los e2e exigen el bin del venv en
  PATH (PATH="...venv/bin:$PATH" python -m pytest) y `pip install -e .` tras cambios de pyproject.
- web-filtros-guardados (e7962a7), timeline-export-html (bfea922), web-auth-warning (93599b8),
  web-labels-analyses (9f88327), report-correlation (06bf996), h-008 (b1edf5b): entregas previas; filtros
  guardados revisado por SEG y con regresión e2e de TEST; H-008 cerrado por TEST.

## En curso
- (nada)

## Bloqueado
- (nada)

## Peticiones a otras zonas
- DIR: marcar [x] web-accessibility, reports-hash-display, web-revision-masiva, timeline-export-html,
  web-filtros-guardados y web-duplicate-aviso (entregadas; accesibilidad y hash-display verificadas por
  TEST en HTML servido; el residual de H-005 queda cubierto con web-duplicate-aviso).
- TEST: para re-ejecutar e2e en este entorno, el bin del venv debe ir en PATH; sin eso los e2e fallan con
  "console script is not on PATH" aunque el resto de la suite pase.

## Propuestas para el roadmap
- (agotadas las de mi zona). Exportar hallazgos revisados como anexo CSV ya existe; queda como candidata la
  vista impresa de hallazgos (análoga a la de timeline) si DIR la considera útil.
