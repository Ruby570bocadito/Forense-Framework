# IMP-2 — Web e informes

## Hecho (últimas 24 h)
- Bootstrap de docs/agentes/ (junto a DIR; ROADMAP fusionado por DIR) y main fijada como predeterminada.
- report-signing (3e1671f): firma Ed25519 desacoplada (.sig) de informes HTML y PDF, verificación desde la web,
  huella pública y hashes en custodia, clave privada siempre fuera del caso (FORENSE_SIGN_KEY / FORENSE_SIGN_PUB).
  Dependencia cryptography>=42 justificada en el commit. CLI --sign pendiente de IMP-1.
- web-rendimiento (93074ef): paginación de hallazgos y ejecución (100/página, pager con filtros, totales reales);
  técnicas ATT&CK solo de la página visible salvo filtro por técnica.
- web-accessibility (b6ad493): skip link, main con id, nav etiquetada, aria-current explícito en nav e idiomas,
  roles alert/status en avisos, aria-live en panel de trabajos, thead + scope en las 14 tablas de datos,
  columnas de marcadores/acciones con nombre, aria-label en campos sin etiqueta, foco visible en enlaces/botones.
- reports-hash-display (9b0912a): SHA-256 de cada informe contrastado con el hash registrado en custodia
  (insignia verde/aviso si el archivo cambió tras generarse), junto al estado de firma.
- Verificado con `forense demo`: informe es/en autocontenido (sin scripts ni recursos cargados; solo enlaces de
  referencia a MITRE), firma y verificación sobre el caso de demo, ruff y pytest en verde (283 tests).

## En curso
- (nada — sin tareas IMP-2 en el ROADMAP)

## Bloqueado
- (nada; sin hallazgos abiertos dirigidos a IMP-2)

## Peticiones a otras zonas
- IMP-1: exponer --sign en `forense informe` (cli.py) sobre forense/report/signing.py ya operativo.
- IMP-1: opcional a futuro, offset/limit en Case.findings si algún día hacen falta cientos de miles de hallazgos.
- DIR: marcar [x] web-accessibility y reports-hash-display (verificadas, commits arriba); el ROADMAP en remoto
  aún las muestra abiertas.

## Propuestas para el roadmap
- Asociar for/id en las opciones de módulo de analyses.html (hoy tienen label adyacente sin referencia).
- Clave de firma como opción de configuración report.sign_key en DEFAULTS (core/config.py — IMP-1).
