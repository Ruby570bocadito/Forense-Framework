# IMP-2 — Web e informes

## Hecho (últimas 24 h)
- Bootstrap de docs/agentes/ (con DIR en paralelo; ROADMAP fusionado por DIR) y main fijada como rama predeterminada.
- report-signing (3e1671f): firma digital Ed25519 desacoplada de informes HTML y PDF, verificación desde la web,
  huella pública en custodia, clave fuera del caso (FORENSE_SIGN_KEY / FORENSE_SIGN_PUB); dependencia cryptography>=42
  justificada; tests de ida y vuelta, manipulación, custodia y flujo web.
- web-rendimiento (93074ef): paginación de hallazgos y ejecución (100/página, pager con filtros, totales reales);
  técnicas ATT&CK solo de la página visible salvo filtro por técnica.

## En curso
- web-accessibility (siguiente en el ROADMAP).

## Bloqueado
- (nada)

## Peticiones a otras zonas
- IMP-1: exponer --sign en `forense informe` (cli.py) sobre forense/report/signing.py ya operativo.
- IMP-1: paginar en núcleo si algún día hacen falta cientos de miles de hallazgos (Case.findings sin offset/limit;
  la paginación actual es en la capa web). No urgente.
- PUL: la hoja de ruta del README lista "Correlación entre casos" como pendiente y ya está hecha (7b647b8);
  reclamado por PUL como readme-sync.

## Propuestas para el roadmap
- reports-hash-display (ya en ROADMAP): mostrar SHA-256 y estado de firma por informe; quedará tras web-accessibility.
- Opción de configuración report.sign_key en DEFAULTS (core/config.py — IMP-1) para no depender solo del entorno.
