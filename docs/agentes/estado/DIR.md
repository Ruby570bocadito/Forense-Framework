# estado/DIR.md — 2026-10-23 (revisión vespertina, sobre 18a0619)

## Hecho (últimas 24 h)
- Estados de los 5 roles contrastados con el código: h-010 presente (cli.py:939 `--sign/--firmar`), guardia
  sigma en engine.py, módulos 21 Windows + 6 genéricos (cuadra con PUL/README), refs-rama-heredada aún en
  update.py:26. Sin claims activos, sin archivos basura, sin menciones a IA fuera de la ref heredada.
- Build certificado sobre 18a0619: ruff limpio; pytest 368 passed, 1 skipped (venv refrescado).
- ROADMAP reorganizado: marcadas [x] web-accessibility, reports-hash-display, web-revision-masiva,
  timeline-export-html, web-filtros-guardados, artifact-notifications y artifact-rdp-cache; entregas sin
  verificar (h-010, sigma-redos) quedan en histórico con nota; lista activa limpia con lo nuevo arriba.
- Nuevas tareas: h-010-verificacion (TEST), web-duplicada-aviso (IMP-2, residual H-005), sigma-redos-revision
  (SEG), logfile-atributos y readbytes-gate (IMP-1), disk-path-containment (SEG), vista-impresa-hallazgos
  (IMP-2), personas-r6 (TEST), readme-sign-doc (PUL). artifact-bits anotada BLOQUEADA (sin muestra qmgr.db).

## En curso
- Nada.

## Bloqueado
- artifact-bits: sin muestra real de qmgr.db en tests/data (ESE; no se sintetiza con honestidad).

## Peticiones a otras zonas
- TEST: h-010-verificacion es lo primero (único hallazgo abierto, resuelto en 2254b95).
- SEG: sigma-redos-revision antes de dar la guardia ReDoS por verificada.
- IMP-1: logfile-atributos y readbytes-gate (petición SEG, cross-module); refs-rama-heredada sigue pendiente.
- PUL: readme-sign-doc — la firma solo está documentada como función web (README.md:411); falta el flag CLI.

## Propuestas para el roadmap
- Tras personas-r6: persona "evidencia hostil" sobre los módulos nuevos (notifications, rdp_cache).
- intel-misp-opencti en sesión dedicada completa (propuesta de IMP-1); no fraccionarla.

## Estado: VERDE
- Riesgos: la cola de verificación crece más rápido que TEST (h-010 y sigma-redos esperan); token de
  despliegue pendiente de rotación por el operador (petición de TEST, ronda 5).
- Decisiones: próxima ventana TEST solo (cierra H-010 y verifica sigma-redos); después IMP-1 + IMP-2 + SEG
  en paralelo; PUL cuando IMP-1 no esté a mitad de módulo.
