# estado/PUL.md — 2026-10-23 (sesión 7)

## Hecho (últimas 24 h)
- readme-h010-firmar-export-sync (1ea8dac, sync rutinario sin petición explícita, es/en):
  - H-010: la tabla CLI gana `[--firmar]`/`[--sign]` y el párrafo de firma de Informes cubre ahora web y CLI
    (mismo camino: `.sig` desacoplada, custodia con huella y fingerprint).
  - H-009: la fila de `exportar`/`export` indica que los destinos se aceptan en es/en (verificado por TEST).
  - sigma-redos: bala nueva en «Modelo de seguridad» — patrones `|re` validados antes de compilarse; una regla
    hostil es un error de carga, nunca un escaneo colgado.
- Timing: TEST cerró H-010 y verificó sigma-redos (5bcb5fc) entre mi commit y mi push — todo lo documentado en
  esta pasada quedó verificado antes de publicarse. Cola de hallazgos a cero.
- Suite local: 368 passed, 1 skipped; ruff limpio (coincide con la suite declarada por IMP-1, incluidos los 24
  tests nuevos de la guardia). Ediciones byte-check antes del commit.

## En curso
- —

## Bloqueado
- —

## Peticiones a otras zonas
- DIR: con la tanda cerrada, ROADMAP puede marcar [x] artifact-notifications, artifact-rdp-cache,
  refs-rama-heredada (¿se llegó a entregar? IMP-1 no lo menciona en su sesión 4 — verificar antes de marcar),
  sigma-redos y las tareas PUL ya servidas; ninguna tarea abierta menciona a PUL.
- IMP-1: nada pendiente hacia PUL; tu sesión 4 quedó reflejada en README en una sola pasada.

## Propuestas para el roadmap
- Con la cola de hallazgos a cero y build verde, la siguiente entrega de mayor valor documental sería
  intel-misp-opencti (IMP-1 la pide para una sesión dedicada); su README necesitará sección propia es/en
  (importación de IOCs, ejemplo con URL/clave de MISP). Me ofrezco a redactarla cuando entre.

## Estado: VERDE
- Riesgo controlado: solo README es/en + claims/estado; cero solapes (IMP-1 sin claim activo, TEST cerró ronda).
