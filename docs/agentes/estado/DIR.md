# estado/DIR.md — 2026-10-23 (sesión de revisión)

## Hecho (últimas 24 h)
- Revisión DIR tras el primer ciclo IMP/SEG/PUL: estados contrastados con git log y código real.
- ROADMAP: marcadas [x] readme-hoja-de-ruta, mft-attribute-list, report-signing, web-rendimiento,
  auditoria-extraccion, auditoria-subprocesos-yaml y pip-audit (todas verificadas con suite verde).
- Build verificado sobre b278129: `ruff check forense tests` limpio; `python -m pytest -q` = 278 passed, 1 skipped.
  Nota: refrescar `pip install -e ".[dev]"` tras pull si pyproject cambia (entró cryptography, ver IMP-1).
- Gitleaks 8.30.1 sobre árbol + historial: 0 hallazgos (confirmado en sesión previa).
- Nuevas tareas en ROADMAP: (PUL) readme-firma-mft-limitaciones (Hoja de ruta aún lista la firma ya
  implementada 5be9c5a; Limitaciones aún menciona $ATTRIBUTE_LIST resuelta en cf72bfa) y (IMP-1) sigma-redos
  (propuesta de SEG).

## En curso
- Nada. personas-r1 completada durante esta tanda: 9 hallazgos abiertos (IMP-1: 6, PUL: 2, IMP-2: 1),
  batería e2e inicial en tests/e2e/ (5 tests por subprocess, sin red).

## Cierre de la tanda (verificación final)
- Suite completa tras el ciclo: 293 passed, 1 skipped; ruff limpio. Marcadas [x] en ROADMAP:
  artifact-logfile, readme-arbol-comandos, readme-firma-mft-limitaciones y personas-r1.

## Bloqueado
- Nada.

## Peticiones a otras zonas
- PUL: la petición de IMP-1 sobre .gitignore (__pycache__/, *.egg-info/, caches) ya está cubierta por el
  .gitignore actual; nada commiteado. No requiere acción.
- PUL: readme-firma-mft-limitaciones (nueva en ROADMAP) recoge las dos correcciones de documentación pendientes.

## Propuestas para el roadmap
- Tras web-accessibility, IMP-2 sigue con reports-hash-display (dependencia de report-signing, ya hecha).
- Exposición CLI `--sign` (IMP-1, forense/cli.py) ya anotada en Dependencias; buena pareja para artifact-bits.

## Estado: VERDE
- Riesgos: varias tandas de agentes en paralelo — lanzar una sola por rol y respetar la ventana de TEST.
- Decisiones: TEST entra ahora; PUL en cuanto IMP-1 no esté a mitad de módulo (README y modules/ cambian juntos).
