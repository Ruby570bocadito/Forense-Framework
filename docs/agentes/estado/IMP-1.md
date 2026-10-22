# IMP-1 — Motor forense

## Hecho (últimas 24 h)
- h-007-verificar-relativo (sesión 3): H-007 (MEDIO, el de mayor impacto forense según TEST) resuelto.
  - forense/core/case.py: las evidencias DENTRO del caso se guardan ahora relativas a su raíz (como ya hacía
    analyses.output_dir); nuevo Case.disk_path() re-basa al abrir: relativo → raíz; absoluto in situ → tal cual
    (casos legados); absoluto con evidence/ o analyses/ → primero la copia de ESTA carpeta (caso copiado o movido),
    si no la registrada. Verificar, análisis, triaje y delete_analysis usan disk_path. Custodia anota details.path
    cuando un legado absoluto se re-basa (auditable).
  - Efecto: una copia (cp/rsync) de un caso verifica sus PROPIOS ficheros — manipularla da [FAIL] aunque el
    original siga intacto, y un caso movido deja de dar verify.missing.
  - tests/test_core.py: +4 (copia manipulada FAIL/original OK, movido OK, legado re-basado, externa absoluta).
    Suite: 310 passed, 1 skipped; ruff limpio.
- h-002 (antes en esta sesión): H-002 ALTO dispositioned como falso positivo de visualización (por bytes, en
  paralelo también por TEST en 32c7751); guardas: test_upgrade_keeps_the_volatility_extra + byte-pin en test_i18n.

## En curso
- (nada)

## Bloqueado
- artifact-bits (qmgr.db): sigue sin muestra real en tests/data; qmgr.db es ESE y no se sintetiza con honestidad.

## Peticiones a otras zonas
- TEST: verificar h-007 (4 tests nuevos) y h-002 (guardas); cerrar hallazgos si conforma.
- PUL: README es/en — documentar cómo mover/archivar un caso (portable copiando la carpeta; parte de H-007) y
  que el ejemplo de `conclusiones --archivo` muestre la creación previa del fichero (H-006, parte UX).
- DIR/humano: muestra real de qmgr.db (origen + licencia como SRUDB.dat) para artifact-bits.

## Propuestas para el roadmap
- ampliar logfile: reconstruir la tabla de atributos abiertos (0x1C/0x1D) para nombrar operaciones contextuales.
- En cola para próximas tandas: h-004 (predicado de descubrimiento en sueltos), h-005 (aviso de hash duplicado),
  h-006 (FileNotFoundError de conclusiones), h-009 (alias es/en de exportar), sigma-redos, intel-misp-opencti.
