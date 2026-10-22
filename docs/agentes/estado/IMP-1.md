# IMP-1 — Motor forense

## Hecho (últimas 24 h)
- artifact-rdp-cache (sesión 3): módulo completo de RDP Bitmap Cache (Cache*.bin / bCache*.bin).
  - forense/modules/windows/rdp_cache.py (triage): valida el contenedor por estructura (cabecera 12 bytes;
    tile = Key1+Key2+Width+Height+BITMAPINFOHEADER 40 bytes+píxeles alineados a DWORD) y extrae cada tile
    como BMP independiente (artefacto del análisis). Filas "rdp_tile" (tile, key, dimensiones, bpp, offset,
    saved_to) + hallazgo LOW rdp_cache.historic_activity (ATT&CK T1021.001) por fichero con tiles. Sin
    marcas de tiempo: el contenedor no las lleva. Corrupción: un tile inválido corta la cadena conservando
    los previos; cabecera+basura o contenedor vacío → 0 tiles, sin error ni hallazgo.
  - forense/demo: build_rdp_cache + Cache0001.bin de la historia (4 tiles; movimiento lateral RDP saliente).
  - forense/core/attack.py: mapeo del hallazgo a T1021.001. tests: módulo demo, corrupción, triaje.
    Suite: 332 passed, 1 skipped; ruff limpio. Fila de README: petición a PUL.
- artifact-notifications (antes en esta sesión): módulo completo de wpndatabase.db (toasts: app, llegada,
  título y cuerpo), build_wpndatabase en demo, 3 tests; SQLite vía ReadOnlySqlite.
- h-007 + h-004 + h-002: verificar re-basado al caso (+4 tests), predicado de descubrimiento en sueltos y
  tool names <=3 letras con .exe (+3 tests), disposición por bytes de H-002 (+2 guardas).

## En curso
- (nada)

## Bloqueado
- artifact-bits (qmgr.db): sigue sin muestra real en tests/data; qmgr.db es ESE y no se sintetiza con honestidad.

## Peticiones a otras zonas
- PUL: dos filas nuevas en la tabla de módulos de ambos README:
  - notifications / Notificaciones de Windows (wpndatabase.db) / apps emisoras, llegada, títulos y cuerpos.
  - rdp_cache / Caché RDP (Bitmap Cache) / tiles del escritorio remoto, evidencia de sesiones RDP salientes.
  Módulos: 22 de Windows (27 en total). Además: documentar cómo mover/archivar un caso (H-007) y que el
  ejemplo de `conclusiones --archivo` muestre la creación previa del fichero (H-006, parte UX).
- TEST: verificar h-007 (4 tests), h-004 (3), artifact-notifications (3) y artifact-rdp-cache (2 + triaje).
- DIR/humano: muestra real de qmgr.db (origen + licencia como SRUDB.dat) para artifact-bits.

## Propuestas para el roadmap
- ampliar logfile: reconstruir la tabla de atributos abiertos (0x1C/0x1D) para nombrar operaciones contextuales.
- En cola: h-005 (aviso hash duplicado), h-006 (FileNotFoundError de conclusiones), h-009 (alias es/en de
  exportar), sigma-redos, intel-misp-opencti.
