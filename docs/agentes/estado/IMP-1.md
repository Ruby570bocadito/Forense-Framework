# IMP-1 — Motor forense

## Hecho (últimas 24 h)
- artifact-notifications (sesión 3): módulo completo de notificaciones de Windows (wpndatabase.db).
  - forense/modules/windows/notifications.py (triage): une Notification con NotificationHandler (AUMID),
    decodifica el payload del toast (XML UTF-16LE/UTF-8 con tolerancia a binario y a escapes) y saca
    título/cuerpo, llegada y caducidad (FILETIME → UTC). Filas "notification" + evento por toast en la
    superlínea; resumen notifications y per_app. Sin hallazgos inventados: los textos son lo que el usuario
    VIO, no la verdad. SQLite siempre vía ReadOnlySqlite (copia temporal, jamás se abre in situ).
  - Tolerancia: truncado real → 1 error y sigue; no-SQLite → lo rechaza el predicado (is_sqlite); esquema
    sin tablas esperadas → degradación a la tabla desnuda; payload binario → campos vacíos, sin excepción.
  - forense/demo: build_wpndatabase + 4 toasts coherentes con la historia (phishing "Factura_0914.pdf",
    chat del ZIP de clientes, aviso de Defender); tests de módulo (demo, corrupción, variantes de payload)
    y triaje demo. Suite: 319 passed, 1 skipped; ruff limpio. Fila de README: petición a PUL.
- h-007 + h-004 (antes en esta sesión): verificar re-basado a la raíz del caso (+4 tests) y predicado de
  descubrimiento también para ficheros sueltos + tool names <=3 letras exigen .exe (+3 tests).
- h-002: disposición por bytes (falso positivo de visualización, también cerrado por TEST en 32c7751) + 2 guardas.

## En curso
- (nada)

## Bloqueado
- artifact-bits (qmgr.db): sigue sin muestra real en tests/data; qmgr.db es ESE y no se sintetiza con honestidad.

## Peticiones a otras zonas
- PUL: fila nueva en la tabla de módulos de ambos README: "notifications / Notificaciones de Windows
  (wpndatabase.db) / apps emisoras, títulos y cuerpos". Módulo nº 20 de Windows (25 en total).
- TEST: verificar h-007 (4 tests), h-004 (3 tests) y artifact-notifications (3 tests + triaje demo).
- DIR/humano: muestra real de qmgr.db (origen + licencia como SRUDB.dat) para artifact-bits.

## Propuestas para el roadmap
- ampliar logfile: reconstruir la tabla de atributos abiertos (0x1C/0x1D) para nombrar operaciones contextuales.
- En cola: artifact-rdp-cache (esta sesión, en cola), h-005 (aviso hash duplicado), h-006 (FileNotFoundError
  de conclusiones), h-009 (alias es/en de exportar), sigma-redos, intel-misp-opencti.
