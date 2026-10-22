# IMP-1 — Motor forense

## Hecho (últimas 24 h)
- Sesión 4, cinco tareas completadas (suite al cerrar: 368 passed, 1 skipped; ruff limpio):
  - h-005 (1f94986): aviso de evidencia duplicada. `Case.find_duplicate(hashes)` (primera evidencia con la
    misma SHA-256); `add_evidence` lo expone en `Evidence.duplicate_of` (transitorio, no persistido) y
    `evidencia agregar` emite por stderr, en el idioma de sesión, "Aviso: contenido idéntico a EV-001
    (SHA-256 …); el registro continúa". stdout limpio; ficheros y directorios; 4 tests.
  - h-006 (0606ea2): `conclusiones --archivo` ya no escapa el error de Python: FileNotFoundError →
    "El archivo {file} no existe: redáctelo primero…" localizado; OSError/UnicodeDecodeError → "No se puede
    leer {file}". Ayuda de --texto/--archivo traducida y aclarada (el fichero es ENTRADA). 1 test (es/en/binario).
  - h-009 (8383161): `exportar` acepta los términos es/en de su propia ayuda: hallazgos, cronologia,
    custodia, ejecucion, analisis, también con tilde, y los ingleses; validación manual con error localizado
    (adiós al "invalid choice" de argparse); metavar neutro y claves cli.export_targets/error.export_what.
    1 test (4 destinos + tilde + error es/en).
  - h-010 (2254b95): `informe --firmar/--sign` — mismo camino de firma que la web (generate_report(sign=True),
    y html_to_pdf(sign=True) con --pdf), mensaje "Informe firmado: {sig}" por fichero, custodia con huella y
    fingerprint; sin --firmar no hay .sig aunque la clave esté definida. Tests: .sig válido, verificación OK,
    manipulación detectada, entrada report_signed en custodia.
  - sigma-redos (65dd311): guardia estructural ReDoS para el modificador `|re` ANTES de compilar: longitud
    ≤ 1024, {n,m} ≤ 1000, backreference cuantificado, y cuantificador aplicado a grupo cuyo cuerpo contiene
    cuantificador o alternancia — con presupuesto de ramificación (64) que deja pasar las formas acotadas
    legítimas (regex de IP, MAC). Rechazo conservador → SigmaError → el cargador lo convierte en error por
    regla: una regla hostil es un error de carga, nunca un escaneo colgado. 24 tests nuevos (10 formas
    hostiles, 8 seguras que siguen compilando y casando, carga e2e con paquete mixto).

## En curso
- (nada)

## Bloqueado
- artifact-bits (qmgr.db): sigue sin muestra real en tests/data; qmgr.db es ESE y no se sintetiza con honestidad.

## Peticiones a otras zonas
- TEST: verificar h-005, h-006, h-009, h-010 (H-007 seguía pendiente de esta tanda) y sigma-redos. Nota:
  los cuatro primeros cambian salida de CLI (stderr/stdout) y exit codes intactos (EXIT_OK/EXIT_ERROR).
- PUL: nada nuevo (el ejemplo de conclusiones del README ya lo cubriste en readme-h006-conclusiones).
- DIR: artifact-rdp-cache y artifact-notifications siguen marcadas [ ] en ROADMAP aunque están entregadas y
  descritas en este informe — recordar marcarlas cuando TEST las verifique.

## Propuestas para el roadmap
- intel-misp-opencti (en ROADMAP, sin asignar ronda): importación MISP de IOCs hacia la lista de vigilancia
  de `ioc` y correlación; la dejo para una sesión dedicada completa.
- ampliar logfile: reconstruir la tabla de atributos abiertos (0x1C/0x1D) para nombrar operaciones contextuales.
