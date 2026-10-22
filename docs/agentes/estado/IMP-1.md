# IMP-1 — Motor forense

## Hecho (últimas 24 h)
- Sesión 5, cuatro tareas completadas (suite al cerrar: 380 passed, 1 skipped; ruff limpio):
  - intel-misp-opencti (2b1fb2f): `forense intel misp EXPORT.json [-o OUT]` convierte una exportación
    JSON de MISP (evento único, `response` o lista de eventos) en una watchlist para `ioc`: un indicador
    por línea, eventos origen como comentarios `#` de procedencia, hashes normalizados, puertos
    separados de las IP, atributos borrados fuera y tipos desconocidos contados como skipped. Sin red
    por diseño: ni URL de instancia ni clave de API llegan al caso. Los tipos mapeados: md5/sha1/
    sha256/sha512, ip-src/dst (con |port), domain/hostname (y |ip), url/uri/link, email, filename
    (solo el hash de filename|hash), regkey, user-agent. La exportación vacía de indicadores usables
    es error localizado; la salida no puede pisar la entrada. Por `ioc.watchlist_match` los indicadores
    llegan a la correlación entre casos (collect_indicators ya los exporta como STIX). Errores
    localizados es/en: intel_input_missing, intel_misp_invalid, intel_misp_too_large (256 MB),
    intel_misp_empty, intel_output_is_input. 6 tests (tests/test_intel.py), incl. e2e con el módulo ioc.
  - refs-rama-heredada (14305d5): `update.REFS = ("main",)`; la rama de desarrollo retirada deja de
    consultarse como fallback de `forense update`. Guarda de regresión en test_notify_update.
  - logfile-atributos (9267745): las operaciones de nivel de atributo (0x05-0x09, 0x0B) ya se reportan.
    `OpenAttributes` reconstruye la tabla de atributos abiertos mientras se recorre el diario: el 0x1C
    registra entradas (OPEN_ATTRIBUTE_ENTRY v1.0+ en redo: allocated@0, type@8, referencia@0x10; nombre
    del atributo en el undo), los volcados de checkpoint 0x1D/0x1E responden por offset en bytes como
    fallback (los índices de tablas de reinicio son offsets), y una entrada rota sólo invalida la parte
    incremental (comportamiento de la referencia). Filas nuevas con campo `attribute` ("$DATA",
    "$DATA (J)", "type_0x..." para códigos raros) y el nombre del fichero si el diario ya lo nombró.
    Constantes verificadas contra ntfslog.h (NT4) y dfir_ntfs (msuhanov). Demo: el $DATA de svchost.exe
    se abre para actualización (0x1C) antes de su cambio de mapping pairs — la fila 0x09 sale ahora
    atribuida. 2 tests de parser nuevos; test de módulo actualizado (records 5, named 3, contextual 1).
  - readbytes-gate (0221fdc): `read_capped(path, limit)` en core.utils, gate central del patrón
    read_bytes de los módulos; `FileTooLarge` es un ValueError, así los except (OSError, ValueError)
    existentes siguen funcionando. Adoptado por psreadline, defender, lnk, tasks y recyclebin (mismo
    comportamiento); rdp_cache y setupapi ganaban un tope que no tenían (256 MB) y reportan la negativa
    como error de análisis en vez de descartar en silencio un fichero que decía ser un artefacto. Tests
    con ficheros sparse: el gate dispara por tamaño lógico, nada se materializa.

## En curso
- (nada)

## Bloqueado
- artifact-bits (qmgr.db): sigue sin muestra real en tests/data; qmgr.db es ESE y no se sintetiza con
  honestidad. Reactivar cuando DIR/humano traiga muestra con origen y licencia.

## Peticiones a otras zonas
- TEST: verificar las cuatro tareas de esta tanda. Notas: `forense intel misp` es un comando nuevo
  (ayuda localizada es/en, exit codes estándar; probar con JSON roto, vacío y con tipos raros);
  logfile cambia la SALIDA del módulo (filas nuevas con campo attribute, summary con contador
  `contextual`; el e2e de texto del demo muestra la fila update_mapping_pairs atribuida);
  readbytes-gate cambia el comportamiento de errores de rdp_cache y setupapi con ficheros gigantes
  (antes se leían enteros, ahora error de análisis).
- PUL: la fila del módulo `logfile` del README dice "soporte básico: operaciones con nombre" — ahora
  también salen las operaciones de atributos vía tabla de atributos abiertos; ampliar la descripción
  es/en si procede. Y `forense intel misp` podría merecer mención en la sección CLI.
- DIR: marcar [x] intel-misp-opencti, refs-rama-heredada, logfile-atributos y readbytes-gate cuando
  TEST verifique.

## Propuestas para el roadmap
- puerta del 0x1E en el parser jumplist: `parse_custom` lee el fichero entero sin tope (fuera del
  alcance de readbytes-gate, que era módulos/core); pequeño trabajo a falta de otra cosa.
- intel-opencti: segunda mitad de la tarea del ROADMAP (colecciones OpenCTI → watchlist), cuando
  MISP haya rodado una tanda de verificación.
