# IMP-1 — Motor forense

## Hecho (últimas 24 h)
- Sesión 6, cuatro entregas (suite al cerrar: 415 passed, 1 skipped; ruff limpio):
  - intel-opencti (ad00865): `forense intel opencti BUNDLE.json [-o OUT]` convierte un bundle STIX 2.1
    de OpenCTI en watchlist para `ioc`, misma filosofía que MISP: sin red, sin claves en el caso. Solo
    patrones de igualdad simple `[ruta = 'literal']` con rutas conocidas (hashes STIX 2.0/2.1,
    domain-name, hostname, ipv4/ipv6, url, email-addr, windows-registry-key, network-traffic
    src/dst_ref.value, file:name, user-agent); todo lo demás contado en skipped sin adivinar
    (AND/OR/LIKE/IN/!=, pattern_type no-STIX, revoked, objetos no indicador, malformed). Notas de
    procedencia por indicador usado con labels/nombre/fecha, tope 100 + línea de resumen. Duplicados
    por valor en cualquier mayúscula, hashes en minúsculas, la salida no pisa la entrada, tope de
    tamaño compartido MAX_INTEL_BYTES (renombrado desde MAX_MISP_BYTES). Errores es/en: intel_opencti_
    invalid/too_large/empty; ayuda de `intel` actualizada (misp|opencti). 7 tests nuevos.
  - jumplist-0x1e (2911d42): parse_custom pasa por read_capped (256 MB): un customDestinations-ms
    crecido u hostil es error de análisis del módulo, no presión de memoria. Test con fichero sparse
    a nivel de parser y a nivel de módulo.
  - sigma-redos-v2 (eb1cf54): guardia ReDoS reescrita con presupuesto global de ambigüedad Σ bits
    (iteraciones × log2(ramificación), recursión en grupos cuantificados: los bits del cuerpo suben
    al exponente) + flag de cuerpo salvaje que propaga por grupos transparentes. Las 8 familias de
    SEG (sesión 8) se rechazan en <0,2 ms antes de compilar; `(a?){22}X` medido en el motor real:
    3,4 s (antes la guardia lo dejaba pasar). Los 9 patrones seguros siguen casando y el lookahead
    `(?=a+(a+)+)` ahora también se rechaza. 7 casos nuevos en la parametrización de rechazos.
  - h-013-vigilar-once-banner (5982bb9): `vigilar --una-vez` anuncia "Pase único sobre {inbox}…"
    (clave nueva cli.watch_once es/en) en lugar del banner continuo con intervalo y Ctrl+C.
    Regresión es/en en test_cli_watch_once. Hallazgo en resuelto-pendiente-verificación.
- H-012 (ALTO): NO reproducible a nivel de byte. Las 6 claves de locales y update.py:82 contienen el
  extra correcto (con corchete y m; verificado byte a byte) y test_memory_extra_spec_is_byte_intact
  pasa. Lo que se perdió es la secuencia de corchete+m en el CANAL de visualización/copia entre el
  agente y el analista (el mismo de H-001/H-002/H-003: el texto del propio hallazgo llegó comido).
  El producto está intacto; "restaurar" el literal lo corrompería con un doble m. Sin cambio de código.

## En curso
- (nada)

## Bloqueado
- artifact-bits (qmgr.db): sin muestra real en tests/data; reactivar cuando entre con origen y licencia.

## Peticiones a otras zonas
- TEST: verificar sigma-redos-v2 (las familias de estado/SEG.md sesión 8 deben dar error de carga),
  intel-opencti (comando nuevo: bundle válido es/en, salida por defecto BUNDLE.watchlist.txt, -o = la
  entrada se rechaza, JSON roto, pattern_type sigma contado como skipped, watchlist conectada a `ioc`)
  y h-013; y CERRAR H-012 como no reproducible tras la comprobación byte a byte
  (`python -m pytest tests/test_i18n.py::test_memory_extra_spec_is_byte_intact`).
- DIR: la cola aún lista sigma-redos-v2 como abierta: entregada en eb1cf54 (la ALTA de SEG sesión 8).
  Marcar [x] sigma-redos-v2, intel-opencti, jumplist-0x1e y h-013 cuando TEST verifique.
- PUL: la tabla CLI del README puede mencionar `forense intel misp|opencti` (A1 cubrió solo misp).

## Propuestas para el roadmap
- h-014-caso-solo-lectura (MEDIO) es la siguiente tarea IMP-1 de la cola; requiere distinguir
  "readonly database" del error genérico de BD dañada y no escribir al abrir en órdenes de lectura.
- (se mantiene) H4 intel-hashlists (NSRL/CSV/hashdeep) como siguiente pieza barata del eje H.
