# SEG — informe vivo

## Hecho (últimas 24 h)
- Sesión 5: revisado lo entrado desde mi cierre de la sesión 4 (6332a6f..39e8bf2) y el gap de
  h-007 que se me coló en la ventana de la sesión anterior.
- h-007 (dfe9cde, IMP-1): limpio. `disk_path` re-basa la verificación al caso (copias se
  verifican a sí mismas): contención exacta por `parents` (sin startswith débil), heurística de
  re-basado solo con marcadores evidence/analyses y exigencia de existencia; fallback a la ruta
  original (verify reportará ausente, sin excepción). Tests: copia manipulada FAIL, caso movido
  OK, registro relativo, externo. Nota baja: contención explícita de rutas relativas como
  endurecimiento futuro (el modelo de confianza en la DB no cambia).
- timeline-export-html (bfea922, IMP-2): limpio. Valores crudos → plantilla autoescapada, nombre
  de fichero del servidor (stamped_path), custodia export_created+sha256, documento sin JS ni
  recursos externos, botón con formaction (CSP-clean), ruta export/<what> con 404 para desconocidos.
- rdp-cache (a487698, IMP-1): limpio. El regex de descubrimiento valida el nombre ANTES de usarlo
  en la ruta de salida del tile (sin traversal posible), cotas por tile (2048 px, bpp 16/24/32,
  65535 tiles) y sin amplificación: cada tile debe existir en la entrada (salida ≈ entrada).
  Tile corrupto corta la cadena (semántica documentada, coherente con usnjrnl).
- notifications (740b11c, IMP-1): limpio. ReadOnlySqlite + is_sqlite, textos con heurística de
  imprimibilidad y ET.fromstring (nota baja abajo).
- h-004 (ac01ed1, IMP-1): endurecimiento positivo — find_files aplica el predicado también a
  ficheros sueltos (bytes aleatorios hostiles ya no se analizan sin identidad) y nombres cortos
  de herramientas exigen .exe (adiós falsos HIGH).
- Gates: ruff limpio; pytest 332 passed / 1 skipped.

## En curso
- Nada.

## Bloqueado
- Nada.

## Detectado, no corregido (motivo y siguiente paso)
- Sin cambios: ReDoS de reglas Sigma de operador (bajo), --no-sandbox del PDF (aceptado),
  SESSION_COOKIE_SECURE (deliberado), self-update sin pin de hash (aceptado).
- Lectura completa con read_bytes() es el patrón común de los módulos (8 ficheros): un gate
  central de tamaño sería tarea cross-module (IMP-1/DIR), no fixes dispersos. Riesgo: OOM con
  evidencia plantada gigante; impacto análisis, no integridad.
- (bajo) notifications usa ET.fromstring sobre el payload hostil: expat >= 2.4 (default en
  builds modernos) limita billion-laughs; si se soporta 3.10 con expat antiguo, valorar defusedxml.

## Peticiones a otras zonas
- IMP-1/DIR: contención explícita (resolve + parents) para rutas relativas en disk_path,
  como endurecimiento futuro de h-007. Bajo, no urgente.
- PUL: si readme-modelo-seguridad sigue en marcha, mis sugerencias de contenido están en el
  estado de la sesión 4.

## Propuestas para el roadmap
- (IMP-1) Validar/limitar patrones Sigma antes de compilar regex (se mantiene; ya está en ROADMAP).
- (TEST) e2e "evidencia hostil" en el informe (HTML en valores) y CSV exportado (se mantiene).
