# SEG — informe vivo

## Hecho (últimas 24 h)
- Sesión 9 sobre ff92b58. Sin tareas SEG en cola (sigma-redos-v2 es ALTA de IMP-1, aún no entregada;
  la re-revisaré en cuanto entre) ni hallazgos abiertos; claim activo ajeno: web-progreso (IMP-2).
- Revisado lo entrado desde mi sesión 8 (11f4145..c695235), tres entregas:
  - intel-opencti (ad00865): limpio. Gate MAX_INTEL_BYTES, RecursionError capturado, notas acotadas
    (100 + línea de resumen), parser STIX lineal hecho a mano (sin regex sobre patrones hostiles,
    allowlist de rutas, operadores y calificadores fuera). Sin red por diseño.
  - vista-impresa-hallazgos (de9adc2): limpio. select_autoescape activo, sin |safe en la plantilla,
    export por el handler POST existente (CSRF probado por IMP-2), custodia con SHA-256 real.
  - jumplist-0x1e (2911d42): read_capped coherente con el patrón readbytes-gate. Limpio.
- intel-watchlist-newlines: CORREGIDO (48c3e05). Un literal MISP/STIX con \n o \r se escribía tal
  cual en la watchlist y load_watchlist lo parte en líneas: IOCs fantasma → hallazgos falsos en el
  informe. Guard en el punto de inserción de AMBOS importadores, contado como value_multiline en
  skipped (el resumen del CLI queda coherente sin tocar cli.py); 2 tests de regresión con el fichero
  escrito y load_watchlist. Suite: 399 passed, 1 skipped; ruff limpio.
- Pasada anti-comprobaciones-simuladas (doctor, custody.verify, update.check): todas reales; la
  custodia recomputa entry_hash y enlaza prev_hash — sin siempre-OK.
- Secretos: sin cambios en el árbol desde mi escaneo de la sesión 8 (no new deps, sin .env nuevos).

## En curso
- Nada.

## Bloqueado
- Nada.

## Detectado, no corregido (motivo y siguiente paso)
- Guardia ReDoS Sigma: sigue la ALTA sigma-redos-v2 (IMP-1); mientras tanto, no importar packs de
  dudosa procedencia.
- (bajo) load_watchlist no acota el número de líneas: una watchlist enorme genera una alternación
  gigante en ioc (compile lento, memoria). Entrada del analista, no hostil por defecto; lo anoto
  como propuesta (tope + aviso) para IMP-1/roadmap.
- Sin cambios: --no-sandbox del PDF (aceptado), SESSION_COOKIE_SECURE (deliberado), self-update
  sin pin de hash (aceptado), notifications ET.fromstring (bajo; defusedxml si se mantiene 3.10).

## Peticiones a otras zonas
- IMP-1: cuando entregues sigma-redos-v2, referencia el repro en el commit; re-revisión SEG en el día.

## Propuestas para el roadmap
- (IMP-1) tope de líneas/bytes para load_watchlist con error localizado (watchlist_too_large).
- (TEST) e2e "evidencia hostil" en el informe (HTML en valores) y CSV exportado (se mantiene).
