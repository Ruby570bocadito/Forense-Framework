# SEG — informe vivo

## Hecho (últimas 24 h)
- Sesión 6: revisado lo entrado desde mi cierre de la sesión 5 (80eff17..cc02c18, 11 commits).
- H-005 (1f94986, IMP-1): limpio. Aviso de evidencia duplicada por stderr (no contamina stdout
  pipeable), búsqueda previa al INSERT (la fila nueva no puede auto-coincidir), `duplicate_of`
  transitorio sin migración de esquema. La carrera concurrente queda documentada como
  mejor-esfuerzo: el aviso no bloquea y la integridad nunca depende de él.
- web-filtros-guardados (e7962a7, IMP-2): limpio. Query con allowlist por página (un formulario
  forjado no puede colar parámetros), cotas (20 filtros, nombre 80, query 500), escritura atómica
  tmp+os.replace, carga defensiva (fichero dañado nunca rompe la página), CSRF global en ambos
  POST, filter_id con regex estricta [0-9a-f]{8}, redirect vía _back(url_for validado), plantilla
  100% autoescapada y sin JS (CSP-clean). La Host-guard anti-rebinding aplica a las rutas nuevas;
  url_for(f.page) acotado por el filtro de load(). ui/saved_filters.json fuera de custodia: OK.
- TEST ronda 4 (5262232/b23ef20): e2e de copia que se verifica a sí misma y timeline-export-html
  con HTTP real, CSRF, escapado hostil y custodia; buen valor de regresión. H-007 queda cerrado.
- h-006 (0606ea2, IMP-1), entregado durante la sesión y revisado: limpio — lectura de --archivo
  con errores localizados vía ForenseError, sin traceback crudo; inserts de locale quirúrgicos.
- Gates: ruff limpio; pytest 343 passed / 1 skipped (re-certificado sobre la base final).

## En curso
- Nada.

## Bloqueado
- Nada.

## Detectado, no corregido (motivo y siguiente paso)
- Sin cambios: ReDoS de reglas Sigma de operador (bajo), --no-sandbox del PDF (aceptado),
  SESSION_COOKIE_SECURE (deliberado), self-update sin pin de hash (aceptado).
- Gate central de tamaño para el patrón read_bytes() común de los módulos (IMP-1/DIR, cross-module).
- (bajo) notifications: ET.fromstring sobre payload hostil; con expat >= 2.4 el riesgo es menor;
  valorar defusedxml si se mantiene soporte 3.10 con expat antiguo.

## Peticiones a otras zonas
- IMP-1/DIR: contención explícita (resolve + parents) para rutas relativas en disk_path (bajo).
- PUL: sugerencias de contenido para readme-modelo-seguridad siguen en el estado de la sesión 4.

## Propuestas para el roadmap
- (IMP-1) Validar/limitar patrones Sigma antes de compilar regex (se mantiene; ya está en ROADMAP).
- (TEST) e2e "evidencia hostil" en el informe (HTML en valores) y CSV exportado (se mantiene).
