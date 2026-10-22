# SEG — informe vivo

## Hecho (últimas 24 h)
- Sesión 4: revisado lo entrado desde mi cierre de la sesión 3 (5be5d96..b9ed4f2).
- report-correlation (06bf996, IMP-2): limpio. La sección nueva del informe solo reutiliza
  core/correlation.py, se acota a 100 filas, nunca rompe el informe (except defensivo sobre un
  bonus) y toda la plantilla queda autoescapada (display, nombres y slugs de casos). El texto
  mantiene el invariante «indicio, no conclusión». Tests de sección ausente/presente incluidos.
- h-002 (cd740c5, IMP-1) y readme h-006 (86be1d6, PUL): solo test/README. Nada que objetar.
- FIX 3 (propuesta SEG de la sesión 3, entregada): guardia anti DNS-rebinding en la web. Sin
  contraseña, before_request rechaza con 403 todo Host que no sea loopback (localhost,
  127.0.0.1, ::1) o IP literal (no rebind-eable); /healthz exento (sonda sin datos, nombres DNS
  de servicio en contenedores); con contraseña no se aplica (Basic no se re-envía entre
  orígenes). Cierra lectura del caso y robo del token CSRF desde una página maliciosa rebind-eada.
  Claves web.host_forbidden es/en; tests: hosts permitidos, prohibidos, healthz y modo con clave.
- Gates sobre la propuesta: ruff limpio; pytest 309 passed / 1 skipped.

## En curso
- Nada.

## Bloqueado
- Nada.

## Detectado, no corregido (motivo y siguiente paso)
- Sin cambios: ReDoS de reglas Sigma de operador (bajo, intel del analista), --no-sandbox del PDF
  (aceptado), SESSION_COOKIE_SECURE (deliberado en HTTP local/LAN), self-update sin pin de hash
  (aceptado).

## Peticiones a otras zonas
- PUL: para readme-modelo-seguridad, sugiero cubrir: evidencia solo lectura (copia + hash),
  descubrimiento ≠ conclusión (estados de revisión), UTC, secretos fuera del caso (clave de firma
  por entorno, webhook por URL), autenticación web opcional + avisos (CLI y banda), guardia de
  Host, firma Ed25519 de informes y safe_load/sin shell. Lo que aplique al usuario final.
- IMP-1: find_embedded_lnks es O(cabeceras × rebanado) en blobs con muchas cabeceras LNK;
  rendimiento, no seguridad.

## Propuestas para el roadmap
- (IMP-1) Validar/limitar patrones Sigma antes de compilar regex (se mantiene; ya está en ROADMAP).
- (TEST) e2e "evidencia hostil" en el informe (HTML en valores de registro) y CSV exportado.
