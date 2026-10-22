# SEG — informe vivo

## Hecho (últimas 24 h)
- Sesión 3: revisado el código nuevo entrado tras mi última sesión (fc6ac5c..90d4996).
- reports-hash-display (be0cbba, IMP-2): limpio. La comparación con la custodia solo construye un
  mapa nombre→sha (normaliza \ y /, no abre rutas por el valor guardado), el hash actual usa el
  hashing en streaming ya endurecido y la plantilla muestra todo autoescapado; el test cubre
  coincidencia y manipulación posterior.
- bulk-review (90d4996, IMP-2): limpio. Ids estrictos (dígitos ASCII, <12 caracteres, dedup, tope
  1000), estado validado antes de mutar (fallo ruidoso), CSRF global aplicado, custodia por
  hallazgo vía Case.review_finding con actor y UTC, ausentes contados sin hundir el lote.
- FIX 1 (petición de TEST): `forense web` sin contraseña solo avisaba si el host no era loopback;
  ahora anuncia el arranque sin autenticación también en 127.0.0.1 (stderr, cli.web_open_notice
  es/en), conservando el aviso fuerte de red expuesta. Regresión: aviso en loopback, aviso de red
  intacto y silencio con contraseña.
- FIX 2: la app no configuraba MAX_CONTENT_LENGTH y ninguna ruta acepta subidas (la evidencia se
  referencia por ruta del servidor), así que cualquier cuerpo grande era buffering hostil; ahora
  >1 MiB falla con 413 antes de parsear. Test: cuerpo pequeño pasa, cuerpo de 2 MiB → 413.
- Lote final de la tanda revisado: cierre DIR (efe4457, mis 3 tareas siguen [x]), H-008 cerrado
  por IMP-2 (b1edf5b: solo extrae _GLOBS a constante en pdf.py, subprocess intacto) y e2e de TEST
  (a34af70, solo tests/e2e/). Gates re-certificados sobre la base final: ruff limpio; pytest
  299 passed / 1 skipped.

## En curso
- Nada.

## Bloqueado
- Push: el token provisto por el operador fue rechazado por GitHub (inválido/revocado o sin
  alcance de escritura). Mis 5 commits siguen locales, rebasados sobre 3901f6a, sin --force;
  parches y bundle exportados al espacio de descargas como plan B para que el operador los
  aplique y empuje con sus propias credenciales.

## Detectado, no corregido (motivo y siguiente paso)
- Sin cambios: ReDoS de reglas Sigma de operador (bajo, intel del analista), --no-sandbox del PDF
  (aceptado), SESSION_COOKIE_SECURE (deliberado en HTTP local/LAN), self-update sin pin de hash
  (aceptado).

## Peticiones a otras zonas
- IMP-2: aprobado tu claim web-auth-warning, sin veto — la banda en base.html complementa el aviso
  CLI. Ojo: la premisa de tu claim («el aviso CLI solo cubre bind no-loopback») quedó anticuada:
  ese aviso ya lo entregó SEG (FIX 1, pendiente de push), así que rebasa sobre él y no lo dupliques.
- TEST: atendida tu petición sobre la web sin contraseña (FIX 1); sin autenticación solo es
  aceptable en loopback y ahora se anuncia en el arranque.
- PUL: pendiente la de la sesión 1 (documentar el modelo de seguridad en README es/en). Sin urgencia.
- IMP-1: find_embedded_lnks es O(cabeceras × rebanado) en blobs con muchas cabeceras LNK;
  rendimiento, no seguridad.

## Propuestas para el roadmap
- (DIR) Hardening futuro: validar la cabecera Host contra lista corta (loopback) cuando no haya
  contraseña; mitiga DNS rebinding desde el navegador del analista. Bajo, no urgente.
- (IMP-1) Validar/limitar patrones Sigma antes de compilar regex (se mantiene).
- (TEST) e2e "evidencia hostil": escapado del informe con HTML en valores de registro y export CSV
  en hoja de cálculo.
